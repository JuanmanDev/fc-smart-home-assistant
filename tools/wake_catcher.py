"""Wake-window catcher for the FC L5 WiFi lock.

Runs INSIDE the HA container (host network) on the LAN:

    docker exec -w /config homeassistant python3 wake_catcher.py --minutes 12

What it does while you wake the lock (bell / 4 + #):
  1. Every 1.5s pokes the MXCHIP candidate IPs (UDP discard poke -> ARP)
     and fires an Alink discovery broadcast on UDP 5683.
  2. Every 5s polls the cloud (getDevice) watching alive / messagetime /
     onlinetime / state.
  3. The INSTANT the lock shows up (ARP MAC resolves, Alink reply, or cloud
     alive flips to 1):
       - fires /v2/lock/openLock (cloud) repeatedly while it stays online
       - LAN: Alink unicast discover (grabs productKey/deviceName), CoAP
         GET / + CoAP ping, TCP port scan (80, 443, 8002, 8060, 9999, 8666)
       - if pk/dn learned: thing.deviceInfo.get + property.get
         (+ thing.service.unlock only with --try-unlock)
  4. Everything is timestamped; window open/close durations are summarized.

Credentials come from the fc_smarthome config entry in HA's .storage —
nothing secret is passed on the command line.
"""

import argparse
import asyncio
import contextlib
import json
import random
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "/config")
from custom_components.fc_smarthome.api.client import FcClient
from custom_components.fc_smarthome.api.endpoints import EndpointRegistry
from custom_components.fc_smarthome.api.errors import FcError
from custom_components.fc_smarthome.api.models import TokenPair
from custom_components.fc_smarthome.local.alink import (
    COAP_GET,
    COAP_PORT,
    AlinkLanDevice,
    CoapMessage,
)

CANDIDATE_IPS = ["192.168.3.90", "192.168.3.91", "192.168.3.92"]
LOCK_OUI = "b0:f8:93"
# Confirmed via DHCP-grant vs cloud-event correlation:
#   .92 / b0:f8:93:91:79:b6 = THE LOCK.  .91 is an always-on MiCO gadget.
BORING_MACS = {"b0:f8:93:02:52:55", "04:78:63:85:4c:8b"}
TCP_PORTS = [80, 443, 8002, 8060, 9999, 8666]

LOG_F = open("/config/wake_catcher.log", "a", encoding="utf-8")


def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}"
    print(line, flush=True)
    LOG_F.write(line + "\n")
    LOG_F.flush()


def load_entry_data() -> dict:
    """Credentials from the fc_smarthome config entry in HA .storage."""
    storage = Path("/config/.storage/core.config_entries")
    entries = json.loads(storage.read_text(encoding="utf-8"))["data"]["entries"]
    for entry in entries:
        if entry.get("domain") == "fc_smarthome":
            return entry.get("data") or {}
    raise SystemExit("no fc_smarthome config entry found in .storage")


def read_arp() -> dict:
    out = {}
    try:
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) >= 4:
                out[f[0]] = (f[3], f[2])  # mac, flags
    except OSError:
        pass
    return out


class Catcher:
    def __init__(self, args) -> None:
        self.args = args
        self.client: FcClient | None = None
        self.device_id = args.device or ""
        self.poke_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.disc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.disc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.disc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.disc_sock.setblocking(False)
        self.coap_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.coap_sock.setblocking(False)
        # state
        self.engaged = False
        self.first_seen = 0.0
        self.last_seen = 0.0
        self.last_ip = ""
        self.last_lan_probe = 0.0
        self.pk = ""
        self.dn = ""
        self.last_cloud = {}
        self.last_cloud_ts = 0.0
        self.cloud_backoff = 0.0
        self.openlock_fires = 0

    # ---------- LAN ----------

    def poke_candidates(self) -> None:
        for ip in CANDIDATE_IPS:
            with contextlib.suppress(OSError):
                self.poke_sock.sendto(b"\x00", (ip, 9))

    def send_discover(self) -> None:
        probe = json.dumps(
            {"id": random.randint(1, 2**31), "version": "1.0", "method": "discover"}
        ).encode()
        for target in ("255.255.255.255", "192.168.3.255", "192.168.0.255"):
            with contextlib.suppress(OSError):
                self.disc_sock.sendto(probe, (target, COAP_PORT))

    async def drain_discover(self, window: float = 0.05) -> list:
        found = []
        loop = asyncio.get_running_loop()
        end = loop.time() + window
        while loop.time() < end:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(self.disc_sock, 4096),
                    timeout=max(0.02, end - loop.time()),
                )
            except asyncio.TimeoutError:
                break
            except OSError:
                break
            entry = {"ip": addr[0], "port": addr[1], "raw": data.hex()}
            try:
                entry["payload"] = json.loads(data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            found.append(entry)
        return found

    async def arp_sighting(self) -> tuple[str, str] | None:
        self.poke_candidates()
        await asyncio.sleep(0.35)  # give ARP a moment
        arp = read_arp()
        for ip in CANDIDATE_IPS:
            mac, flags = arp.get(ip, ("", ""))
            if mac and mac != "00:00:00:00:00:00" and flags == "0x2":
                if mac.lower() not in BORING_MACS:
                    return ip, mac
        for ip, (mac, flags) in arp.items():
            if mac.lower().startswith(LOCK_OUI) and flags == "0x2":
                if mac.lower() not in BORING_MACS:
                    return ip, mac
        return None

    async def coap_get_root(self, ip: str) -> str:
        loop = asyncio.get_running_loop()
        msg = CoapMessage(code=COAP_GET, msg_id=random.randint(1, 0xFFFF),
                          token=bytes([random.randrange(256), random.randrange(256)]))
        try:
            await loop.sock_sendto(self.coap_sock, msg.encode(), (ip, COAP_PORT))
            data, _ = await asyncio.wait_for(
                loop.sock_recvfrom(self.coap_sock, 4096), timeout=1.5
            )
            reply = CoapMessage.decode(data)
            code = f"{reply.code >> 5}.{reply.code & 0x1F}"
            return f"CoAP reply {code} type={reply.mtype} payload={reply.payload[:80].hex()}"
        except (asyncio.TimeoutError, OSError) as err:
            return f"CoAP no reply ({type(err).__name__})"

    async def tcp_scan(self, ip: str) -> list:
        open_ports = []
        for port in TCP_PORTS:
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=0.6
                )
                w.close()
                open_ports.append(port)
            except Exception:  # noqa: BLE001
                pass
        return open_ports

    async def lan_probe(self, ip: str) -> None:
        log(f"LAN PROBE of {ip} ...")
        # unicast discover
        probe = json.dumps(
            {"id": random.randint(1, 2**31), "version": "1.0", "method": "discover"}
        ).encode()
        loop = asyncio.get_running_loop()
        with contextlib.suppress(OSError):
            await loop.sock_sendto(self.disc_sock, probe, (ip, COAP_PORT))
        replies = await self.drain_discover(window=1.5)
        for r in replies:
            log(f"  discover reply from {r['ip']}: {r}")
            pay = r.get("payload")
            if isinstance(pay, dict):
                self.pk = str(pay.get("productKey") or "")
                self.dn = str(pay.get("deviceName") or "")
                if self.pk or self.dn:
                    log(f"  LEARNED pk={self.pk!r} dn={self.dn!r}")
        log("  " + await self.coap_get_root(ip))
        ports = await self.tcp_scan(ip)
        log(f"  TCP open ports on {ip}: {ports if ports else 'none'}")
        if self.pk and self.dn:
            dev = AlinkLanDevice(ip, product_key=self.pk, device_name=self.dn, timeout=3.0)
            for name, coro in (
                ("deviceInfo.get", dev.get_device_info()),
                ("property.get", dev.get_property()),
            ):
                try:
                    log(f"  Alink RPC {name}: {await coro}")
                except Exception as err:  # noqa: BLE001
                    log(f"  Alink RPC {name} FAILED: {err}")
            if self.args.try_unlock:
                try:
                    log(f"  Alink UNLOCK: {await dev.unlock()}")
                except Exception as err:  # noqa: BLE001
                    log(f"  Alink UNLOCK FAILED: {err}")

    # ---------- cloud ----------

    async def cloud_poll(self) -> None:
        now = time.monotonic()
        if now < self.cloud_backoff:
            return
        try:
            dev = await self.client.get_device(self.device_id)
            raw = dev.raw if dev else {}
            cat = raw.get("deviceCategory") or {}
            cur = {
                "alive": cat.get("alive"),
                "messagetime": raw.get("messagetime"),
                "onlinetime": raw.get("onlinetime"),
                "state": raw.get("state"),
                "message": raw.get("message"),
            }
            if cur != self.last_cloud:
                for k, v in cur.items():
                    if self.last_cloud and v != self.last_cloud.get(k):
                        log(f"CLOUD {k}: {self.last_cloud.get(k)!r} -> {v!r}")
                        if k == "messagetime":
                            # lock just pushed an event — it is online NOW
                            await self.fire_openlock(reason="cloud messagetime")
                self.last_cloud = cur
                log(f"CLOUD snapshot: {cur}")
            self.last_cloud_ts = now
            if cat.get("alive") == 1:
                await self.fire_openlock(reason="cloud alive=1")
        except FcError as err:
            log(f"CLOUD poll error: {err}")
            self.cloud_backoff = now + 20
        except Exception as err:  # noqa: BLE001
            log(f"CLOUD poll exception: {type(err).__name__}: {err}")
            self.cloud_backoff = now + 20

    async def fire_openlock(self, reason: str) -> None:
        if self.openlock_fires >= self.args.max_openlock:
            return
        self.openlock_fires += 1
        try:
            res = await self.client.unlock(self.device_id)
            log(f"OPENLOCK #{self.openlock_fires} ({reason}): SUCCESS -> {res.message} raw={res.raw}")
        except FcError as err:
            log(f"OPENLOCK #{self.openlock_fires} ({reason}): FAILED -> {err}")
        except Exception as err:  # noqa: BLE001
            log(f"OPENLOCK #{self.openlock_fires} ({reason}): EXC -> {type(err).__name__}: {err}")

    # ---------- main ----------

    async def run(self) -> int:
        data = load_entry_data()
        region = data.get("region", "us")
        registry = EndpointRegistry.load(region, data.get("endpoints_file") or None)
        self.client = FcClient(
            data.get("email", ""),
            data.get("password", ""),
            region,
            registry,
            secure_data=data.get("secure_data"),
            private_key_b64=data.get("private_key"),
            country_code=data.get("country_code"),
        )
        if data.get("tokens"):
            self.client.tokens = TokenPair.from_dict(data["tokens"])
        await self.client.login()
        log("=== wake_catcher start ===")
        if not self.device_id:
            devs = await self.client.get_devices()
            if not devs:
                log("no devices in account; abort")
                return 1
            self.device_id = devs[0].device_id
            log(f"watching device {devs[0].name} ({self.device_id})")
        deadline = time.monotonic() + self.args.minutes * 60
        next_arp = 0.0
        next_cloud = 0.0
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_arp:
                next_arp = now + 1.5
                self.send_discover()
                sight = await self.arp_sighting()
                if sight:
                    ip, mac = sight
                    self.last_seen = time.monotonic()
                    self.last_ip = ip
                    if not self.engaged:
                        self.engaged = True
                        self.first_seen = self.last_seen
                        self.last_lan_probe = self.last_seen
                        log(f"*** LAN SIGHTING: {ip} is {mac} — LOCK IS AWAKE ***")
                        await self.fire_openlock(reason="lan sighting")
                        await self.lan_probe(ip)
                    elif time.monotonic() - self.last_lan_probe > 6:
                        self.last_lan_probe = time.monotonic()
                        await self.lan_probe(ip)
                elif self.engaged and time.monotonic() - self.last_seen > 20:
                    self.engaged = False
                    dur = self.last_seen - self.first_seen
                    log(f"*** WINDOW CLOSED (visible ~{dur:.0f}s) ***")
            if now >= next_cloud:
                next_cloud = now + 5.0
                await self.cloud_poll()
            replies = await self.drain_discover()
            for r in replies:
                log(f"UNEXPECTED discover reply: {r}")
                self.last_seen = time.monotonic()
                if not self.engaged:
                    self.engaged = True
                    self.first_seen = self.last_seen
                    await self.fire_openlock(reason="discover reply")
                    await self.lan_probe(r["ip"])
            await asyncio.sleep(0.2)
        log(f"=== done: openlock_fires={self.openlock_fires} "
            f"pk={self.pk!r} dn={self.dn!r} ===")
        await self.client.close()
        return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=12.0)
    ap.add_argument("--device", default="")
    ap.add_argument("--max-openlock", type=int, default=6)
    ap.add_argument("--try-unlock", action="store_true",
                    help="also attempt thing.service.unlock over LAN")
    args = ap.parse_args()
    return asyncio.run(Catcher(args).run())


if __name__ == "__main__":
    sys.exit(main())
