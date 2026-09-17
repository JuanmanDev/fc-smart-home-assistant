"""FCFC-over-UDP command probe + TLS fingerprint of the cloud.

1. Send FCFC command frames (status/unlock/pair) over UDP to LAN devices
2. Try Alink CoAP URIs (/topic/... MQTT-over-CoAP shape, DTLS port)
3. Fingerprint TLS of www.fcsmartlock.com to fix the aiohttp client config
"""

from __future__ import annotations

import random
import socket
import ssl
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from custom_components.fc_smarthome.local.ble import build_frame, parse_frame


def udp_txn(host: str, port: int, frame: bytes, timeout: float = 2.5) -> bytes | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(frame, (host, port))
        return s.recvfrom(2048)[0]
    except socket.timeout:
        return None
    finally:
        s.close()


def coap_post_raw(host: str, port: int, uri: str, payload: bytes, timeout: float = 2.5) -> bytes | None:
    msg_id = random.randint(1, 0xFFFF)
    header = struct.pack("!BBH", 0x42, 0x02, msg_id)
    token = bytes([random.randint(0, 255), random.randint(0, 255)])
    opts = b""
    prev = 0
    for part in [p for p in uri.strip("/").split("/") if p]:
        pb = part.encode()
        delta = 11 - prev if prev < 11 else 0
        prev = 11
        if len(pb) < 13:
            opts += bytes([(delta << 4) | len(pb)]) + pb
        else:
            opts += bytes([(delta << 4) | 13]) + bytes([len(pb) - 13]) + pb
    pkt = header + token + opts + bytes([0xFF]) + payload
    return udp_txn(host, port, pkt, timeout)


def main() -> None:
    import os
    ips = sys.argv[1:] or [i.strip() for i in os.environ.get("FC_LAN_IPS", "").split(",") if i.strip()]

    print("== FCFC over UDP (ports 5683 + 9999 + 8666 + 5684) ==")
    for ip in ips:
        for port in (5683, 5684, 9999, 8666, 8060):
            for cmd, payload, label in [
                (0x00, b"FC-DISCOVERY", "discovery"),
                (0x01, b"000000", "pair"),
                (0x03, b"", "status"),
                (0x13, b"", "beep"),
            ]:
                frame = build_frame(cmd, payload, seq=random.randint(0, 255))
                r = udp_txn(ip, port, frame)
                if r:
                    parsed = parse_frame(r) if r[:4] == b"FCFC" else None
                    if parsed:
                        c, sq, body = parsed
                        print(
                            f"  {ip}:{port} {label}(0x{cmd:02x}) -> FCFC cmd=0x{c:02x} "
                            f"seq={sq} body={body.hex()}"
                        )
                    else:
                        print(
                            f"  {ip}:{port} {label}(0x{cmd:02x}) -> raw "
                            f"({len(r)}B) {r[:40].hex()} {r[:30]!r}"
                        )
                    break  # port speaks FCFC; stop probing cmds on this port

    print("\n== Alink CoAP /topic/ URIs (MQTT-over-CoAP) ==")
    body = (
        b'{"id":1,"version":"1.0","method":"thing.deviceInfo.get",'
        b'"params":{},"sys":{"ack":1}}'
    )
    uris = [
        "/topic/sys/a1FCDEMO/dev1/thing/deviceInfo/get",
        "/topic/sys/a1FCDEMO/dev1/thing/event/local/post",
        "/topic/sys/a1FCDEMO/dev1/thing/service/localControl",
        "/sys/a1FCDEMO/dev1/thing/deviceInfo/get",
        "/topic/ext/local/thing/discovery",
        "/topic/discover",
        "/topic/fc/discover",
        "/fc/status",
        "/status",
        "/info",
        "/api/device/info",
    ]
    for ip in ips:
        for uri in uris:
            r = coap_post_raw(ip, 5683, uri, body)
            if r and not (r[1] == 0x84 and len(r) <= 8):  # skip plain 4.04 ACKs
                print(f"  {ip} {uri}: {r[:60].hex()} {r[:40]!r}")

    print("\n== TLS fingerprint of cloud ==")
    host = "www.fcsmartlock.com"
    for tls_name, ctx_kwargs in [
        ("default", {}),
        ("TLSv1.2 only", {"minimum_version": ssl.TLSVersion.TLSv1_2, "maximum_version": ssl.TLSVersion.TLSv1_2}),
        ("no-verify + all ciphers", {"check_hostname": False}),
        ("unsafe legacy renegotiation", {}),
    ]:
        try:
            ctx = ssl.create_default_context(**ctx_kwargs)
            if "legacy" in tls_name:
                ctx.options |= 0x04  # SSL_OP_LEGACY_SERVER_CONNECT
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    print(
                        f"  {tls_name}: OK {tls.version()} cipher={tls.cipher()[0]}"
                    )
                    cert = tls.getpeercert(binary_form=True)
                    import hashlib
                    print(f"    cert sha256={hashlib.sha256(cert).hexdigest()[:32]}…")
        except Exception as err:
            print(f"  {tls_name}: {type(err).__name__}: {err}")

    print("\n== aiohttp test (what our client uses) ==")
    import asyncio

    async def aiohttp_test():
        import aiohttp

        async with aiohttp.ClientSession() as session:
            for url in (
                "https://www.fcsmartlock.com/",
                "https://www.fcsmartlock.com/api/app/login",
            ):
                try:
                    async with session.post(
                        url, json={"email": "probe@invalid.test", "password": "x"}
                    ) as resp:
                        print(f"  {url}: {resp.status} {(await resp.text())[:100]!r}")
                except Exception as err:
                    print(f"  {url}: {type(err).__name__}: {err}")

    asyncio.run(aiohttp_test())


if __name__ == "__main__":
    main()
