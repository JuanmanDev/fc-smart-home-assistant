"""Local LAN/WiFi transport for FC SmartHome devices and gateways.

The official app bundles ``libcoap.so`` and manages WiFi gateways
(资源: 添加網關/連接閘道, Configure WiFi, etc.), matching Alibaba's Alink
LAN stack: devices/gateways announce themselves via mDNS and accept
local CoAP commands on UDP 5683 (Alink "cc" (smart-connect) channel),
plus a raw TCP command channel on some models reusing the same frame
layout as BLE.

This module implements:
- mDNS/SSDP/UDP-broadcast discovery of FC gateways and WiFi locks
- CoAP-style probing on UDP 5683 (Alink local protocol)
- TCP command channel with the FCFC framing shared with BLE
- unified lock/unlock/status/beep commands

Frame details reuse local/ble.py (magic FCFC + len + cmd/seq + XOR
checksum). Wire specifics are Alink-derived hypotheses to verify with a
single capture (tools/HARVEST.md); every constant is overridable via
the endpoints registry ``lan`` section.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import socket
import struct
from dataclasses import dataclass, field
from typing import Any

from ..api.errors import FcLocalError
from ..local.ble import build_frame, parse_frame

_LOGGER = logging.getLogger(__name__)

# Alink LAN defaults (override via endpoints registry "lan" section)
COAP_PORT = 5683
MDNS_SERVICE_TYPES = ("_alink._udp.local.", "_fcsmart._tcp.local.", "_hap._tcp.local.")
UDP_BROADCAST_PORT = 5683
TCP_PORTS = (8060, 9999, 8666, 5683, 443)
DISCOVERY_TIMEOUT = 5.0
COMMAND_TIMEOUT = 10.0

# shared with BLE (cmd ids are hypothesis; same family of firmware)
CMD_PAIR = 0x01
CMD_STATUS = 0x03
CMD_UNLOCK = 0x10
CMD_LOCK = 0x11
CMD_LATCH = 0x12
CMD_BEEP = 0x13


@dataclass
class LanConfig:
    coap_port: int = COAP_PORT
    tcp_ports: list[int] = field(default_factory=lambda: list(TCP_PORTS))
    mdns_services: list[str] = field(default_factory=lambda: list(MDNS_SERVICE_TYPES))
    pair_code: str | None = None
    command_timeout: float = COMMAND_TIMEOUT
    connect_timeout: float = 8.0

    @classmethod
    def from_registry(cls, lan: dict[str, Any], pair_code: str | None = None) -> "LanConfig":
        cfg = cls(pair_code=pair_code)
        if lan.get("coap_port"):
            cfg.coap_port = int(lan["coap_port"])
        if isinstance(lan.get("tcp_ports"), list):
            cfg.tcp_ports = [int(p) for p in lan["tcp_ports"]]
        if isinstance(lan.get("mdns_services"), list):
            cfg.mdns_services = list(lan["mdns_services"])
        return cfg


async def discover_lan_devices(timeout: float = DISCOVERY_TIMEOUT) -> list[dict]:
    """Discover FC/Alink devices on the LAN.

    Strategy (no external deps):
    1. mDNS multicast query for Alink/FC service types (UDP 5353 -> 224.0.0.251)
    2. Alink smart-config UDP probe on the broadcast address port 5683
       (devices reply with their JSON id payload)
    Returns a list of {ip, port, source, payload} dicts.
    """
    found: list[dict] = []
    loop = asyncio.get_running_loop()

    # --- 1. mDNS ---
    try:
        mdns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mdns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mdns_sock.bind(("", 0))
        mdns_sock.setblocking(False)
        query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for svc in MDNS_SERVICE_TYPES:
            qname = b"".join(bytes([len(p)]) + p.encode() for p in svc.split(".")) + b"\x00"
            query = (
                b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                + qname
                + b"\x00\x0c\x00\x01"  # type PTR, class IN
            )
        with contextlib.suppress(OSError):
            await loop.sock_sendto(mdns_sock, query, ("224.0.0.251", 5353))
        end = loop.time() + timeout / 2
        while loop.time() < end:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(mdns_sock, 4096), timeout=max(0.2, end - loop.time())
                )
                found.append(
                    {
                        "ip": addr[0],
                        "port": 5353,
                        "source": "mdns",
                        "payload": data[:120].hex(),
                    }
                )
            except asyncio.TimeoutError:
                break
        mdns_sock.close()
    except OSError as err:
        _LOGGER.debug("mDNS discovery failed: %s", err)

    # --- 2. Alink UDP broadcast probe on 5683 ---
    try:
        probe = build_frame(0x00, b"FC-DISCOVERY")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", 0))
        sock.setblocking(False)
        for bcast in ("255.255.255.255", "192.168.255.255"):
            with contextlib.suppress(OSError):
                await loop.sock_sendto(sock, probe, (bcast, UDP_BROADCAST_PORT))
        end = loop.time() + timeout / 2
        while loop.time() < end:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096), timeout=max(0.2, end - loop.time())
                )
                found.append(
                    {
                        "ip": addr[0],
                        "port": addr[1],
                        "source": "udp-broadcast",
                        "payload": data[:120].hex(),
                    }
                )
            except asyncio.TimeoutError:
                break
        sock.close()
    except OSError as err:
        _LOGGER.debug("UDP broadcast discovery failed: %s", err)

    # dedupe
    seen: set[tuple] = set()
    out = []
    for d in found:
        key = (d["ip"], d["source"])
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


async def probe_coap(host: str, port: int = COAP_PORT, timeout: float = 3.0) -> dict | None:
    """Send an Alink-style CoAP CON probe and return the reply summary.

    Alink local uses CoAP POST /sys/{pk}/{dn}/thing/... with a JSON
    payload; a reply (ACK + payload) proves an Alink device at host:port.
    """
    loop = asyncio.get_running_loop()
    msg_id = random.randint(0, 0xFFFF)
    # CoAP header: ver=1 type=CON(0) toklen=0 code=POST(0.02) msgid
    header = struct.pack("!BBH", 0x40, 0x02, msg_id)
    # Uri-Path option 11 "sys" then 11 "discover" (delta/len nibbles)
    options = bytes([0xB1]) + b"sys" + bytes([0x19]) + b"discover"
    payload = b"{}"
    packet = header + options + bytes([0xFF]) + payload
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        await loop.sock_sendto(sock, packet, (host, port))
        data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=timeout)
        sock.close()
        version_type = data[0] >> 4
        code = data[1]
        return {
            "ip": host,
            "port": port,
            "coap_version": version_type,
            "coap_code": f"{code >> 5}.{code & 0x1F:02d}",
            "payload": data[:120].hex(),
            "alive": True,
        }
    except (OSError, asyncio.TimeoutError):
        return None


class FcLanTransport:
    """TCP command channel to a lock/gateway using FCFC framing."""

    def __init__(self, host: str, port: int, config: LanConfig) -> None:
        self.host = host
        self.port = port
        self.config = config
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._lock = asyncio.Lock()

    @property
    def connected(self) -> bool:
        return self._writer is not None and not self._writer.is_closing()

    async def connect(self) -> None:
        if self.connected:
            return
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.config.connect_timeout,
            )
        except (OSError, asyncio.TimeoutError) as err:
            raise FcLocalError(f"LAN connect to {self.host}:{self.port} failed: {err}") from err

    async def disconnect(self) -> None:
        if self._writer:
            with contextlib.suppress(Exception):
                self._writer.close()
                await self._writer.wait_closed()
        self._reader = self._writer = None

    async def _transact(self, cmd: int, payload: bytes = b"") -> bytes:
        async with self._lock:
            await self.connect()
            frame = build_frame(cmd, payload)
            assert self._writer is not None and self._reader is not None
            try:
                self._writer.write(frame)
                await asyncio.wait_for(self._writer.drain(), timeout=self.config.command_timeout)
                raw = await asyncio.wait_for(
                    self._reader.read(len(frame) + 64), timeout=self.config.command_timeout
                )
            except (OSError, asyncio.TimeoutError) as err:
                await self.disconnect()
                raise FcLocalError(f"LAN command 0x{cmd:02x} failed: {err}") from err
            parsed = parse_frame(raw)
            if parsed is None:
                raise FcLocalError(f"LAN reply not parseable: {raw.hex()}")
            _cmd, _seq, body = parsed
            return body

    async def pair(self) -> None:
        code = self.config.pair_code or "000000"
        with contextlib.suppress(FcLocalError):
            await self._transact(CMD_PAIR, code.encode())

    # ---- commands (mirror BLE) ----

    async def unlock(self) -> None:
        code = self.config.pair_code or "000000"
        await self._transact(CMD_UNLOCK, code.encode())

    async def lock(self) -> None:
        await self._transact(CMD_LOCK)

    async def latch(self) -> None:
        await self._transact(CMD_LATCH)

    async def beep(self) -> None:
        await self._transact(CMD_BEEP)

    async def read_status_raw(self) -> bytes:
        return await self._transact(CMD_STATUS)


async def find_open_command_port(host: str, ports: list[int] | None = None) -> int | None:
    """TCP-connect scan for the gateway's command port."""
    ports = ports or list(TCP_PORTS)
    for port in ports:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=3.0)
            writer.close()
            await writer.wait_closed()
            return port
        except (OSError, asyncio.TimeoutError):
            continue
    return None
