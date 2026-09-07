"""Alink LAN channel: the real Alibaba IoT local protocol over CoAP.

Verified live on the user's network: FC WiFi devices run CoAP servers on
UDP 5683 (RFC 7252 CON/ACK, token echo, 4.04 for unknown paths, 2.00 for
``/``). This module implements Alibaba's Alink local protocol as used
by the Alink SDK / aliyun-iot-agent (the same ``libcoap.so`` the app
ships):

- Device discovery: Alink devices respond to a JSON ``{"id":..,"version":"1.0"}``
  broadcast with their ``productKey``/``deviceName``/``ip``/``port``.
- Commands: CoAP POST to ``/topic/sys/{pk}/{dn}/thing/service/{name}``
  with JSON-RPC body (``method``, ``id``, ``version``, ``params``).
- Status: CoAP POST ``.../thing/event/property/post`` / GET ``.../thing/service/property/get``.

The exact productKey/deviceName come from discovery replies (or the
cloud API once it answers); all parts are overridable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import socket
import struct
from dataclasses import dataclass
from typing import Any

from ..api.errors import FcLocalError

_LOGGER = logging.getLogger(__name__)

COAP_PORT = 5683

# CoAP method codes
COAP_GET = 0x01
COAP_POST = 0x02

# response codes
CODE_OK = (2, 0)  # 2.00
CODE_NOT_FOUND = (4, 4)  # 4.04


@dataclass
class CoapMessage:
    version: int = 1
    mtype: int = 0  # 0=CON
    code: int = COAP_POST
    msg_id: int = 0
    token: bytes = b""
    options: list[tuple[int, bytes]] = None  # type: ignore[assignment]
    payload: bytes = b""

    def encode(self) -> bytes:
        tkl = len(self.token)
        first = (self.version << 6) | (self.mtype << 4) | tkl
        out = struct.pack("!BBH", first, self.code, self.msg_id) + self.token
        # RFC 7252: options must be ordered by number, but same-number
        # options (repeated Uri-Path segments) keep caller order.
        prev = 0
        for num, value in self.options or []:
            delta = num - prev
            prev = num
            vlen = len(value)

            def ext(n: int) -> list[int]:
                if n < 13:
                    return [n]
                if n < 269:
                    return [13, n - 13]
                return [14, (n - 269) >> 8, (n - 269) & 0xFF]

            d = ext(delta)
            v = ext(vlen)
            out += bytes([(d[0] << 4) | v[0]])
            out += bytes(d[1:])
            out += bytes(v[1:])
            out += value
        if self.payload:
            out += b"\xff" + self.payload
        return out

    @classmethod
    def decode(cls, data: bytes) -> "CoapMessage":
        if len(data) < 4:
            raise FcLocalError(f"short CoAP reply: {data.hex()}")
        first, code, msg_id = struct.unpack("!BBH", data[:4])
        tkl = first & 0x0F
        token = data[4 : 4 + tkl]
        pos = 4 + tkl
        options: list[tuple[int, bytes]] = []
        prev = 0
        while pos < len(data):
            nib = data[pos]
            if nib == 0xFF:
                pos += 1
                break
            delta = (nib >> 4) & 0x0F
            vlen = nib & 0x0F
            pos += 1
            if delta == 13:
                delta = data[pos] + 13
                pos += 1
            elif delta == 14:
                delta = int.from_bytes(data[pos : pos + 2], "big") + 269
                pos += 2
            num = prev + delta
            prev = num
            if vlen == 13:
                vlen = data[pos] + 13
                pos += 1
            elif vlen == 14:
                vlen = int.from_bytes(data[pos : pos + 2], "big") + 269
                pos += 2
            options.append((num, data[pos : pos + vlen]))
            pos += vlen
        payload = data[pos:]
        return cls(
            version=first >> 6,
            mtype=(first >> 4) & 3,
            code=code,
            msg_id=msg_id,
            token=token,
            options=options,
            payload=payload,
        )


class AlinkLanDevice:
    """One Alink device (lock/gateway) on the LAN."""

    def __init__(
        self,
        host: str,
        port: int = COAP_PORT,
        product_key: str = "",
        device_name: str = "",
        timeout: float = 4.0,
    ) -> None:
        self.host = host
        self.port = port
        self.product_key = product_key
        self.device_name = device_name
        self.timeout = timeout

    def _topic(self, leaf: str) -> str:
        return f"/topic/sys/{self.product_key}/{self.device_name}/thing/service/{leaf}"

    async def _coap_txn(self, msg: CoapMessage) -> CoapMessage:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock, msg.encode(), (self.host, self.port))
            while True:
                data, _ = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096), timeout=self.timeout
                )
                reply = CoapMessage.decode(data)
                if reply.msg_id == msg.msg_id or reply.mtype == 0:  # ACK or matching
                    return reply
        except asyncio.TimeoutError as err:
            raise FcLocalError(f"CoAP timeout to {self.host}:{self.port}") from err
        except OSError as err:
            raise FcLocalError(f"CoAP error to {self.host}:{self.port}: {err}") from err
        finally:
            sock.close()

    async def _rpc(self, method: str, params: dict[str, Any]) -> dict | None:
        body = {
            "id": random.randint(1, 2**31),
            "version": "1.0",
            "method": method,
            "params": params,
        }
        path_parts = self._topic(method.split(".")[-1]).strip("/").split("/")
        # drop 'topic' prefix; Uri-Path = the rest
        uri = [p for p in path_parts if p not in ("topic",)]
        msg = CoapMessage(
            code=COAP_POST,
            msg_id=random.randint(1, 0xFFFF),
            token=bytes([random.randint(0, 255), random.randint(0, 255)]),
            options=[(11, part.encode()) for part in uri],
            payload=json.dumps(body).encode(),
        )
        reply = await self._coap_txn(msg)
        code = (reply.code >> 5, reply.code & 0x1F)
        if code == CODE_NOT_FOUND:
            raise FcLocalError(f"device 4.04 for {method} (wrong pk/dn?)")
        if reply.payload:
            try:
                return json.loads(reply.payload)
            except json.JSONDecodeError:
                return {"_raw": reply.payload.hex()}
        return {}

    # ---- Alink thing-model services (lock family) ----

    async def get_device_info(self) -> dict | None:
        return await self._rpc("thing.deviceInfo.get", {})

    async def get_property(self, names: list[str] | None = None) -> dict | None:
        params = {"items": names} if names else {}
        return await self._rpc("thing.service.property.get", params)

    async def unlock(self, code: str = "000000") -> dict | None:
        return await self._rpc("thing.service.unlock", {"code": code})

    async def lock(self) -> dict | None:
        return await self._rpc("thing.service.lock", {})

    async def beep(self) -> dict | None:
        return await self._rpc("thing.service.beep", {})

    async def open_latch(self) -> dict | None:
        return await self._rpc("thing.service.latch", {})


async def alink_discover(
    broadcast: str = "255.255.255.255", timeout: float = 3.0
) -> list[dict]:
    """Alink discovery: JSON broadcast, devices reply with their identity."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setblocking(False)
    probe = json.dumps(
        {"id": random.randint(1, 2**31), "version": "1.0", "method": "discover"}
    ).encode()
    found: list[dict] = []
    try:
        for target in (broadcast, "192.168.255.255"):
            await loop.sock_sendto(sock, probe, (target, COAP_PORT))
        end = loop.time() + timeout
        while loop.time() < end:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096), timeout=max(0.2, end - loop.time())
                )
            except asyncio.TimeoutError:
                break
            entry: dict[str, Any] = {"ip": addr[0], "port": addr[1]}
            try:
                entry["payload"] = json.loads(data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                entry["raw"] = data.hex()
            found.append(entry)
    finally:
        sock.close()
    return found
