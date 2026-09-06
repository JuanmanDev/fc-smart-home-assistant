"""Local Bluetooth Low Energy transport for FC SmartHome devices.

Fingerchip locks pair over BLE. This module provides:
- scanning by name prefix / advertised service UUID
- pairing handshake (magic header + rolling token)
- local command channel: lock/unlock/latch/beep, read devStatus
- local event subscription via notifications

Frame layout is the hypothesis from sibling Alibaba-style lock BLE firmwares
(4-byte magic 'FCFC', length, command, payload, checksum). It MUST be verified
with a btsnoop/HCI capture of the official app (tools/HARVEST.md).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from dataclasses import dataclass, field
from typing import Any, Callable

from ..api.const import DEVICE_STATUS_MASKS
from ..api.errors import FcLocalError
from ..api.models import LockStatus

_LOGGER = logging.getLogger(__name__)

BLE_IMPORT_ERROR = None
try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.characteristic import BleakGATTCharacteristic
except ImportError as err:  # pragma: no cover - optional runtime dependency
    BLE_IMPORT_ERROR = str(err)

MAGIC = b"FCFC"


def checksum(data: bytes) -> int:
    """XOR checksum used at the end of the frame (verify against capture)."""
    c = 0
    for b in data:
        c ^= b
    return c


def build_frame(cmd: int, payload: bytes = b"", seq: int | None = None) -> bytes:
    if seq is None:
        seq = random.randint(0x00, 0xFF)
    body = bytes([cmd, seq]) + payload
    frame = MAGIC + bytes([len(body)]) + body
    return frame + bytes([checksum(body)])


def parse_frame(data: bytes) -> tuple[int, int, bytes] | None:
    """Return (cmd, seq, payload) if the buffer holds a complete frame."""
    if len(data) < 8 or not data.startswith(MAGIC):
        return None
    length = data[4]
    total = 5 + length + 1
    if len(data) < total:
        return None
    body = data[5 : 5 + length]
    if checksum(body) != data[5 + length]:
        _LOGGER.warning("BLE frame checksum mismatch: %s", data.hex())
        return None
    return body[0], body[1], body[2:]


@dataclass
class BleConfig:
    name_prefixes: list[str] = field(default_factory=list)
    service_uuid: str = "0000fe00-0000-1000-8000-00805f9b34fb"
    write_characteristic: str = "0000fe01-0000-1000-8000-00805f9b34fb"
    notify_characteristic: str = "0000fe02-0000-1000-8000-00805f9b34fb"
    pair_code: str | None = None
    connect_timeout: float = 12.0
    command_timeout: float = 10.0

    @classmethod
    def from_registry(cls, ble: dict[str, Any], pair_code: str | None = None) -> "BleConfig":
        return cls(
            name_prefixes=list(ble.get("name_prefixes") or []),
            service_uuid=ble.get("service_uuid") or cls.service_uuid,
            write_characteristic=ble.get("write_characteristic") or cls.write_characteristic,
            notify_characteristic=ble.get("notify_characteristic") or cls.notify_characteristic,
            pair_code=pair_code,
        )


# command ids (hypothesis; verify with capture)
CMD_PAIR = 0x01
CMD_PAIR_ACK = 0x02
CMD_STATUS = 0x03
CMD_UNLOCK = 0x10
CMD_LOCK = 0x11
CMD_LATCH = 0x12
CMD_BEEP = 0x13
CMD_STATUS_NOTIFY = 0x20
CMD_EVENT = 0x21


class FcBleTransport:
    """BLE command channel to a single lock."""

    def __init__(self, device: "BLEDevice", config: BleConfig) -> None:
        self.device = device
        self.config = config
        self._client: "BleakClient | None" = None
        self._notify_char: "BleakGATTCharacteristic | None" = None
        self._lock = asyncio.Lock()
        self._pending: dict[int, asyncio.Future] = {}
        self._event_callbacks: list[Callable[[dict], None]] = []
        self._status: LockStatus | None = None

    # ---------- lifecycle ----------

    async def connect(self) -> None:
        if BLE_IMPORT_ERROR:
            raise FcLocalError(f"bleak is not installed: {BLE_IMPORT_ERROR}")
        if self._client and self._client.is_connected:
            return
        client = BleakClient(self.device)
        await asyncio.wait_for(client.connect(), timeout=self.config.connect_timeout)
        self._client = client
        try:
            char = await self._find_notify_characteristic()
            if char is not None:
                await client.start_notify(char, self._on_notify)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Notify subscription failed: %s", err)
        await self._pair()

    async def _find_notify_characteristic(self):
        services = self._client.services
        if services is None:
            return None
        for service in services:
            for char in service.characteristics:
                if char.uuid.lower() == self.config.notify_characteristic.lower():
                    return char
        for service in services:
            for char in service.characteristics:
                if "notify" in char.properties:
                    return char
        return None

    async def disconnect(self) -> None:
        if self._client:
            with contextlib.suppress(Exception):
                await self._client.disconnect()
        self._client = None

    @property
    def connected(self) -> bool:
        return bool(self._client and self._client.is_connected)

    # ---------- frame plumbing ----------

    def _on_notify(self, _char, data: bytearray) -> None:
        frame = parse_frame(bytes(data))
        if frame is None:
            _LOGGER.debug("Unparseable BLE notification: %s", bytes(data).hex())
            return
        cmd, seq, payload = frame
        fut = self._pending.pop(seq, None)
        if cmd in (CMD_PAIR_ACK,):
            if fut and not fut.done():
                fut.set_result(payload)
        elif cmd == CMD_STATUS_NOTIFY:
            self._handle_status(payload)
        elif cmd == CMD_EVENT:
            self._handle_event(payload)
        if fut and not fut.done() and cmd in (CMD_STATUS, CMD_UNLOCK, CMD_LOCK, CMD_LATCH, CMD_BEEP):
            fut.set_result(payload)

    async def _transact(self, cmd: int, payload: bytes = b"", timeout: float | None = None) -> bytes:
        async with self._lock:
            if not self.connected:
                await self.connect()
            loop = asyncio.get_running_loop()
            fut: asyncio.Future = loop.create_future()
            frame = build_frame(cmd, payload)
            # reuse seq byte as correlation id
            seq = frame[6]
            self._pending[seq] = fut
            try:
                await self._client.write_gatt_char(
                    self.config.write_characteristic, frame, response=True
                )
                return await asyncio.wait_for(fut, timeout or self.config.command_timeout)
            except asyncio.TimeoutError as err:
                self._pending.pop(seq, None)
                raise FcLocalError(f"BLE command 0x{cmd:02x} timed out") from err
            except Exception as err:  # noqa: BLE001
                self._pending.pop(seq, None)
                raise FcLocalError(f"BLE write failed: {err}") from err

    async def _pair(self) -> None:
        code = self.config.pair_code or "000000"
        try:
            await self._transact(CMD_PAIR, code.encode(), timeout=self.config.command_timeout)
        except FcLocalError:
            _LOGGER.debug("BLE pairing handshake not answered; continuing")

    # ---------- status & events ----------

    def _handle_status(self, payload: bytes) -> None:
        if len(payload) < 1:
            return
        dev_status = payload[0]
        battery = payload[1] if len(payload) > 1 else None
        status = LockStatus.from_dev_status(self.device.address, dev_status, DEVICE_STATUS_MASKS)
        if battery is not None:
            status.battery = battery
        self._status = status
        self._emit({"type": "status", "status": status})

    def _handle_event(self, payload: bytes) -> None:
        if not payload:
            return
        etype = payload[0]
        method = payload[1] if len(payload) > 1 else None
        user = payload[2:].decode(errors="replace") if len(payload) > 2 else None
        self._emit(
            {
                "type": "event",
                "event_code": etype,
                "method_code": method,
                "user": user,
                "device_id": self.device.address,
            }
        )

    def _emit(self, data: dict) -> None:
        for cb in self._event_callbacks:
            try:
                cb(data)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("BLE event callback error")

    def on_event(self, callback: Callable[[dict], None]) -> Callable[[], None]:
        self._event_callbacks.append(callback)

        def _remove() -> None:
            with contextlib.suppress(ValueError):
                self._event_callbacks.remove(callback)

        return _remove

    # ---------- public commands ----------

    async def read_status(self) -> LockStatus:
        payload = await self._transact(CMD_STATUS)
        if payload:
            self._handle_status(payload)
        return self._status or LockStatus(device_id=self.device.address)

    async def unlock(self) -> None:
        await self._transact(CMD_UNLOCK, (self.config.pair_code or "000000").encode())

    async def lock(self) -> None:
        await self._transact(CMD_LOCK)

    async def latch(self) -> None:
        await self._transact(CMD_LATCH)

    async def beep(self) -> None:
        payload = await self._transact(CMD_BEEP)
        if payload:
            _LOGGER.debug("beep ack: %s", payload.hex())


class FcBleManager:
    """Scanner + per-device transports with auto reconnect."""

    def __init__(self, config: BleConfig) -> None:
        self.config = config
        self._transports: dict[str, FcBleTransport] = {}
        self._discovered: dict[str, "BLEDevice"] = {}
        self._lock = asyncio.Lock()

    async def scan(self, timeout: float = 10.0) -> list[dict]:
        if BLE_IMPORT_ERROR:
            raise FcLocalError(f"bleak is not installed: {BLE_IMPORT_ERROR}")
        prefixes = tuple(p.lower() for p in self.config.name_prefixes)
        wanted_uuid = self.config.service_uuid.lower()
        found: list[dict] = []
        devices = await BleakScanner.discover(timeout=timeout)
        for dev in devices:
            uuids = [str(u).lower() for u in (dev.details.get("uuids") or [])] if isinstance(dev.details, dict) else []
            name = (dev.name or "").lower()
            if prefixes and not name.startswith(prefixes):
                continue
            if wanted_uuid and wanted_uuid not in uuids and not name.startswith(prefixes):
                continue
            self._discovered[dev.address] = dev
            found.append(
                {
                    "address": dev.address,
                    "name": dev.name,
                    "rssi": dev.details.get("rssi") if isinstance(dev.details, dict) else None,
                }
            )
        return found

    def known(self) -> list[dict]:
        return [
            {"address": addr, "name": dev.name}
            for addr, dev in self._discovered.items()
        ]

    async def transport(self, address: str) -> FcBleTransport:
        async with self._lock:
            existing = self._transports.get(address)
            if existing and existing.connected:
                return existing
            dev = self._discovered.get(address)
        if dev is None:
            # scan outside the lock; re-check under it after
            devices = await BleakScanner.discover(timeout=5.0)
            for d in devices:
                self._discovered.setdefault(d.address, d)
            async with self._lock:
                dev = self._discovered.get(address)
        if dev is None:
            raise FcLocalError(f"BLE device {address} not found")
        transport = FcBleTransport(dev, self.config)
        await transport.connect()
        async with self._lock:
            # keep the newest connected transport for this address
            self._transports[address] = transport
        return transport

    async def close(self) -> None:
        for transport in self._transports.values():
            with contextlib.suppress(FcLocalError):
                await transport.disconnect()
        self._transports.clear()
