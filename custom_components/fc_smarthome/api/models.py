"""Data models for FC SmartHome devices, users and events."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now_ts() -> int:
    return int(time.time() * 1000)


def parse_ts(value: Any) -> datetime | None:
    """Parse epoch seconds/millis or ISO string into aware UTC datetime."""
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        if v < 10_000_000_000:
            v *= 1000.0
        try:
            return datetime.fromtimestamp(v / 1000.0, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


class LockEventType(str, Enum):
    UNLOCKED = "unlocked"
    LOCKED = "locked"
    DOOR_OPEN = "door_open"
    DOOR_LEFT_OPEN = "door_left_open"
    TAMPER = "tamper"
    LOW_BATTERY = "low_battery"
    BELL = "bell"
    USER_ADDED = "user_added"
    USER_REMOVED = "user_removed"
    MALFUNCTION = "malfunction"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, value: Any) -> "LockEventType":
        if isinstance(value, cls):
            return value
        text = str(value or "").lower()
        alias = {
            "unlock": cls.UNLOCKED,
            "open": cls.UNLOCKED,
            "lock": cls.LOCKED,
            "close": cls.LOCKED,
            "door": cls.DOOR_OPEN,
            "pry": cls.TAMPER,
            "alarm": cls.TAMPER,
            "battery": cls.LOW_BATTERY,
            "bell": cls.BELL,
            "ring": cls.BELL,
            "fingerprint": cls.UNLOCKED,
        }
        if text in alias:
            return alias[text]
        try:
            return cls(text)
        except ValueError:
            return cls.UNKNOWN


class LockUserType(str, Enum):
    PASSWORD = "password"
    FINGER = "finger"
    CARD = "card"
    NFC = "nfc"
    REMOTE = "remote"
    KEY = "key"
    FACE = "face"
    TEMP = "temp"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, value: Any) -> "LockUserType":
        if isinstance(value, cls):
            return value
        text = str(value).lower()
        alias = {"fingerprint": cls.FINGER, "passcode": cls.PASSWORD, "tag": cls.NFC}
        if text in alias:
            return alias[text]
        try:
            return cls(text)
        except ValueError:
            return cls.UNKNOWN


class UnlockMethod(str, Enum):
    PASSWORD = "password"
    FINGER = "finger"
    CARD = "card"
    NFC = "nfc"
    REMOTE = "remote"
    KEY = "key"
    FACE = "face"
    APP = "app"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, value: Any) -> "UnlockMethod":
        if isinstance(value, cls):
            return value
        text = str(value or "").lower()
        alias = {"fingerprint": cls.FINGER, "passcode": cls.PASSWORD, "tag": cls.CARD}
        if text in alias:
            return alias[text]
        try:
            return cls(text)
        except ValueError:
            return cls.UNKNOWN


@dataclass
class LockUser:
    user_id: str
    name: str
    type: LockUserType = LockUserType.UNKNOWN
    active: bool = True
    password_masked: str | None = None
    card_id: str | None = None
    created_at: datetime | None = None
    last_used: datetime | None = None
    raw: dict = field(default_factory=dict)


@dataclass
class LockEvent:
    type: LockEventType
    device_id: str
    timestamp: datetime | None = None
    method: UnlockMethod | None = None
    user: str | None = None
    user_id: str | None = None
    remote: bool = False
    photo_url: str | None = None
    description: str = ""
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "event_type": self.type.value,
            "method": self.method.value if self.method else None,
            "user": self.user,
            "user_id": self.user_id,
            "remote": self.remote,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "photo_url": self.photo_url,
            "description": self.description,
        }


@dataclass
class LockStatus:
    device_id: str
    locked: bool | None = None
    door_open: bool | None = None
    door_open_long: bool | None = None
    tamper: bool | None = None
    low_battery: bool | None = None
    child_lock: bool | None = None
    motor_error: bool | None = None
    latch_open: bool | None = None
    motor_moving: bool | None = None
    battery: int | None = None
    signal: int | None = None
    online: bool = True
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dev_status(cls, device_id: str, dev_status: int, masks: dict[str, int]) -> "LockStatus":
        def bit(mask_name: str) -> bool | None:
            mask = masks.get(mask_name)
            if mask is None:
                return None
            return bool(dev_status & mask)

        return cls(
            device_id=device_id,
            locked=bit("locked"),
            motor_moving=bit("motor_moving"),
            door_open=bit("door_open"),
            door_open_long=bit("door_open_long"),
            tamper=bit("tamper"),
            low_battery=bit("low_battery"),
            child_lock=bit("child_lock"),
            motor_error=bit("motor_error"),
            latch_open=bit("latch_open"),
        )

    @property
    def is_locked(self) -> bool | None:
        if self.latched() is not None:
            return self.latched()
        return self.locked

    def latched(self) -> bool | None:
        if self.locked is True:
            return True
        if self.latch_open is True:
            return False
        if self.locked is False:
            return False
        return None

    @property
    def has_problem(self) -> bool:
        return bool(self.tamper or self.door_open_long or self.motor_error)

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "locked": self.locked,
            "is_locked": self.is_locked,
            "door_open": self.door_open,
            "door_open_long": self.door_open_long,
            "tamper": self.tamper,
            "low_battery": self.low_battery,
            "child_lock": self.child_lock,
            "motor_error": self.motor_error,
            "latch_open": self.latch_open,
            "motor_moving": self.motor_moving,
            "battery": self.battery,
            "signal": self.signal,
        }


@dataclass
class Device:
    device_id: str
    name: str
    model: str = ""
    category: str = ""
    manufacturer: str = ""
    online: bool = False
    battery: int | None = None
    signal: int | None = None
    capabilities: dict[str, Any] = field(default_factory=dict)
    last_update: datetime | None = None
    raw: dict = field(default_factory=dict)

    @property
    def is_lock(self) -> bool:
        return self.category.lower() in {"lock", "safe", "zh", "door_lock"} or "lock" in self.category.lower()

    @property
    def is_doorbell(self) -> bool:
        return "bell" in self.category.lower() or "doorbell" in (self.raw.get("function") or "")


@dataclass
class ControlResult:
    success: bool
    message: str = ""
    command_id: str | None = None
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "message": self.message,
            "command_id": self.command_id,
        }


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str | None = None
    user_id: str | None = None
    expires_at: float = 0.0
    session_id: str | None = None
    family_id: str | None = None

    @property
    def valid(self) -> bool:
        return bool(self.access_token) and (self.expires_at == 0 or time.time() < self.expires_at - 120)

    def to_dict(self) -> dict:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "user_id": self.user_id,
            "expires_at": self.expires_at,
            "session_id": self.session_id,
            "family_id": self.family_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TokenPair":
        return cls(
            access_token=data.get("access_token", ""),
            refresh_token=data.get("refresh_token"),
            user_id=data.get("user_id"),
            expires_at=data.get("expires_at", 0.0),
            session_id=data.get("session_id"),
            family_id=data.get("family_id"),
        )
