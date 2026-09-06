"""Endpoint registry: defaults, overrides file, candidate probing.

The FC SmartHome app (Shenzhen Fingerchip) cloud endpoints are not publicly
documented. Defaults below are working hypotheses that MUST be confirmed with
a mitmproxy capture of the official app (see tools/HARVEST.md). Users can
override any path/host without touching code via a JSON file, and the probe
tool (tools/probe_endpoints.py) records which candidates actually answer.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_REGIONS: dict[str, str] = {
    "us": "https://api.fingercrystal.com",
    "eu": "https://api-eu.fingercrystal.com",
    "cn": "https://api-cn.fingercrystal.com",
    "ru": "https://api-ru.fingercrystal.com",
}

DEFAULT_PATHS: dict[str, str] = {
    "login": "/api/app/login",
    "refresh": "/api/app/token/refresh",
    "logout": "/api/app/logout",
    "devices": "/api/app/device/list",
    "device_status": "/api/app/device/{id}/status",
    "control": "/api/app/device/{id}/command",
    "lock": "/api/app/device/{id}/lock",
    "unlock": "/api/app/device/{id}/unlock",
    "latch": "/api/app/device/{id}/open",
    "users": "/api/app/lock/{id}/user/list",
    "users_add": "/api/app/lock/{id}/user/add",
    "users_delete": "/api/app/lock/{id}/user/delete",
    "users_update": "/api/app/lock/{id}/user/update",
    "fingerprint_enroll": "/api/app/lock/{id}/fingerprint/enroll",
    "logs": "/api/app/lock/{id}/log/list",
    "bell": "/api/app/device/{id}/bell",
    "beep": "/api/app/device/{id}/beep",
    "child_lock": "/api/app/lock/{id}/child-lock",
}

DEFAULT_WEBSOCKET: dict[str, Any] = {
    "enabled": False,
    "path": "/api/app/ws",
}

DEFAULT_MQTT: dict[str, Any] = {
    "enabled": False,
    "host": None,
    "port": 1883,
    "username": None,
    "password": None,
    "topic_prefix": "fc/smarthome",
}

DEFAULT_BLE: dict[str, Any] = {
    "name_prefixes": ["FC", "Yi", "EL", "DX", "K3", "DZ", "SL"],
    "service_uuid": "0000fe00-0000-1000-8000-00805f9b34fb",
    "write_characteristic": "0000fe01-0000-1000-8000-00805f9b34fb",
    "notify_characteristic": "0000fe02-0000-1000-8000-00805f9b34fb",
    "manufacturer_id": None,
    "magic": "FCFC",
}

OVERRIDE_FILENAMES = ("fc_smarthome_endpoints.json", "fc_endpoints.json")

VERIFIED_KEYS: set[str] = set()


@dataclass
class EndpointRegistry:
    region: str = "us"
    regions: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_REGIONS))
    paths: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PATHS))
    websocket: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_WEBSOCKET))
    mqtt: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_MQTT))
    ble: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_BLE))
    source_file: str | None = None

    @classmethod
    def load(cls, region: str = "us", override_path: str | Path | None = None) -> "EndpointRegistry":
        data: dict[str, Any] = {}
        source = None
        candidates: list[Path] = []
        if override_path:
            candidates.append(Path(override_path))
        env_file = os.environ.get("FC_ENDPOINTS_FILE")
        if env_file:
            candidates.append(Path(env_file))
        for name in OVERRIDE_FILENAMES:
            candidates.append(Path.cwd() / name)
            candidates.append(Path.home() / ".fcsmarthome" / name)
        for cand in candidates:
            if cand and cand.is_file():
                try:
                    data = json.loads(cand.read_text(encoding="utf-8"))
                    source = str(cand)
                    break
                except (OSError, json.JSONDecodeError):
                    continue
        reg = cls(region=region)
        if data:
            reg.regions.update({k.lower(): v for k, v in (data.get("regions") or {}).items()})
            reg.paths.update(data.get("paths") or {})
            ws = dict(reg.websocket)
            ws.update(data.get("websocket") or {})
            reg.websocket = ws
            mq = dict(reg.mqtt)
            mq.update(data.get("mqtt") or {})
            reg.mqtt = mq
            ble = dict(reg.ble)
            ble.update(data.get("ble") or {})
            reg.ble = ble
            reg.source_file = source
            reg.paths = {k: v for k, v in reg.paths.items() if v is not None}
        return reg

    @property
    def base_url(self) -> str:
        return self.regions.get(self.region, self.regions["us"]).rstrip("/")

    def url(self, key: str, device_id: str | None = None) -> str:
        path = self.paths[key]
        if device_id is not None:
            path = path.replace("{id}", str(device_id))
        return f"{self.base_url}{path}"

    def websocket_url(self) -> str | None:
        if not self.websocket.get("enabled"):
            return None
        return self.base_url.replace("https://", "wss://").replace("http://", "ws://") + self.websocket.get("path", "/api/app/ws")

    def unverified(self) -> dict[str, str]:
        return {k: v for k, v in self.paths.items() if k not in VERIFIED_KEYS}

    def to_dict(self) -> dict:
        return {
            "region": self.region,
            "regions": self.regions,
            "paths": self.paths,
            "websocket": self.websocket,
            "mqtt": self.mqtt,
            "ble": self.ble,
            "source_file": self.source_file,
        }
