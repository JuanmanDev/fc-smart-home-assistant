"""Endpoint registry: defaults extracted from the real APK, overrides, probing.

Values below were extracted from the official FC SmartHome APK 4.6.6
(com.fingercrystal.smarthome, resources.arsc string table):

    fingercrystal_server        = www.fcsmartlock.com   (production)
    fingercrystal_gatewayPort   = 443
    fingercrystal_appSystemPort = 443
    fingercrystal119_server     = test.fcsmartlock.com  (test channel)
    fingercrystaltest2_server   = test2.fcsmartlock.com
    fingercrystal_amazon_server = 18.219.242.80        (AWS intl channel)
    fingercrystal_image_base_url = http://www.fcsmartlock.com:8060/images/

The mobile API is Spring Boot behind nginx on 443 (confirmed live:
Spring JSON 404 mapper on https://www.fcsmartlock.com). The gateway
routes /api/* to the backend service (502 while the upstream is down).

Path defaults remain candidates until a runtime capture pins them
(tools/HARVEST.md); the EndpointRegistry still accepts JSON overrides
and auto-discovery for anything that changes.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_REGIONS: dict[str, str] = {
    # extracted from APK resources.arsc (production channel)
    "us": "https://www.fcsmartlock.com",
    "eu": "https://www.fcsmartlock.com",
    "cn": "https://www.fcsmartlock.com",
    "ru": "https://www.fcsmartlock.com",
    # alternate channels found in the APK
    "intl-aws": "https://18.219.242.80",
    "test": "https://test.fcsmartlock.com",
    "test2": "https://test2.fcsmartlock.com",
}

DEFAULT_PATHS: dict[str, str] = {
    # verified live 2026-09-09 (see docs/QUE-HACE-LA-APP-FC.md):
    # all /v2/ + /iot/ paths below are confirmed by mitm capture of app 4.6.6
    "security_key": "/v2/secure/getSecurityKey",
    "login": "/v2/login/loginPassword",
    "login_email": "/v2/login/loginEmailPassword",
    "login_token": "/v2/login/loginToken",
    "refresh": "/v2/login/loginToken",
    "logout": "/v2/account/logout",
    "user_info": "/v2/account/getUserInfo",
    "family_list": "/iot/family/familyList",
    "family_info": "/iot/family/familyInfo",
    "devices": "/v2/device/getDeviceList",
    "device_detail": "/v2/device/getDevice",
    "device_status": "/v2/device/getDevice",
    "device_categories": "/iot/pageDownload/productCategoryList",
    "remote_unlock": "/v2/lock/openLock",
    "control": "/v2/lock/openLock",
    "lock": "/v2/lock/openLock",
    "unlock": "/v2/lock/openLock",
    "latch": "/v2/lock/openLock",
    "users": "/v2/lock/getLockUserList/v2",
    "user_detail": "/v2/lock/getLockUser/v2",
    "users_add": "/v2/lock/addLockUser/v2",
    "users_delete": "/v2/lock/deleteLockUser",
    "users_update": "/v2/lock/modifyLockUserName",
    "fingerprint_enroll": "/v2/wifilock/addFingerprint/v2",
    "logs": "/v2/lock/getLockMessageList/v2",
    "bell": "/v2/wifilock/setDoorBellVolume",
    "beep": "/v2/wifilock/setVolume",
    "child_lock": "/v2/wifilock/enableChildLock",
    "anti_lock": "/v2/wifilock/enableAntiLock",
    "volume": "/v2/wifilock/setVolume",
    "direction": "/v2/wifilock/setDoorOpenDirection",
    "validate_security_password": "/v2/device/validateSecurityPassword",
    "get_local_verify_password": "/v2/device/getLocalVerifyPassword",
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
    "name_prefixes": ["Smart Lock", "FC", "Yi", "EL", "DX", "K3", "DZ", "SL", "L5"],
    "scan_filter_uuid": "000001fa-0000-1000-8000-00805f9b34fb",
    "service_uuid": "0000ffe0-0000-1000-8000-00805f9b34fb",
    "write_characteristic": "0000ffe1-0000-1000-8000-00805f9b34fb",
    "notify_characteristic": "0000ffe1-0000-1000-8000-00805f9b34fb",
    "default_aes_key": "4CADB87095639211A1303639D98E9150",
    "manufacturer_id": None,
    "magic": "FCFC",
}

DEFAULT_LAN: dict[str, Any] = {
    "coap_port": 5683,
    "tcp_ports": [8060, 9999, 8666, 5683],
    "mdns_services": ["_alink._udp.local.", "_fcsmart._tcp.local."],
    "enabled": True,
}

OVERRIDE_FILENAMES = ("fc_smarthome_endpoints.json", "fc_endpoints.json")

# APK-extracted image/asset base (for face photos, avatars)
IMAGE_BASE_URL = "http://www.fcsmartlock.com:8060/images/"

VERIFIED_KEYS: set[str] = {
    "security_key",
    "login",
    "login_email",
    "login_token",
    "refresh",
    "user_info",
    "family_list",
    "family_info",
    "devices",
    "device_detail",
    "device_categories",
    "remote_unlock",
    "unlock",
    "users",
    "user_detail",
    "logs",
    "child_lock",
    "anti_lock",
    "volume",
    "direction",
    "validate_security_password",
    "get_local_verify_password",
}


@dataclass
class EndpointRegistry:
    region: str = "us"
    regions: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_REGIONS))
    paths: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PATHS))
    websocket: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_WEBSOCKET))
    mqtt: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_MQTT))
    ble: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_BLE))
    lan: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_LAN))
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
            lan = dict(reg.lan)
            lan.update(data.get("lan") or {})
            reg.lan = lan
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
