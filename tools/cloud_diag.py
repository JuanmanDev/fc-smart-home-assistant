"""Cloud diagnostic: dump raw device JSON looking for LAN/Alink fields.

Usage:
    python tools/cloud_diag.py

Prints the FULL raw getDeviceList + getDevice payloads (all keys), then
highlights keys useful for the LAN channel: productKey, deviceName, ip,
wifissid, online/state flags.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from custom_components.fc_smarthome.api.client import FcClient
from custom_components.fc_smarthome.api.endpoints import EndpointRegistry


def _load_env_file() -> None:
    envf = Path(__file__).resolve().parents[1] / ".env"
    if envf.is_file():
        for line in envf.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


INTERESTING = [
    "productKey", "deviceName", "pk", "dn", "ip", "lanip", "localIp",
    "wifissid", "wifimac", "mac", "bleMac", "online", "state", "devStatus",
    "endpoint", "shortaddress", "autoWakeUp", "enableWifi", "automaticWakeupTime",
    "iotid", "iotId", "productid", "productId", "qspms", "saas",
]


async def main() -> int:
    _load_env_file()
    region = os.environ.get("FC_REGION", "eu")
    registry = EndpointRegistry.load(region)
    client = FcClient(
        os.environ.get("FC_PHONE", ""),
        os.environ.get("FC_PASSWORD", ""),
        region,
        registry,
        country_code=os.environ.get("FC_CC", "34"),
    )
    try:
        await client.login()
        print("[login] OK")
        devices = await client.get_devices()
        for dev in devices:
            print("=" * 70)
            print(f"DEVICE {dev.name} ({dev.device_id}) model={dev.model}")
            print("=" * 70)
            raw = dev.raw
            print(json.dumps(raw, indent=2, ensure_ascii=False, default=str))
            print("-" * 70)
            print("INTERESTING KEYS:")
            flat = {}

            def walk(prefix, obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        walk(f"{prefix}.{k}" if prefix else k, v)
                else:
                    flat[prefix] = obj

            walk("", raw)
            for k, v in flat.items():
                leaf = k.split(".")[-1].lower()
                if any(t.lower() == leaf for t in INTERESTING):
                    print(f"  {k} = {v!r}")
            print()
        if devices:
            first = devices[0]
            detail = await client.get_device(first.device_id)
            if detail:
                print("=" * 70)
                print(f"getDevice detail for {first.device_id}")
                print(json.dumps(detail.raw, indent=2, ensure_ascii=False, default=str))
    finally:
        await client.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
