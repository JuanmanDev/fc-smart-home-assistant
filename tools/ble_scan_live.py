"""Live BLE scan for FC locks."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from custom_components.fc_smarthome.api.endpoints import EndpointRegistry
from custom_components.fc_smarthome.local.ble import BleConfig, FcBleManager


async def main() -> None:
    reg = EndpointRegistry.load("us")
    mgr = FcBleManager(BleConfig.from_registry(reg.ble))
    print("scanning BLE 12s (broad mode: any device)...")
    found = await mgr.scan(timeout=12.0, broad=True)
    for d in found:
        print(f"  {d['address']}  {d['name']!r} rssi={d.get('rssi')} lock_like={d.get('possibly_lock')}")
    if not found:
        print("  none found")


if __name__ == "__main__":
    asyncio.run(main())
