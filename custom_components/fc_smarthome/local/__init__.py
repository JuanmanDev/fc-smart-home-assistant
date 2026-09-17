"""Local control package: BLE transport, LAN transport, and the router.

- ble.py    — BLE GATT channel (scan, pair, commands, notifications)
- lan.py    — LAN/WiFi channel (mDNS/UDP discovery, CoAP probe, TCP FCFC)
- router.py — local-first transport router (LAN → BLE → cloud)
"""

from .ble import FcBleManager, FcBleTransport, build_frame, parse_frame
from .lan import FcLanTransport, LanConfig, discover_lan_devices, probe_coap
from .router import FcTransportRouter

__all__ = [
    "FcBleManager",
    "FcBleTransport",
    "FcLanTransport",
    "LanConfig",
    "FcTransportRouter",
    "discover_lan_devices",
    "probe_coap",
    "build_frame",
    "parse_frame",
]

