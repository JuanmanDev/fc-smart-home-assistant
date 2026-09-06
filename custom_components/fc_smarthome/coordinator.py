"""DataUpdateCoordinator for FC SmartHome.

Event-first: consumes cloud history deltas each cycle (and BLE push when
available) and fires HA events; polling is the fallback and always resyncs.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

try:  # pragma: no cover - HA runtime
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant, callback
    from homeassistant.helpers.update_coordinator import (
        DataUpdateCoordinator,
        UpdateFailed,
    )

    _HA_AVAILABLE = True
except ImportError:  # library-only environment (CLI, tests)
    _HA_AVAILABLE = False
    ConfigEntry = HomeAssistant = callback = None

    class DataUpdateCoordinator:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs):
            self.hass = kwargs.get("hass")
            self.name = kwargs.get("name")

        def __getattr__(self, item):
            raise RuntimeError("Home Assistant runtime required")

    class UpdateFailed(Exception):  # type: ignore[no-redef]
        pass

from .api.client import FcClient
from .api.models import Device, LockEvent, LockEventType, LockStatus
from .const import DEFAULT_POLL_INTERVAL

_LOGGER = logging.getLogger(__name__)


class FcCoordinator(DataUpdateCoordinator):
    """Coordinator keeping device list + statuses + last events in memory."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: FcClient) -> None:
        self.entry = entry
        self.client = client
        self.devices: dict[str, Device] = {}
        self.statuses: dict[str, LockStatus] = {}
        self.last_event: dict[str, LockEvent | None] = {}
        self._seen_log_ids: dict[str, set] = {}
        interval = entry.options.get("poll_interval", DEFAULT_POLL_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            name="FC SmartHome",
            update_interval=timedelta(seconds=max(15, int(interval))),
        )

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            await self.client.ensure_logged_in()
            devices = await self.client.get_devices()
            self.devices = {d.device_id: d for d in devices}
            for device in devices:
                try:
                    self.statuses[device.device_id] = await self.client.get_device_status(
                        device.device_id
                    )
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("status fetch failed for %s", device.device_id)
                try:
                    events = await self.client.get_history(device.device_id, limit=20)
                    self._process_new_events(device.device_id, events)
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("history fetch failed for %s", device.device_id)
            return {
                "devices": self.devices,
                "statuses": self.statuses,
                "last_event": self.last_event,
            }
        except Exception as err:  # noqa: BLE001
            raise UpdateFailed(f"FC SmartHome update failed: {err}") from err

    @property
    def _bus(self):
        return self.hass.bus

    def _process_new_events(self, device_id: str, events: list[LockEvent]) -> None:
        seen = self._seen_log_ids.setdefault(device_id, set())
        fresh: list[LockEvent] = []
        for ev in events:
            key = (ev.timestamp, ev.type.value, ev.user_id or "", ev.method.value if ev.method else "")
            if key in seen:
                continue
            seen.add(key)
            fresh.append(ev)
        if not fresh:
            return
        self.last_event[device_id] = fresh[0]
        for ev in fresh:
            self.hass.bus.async_fire(
                "fc_smarthome_event",
                {
                    "device_id": device_id,
                    "device_name": (self.devices.get(device_id).name if self.devices.get(device_id) else device_id),
                    "event_type": ev.type.value,
                    "method": ev.method.value if ev.method else None,
                    "user": ev.user,
                    "user_id": ev.user_id,
                    "remote": ev.remote,
                    "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                },
            )
