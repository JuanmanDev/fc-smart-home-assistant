"""DataUpdateCoordinator for FC SmartHome.

Event-first design:
- every cycle pulls device list + statuses + history deltas
- new history entries fire both the legacy bus event and update the
  EventEntity + last_event sensor immediately
- keeps an in-memory access-log ring buffer per device (who/how/when)
- tracks bell rings (doorbell playing state) for binary_sensor exposure
"""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import timedelta
from typing import Any

try:  # pragma: no cover - HA runtime
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.exceptions import ConfigEntryAuthFailed
    from homeassistant.helpers.update_coordinator import (
        DataUpdateCoordinator,
        UpdateFailed,
    )

    _HA_AVAILABLE = True
except ImportError:  # library-only environment (CLI, tests)
    _HA_AVAILABLE = False
    ConfigEntry = HomeAssistant = None

    class DataUpdateCoordinator:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs):
            self.hass = kwargs.get("hass")
            self.name = kwargs.get("name")

        def __getattr__(self, item):
            raise RuntimeError("Home Assistant runtime required")

    class UpdateFailed(Exception):  # type: ignore[no-redef]
        pass

    class ConfigEntryAuthFailed(Exception):  # type: ignore[no-redef]
        pass

from .api.client import FcClient
from .api.errors import FcAuthError
from .api.models import Device, LockEvent, LockEventType, LockStatus
from .const import DEFAULT_POLL_INTERVAL, EVENT_FC_EVENT

_LOGGER = logging.getLogger(__name__)

ACCESS_LOG_MAX = 200
BELL_LATCH_SECONDS = 60


class FcCoordinator(DataUpdateCoordinator):
    """Coordinator keeping device list + statuses + events in memory."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: FcClient) -> None:
        self.entry = entry
        self.client = client
        self.devices: dict[str, Device] = {}
        self.statuses: dict[str, LockStatus] = {}
        self.last_event: dict[str, LockEvent | None] = {}
        self.access_log: dict[str, deque[dict]] = {}
        self.bell_active: dict[str, bool] = {}
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
            self._expire_bells()
            devices = await self.client.get_devices()
            self.devices = {d.device_id: d for d in devices}
            for device in devices:
                try:
                    self.statuses[device.device_id] = await self.client.get_device_status(
                        device.device_id
                    )
                except FcAuthError:
                    raise
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("status fetch failed for %s", device.device_id)
                try:
                    events = await self.client.get_history(device.device_id, limit=30)
                    self._process_new_events(device.device_id, events)
                except FcAuthError:
                    raise
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("history fetch failed for %s", device.device_id)
            return {
                "devices": self.devices,
                "statuses": self.statuses,
                "last_event": self.last_event,
            }
        except FcAuthError as err:
            # platinum: route auth failures into HA's reauth flow
            raise ConfigEntryAuthFailed(f"FC SmartHome auth failed: {err}") from err
        except Exception as err:  # noqa: BLE001
            raise UpdateFailed(f"FC SmartHome update failed: {err}") from err

    def _expire_bells(self) -> None:
        now = time.time()
        expired = [
            device_id
            for device_id, ts in self.bell_active.items()
            if now - ts > BELL_LATCH_SECONDS
        ]
        for device_id in expired:
            self.bell_active.pop(device_id, None)

    def _process_new_events(self, device_id: str, events: list[LockEvent]) -> None:
        seen = self._seen_log_ids.setdefault(device_id, set())
        log = self.access_log.setdefault(device_id, deque(maxlen=ACCESS_LOG_MAX))
        fresh: list[LockEvent] = []
        for ev in events:
            key = self._event_key(ev)
            if key in seen:
                continue
            seen.add(key)
            fresh.append(ev)
        if not fresh:
            return
        for ev in fresh:
            log.appendleft(ev.to_dict())
        self.last_event[device_id] = fresh[0]
        for ev in fresh:
            self._fire_event(ev)
        _LOGGER.debug("fired %d new events for %s", len(fresh), device_id)

    def _process_new_events_single(self, ev: LockEvent) -> bool:
        """Dedup+record+fire one event (used by fetch_history service)."""
        seen = self._seen_log_ids.setdefault(ev.device_id, set())
        key = self._event_key(ev)
        if key in seen:
            return False
        seen.add(key)
        self.access_log.setdefault(ev.device_id, deque(maxlen=ACCESS_LOG_MAX)).appendleft(
            ev.to_dict()
        )
        self.last_event[ev.device_id] = ev
        self._fire_event(ev)
        return True

    @staticmethod
    def _event_key(ev: LockEvent) -> tuple:
        return (
            ev.timestamp.isoformat() if ev.timestamp else "",
            ev.type.value,
            ev.user_id or "",
            ev.method.value if ev.method else "",
            str(ev.raw.get("id", "")),
        )

    def _fire_event(self, ev: LockEvent) -> None:
        device_id = ev.device_id
        payload = {
            "device_id": device_id,
            "device_name": (
                self.devices[device_id].name if device_id in self.devices else device_id
            ),
            "event_type": ev.type.value,
            "method": ev.method.value if ev.method else None,
            "user": ev.user,
            "user_id": ev.user_id,
            "remote": ev.remote,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "description": ev.description,
        }
        if ev.type is LockEventType.BELL:
            # store the latch time; binary_sensor turns off after
            # BELL_LATCH_SECONDS (reset each coordinator cycle)
            self.bell_active[device_id] = time.time()
        self.hass.bus.async_fire(EVENT_FC_EVENT, payload)
