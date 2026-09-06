"""Event entities: every lock action (unlock by user X via finger, bell, tamper…)."""

from __future__ import annotations

from collections import deque

from homeassistant.components.event import EventEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = [
        FCEventEntity(coordinator, device_id)
        for device_id, device in coordinator.devices.items()
        if device.is_lock or device.is_doorbell
    ]
    async_add_entities(entities)


class FCEventEntity(CoordinatorEntity, EventEntity):
    _attr_has_entity_name = True
    _attr_name = "Events"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_events"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )
        self._triggered: deque = deque(maxlen=50)
        coordinator.hass.bus.async_listen_once("homeassistant_started", self._on_start)

    async def _on_start(self, _event) -> None:
        pass

    @property
    def event_types(self) -> list[str]:
        return [
            "unlocked",
            "locked",
            "door_open",
            "door_left_open",
            "tamper",
            "low_battery",
            "bell",
            "user_added",
            "user_removed",
            "malfunction",
            "unknown",
        ]

    def _handle_coordinator_update(self) -> None:
        last = self.coordinator.last_event.get(self.device_id)
        if last:
            self._triggered.append(
                {
                    "event_type": last.type.value,
                    "event": {
                        "method": last.method.value if last.method else None,
                        "user": last.user,
                        "user_id": last.user_id,
                        "remote": last.remote,
                        "timestamp": last.timestamp.isoformat() if last.timestamp else None,
                    },
                }
            )
        self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict:
        return {"recent_events": list(self._triggered)}
