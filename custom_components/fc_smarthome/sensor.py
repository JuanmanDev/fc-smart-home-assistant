"""Sensor platform: battery, signal, and last-event method per lock."""

from __future__ import annotations

import logging

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities: list[SensorEntity] = []
    for device_id, device in coordinator.devices.items():
        entities.append(FCLastEventSensor(coordinator, device_id))
        status = coordinator.statuses.get(device_id)
        if status and status.battery is not None:
            entities.append(FCBatterySensor(coordinator, device_id))
        if status and status.signal is not None:
            entities.append(FCSignalSensor(coordinator, device_id))
    async_add_entities(entities)


class FCSensorBase(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: FcCoordinator, device_id: str, key: str, name: str) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_{key}"
        self._attr_name = name
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )


class FCBatterySensor(FCSensorBase):
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "%"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "battery", "Battery")

    @property
    def native_value(self) -> int | None:
        status = self.coordinator.statuses.get(self.device_id)
        return status.battery if status else None


class FCSignalSensor(FCSensorBase):
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "dBm"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "signal", "Signal")

    @property
    def native_value(self) -> int | None:
        status = self.coordinator.statuses.get(self.device_id)
        return status.signal if status else None


class FCLastEventSensor(FCSensorBase):
    """Who unlocked last: user + method + time as state/attributes."""

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "last_event", "Last event")

    @property
    def native_value(self) -> str | None:
        last = self.coordinator.last_event.get(self.device_id)
        if not last:
            return None
        if last.user:
            return f"{last.user} ({last.method.value if last.method else 'unknown'})"
        if last.method:
            return last.method.value
        return last.type.value

    @property
    def extra_state_attributes(self) -> dict:
        last = self.coordinator.last_event.get(self.device_id)
        if not last:
            return {"device_id": self.device_id}
        return {
            "device_id": self.device_id,
            **last.to_dict(),
        }
