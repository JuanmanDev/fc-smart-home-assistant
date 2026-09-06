"""Binary sensors: door open, tamper, low battery, motor error, online."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = []
    for device_id, device in coordinator.devices.items():
        status = coordinator.statuses.get(device_id)
        if status is None:
            continue
        if status.door_open is not None:
            entities.append(FCBinarySensor(coordinator, device_id, "door", BinarySensorDeviceClass.DOOR, "door_open"))
        if status.door_open_long is not None:
            entities.append(FCBinarySensor(coordinator, device_id, "door_open_long", BinarySensorDeviceClass.PROBLEM, "door_open_long"))
        if status.tamper is not None:
            entities.append(FCBinarySensor(coordinator, device_id, "tamper", BinarySensorDeviceClass.TAMPER, "tamper"))
        if status.motor_error is not None:
            entities.append(FCBinarySensor(coordinator, device_id, "motor_error", BinarySensorDeviceClass.PROBLEM, "motor_error"))
    async_add_entities(entities)


class FCBinarySensor(CoordinatorEntity, BinarySensorEntity):
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: FcCoordinator,
        device_id: str,
        key: str,
        device_class: BinarySensorDeviceClass,
        attr: str,
    ) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_{key}"
        self._attr_name = key.replace("_", " ").title()
        self._attr_device_class = device_class
        self._attr = attr
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )

    @property
    def is_on(self) -> bool | None:
        status = self.coordinator.statuses.get(self.device_id)
        if status is None:
            return None
        return bool(getattr(status, self._attr))
