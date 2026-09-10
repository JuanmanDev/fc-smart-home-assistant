"""Binary sensors: door, bell ringing, tamper, low battery, motor error, online."""

from __future__ import annotations

import time

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.const import EntityCategory
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = []
    for device_id, device in coordinator.devices.items():
        entities.append(
            FCBinary(coordinator, device_id, "door", BinarySensorDeviceClass.DOOR, "door_open")
        )
        entities.append(
            FCBinary(coordinator, device_id, "tamper", BinarySensorDeviceClass.TAMPER, "tamper")
        )
        entities.append(
            FCBinary(
                coordinator,
                device_id,
                "door_open_long",
                BinarySensorDeviceClass.PROBLEM,
                "door_open_long",
            )
        )
        entities.append(
            FCBinary(
                coordinator,
                device_id,
                "motor_error",
                BinarySensorDeviceClass.PROBLEM,
                "motor_error",
            )
        )
        entities.append(
            FCBinary(
                coordinator,
                device_id,
                "low_battery",
                BinarySensorDeviceClass.PROBLEM,
                "low_battery",
            )
        )
        entities.append(
            FCBleInRangeBinarySensor(coordinator, device_id)
        )
        if device.is_doorbell or device.is_lock:
            entities.append(
                FCBellPlaying(coordinator, device_id)
            )
    async_add_entities(entities)


class FCBinary(CoordinatorEntity, BinarySensorEntity):
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
        if key != "door":
            self._attr_entity_category = EntityCategory.DIAGNOSTIC
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
        value = getattr(status, self._attr)
        return bool(value) if value is not None else None

    @property
    def available(self) -> bool:
        return self.device_id in self.coordinator.devices


class FCBellPlaying(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor that's ON while the doorbell is ringing (event-latched)."""

    _attr_has_entity_name = True
    _attr_name = "Bell ringing"
    _attr_icon = "mdi:bell-ring"
    _attr_device_class = BinarySensorDeviceClass.SOUND

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_bell_ringing"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )

    @property
    def is_on(self) -> bool:
        ts = self.coordinator.bell_active.get(self.device_id)
        if not ts:
            return False
        return (time.time() - ts) < 30.0

    @property
    def available(self) -> bool:
        return self.device_id in self.coordinator.devices


class FCBleInRangeBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor indicating if lock is actively in BLE range."""

    _attr_has_entity_name = True
    _attr_name = "Bluetooth in range"
    _attr_icon = "mdi:bluetooth-connect"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_ble_in_range"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )

    @property
    def is_on(self) -> bool:
        last = self.coordinator.ble_last_seen.get(self.device_id, 0)
        return (time.time() - last) < 120.0

    @property
    def available(self) -> bool:
        return self.device_id in self.coordinator.devices

