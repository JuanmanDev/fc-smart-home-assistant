"""Switch platform: child lock toggle (with inline doc for NFC emulation)."""

from __future__ import annotations

import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = []
    for device_id, device in coordinator.devices.items():
        status = coordinator.statuses.get(device_id)
        if status is not None and status.child_lock is not None:
            entities.append(FCChildLockSwitch(coordinator, device_id))
    async_add_entities(entities)


class FCChildLockSwitch(CoordinatorEntity, SwitchEntity):
    _attr_has_entity_name = True
    _attr_name = "Child lock"
    _attr_icon = "mdi:human-child"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_child_lock"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )

    @property
    def is_on(self) -> bool | None:
        status = self.coordinator.statuses.get(self.device_id)
        return status.child_lock if status else None

    async def async_turn_on(self, **kwargs):
        await self.coordinator.client.set_child_lock(self.device_id, True)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs):
        await self.coordinator.client.set_child_lock(self.device_id, False)
        await self.coordinator.async_request_refresh()
