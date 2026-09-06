"""Buttons: ring bell, beep/locate, sync now."""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    entities: list[ButtonEntity] = []
    for device_id, device in coordinator.devices.items():
        if device.is_lock or device.is_doorbell:
            entities.append(FCButton(coordinator, device_id, "ring_bell", "Ring bell", coordinator.client.ring_bell))
            entities.append(FCButton(coordinator, device_id, "beep", "Beep", coordinator.client.beep))
        entities.append(FCButton(coordinator, device_id, "sync", "Sync now", None))
    async_add_entities(entities)


class FCButton(CoordinatorEntity, ButtonEntity):
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: FcCoordinator,
        device_id: str,
        key: str,
        name: str,
        action,
    ) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_{key}"
        self._attr_name = name
        self._action = action
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )

    async def async_press(self) -> None:
        if self._action is None:
            await self.coordinator.async_request_refresh()
            return
        result = await self._action(self.device_id)
        if not result.success:
            _LOGGER.error("%s failed: %s", self._attr_name, result.message)
