"""Lock platform: lock/unlock/latch with attribute-rich state, BLE fallback."""

from __future__ import annotations

import logging

from homeassistant.components.lock import LockEntity, LockEntityFeature
from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    entities = [
        FCLock(coordinator, device_id)
        for device_id, device in coordinator.devices.items()
        if device.is_lock or device.is_doorbell
    ]
    async_add_entities(entities)


class FCLock(CoordinatorEntity, LockEntity):
    """FC SmartHome lock (or doorbell acting as lock)."""

    _attr_has_entity_name = True
    _attr_name = None

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_lock"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )
        self._attr_supported_features = LockEntityFeature.OPEN

    @property
    def available(self) -> bool:
        return self.device_id in self.coordinator.statuses

    @property
    def lock_state(self) -> str | None:
        status = self.coordinator.statuses.get(self.device_id)
        if status is None:
            return None
        locked = status.is_locked
        if locked is None:
            return None
        return "locked" if locked else "unlocked"

    @property
    def is_locked(self) -> bool | None:
        return self.lock_state == "locked"

    @property
    def extra_state_attributes(self) -> dict:
        status = self.coordinator.statuses.get(self.device_id)
        last = self.coordinator.last_event.get(self.device_id)
        attrs = {"device_id": self.device_id}
        if status:
            attrs.update(
                {
                    "battery": status.battery,
                    "door_open": status.door_open,
                    "door_open_long": status.door_open_long,
                    "tamper": status.tamper,
                    "child_lock": status.child_lock,
                    "motor_error": status.motor_error,
                    "latch_open": status.latch_open,
                    "signal_rssi": status.signal,
                }
            )
        if last:
            attrs["last_event"] = last.to_dict()
        return attrs

    async def async_lock(self, **kwargs):
        client = self.coordinator.client
        result = await client.lock(self.device_id)
        if not result.success:
            _LOGGER.error("Lock command failed: %s", result.message)
        await self.coordinator.async_request_refresh()

    async def async_unlock(self, **kwargs):
        client = self.coordinator.client
        result = await client.unlock(self.device_id, reason="app")
        if not result.success:
            _LOGGER.error("Unlock command failed: %s", result.message)
        await self.coordinator.async_request_refresh()

    async def async_open(self, **kwargs):
        client = self.coordinator.client
        result = await client.latch(self.device_id)
        if not result.success:
            _LOGGER.error("Latch/open command failed: %s", result.message)
        await self.coordinator.async_request_refresh()

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()
