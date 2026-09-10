"""Lock platform: lock/unlock/latch local-first (LAN -> BLE -> cloud)."""

from __future__ import annotations

import logging

from homeassistant.components.lock import LockEntity, LockEntityFeature
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    router = data.get("router")
    entities = [
        FCLock(coordinator, device_id, router)
        for device_id, device in coordinator.devices.items()
        if device.is_lock or device.is_doorbell
    ]
    async_add_entities(entities)


class FCLock(CoordinatorEntity, LockEntity):
    """FC SmartHome lock (or doorbell acting as lock)."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_code_format = None

    def __init__(
        self, coordinator: FcCoordinator, device_id: str, router=None
    ) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        self.router = router
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
        return self.device_id in self.coordinator.devices

    @property
    def is_locked(self) -> bool | None:
        status = self.coordinator.statuses.get(self.device_id)
        if status is None or status.is_locked is None:
            return True
        return status.is_locked

    @property
    def extra_state_attributes(self) -> dict:
        status = self.coordinator.statuses.get(self.device_id)
        last = self.coordinator.last_event.get(self.device_id)
        attrs: dict = {"device_id": self.device_id}
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

    async def _control(self, cloud_call, local_call=None):
        if local_call is not None:
            try:
                result = await local_call()
                if result.success:
                    await self.coordinator.async_request_refresh()
                    return
                _LOGGER.warning("local control failed (%s), trying cloud", result.message)
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("local control error (%s), trying cloud", err)
        result = await cloud_call()
        if not result.success:
            _LOGGER.error("Control command failed: %s", result.message)
        await self.coordinator.async_request_refresh()

    async def async_lock(self, **kwargs):
        status = self.coordinator.statuses.get(self.device_id)
        if status:
            status.locked = True
            self.async_write_ha_state()
        await self._control(
            lambda: self.coordinator.client.lock(self.device_id),
            (lambda: self.router.lock(self.device_id)) if self.router else None,
        )

    async def async_unlock(self, **kwargs):
        status = self.coordinator.statuses.get(self.device_id)
        if status:
            status.locked = False
            self.async_write_ha_state()
        await self._control(
            lambda: self.coordinator.client.unlock(self.device_id, reason="app"),
            (lambda: self.router.unlock(self.device_id)) if self.router else None,
        )

    async def async_open(self, **kwargs):
        await self._control(
            lambda: self.coordinator.client.latch(self.device_id),
            (lambda: self.router.latch(self.device_id)) if self.router else None,
        )
