"""FC SmartHome HA integration setup.

One integration, one cloud client, one coordinator, all platforms.
Local BLE is opt-in per entry (options) and augments cloud control.
"""

from __future__ import annotations

import logging

try:  # pragma: no cover - HA environment
    import voluptuous as vol

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant, ServiceCall
    from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
    from homeassistant.helpers import config_validation as cv

    _HA_AVAILABLE = True
except ImportError:  # library-only environment (CLI, tests)
    _HA_AVAILABLE = False
    vol = None
    ConfigEntry = HomeAssistant = ServiceCall = None
    ConfigEntryNotReady = HomeAssistantError = None
    cv = None

from .api.client import FcClient
from .api.endpoints import EndpointRegistry
from .api.models import LockUserType
from .const import (
    CONF_EMAIL,
    CONF_ENDPOINTS_FILE,
    CONF_LOCAL_BLE,
    CONF_LOCAL_LAN,
    CONF_PASSWORD,
    CONF_REGION,
    DOMAIN,
    PLATFORMS,
    SERVICE_ADD_USER,
    SERVICE_BEEP,
    SERVICE_DELETE_USER,
    SERVICE_ENROLL_FINGERPRINT,
    SERVICE_FETCH_HISTORY,
    SERVICE_RENAME_USER,
    SERVICE_RING_BELL,
    SERVICE_SET_CHILD_LOCK,
)
from .coordinator import FcCoordinator

_LOGGER = logging.getLogger(__name__)

if _HA_AVAILABLE:
    CONFIG_SCHEMA = vol.Schema({DOMAIN: vol.Schema({})}, extra=vol.ALLOW_EXTRA)
else:
    CONFIG_SCHEMA = None

if _HA_AVAILABLE:
    ADD_USER_SCHEMA = vol.Schema(
        {
            vol.Required("device_id"): cv.string,
            vol.Required("name"): cv.string,
            vol.Required("user_type"): vol.In(
                [t.value for t in LockUserType if t != LockUserType.UNKNOWN]
            ),
            vol.Optional("password"): cv.string,
            vol.Optional("card_id"): cv.string,
        }
    )
    DELETE_USER_SCHEMA = vol.Schema(
        {
            vol.Required("device_id"): cv.string,
            vol.Required("user_id"): cv.string,
        }
    )
    RENAME_USER_SCHEMA = vol.Schema(
        {
            vol.Required("device_id"): cv.string,
            vol.Required("user_id"): cv.string,
            vol.Required("name"): cv.string,
        }
    )
    ENROLL_FINGERPRINT_SCHEMA = vol.Schema(
        {
            vol.Required("device_id"): cv.string,
            vol.Required("name"): cv.string,
        }
    )
    DEVICE_ID_SCHEMA = vol.Schema({vol.Required("device_id"): cv.string})
    CHILD_LOCK_SCHEMA = vol.Schema(
        {
            vol.Required("device_id"): cv.string,
            vol.Required("enabled"): cv.boolean,
        }
    )
else:
    ADD_USER_SCHEMA = DELETE_USER_SCHEMA = RENAME_USER_SCHEMA = None
    ENROLL_FINGERPRINT_SCHEMA = DEVICE_ID_SCHEMA = CHILD_LOCK_SCHEMA = None


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up FC SmartHome from a config entry."""
    if not _HA_AVAILABLE:  # pragma: no cover - never happens inside HA
        raise RuntimeError("Home Assistant runtime required")
    hass.data.setdefault(DOMAIN, {})
    endpoints = EndpointRegistry.load(
        entry.data.get(CONF_REGION, "us"),
        entry.data.get(CONF_ENDPOINTS_FILE) or None,
    )
    client = FcClient(
        email=entry.data[CONF_EMAIL],
        password=entry.data[CONF_PASSWORD],
        region=entry.data.get(CONF_REGION, "us"),
        endpoints=endpoints,
        on_token_refreshed=None,
    )
    try:
        await client.login()
    except Exception as err:  # noqa: BLE001
        raise ConfigEntryNotReady(f"FC SmartHome login failed: {err}") from err

    coordinator = FcCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()

    # Local-first transport router (LAN -> BLE -> cloud)
    router = None
    if entry.options.get(CONF_LOCAL_BLE) or entry.options.get(CONF_LOCAL_LAN):
        router = await _setup_local(hass, entry, endpoints, client, coordinator)

    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
        "ble": router.ble_manager if router else None,
        "router": router,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_reload_entry))

    _register_services(hass)
    return True


async def _setup_local(hass: HomeAssistant, entry: ConfigEntry, endpoints, client, coordinator):
    """Build the local transport router with LAN + BLE channels."""
    try:
        from .local.ble import FcBleManager, BleConfig
        from .local.lan import LanConfig, discover_lan_devices
        from .local.router import FcTransportRouter
    except ImportError as err:
        _LOGGER.warning("Local control unavailable: %s", err)
        return None
    ble_manager = None
    if entry.options.get(CONF_LOCAL_BLE):
        ble_manager = FcBleManager(BleConfig.from_registry(endpoints.ble))

    lan_config = LanConfig.from_registry(endpoints.lan)
    router = FcTransportRouter(client, ble_manager=ble_manager, lan_config=lan_config)

    # LAN discovery (best-effort, non-blocking on failure)
    if endpoints.lan.get("enabled", True):
        try:
            devices = await discover_lan_devices(timeout=5.0)
            for d in devices:
                _LOGGER.debug("LAN discovery found %s (%s)", d["ip"], d["source"])
            if devices:
                # probe coap on found ips to identify Alink devices
                from .local.lan import probe_coap

                for d in devices:
                    if d["source"] == "udp-broadcast":
                        result = await probe_coap(d["ip"])
                        if result:
                            _LOGGER.info(
                                "Alink device confirmed at %s (code %s)",
                                result["ip"],
                                result["coap_code"],
                            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("LAN discovery skipped: %s", err)

    # map cloud device ids to LAN hosts if we learned them (heuristic: match
    # by order; refined when devices report gateway ip in cloud payloads)
    return router


async def _reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


def _client_for_service(hass: HomeAssistant, device_id: str):
    entry_data = hass.data.get(DOMAIN, {})
    for data in entry_data.values():
        coordinator = data.get("coordinator")
        if coordinator and device_id in coordinator.devices:
            return data["client"], coordinator
    raise HomeAssistantError(f"No FC SmartHome entry owns device {device_id}")


def _register_services(hass: HomeAssistant) -> None:
    if not hass.services.has_service(DOMAIN, SERVICE_FETCH_HISTORY):

        async def _fetch_history(call: ServiceCall):
            client, coordinator = _client_for_service(hass, call.data["device_id"])
            events = await client.get_history(call.data["device_id"], limit=100)
            entries = [ev.to_dict() for ev in events]
            for ev in events:
                coordinator._process_new_events_single(ev)
            return {"entries": entries}

        hass.services.async_register(
            DOMAIN, SERVICE_FETCH_HISTORY, _fetch_history, supports_response=True
        )

    if not hass.services.has_service(DOMAIN, SERVICE_ADD_USER):

        async def _add_user(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.add_user(
                call.data["device_id"],
                call.data["name"],
                LockUserType.coerce(call.data["user_type"]),
                password=call.data.get("password"),
                card_id=call.data.get("card_id"),
            )

        hass.services.async_register(DOMAIN, SERVICE_ADD_USER, _add_user, ADD_USER_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_DELETE_USER):

        async def _delete_user(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.delete_user(call.data["device_id"], call.data["user_id"])

        hass.services.async_register(DOMAIN, SERVICE_DELETE_USER, _delete_user, DELETE_USER_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_RENAME_USER):

        async def _rename_user(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.rename_user(call.data["device_id"], call.data["user_id"], call.data["name"])

        hass.services.async_register(DOMAIN, SERVICE_RENAME_USER, _rename_user, RENAME_USER_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_ENROLL_FINGERPRINT):

        async def _enroll(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.enroll_fingerprint(call.data["device_id"], call.data["name"])

        hass.services.async_register(
            DOMAIN, SERVICE_ENROLL_FINGERPRINT, _enroll, ENROLL_FINGERPRINT_SCHEMA
        )

    if not hass.services.has_service(DOMAIN, SERVICE_RING_BELL):

        async def _ring(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.ring_bell(call.data["device_id"])

        hass.services.async_register(DOMAIN, SERVICE_RING_BELL, _ring, DEVICE_ID_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_BEEP):

        async def _beep(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.beep(call.data["device_id"])

        hass.services.async_register(DOMAIN, SERVICE_BEEP, _beep, DEVICE_ID_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_SET_CHILD_LOCK):

        async def _child_lock(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.set_child_lock(call.data["device_id"], call.data["enabled"])

        hass.services.async_register(DOMAIN, SERVICE_SET_CHILD_LOCK, _child_lock, CHILD_LOCK_SCHEMA)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    data = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if data:
        ble = data.get("ble")
        if ble:
            try:
                await ble.close()
            except Exception:  # noqa: BLE001
                pass
        await data["client"].close()
    return unload_ok
