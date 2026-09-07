"""Config flow for FC SmartHome, including reauth."""

from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.core import callback

from .api.client import FcClient
from .api.endpoints import EndpointRegistry
from .api.errors import FcAuthError, FcError
from .const import (
    CONF_EMAIL,
    CONF_ENDPOINTS_FILE,
    CONF_LOCAL_BLE,
    CONF_PASSWORD,
    CONF_POLL_INTERVAL,
    CONF_REGION,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(
            CONF_REGION,
            default="us",
            description="Server channel (extracted from the official app)",
        ): vol.In(["us", "eu", "cn", "ru", "intl-aws", "test", "test2"]),
        vol.Optional(CONF_ENDPOINTS_FILE, default=""): str,
    }
)

REAUTH_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PASSWORD): str,
    }
)


class FCSmartHomeConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return FCSmartHomeOptionsFlow(config_entry)

    async def _validate(
        self, email: str, password: str, region: str, endpoints_file: str
    ) -> dict:
        registry = EndpointRegistry.load(region, endpoints_file or None)
        client = FcClient(email, password, region, registry)
        try:
            await client.login()
        except FcAuthError:
            return {"errors": {"base": "invalid_auth"}}
        except FcError:
            return {"errors": {"base": "cannot_connect"}}
        finally:
            await client.close()
        return {"ok": True}

    async def async_step_user(self, user_input=None):
        errors: dict[str, str] = {}
        if user_input is not None:
            result = await self._validate(
                user_input[CONF_EMAIL],
                user_input[CONF_PASSWORD],
                user_input[CONF_REGION],
                user_input.get(CONF_ENDPOINTS_FILE, ""),
            )
            if result.get("ok"):
                await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_EMAIL],
                    data=user_input,
                )
            errors = result.get("errors", {})
        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth(self, entry_data):
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        errors: dict[str, str] = {}
        if user_input is not None:
            entry = self._get_reauth_entry()
            data = dict(entry.data)
            data[CONF_PASSWORD] = user_input[CONF_PASSWORD]
            result = await self._validate(
                data[CONF_EMAIL],
                data[CONF_PASSWORD],
                data.get(CONF_REGION, "us"),
                data.get(CONF_ENDPOINTS_FILE, ""),
            )
            if result.get("ok"):
                return self.async_update_reload_and_abort(
                    entry, data=data, reason="reauth_successful"
                )
            errors = result.get("errors", {})
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=REAUTH_SCHEMA,
            errors=errors,
        )


class FCSmartHomeOptionsFlow(OptionsFlow):
    def __init__(self, entry: ConfigEntry) -> None:
        self.entry = entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        current = self.entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_POLL_INTERVAL,
                        default=current.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
                    ): vol.All(vol.Coerce(int), vol.Range(min=15, max=3600)),
                    vol.Optional(
                        CONF_LOCAL_BLE,
                        default=current.get(CONF_LOCAL_BLE, False),
                    ): bool,
                }
            ),
        )
