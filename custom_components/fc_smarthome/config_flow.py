"""Config flow for FC SmartHome."""

from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback

from .api.client import FcClient
from .api.errors import FcAuthError, FcError
from .const import CONF_EMAIL, CONF_ENDPOINTS_FILE, CONF_LOCAL_BLE, CONF_PASSWORD, CONF_POLL_INTERVAL, CONF_REGION, DEFAULT_POLL_INTERVAL, DOMAIN

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_REGION, default="us"): vol.In(["us", "eu", "cn", "ru"]),
        vol.Optional(CONF_ENDPOINTS_FILE, description={"suggested": ""}): str,
    }
)


class FCFlowMixin:
    """Shared helpers for the flows."""

    async def _validate(self, email: str, password: str, region: str, endpoints_file: str):
        from .api.endpoints import EndpointRegistry

        registry = EndpointRegistry.load(region, endpoints_file or None)
        client = FcClient(email, password, region, registry)
        try:
            await client.login()
        except FcAuthError as err:
            return {"errors": {"base": "invalid_auth"}}
        except FcError as err:
            return {"errors": {"base": "cannot_connect"}}
        finally:
            await client.close()
        return {"client_ok": True}


class FCSmartHomeConfigFlow(FCFlowMixin, config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors: dict[str, str] = {}
        if user_input is not None:
            result = await self._validate(
                user_input[CONF_EMAIL],
                user_input[CONF_PASSWORD],
                user_input[CONF_REGION],
                user_input.get(CONF_ENDPOINTS_FILE, ""),
            )
            if result.get("client_ok"):
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

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return FCSmartHomeOptionsFlow(config_entry)


class FCSmartHomeOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry):
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
