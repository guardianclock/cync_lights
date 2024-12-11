"""Config flow for Cync Room Lights integration."""
from __future__ import annotations
import logging
import voluptuous as vol
from typing import Any
from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.core import callback
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,       
    }
)
STEP_TWO_FACTOR_CODE = vol.Schema(
    {
        vol.Required("two_factor_code"): str,
    }
)

async def cync_login(hub, user_input: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input"""
    response = await hub.authenticate(user_input["username"], user_input["password"])
    if response.get('access_token'):
        hub.access_token = response['access_token']
        hub.refresh_token = response['refresh_token']
        hub.user_id = response['user_id']
        return {
            'title': 'cync_lights_' + user_input['username'],
            'data': {
                'cync_credentials': {
                    'access_token': response['access_token'],
                    'refresh_token': response['refresh_token'],
                    'user_id': response['user_id']
                },
                'user_input': user_input
            }
        }
    else:
        if response.get('two_factor_code_required'):
            raise TwoFactorCodeRequired
        else:
            raise InvalidAuth

async def submit_two_factor_code(hub, user_input: dict[str, Any]) -> dict[str, Any]:
    """Validate the two factor code"""
    response = await hub.auth_two_factor(user_input["two_factor_code"])
    if response.get('access_token'):
        hub.access_token = response['access_token']
        hub.refresh_token = response['refresh_token']
        hub.user_id = response['user_id']
        return {
            'title': 'cync_lights_' + hub.username,
            'data': {
                'cync_credentials': {
                    'access_token': response['access_token'],
                    'refresh_token': response['refresh_token'],
                    'user_id': response['user_id']
                },
                'user_input': {'username': hub.username, 'password': hub.password}
            }
        }
    else:
        raise InvalidAuth

class CyncUserData:
    def __init__(self):
        self.username = None
        self.password = None
        self.access_token = None
        self.refresh_token = None
        self.user_id = None

    async def get_devices(self):
        """Fetch devices from the Cync API."""
        headers = {
            "access-token": self.access_token
        }
        url = f"/v2/user/{self.user_id}/subscribe/devices?version=0"
        async with self.hass.client_session.get(url, headers=headers) as resp:
            if resp.status != 200:
                raise HomeAssistantError(f"Failed to fetch devices: {resp.status}")
            return await resp.json()

    async def authenticate(self, username: str, password: str) -> dict:
        # Implementation for authentication would go here
        pass

    async def auth_two_factor(self, two_factor_code: str) -> dict:
        # Implementation for two factor authentication would go here
        pass

class CyncConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Cync Room Lights."""

    def __init__(self):
        self.cync_hub = CyncUserData()
        self.data = {}
        self.options = {}

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle user and password for Cync account."""
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=STEP_USER_DATA_SCHEMA
            )

        errors = {}

        try:
            info = await cync_login(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_devices()
        except TwoFactorCodeRequired:
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.error(f"Error during login: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_select_switches()

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_two_factor_code(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle two factor authentication for Cync account."""
        if user_input is None:
            return self.async_show_form(
                step_id="two_factor_code", data_schema=STEP_TWO_FACTOR_CODE
            )

        errors = {}

        try:
            info = await submit_two_factor_code(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_devices()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.error(f"Error during two factor authentication: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_select_switches()

        return self.async_show_form(
            step_id="two_factor_code", data_schema=STEP_TWO_FACTOR_CODE, errors=errors
        )

    async def async_step_select_switches(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Select devices for entity creation"""
        if user_input is not None:
            self.options = user_input
            return await self._async_finish_setup()

        try:
            devices = self.data["data"]["cync_config"]
        except KeyError:
            _LOGGER.error("Device list not available; skipping device selection")
            return await self._async_finish_setup()

        switches_data_schema = vol.Schema(
            {
                vol.Optional(
                    "devices",
                    description={"suggested_value": list(devices.keys()) if devices else []},
                ): cv.multi_select({device_id: f'{device.get("name", "Unnamed Device")}' for device_id, device in devices.items()}),
            }
        )
        
        return self.async_show_form(step_id="select_switches", data_schema=switches_data_schema)

    async def _async_finish_setup(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Finish setup and create entry"""
        existing_entry = await self.async_set_unique_id(self.data['title'])
        if not existing_entry:              
            return self.async_create_entry(title=self.data["title"], data=self.data["data"], options=self.options)
        else:
            self.hass.config_entries.async_update_entry(existing_entry, data=self.data['data'], options=self.options)
            await self.hass.config_entries.async_reload(existing_entry.entry_id)
            return self.hass.config_entries.async_abort(reason="reauth_successful")

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return CyncOptionsFlowHandler(config_entry)


class CyncOptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.entry = config_entry
        self.cync_hub = CyncUserData()
        self.data = {}

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            if user_input['re-authenticate'] == "No":
                return await self.async_step_select_switches()
            else:
                return await self.async_step_auth()

        data_schema = vol.Schema(
            {
                vol.Required(
                    "re-authenticate", default="No"): vol.In(["Yes", "No"]),
            }
        )

        return self.async_show_form(step_id="init", data_schema=data_schema)

    async def async_step_auth(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Attempt to re-authenticate"""
        errors = {}

        try:
            info = await cync_login(self.cync_hub, self.entry.data['user_input'])
            info["data"]["cync_config"] = await self.cync_hub.get_devices()
        except TwoFactorCodeRequired:
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.error(f"Error during re-authentication: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_select_switches()

        return self.async_show_form(
            step_id="auth", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_two_factor_code(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle two factor authentication for Cync account."""
        if user_input is None:
            return self.async_show_form(
                step_id="two_factor_code", data_schema=STEP_TWO_FACTOR_CODE
            )

        errors = {}

        try:
            info = await submit_two_factor_code(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_devices()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.error(f"Error during two factor authentication: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_select_switches()

        return self.async_show_form(
            step_id="two_factor_code", data_schema=STEP_TWO_FACTOR_CODE, errors=errors
        )

    async def async_step_select_switches(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if "data" in self.data and self.data["data"] != self.entry.data:
            self.hass.config_entries.async_update_entry(self.entry, data=self.data["data"])

        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        try:
            devices = self.entry.data.get("cync_config", {})
        except KeyError:
            _LOGGER.error("Device list not available in existing config; skipping device selection")
            return self.async_create_entry(title="", data={})

        switches_data_schema = vol.Schema(
            {
                vol.Optional(
                    "devices",
                    description={"suggested_value": list(devices.keys()) if devices else []},
                ): cv
