"""Config flow for Cync Room Lights integration.."""
from __future__ import annotations
import logging
from typing import Any, Dict
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.core import HomeAssistant, callback
import aiohttp
import asyncio

from .const import DOMAIN
from .cync_hub import CyncUserData

_LOGGER = logging.getLogger(__name__)

# Define schemas for user input
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

# Custom exceptions
class TwoFactorCodeRequired(HomeAssistantError):
    """Error to indicate two-factor authentication is required."""

class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid authentication."""

# Standalone functions for authentication
async def cync_login(hub: CyncUserData, user_input: Dict[str, Any]) -> Dict[str, Any]:
    """Attempt to log in with provided credentials."""
    _LOGGER.debug("Attempting login")
    response = await hub.authenticate(user_input["username"], user_input["password"])
    if response['authorized']:
        _LOGGER.debug("Successfully authenticated")
        return {
            'title': f'cync_lights_{user_input["username"]}',
            'data': {
                'cync_credentials': hub.access_token, 
                'user_input': user_input
            }
        }
    elif response['two_factor_code_required']:
        _LOGGER.debug("Two-factor authentication required")
        raise TwoFactorCodeRequired
    else:
        _LOGGER.debug("Authentication failed")
        raise InvalidAuth

async def submit_two_factor_code(hub: CyncUserData, user_input: Dict[str, Any]) -> Dict[str, Any]:
    """Submit two-factor authentication code."""
    response = await hub.auth_two_factor(user_input["two_factor_code"])
    if response['authorized']:
        return {
            'title': f'cync_lights_{hub.username}',
            'data': {
                'cync_credentials': hub.access_token, 
                'user_input': {'username': hub.username, 'password': hub.password}
            }
        }
    raise InvalidAuth

class CyncConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the Cync configuration flow."""

    VERSION = 1

    def __init__(self):
        super().__init__()
        self.cync_hub = CyncUserData() 
        await self.cync_hub.initial_setup()

    async def async_step_user(self, user_input: Dict[str, Any] | None = None) -> FlowResult:
        """Handle the initial step."""
        if user_input is None:
            return self.async_show_form(
                step_id="user", 
                data_schema=STEP_USER_DATA_SCHEMA,
                errors={}
            )
        
        errors = {}
        try:
            info = await cync_login(CyncUserData(), user_input)
            info["data"]["cync_config"] = await CyncUserData().get_cync_config()
        except TwoFactorCodeRequired:
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Unexpected error during login: {e}")
            errors["base"] = "unknown"
        else:
            return await self._async_finish_setup(info)

        return self.async_show_form(
            step_id="user", 
            data_schema=STEP_USER_DATA_SCHEMA, 
            errors=errors
        )

    async def async_step_two_factor_code(self, user_input: Dict[str, Any] | None = None) -> FlowResult:
        """Handle the two-factor authentication step."""
        if user_input is None:
            return self.async_show_form(
                step_id="two_factor_code", 
                data_schema=STEP_TWO_FACTOR_CODE,
                errors={}
            )
        
        errors = {}
        try:
            info = await submit_two_factor_code(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Unexpected error during 2FA: {e}")
            errors["base"] = "unknown"
        else:
            return await self._async_finish_setup(info)

        return self.async_show_form(
            step_id="two_factor_code", 
            data_schema=STEP_TWO_FACTOR_CODE, 
            errors=errors
        )

    async def _async_finish_setup(self, info: Dict[str, Any]) -> FlowResult:
        """Finish setup with the provided information."""
        await self.async_set_unique_id(info['title'])
        self._abort_if_unique_id_configured()

        return self.async_create_entry(
            title=info['title'],
            data=info['data'],
            options={}
        )

class CyncOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle Cync options flow."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry
        self.cync_hub = CyncUserData(config_entry.data['user_input'])

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle the initial step of options flow."""
        if user_input is not None:
            if user_input['re-authenticate'] == "No":
                return await self.async_step_select_switches()
            else:
                return await self.async_step_auth()
        
        return self.async_show_form(
            step_id="init", 
            data_schema=vol.Schema({
                vol.Required("re-authenticate", default="No"): vol.In(["Yes", "No"]),
            }),
            errors={}
        )

    async def async_step_auth(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle authentication for options re-authentication."""
        errors = {}
        try:
            info = await cync_login(self.cync_hub, self.config_entry.data['user_input'])
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
        except TwoFactorCodeRequired:
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Unexpected error during re-authentication: {e}")
            errors["base"] = "unknown"
        else:
            self.hass.config_entries.async_update_entry(self.config_entry, data=info['data'])
            return await self.async_step_select_switches()

        return self.async_show_form(
            step_id="user", 
            data_schema=STEP_USER_DATA_SCHEMA, 
            errors=errors
        )

    async def async_step_two_factor_code(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle two-factor authentication in options flow."""
        if user_input is None:
            return self.async_show_form(
                step_id="two_factor_code", 
                data_schema=STEP_TWO_FACTOR_CODE,
                errors={}
            )
        
        errors = {}
        try:
            info = await submit_two_factor_code(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Unexpected error during 2FA in options: {e}")
            errors["base"] = "unknown"
        else:
            self.hass.config_entries.async_update_entry(self.config_entry, data=info['data'])
            return await self.async_step_select_switches()

        return self.async_show_form(
            step_id="two_factor_code", 
            data_schema=STEP_TWO_FACTOR_CODE, 
            errors=errors
        )

    async def async_step_select_switches(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle device selection in options flow."""
        if user_input is not None:
            # Update the config entry with the new selections
            self.hass.config_entries.async_update_entry(self.config_entry, options=user_input)
            return self.async_create_entry(title="", data=user_input)

        # Generate the schema for device selection based on the current configuration
        cync_config = self.config_entry.data.get('cync_config', {})
        rooms = {
            room: f"{info['name']} ({info['home_name']})"
            for room, info in cync_config.get('rooms', {}).items() 
            if not info.get('isSubgroup', False)
        }
        subgroups = {
            room: f"{info['name']} ({info.get('parent_room', '')}:{info['home_name']})"
            for room, info in cync_config.get('rooms', {}).items() 
            if info.get('isSubgroup', False)
        }
        switches = {
            switch_id: f"{info['name']} ({info['room_name']}:{info['home_name']})"
            for switch_id, info in cync_config.get('devices', {}).items() 
            if info.get('ONOFF', False) and info.get('MULTIELEMENT', 1) == 1
        }
        motion_sensors = {
            device_id: f"{info['name']} ({info['room_name']}:{info['home_name']})"
            for device_id, info in cync_config.get('devices', {}).items() 
            if info.get('MOTION', False)
        }
        ambient_light_sensors = {
            device_id: f"{info['name']} ({info['room_name']}:{info['home_name']})"
            for device_id, info in cync_config.get('devices', {}).items() 
            if info.get('AMBIENT_LIGHT', False)
        }

        # Current options for pre-selecting values
        current_options = self.config_entry.options

        switches_data_schema = vol.Schema({
            vol.Optional("rooms", description={"suggested_value": current_options.get("rooms", [])}): cv.multi_select(rooms),
            vol.Optional("subgroups", description={"suggested_value": current_options.get("subgroups", [])}): cv.multi_select(subgroups),
            vol.Optional("switches", description={"suggested_value": current_options.get("switches", [])}): cv.multi_select(switches),
            vol.Optional("motion_sensors", description={"suggested_value": current_options.get("motion_sensors", [])}): cv.multi_select(motion_sensors),
            vol.Optional("ambient_light_sensors", description={"suggested_value": current_options.get("ambient_light_sensors", [])}): cv.multi_select(ambient_light_sensors),
        })

        return self.async_show_form(
            step_id="select_switches", 
            data_schema=switches_data_schema,
            errors={}
        )
