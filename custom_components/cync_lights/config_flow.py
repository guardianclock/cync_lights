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
from typing import Any, Dict
import aiohttp
import sys
import asyncio
from .const import DOMAIN
from .cync_hub import CyncUserData


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

class TwoFactorCodeRequired(HomeAssistantError):
    pass

class InvalidAuth(HomeAssistantError):
    pass

# These should be standalone functions, not methods of CyncUserData
async def cync_login(hub, user_input: Dict[str, Any]) -> Dict[str, Any]:
    response = await hub.authenticate(user_input["username"], user_input["password"])
    if response['authorized']:
        _LOGGER.info(hub.access_token)
        return {
            'title': 'cync_lights_' + user_input['username'],
            'data': {
                'cync_credentials': hub.access_token, 
                'user_input': user_input
            }
        }
    else:
        if response['two_factor_code_required']:
            raise TwoFactorCodeRequired
        else:
            raise InvalidAuth

async def submit_two_factor_code(hub, user_input: Dict[str, Any]) -> Dict[str, Any]:
    response = await hub.auth_two_factor(user_input["factor_code"])
    if response['authorized']:
        return {
            'title': 'cync_lights_' + hub.username,
            'data': {
                'cync_credentials': hub.access_token, 
                'user_input': {'username': hub.username, 'password': hub.password}
            }
        }
    else:
        raise InvalidAuth

class CyncConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    def __init__(self):
        self.cync_hub = CyncUserData()
        self.data = {}
        self.options = {}
        
        VERSION = 1

    async def async_step_user(self, user_input: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if user_input is None:
            return {"type": "form", "step_id": "user", "data_schema": STEP_USER_DATA_SCHEMA}
    
        errors = {}
    
        try:
            info = await cync_login(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
            self.data = info
            return await self._async_finish_setup()
        except TwoFactorCodeRequired:
            return {"type": "form", "step_id": "step_two_factor_code", "data_schema": STEP_TWO_FACTOR_CODE}
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Error during login: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
    
        return {"type": "form", "step_id": "user", "data_schema": STEP_USER_DATA_SCHEMA, "errors": errors}

    async def async_step_two_factor_code(self, user_input: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if user_input is None:
            return {"type": "form", "step_id": "two_factor_code", "data_schema": STEP_TWO_FACTOR_CODE}
    
        errors = {}
    
        try:
            info = await submit_two_factor_code(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
            self.data = info
            return await self.async_step_select_switches()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Error during two factor authentication: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
    
        return {"type": "form", "step_id": "two_factor_code", "data_schema": STEP_TWO_FACTOR_CODE, "errors": errors}

    async def async_step_select_switches(self, user_input: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if user_input is not None:
            self.options = user_input
            return await self._async_finish_setup()
    
        # Mock selection for debugging
        switches_data_schema = vol.Schema(
            {
                vol.Optional("devices", description={"suggested_value": ["device1", "device2"]}):
                    cv.multi_select(["device1", "device2", "device3"])
            }
        )
        return {"type": "form", "step_id": "select_switches", "data_schema": switches_data_schema}

    async def _async_finish_setup(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Finish setup and create entry"""
        existing_entry = await self.async_set_unique_id(self.data['title'])
        
        if not existing_entry:
            return {
                "type": "create_entry",
                "title": self.data["title"],
                "data": self.data["data"],
                "options": self.options
            }
        else:
            self.hass.config_entries.async_update_entry(existing_entry, data=self.data['data'], options=self.options)
            await self.hass.config_entries.async_reload(existing_entry.entry_id)
            return {
                "type": "abort",
                "reason": "reauth_successful"
            }


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
                    "re-authenticate",default="No"): vol.In(["Yes","No"]),
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
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
        except TwoFactorCodeRequired:
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.error(str(type(e).__name__) + ": " + str(e))
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_select_switches()

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
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.error(str(type(e).__name__) + ": " + str(e))
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
            self.hass.config_entries.async_update_entry(self.entry, data = self.data["data"])

        if user_input is not None:
            return self.async_create_entry(title="",data=user_input)

        switches_data_schema = vol.Schema(
            {
                vol.Optional(
                    "rooms",
                    description = {"suggested_value" : [room for room in self.entry.options["rooms"] if room in self.entry.data["cync_config"]["rooms"].keys()]},
                ): cv.multi_select({room : f'{room_info["name"]} ({room_info["home_name"]})' for room,room_info in self.entry.data["cync_config"]["rooms"].items() if not self.data["data"]["cync_config"]["rooms"][room]['isSubgroup']}),
                vol.Optional(
                    "subgroups",
                    description = {"suggested_value" : [room for room in self.entry.options["subgroups"] if room in self.entry.data["cync_config"]["rooms"].keys()]},
                ): cv.multi_select({room : f'{room_info["name"]} ({room_info.get("parent_room","")}:{room_info["home_name"]})' for room,room_info in self.entry.data["cync_config"]["rooms"].items() if self.data["data"]["cync_config"]["rooms"][room]['isSubgroup']}),
                vol.Optional(
                    "switches",
                    description = {"suggested_value" : [sw for sw in self.entry.options["switches"] if sw in self.entry.data["cync_config"]["devices"].keys()]},
                ): cv.multi_select({switch_id : f'{sw_info["name"]} ({sw_info["room_name"]}:{sw_info["home_name"]})' for switch_id,sw_info in self.entry.data["cync_config"]["devices"].items() if sw_info.get('ONOFF',False) and sw_info.get('MULTIELEMENT',1) == 1}),
                vol.Optional(
                    "motion_sensors",
                    description = {"suggested_value" : [sensor for sensor in self.entry.options["motion_sensors"] if sensor in self.entry.data["cync_config"]["devices"].keys()]},
                ): cv.multi_select({device_id : f'{device_info["name"]} ({device_info["room_name"]}:{device_info["home_name"]})' for device_id,device_info in self.entry.data["cync_config"]["devices"].items() if device_info.get('MOTION',False)}),
                vol.Optional(
                    "ambient_light_sensors",
                    description = {"suggested_value" : [sensor for sensor in self.entry.options["ambient_light_sensors"] if sensor in self.entry.data["cync_config"]["devices"].keys()]},
                ): cv.multi_select({device_id : f'{device_info["name"]} ({device_info["room_name"]}:{device_info["home_name"]})' for device_id,device_info in self.entry.data["cync_config"]["devices"].items() if device_info.get('AMBIENT_LIGHT',False)}),
            }
        )

        return self.async_show_form(step_id="select_switches", data_schema=switches_data_schema)

class TwoFactorCodeRequired(HomeAssistantError):
    """Error to indicate we cannot connect."""

class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
