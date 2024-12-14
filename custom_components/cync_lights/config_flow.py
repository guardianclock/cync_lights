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
    _LOGGER.error("Login")
    response = await hub.authenticate(user_input["username"], user_input["password"])
    if response['authorized']:
        _LOGGER.error("Authorized")
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
            _LOGGER.error("Two Factor")
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
            _LOGGER.error("Login")
            info = await cync_login(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
        except TwoFactorCodeRequired:
            _LOGGER.error("2FA")
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            _LOGGER.error("Invalid Auth")
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Error during login: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self._async_finish_setup()
    
        return {"type": "form", "step_id": "user", "data_schema": STEP_USER_DATA_SCHEMA, "errors": errors}

    async def async_step_two_factor_code(self, user_input: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if user_input is None:
            return {"type": "form", "step_id": "two_factor_code", "data_schema": STEP_TWO_FACTOR_CODE}
    
        errors = {}
    
        try:
            info = await submit_two_factor_code(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Error during two factor authentication: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_select_switches()
    
        return {"type": "form", "step_id": "two_factor_code", "data_schema": STEP_TWO_FACTOR_CODE, "errors": errors}

    async def async_step_select_switches(self, user_input: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if user_input is not None:
            self.options = user_input
            return await self._async_finish_setup()
    
        switches_data_schema = vol.Schema(
            {
                vol.Optional("devices", description={"suggested_value": ["device1", "device2"]}):
                    cv.multi_select(["device1", "device2", "device3"])
            }
        )
        return {"type": "form", "step_id": "select_switches", "data_schema": switches_data_schema}

    async def _async_finish_setup(self, user_input: dict[str, Any] | None = None) -> FlowResult:
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

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            if user_input['re-authenticate'] == "No":
                return await self.async_step_select_switches()
            else:
                return await self.async_step_auth()

        data_schema = vol.Schema(
            {
                vol.Required("re-authenticate", default="No"): vol.In(["Yes","No"]),
            }
        )

        # Use explicit return with type 'form' instead of async_show_form
        return {"type": "form", "step_id": "init", "data_schema": data_schema}

    async def async_step_auth(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Attempt to re-authenticate"""
        errors = {}

        try:
            _LOGGER.error("Login")
            info = await cync_login(self.cync_hub, self.entry.data['user_input'])
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
        except TwoFactorCodeRequired:
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(str(type(e).__name__) + ": " + str(e))
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_select_switches()

        # Explicitly return with 'form' type for error case
        return {"type": "form", "step_id": "auth", "data_schema": STEP_USER_DATA_SCHEMA, "errors": errors}

    async def async_step_two_factor_code(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle two factor authentication for Cync account."""
        if user_input is None:
            return {"type": "form", "step_id": "two_factor_code", "data_schema": STEP_TWO_FACTOR_CODE}

        errors = {}

        try:
            info = await submit_two_factor_code(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(str(type(e).__name__) + ": " + str(e))
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_select_switches()

        return {"type": "form", "step_id": "two_factor_code", "data_schema": STEP_TWO_FACTOR_CODE, "errors": errors}

    async def async_step_select_switches(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Manage the options."""
        if "data" in self.data and self.data["data"] != self.entry.data:
            self.hass.config_entries.async_update_entry(self.entry, data=self.data["data"])

        if user_input is not None:
            return {"type": "create_entry", "title": "", "data": user_input}

        switches_data_schema = vol.Schema(
            {
                # ... (your existing schema)
            }
        )

        return {"type": "form", "step_id": "select_switches", "data_schema": switches_data_schema}

class TwoFactorCodeRequired(HomeAssistantError):
    """Error to indicate we cannot connect."""

class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
