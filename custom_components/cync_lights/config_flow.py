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
import aiohttp  # Moved here for completeness
from .const import DOMAIN, API_AUTH, API_2FACTOR_AUTH, API_REQUEST_CODE

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema({
    vol.Required("username"): str,
    vol.Required("password"): str,
})

STEP_TWO_FACTOR_CODE = vol.Schema({
    vol.Required("two_factor_code"): str,
})

class TwoFactorCodeRequired(HomeAssistantError):
    """Error to indicate two-factor authentication is required."""

class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid authentication."""

class CyncUserData:
    def __init__(self):
        self.username = None
        self.password = None
        self.access_token = None
        self.refresh_token = None
        self.user_id = None

    async def _api_request(self, url, method, data=None):
        """Helper method for making API requests."""
        headers = {"Access-Token": self.access_token} if self.access_token else {}
        async with aiohttp.ClientSession() as session:
            async with getattr(session, method.lower())(url, json=data, headers=headers) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    content = await resp.text()
                    raise HomeAssistantError(f"API request failed with status {resp.status}: {content}")

    async def get_devices(self):
        """Fetch devices from the Cync API."""
        url = f"/v2/user/{self.user_id}/subscribe/devices?version=0"
        return await self._api_request(url, "GET")

    async def authenticate(self, username: str, password: str) -> dict:
        auth_data = {'corp_id': "1007d2ad150c4000", 'email': username, 'password': password}
        async with aiohttp.ClientSession() as session:
            async with session.post(API_AUTH, json=auth_data) as resp:
                if resp.status == 200:
                    return {'authorized': True, 'access_token': (await resp.json())['access_token']}
                elif resp.status == 400:  # Assuming this means 2FA is required
                    # Here you might need to make an additional call to request the 2FA code
                    request_code_data = {'corp_id': "1007d2ad150c4000", 'email': username, 'local_lang': "en-us"}
                    await session.post(API_REQUEST_CODE, json=request_code_data)
                    return {'authorized': False, 'two_factor_code_required': True}
                else:
                    return {'authorized': False, 'two_factor_code_required': False}

    async def auth_two_factor(self, two_factor_code: str) -> dict:
        if not self.username:
            raise InvalidAuth("User not authenticated for two-factor step")
        
        two_factor_data = {
            'corp_id': "1007d2ad150c4000",
            'email': self.username,
            'two_factor': two_factor_code,
            'resource': "abcdefghijklmnop"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(API_2FACTOR_AUTH, json=two_factor_data) as resp:
                if resp.status == 200:
                    response = await resp.json()
                    if 'authorized' in response and response['authorized']:
                        # Assuming the response contains these fields
                        self.access_token = response.get('access_token')
                        self.user_id = response.get('user_id')
                        self.auth_code = response.get('auth_code')  # Check if this field exists in the response
                        return {'authorized': True}
                    else:
                        return {'authorized': False}  # If authorized key exists but is False
                else:
                    return {'authorized': False}

async def cync_login(hub, user_input: dict[str, Any]) -> dict[str, Any]:
    """Authenticate user with Cync service using username and password."""
    response = await hub.authenticate(user_input["username"], user_input["password"])
    _LOGGER.debug(f"Authentication response: {response}")
    
    if response is None or not response.get('authorized'):
        if response.get('two_factor_code_required'):
            raise TwoFactorCodeRequired("Two-factor authentication required")
        raise InvalidAuth("Authentication failed or returned None")
    
    hub.username = user_input["username"]
    return {
        'title': 'cync_lights_' + user_input['username'],
        'data': {
            'user_input': user_input
        }
    }

async def submit_two_factor_code(hub, user_input: dict[str, Any]) -> dict[str, Any]:
    """Submit two-factor authentication code to get access token."""
    response = await hub.auth_two_factor(user_input["two_factor_code"])
    
    if not response.get('authorized'):
        raise InvalidAuth("Invalid two-factor code or unexpected response")
    
    return {
        'title': 'cync_lights_' + hub.username,
        'data': {
            'cync_credentials': {
                'access_token': hub.access_token,
                'refresh_token': hub.refresh_token,
                'user_id': hub.user_id
            },
            'user_input': {'username': hub.username, 'password': hub.password}
        }
    }

class CyncConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    def __init__(self):
        self.cync_hub = CyncUserData()
        self.data = {}
        self.options = {}

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle initial user input for username and password."""
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=STEP_USER_DATA_SCHEMA)

        errors = {}

        try:
            info = await cync_login(self.cync_hub, user_input)
        except TwoFactorCodeRequired:
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Error during login: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_two_factor_code()

        return self.async_show_form(step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors)

    async def async_step_two_factor_code(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle two-factor authentication step."""
        if user_input is None:
            return self.async_show_form(step_id="two_factor_code", data_schema=STEP_TWO_FACTOR_CODE)

        errors = {}

        try:
            info = await submit_two_factor_code(self.cync_hub, user_input)
            info["data"]["cync_config"] = await self.cync_hub.get_devices()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Error during two factor authentication: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_select_switches()

        return self.async_show_form(step_id="two_factor_code", data_schema=STEP_TWO_FACTOR_CODE, errors=errors)

    async def async_step_select_switches(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Allow user to select which devices to integrate."""
        if user_input is not None:
            self.options = user_input
            return await self._async_finish_setup()

        try:
            devices = self.data["data"]["cync_config"]
        except KeyError:
            _LOGGER.error("Device list not available; skipping device selection")
            return await self._async_finish_setup()

        switches_data_schema = vol.Schema({
            vol.Optional("devices", description={"suggested_value": list(devices.keys()) if devices else []}):
                cv.multi_select({device_id: f'{device.get("name", "Unnamed Device")}' for device_id, device in devices.items()}),
        })
        
        return self.async_show_form(step_id="select_switches", data_schema=switches_data_schema)

    async def _async_finish_setup(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Finalize the setup by creating or updating the config entry."""
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
        """Return the options flow handler for this integration."""
        return CyncOptionsFlowHandler(config_entry)

class CyncOptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow with existing config entry."""
        self.entry = config_entry
        self.cync_hub = CyncUserData()
        self.data = {}

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Initial step of options flow, asking if re-authentication is needed."""
        if user_input is not None:
            if user_input['re-authenticate'] == "No":
                return await self.async_step_select_switches()
            else:
                return await self.async_step_auth()

        data_schema = vol.Schema({
            vol.Required("re-authenticate", default="No"): vol.In(["Yes", "No"]),
        })

        return self.async_show_form(step_id="init", data_schema=data_schema)

    async def async_step_auth(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Re-authentication step in options flow."""
        errors = {}

        try:
            info = await cync_login(self.cync_hub, self.entry.data['user_input'])
        except TwoFactorCodeRequired:
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:
            _LOGGER.error(f"Error during re-authentication: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_two_factor_code()

        return self.async_show_form(step_id="auth", data_schema=STEP_USER_DATA_SCHEMA, errors=errors)

async def async_step_two_factor_code(self, user_input: dict[str, Any] | None = None) -> FlowResult:
    """
    Handle two-factor authentication in re-authentication process.

    :param user_input: Two-factor code or None if first call
    :return: FlowResult to continue or show form with errors
    """
    if user_input is None:
        return self.async_show_form(step_id="two_factor_code", data_schema=STEP_TWO_FACTOR_CODE)

    errors = {}

    try:
        info = await submit_two_factor_code(self.cync_hub, user_input)
        info["data"]["cync_config"] = await self.cync_hub.get_devices()
    except InvalidAuth:
        errors["base"] = "invalid_auth"
    except Exception as e:
        _LOGGER.error(f"Error during two factor authentication: {str(type(e).__name__)} - {str(e)}")
        errors["base"] = "unknown"
    else:
        self.data = info
        return await self.async_step_select_switches()

    return self.async_show_form(step_id="two_factor_code", data_schema=STEP_TWO_FACTOR_CODE, errors=errors)
