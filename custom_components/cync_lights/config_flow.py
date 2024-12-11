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

# Schema for the user step, requiring username and password
STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,       
    }
)

# Schema for two-factor authentication, requiring a code
STEP_TWO_FACTOR_CODE = vol.Schema(
    {
        vol.Required("two_factor_code"): str,
    }
)

class TwoFactorCodeRequired(HomeAssistantError):
    """Error to indicate two-factor authentication is required."""

class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid authentication."""

async def cync_login(hub, user_input: dict[str, Any]) -> dict[str, Any]:
    """
    Authenticate user with Cync service using username and password.

    :param hub: CyncUserData object to handle authentication
    :param user_input: Dictionary containing username and password
    :return: Dictionary with preliminary authentication details or raises exceptions
    :raises TwoFactorCodeRequired: If two-factor authentication is required
    """
    response = await hub.authenticate(user_input["username"], user_input["password"])
    
    if response is None:
        raise InvalidAuth("Authentication failed or returned None")
    
    if response.get('two_factor_code_required'):
        raise TwoFactorCodeRequired("Two-factor authentication required")
    elif response.get('access_token'):
        # This should not happen if access token is only available post 2FA
        raise InvalidAuth("Unexpected access token without 2FA")
    else:
        # Here, you might want to store some preliminary data like username for the next step
        hub.username = user_input["username"]
        return {
            'title': 'cync_lights_' + user_input['username'],
            'data': {
                'user_input': user_input
            }
        }

async def submit_two_factor_code(hub, user_input: dict[str, Any]) -> dict[str, Any]:
    """
    Submit two-factor authentication code to get access token.

    :param hub: CyncUserData object holding preliminary authentication state
    :param user_input: Dictionary containing two-factor code
    :return: Dictionary with authentication details including the access token
    :raises: InvalidAuth if the two-factor code is incorrect
    """
    response = await hub.auth_two_factor(user_input["two_factor_code"])
    
    if response is None:
        raise InvalidAuth("Two-factor authentication failed or returned None")
    
    if response.get('access_token'):
        hub.access_token = response['access_token']
        hub.refresh_token = response.get('refresh_token', None)  # Assuming refresh_token might not always be present
        hub.user_id = response.get('user_id', None)  # Same for user_id
        return {
            'title': 'cync_lights_' + hub.username,
            'data': {
                'cync_credentials': {
                    'access_token': response['access_token'],
                    'refresh_token': response.get('refresh_token'),
                    'user_id': response.get('user_id')
                },
                'user_input': {'username': hub.username, 'password': hub.password}
            }
        }
    else:
        raise InvalidAuth("Invalid two-factor code or unexpected response")

class CyncUserData:
    """Handles user data and API interactions for Cync service."""

    def __init__(self):
        self.username = None
        self.password = None
        self.access_token = None
        self.refresh_token = None
        self.user_id = None

    async def get_devices(self):
        """
        Fetch devices from the Cync API.

        :return: JSON response containing device information
        :raises: HomeAssistantError if the API call fails
        """
        headers = {
            "access-token": self.access_token
        }
        url = f"/v2/user/{self.user_id}/subscribe/devices?version=0"
        async with self.hass.client_session.get(url, headers=headers) as resp:
            if resp.status != 200:
                raise HomeAssistantError(f"Failed to fetch devices: {resp.status}")
            return await resp.json()

    async def authenticate(self, username: str, password: str) -> dict:
        """
        Authenticate with the Cync API and get an access token.

        :param username: The user's Cync username
        :param password: The user's Cync password
        :return: Dictionary with authentication result
        :raises HomeAssistantError: If authentication fails
        """
        auth_data = {'corp_id': "1007d2ad150c4000", 'email': username, 'password': password}
        async with aiohttp.ClientSession() as session:
            async with session.post(API_AUTH, json=auth_data) as resp:
                if resp.status == 200:
                    response = await resp.json()
                    self.access_token = response.get('access_token')
                    self.refresh_token = response.get('refresh_token')
                    self.user_id = response.get('user_id')
                    return {'authorized': True}
                elif resp.status == 400:
                    # Assuming this status code means 2FA is required
                    return {'authorized': False, 'two_factor_code_required': True}
                else:
                    content = await resp.text()
                    raise HomeAssistantError(f"Authentication failed: {content}")

    async def auth_two_factor(self, two_factor_code: str) -> dict:
        """
        Authenticate with a two-factor code.

        :param two_factor_code: The two-factor authentication code
        :return: Dictionary with authentication result
        :raises HomeAssistantError: If two-factor authentication fails
        """
        if not self.username or not self.password:
            raise HomeAssistantError("User not authenticated for two-factor step")

        two_factor_data = {
            'corp_id': "1007d2ad150c4000",
            'email': self.username,
            'password': self.password,
            'two_factor': two_factor_code,
            'resource': "abcdefghijklmnop"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(API_2FACTOR_AUTH, json=two_factor_data) as resp:
                if resp.status == 200:
                    response = await resp.json()
                    self.access_token = response.get('access_token')
                    self.refresh_token = response.get('refresh_token')
                    self.user_id = response.get('user_id')
                    return {'authorized': True, 'access_token': self.access_token}
                else:
                    content = await resp.text()
                    raise HomeAssistantError(f"Two-factor authentication failed: {content}")

class CyncConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the configuration flow for Cync Room Lights."""

    def __init__(self):
        self.cync_hub = CyncUserData()
        self.data = {}
        self.options = {}

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """
        Handle initial user input for username and password.

        :param user_input: User's input or None for first call
        :return: FlowResult to proceed with the configuration process
        """
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=STEP_USER_DATA_SCHEMA
            )

        errors = {}

        try:
            info = await cync_login(self.cync_hub, user_input)
        except TwoFactorCodeRequired:
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.error(f"Error during login: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_two_factor_code()

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_two_factor_code(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """
        Handle two-factor authentication step.

        :param user_input: User's two-factor code or None for first call
        :return: FlowResult to continue the configuration process
        """
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
        """
        Allow user to select which devices to integrate.

        :param user_input: User's device selection or None for first call
        :return: FlowResult to finalize setup or show form for selection
        """
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
        """
        Finalize the setup by creating or updating the config entry.

        :param user_input: Optional user input for final setup steps
        :return: FlowResult indicating successful setup or abort
        """
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
    """Handles options flow for Cync Room Lights integration."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow with existing config entry."""
        self.entry = config_entry
        self.cync_hub = CyncUserData()
        self.data = {}

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """
        Initial step of options flow, asking if re-authentication is needed.

        :param user_input: User's choice or None for first call
        :return: FlowResult to proceed to next step or show form
        """
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
        """
        Re-authentication step in options flow.

        :param user_input: User's input for re-authentication or None if first call
        :return: FlowResult to proceed or show form with errors
        """
        errors = {}

        try:
            info = await cync_login(self.cync_hub, self.entry.data['user_input'])
        except TwoFactorCodeRequired:
            return await self.async_step_two_factor_code()
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.error(f"Error during re-authentication: {str(type(e).__name__)} - {str(e)}")
            errors["base"] = "unknown"
        else:
            self.data = info
            return await self.async_step_two_factor_code()

        return self.async_show_form(
            step_id="auth", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_two_factor_code(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """
        Handle two-factor authentication in re-authentication process.

        :param user_input: Two-factor code or None if first call
        :return: FlowResult to continue or show form with errors
        """
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
        """
        Manage options for device selection in the options flow.

        :param user_input: User's device selection or None if showing the form for the first time
        :return: FlowResult to finalize the options or show the selection form
        """
        # Update the config entry if new data is available and different from what's already stored
        if "data" in self.data and self.data["data"] != self.entry.data:
            self.hass.config_entries.async_update_entry(self.entry, data=self.data["data"])

        if user_input is not None:
            # If user input is provided, finalize the options update
            return self.async_create_entry(title="", data=user_input)

        try:
            # Attempt to fetch the devices from the existing config data
            devices = self.entry.data.get("cync_config", {})
        except KeyError:
            # Log an error if device data is not available, but continue with an empty selection
            _LOGGER.error("Device list not available in existing config; skipping device selection")
            return self.async_create_entry(title="", data={})

        # Create a schema for device selection
        switches_data_schema = vol.Schema(
            {
                vol.Optional(
                    "devices",
                    description={"suggested_value": list(devices.keys()) if devices else []},
                ): cv.multi_select({device_id: f'{device.get("name", "Unnamed Device")}' for device_id, device in devices.items()}),
            }
        )
        
        # Show the form for device selection
        return self.async_show_form(step_id="select_switches", data_schema=switches_data_schema)
   
