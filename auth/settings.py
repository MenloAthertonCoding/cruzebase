from django.conf import settings
from rest_framework.settings import APISettings


USER_SETTINGS = getattr(settings, 'REST_AUTH', None)

DEFAULTS = {
    'PASSWORD_VALIDATOR_MIN_LENGTH': 8
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'PASSWORD_VALIDATOR_MIN_LENGTH'
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)