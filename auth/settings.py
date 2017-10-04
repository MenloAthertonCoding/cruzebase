from django.conf import settings
from rest_framework.settings import APISettings


USER_SETTINGS = getattr(settings, 'REST_AUTH', None)

DEFAULTS = {
    'PASSWORD_MIN_LENGTH': 8,
    'USERNAME_MIN_LENGTH': 4,
    'EMAIL_VALIDATE_DOMAIN': True
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = ()

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)