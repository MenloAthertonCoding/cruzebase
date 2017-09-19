from datetime import timedelta

from django.conf import settings
from rest_framework.settings import APISettings

from jwt.algorithms import HMACAlgorithm

USER_SETTINGS = getattr(settings, 'REST_AUTH', None)

DEFAULTS = {
    'TOKEN_PRIVATE_KEY': None,
    'TOKEN_PUBLIC_KEY': None,
    'TOKEN_SECRET_KEY': settings.SECRET_KEY,

    'TOKEN_VERIFICATION_ALGORITHM_INSTANCE':
    HMACAlgorithm(HMACAlgorithm.SHA256),

    'TOKEN_VERIFY': True,
    'TOKEN_VERIFY_EXPIRATION': True,
    'TOKEN_VERIFY_NOT_BEFORE': True,

    'TOKEN_HEADER_CLAIMSET_CLASS':
    'jwt.claimsets.HS256HeaderClaimset',

    'TOKEN_PAYLOAD_CLAIMSET_CLASS':
    'authtoken.claimset.PayloadClaimset',

    'TOKEN_EXPIRATION_TIME_DELTA': timedelta(days=7),
    'TOKEN_NOT_BEFORE_TIME_DELTA': timedelta(seconds=3),
    'TOKEN_ISSUER': None,
    'TOKEN_AUDIENCE': None,

    'TOKEN_LEEWAY': 0,

    'TOKEN_ALLOW_REFRESH': False,
    'TOKEN_REFRESH_EXPIRATION_TIME_DELTA': timedelta(days=7),

}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'TOKEN_HEADER_CLAIMSET_CLASS',
    'TOKEN_PAYLOAD_CLAIMSET_CLASS',
)
api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)

def secret_key():
    """Returns the secret key. Return 'TOKEN_PRIVATE_KEY' if it is not
    None, otherwise 'TOKEN_SECRET_KEY'.
    """
    return api_settings.TOKEN_PRIVATE_KEY or api_settings.TOKEN_SECRET_KEY
