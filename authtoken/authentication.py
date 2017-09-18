from django.utils.translation import ugettext_lazy as _

from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from jwt.exceptions import TokenException
from jwt import BaseToken, token_factory, compare

from auth.models import UserProfile
from authtoken.settings import api_settings, secret_key

def get_token_instance(user_profile):
    """Returns a token instance
    """
    return token_factory(
        api_settings.TOKEN_HEADER_COMPONENT_CLASS,
        api_settings.TOKEN_PAYLOAD_COMPONENT_CLASS,
        {
            'payload': {'aud': api_settings.TOKEN_AUDIENCE or user_profile.id}
        }
    )

def get_token_instance_sig(user, secret, enc=None, instance=None):
    if instance is None:
        instance = get_token_instance(user)

    return BaseToken.clean(instance.sign(secret, enc).build())[2]

def authenticate_credentials(kwargs):
    """
    Returns a Django `User` object if `token` is valid, Django `User` object
    exists and is active.
    """
    try:
        user_profile = UserProfile.objects.get(**kwargs)
    except UserProfile.DoesNotExist:
        raise AuthenticationFailed

    if not user_profile.user.is_active:
        raise AuthenticationFailed

    return user_profile


class JSONWebTokenAuthentication(authentication.BaseAuthentication):
    """
    JSON Web Token based authentication conforming to RFC 7519.

    See https://jwt.io/introduction/ and https://openid.net/specs/draft-jones-json-web-token-07.html
    for more about JWTs.

    Clients should authenticate by passing the JWT token key in the "Authorization"
    HTTP header, prepended with the string "Bearer ".

    For example:
        Authorization: Bearer eyJhbGciO.eyJzdWIiOiIxMjM0NTY3ODkwIiwib.TJVA95OrM7E2cBab3
    """
    keyword = 'Bearer'
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        """
        Authenticate the request if the signature is valid and return a two-tuple of (user, token).
        """
        auth = authentication.get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode(): # encode to bytestring
            return None

        # Ensure the token exists in request headers
        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise AuthenticationFailed(msg)

        try:
            token = auth[1]
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise AuthenticationFailed(msg)

        # Get username or user id in request headers
        username = request.META.get('X_USERNAME')
        user_id = request.META.get('HTTP_USER_ID') # ex. USER-ID: 100

        try:
            # Get user from username, user_id, or from token payload.
            if username:
                user_profile = authenticate_credentials({'user__username': username})
            elif user_id:
                user_profile = authenticate_credentials({'id': user_id})
            elif 'aud' in BaseToken.clean(token)[1]: # `aud` in payload
                user_profile = authenticate_credentials({'id': BaseToken.clean(token)[1]['aud']})

            # Verify token
            if compare(token, get_token_instance(user_profile),
                       secret_key(),
                       api_settings.TOKEN_VERIFICATION_ALGORITHM_INSTANCE):
                return (user_profile.user, token)

        except AuthenticationFailed:
            raise AuthenticationFailed(_('Provided credentials invalid.'))
        except TokenException as exc:
            raise AuthenticationFailed(_(str(exc)))

        return None

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return '{0} realm="{1}"'.format(self.keyword, self.www_authenticate_realm)
