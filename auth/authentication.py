import hmac, hashlib

from django.utils.translation import ugettext_lazy as _

from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from auth.models import UserProfile
from auth.jwt import PayloadComponent

from jwt.components import HeaderComponent
from jwt.exceptions import TokenException
from jwt import BaseToken, token_factory

def get_token_instance(user_profile):
    return token_factory(
        HeaderComponent,
        PayloadComponent,
        {
            'payload': {'sub': user_profile.id}
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
        raise AuthenticationFailed('No such user') # TODO update

    if not user_profile.user.is_active:
        raise AuthenticationFailed('User is inactive') # TODO update

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


        username = request.META.get('X_USERNAME')
        user_id = request.META.get('HTTP_USER_ID') # ex. USER-ID: 100

        try:
            if username:
                user_profile = authenticate_credentials({'user__username': username})
            elif user_id:
                user_profile = authenticate_credentials({'id': user_id})
            elif 'sub' in BaseToken.clean(token)[1]: # `sub` in payload
                user_profile = authenticate_credentials({'id': BaseToken.clean(token)[1]['sub']})

            if BaseToken.is_valid(get_token_instance_sig(user_profile, 'secret'), token): # TODO get actual secret
                print('Is true')
                return (user_profile.user, token)
        except TokenException as te:
            raise AuthenticationFailed(_(str(te)))

        return None

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return '{0} realm="{1}"'.format(self.keyword, self.www_authenticate_realm)
