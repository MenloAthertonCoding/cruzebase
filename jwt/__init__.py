import json
import binascii
from base64 import urlsafe_b64encode, urlsafe_b64decode

from jwt.exceptions import (
    TokenException,
    TokenMalformedException,
    InvalidTokenException
)

from jwt.components import component_factory


class BaseToken:
    """
    JWT Token class. Signs, builds, and validates JWT tokens.
    """
    header_cls = None
    payload_cls = None
    extra_kwargs = {}

    def __init__(self):
        try:
            self.header = self.header_cls()
        except TypeError:
            # TODO test that key exists 
            self.header = self.header_cls(**self.extra_kwargs['header'])

        try:
            self.payload = self.payload_cls()
        except TypeError:
            # TODO test that key exists 
            self.payload = self.payload_cls(**self.extra_kwargs['payload'])

    def sign(self, secret, alg_instance):
        sig = alg_instance.sign(self._join(), secret)
        if not isinstance(sig, bytes):
            raise AssertionError(
                'Expected a `bytes` to be returned '
                'from the view, but received a {0}'.format(type(sig)))

        self.sig = urlsafe_b64encode(sig)
        return self

    def _is_signed(self):
        return hasattr(self, 'sig')

    def _sig(self):
        if not self._is_signed():
            raise TokenException('Token not signed') # TODO fix
        return self.sig

    def _join(self):
        return self.join(self.header, self.payload)

    @staticmethod
    def join(header, payload):
        return header.as_comp() + b'.' + payload.as_comp()

    def build(self):
        """
        Builds a JWT from header, payload, and signature. If signature has not been
        generated, `TokenException` will be raised.
        """
        return self._join() + b'.' + self._sig()

    def is_valid(self, token, secret, alg_instance):
        """
        Validates that `token` is valid and has not been tampered with.
        """
        clean_data = BaseToken.clean(token)
        if not alg_instance.verify(self._join(), secret, clean_data[2]):
            raise InvalidTokenException('Invalid token. Has the token been tampered with?', token)
        # TODO check each claims .is_valid()
        return True

    @staticmethod
    def _split(token):
        """
        Splits a JWT token into a three-tuple that can be deserialized.

        `token` must be a byte array.
        """
        try:
            header, payload, sig = token.split(b'.')
        except ValueError:
            raise TokenException('Invalid token header. Token string should '\
                                 'split header, payload, and signature by . (period).', token)

        return (header, payload, sig)

    @staticmethod
    def clean(token):
        header64, payload64, sig = BaseToken._split(token)

        try:
            header = json.loads(urlsafe_b64decode(header64).decode())
            payload = json.loads(urlsafe_b64decode(payload64).decode())
            sig = urlsafe_b64decode(sig)
        except binascii.Error:
            raise TokenMalformedException('Invalid token header. Token padding malformed.', token)
        return (header, payload, sig)

def token_factory(header, payload, kwargs=None):

    class FactoryToken(BaseToken):
        header_cls = header
        payload_cls = payload
        if kwargs is not None:
            extra_kwargs = kwargs

    return FactoryToken()

def compare(token, instance, secret, alg_instance):
    return instance.is_valid(token, secret, alg_instance)
