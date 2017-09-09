import json, hmac, hashlib, binascii
from base64 import urlsafe_b64encode, urlsafe_b64decode

from jwt.exceptions import TokenException, TokenMalformedException


class BaseToken:
    """
    JWT Token class. Signs, builds, and validates JWT tokens.
    """
    header_cls = None
    payload_cls = None
    extra_kwargs = {}
    validated_data = None

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

    def sign(self, secret, enc=None):
        if enc is None:
            enc = hashlib.sha256 # TODO For now hardcode 256

        self.sig = urlsafe_b64encode(
            hmac.new(
                secret.encode(),
                self.urlsafe_b64encode_components(self.header, self.payload),
                digestmod=enc
            ).hexdigest().encode()
        )

        # TODO b64enc sig
        return self

    def _is_signed(self):
        return hasattr(self, 'sig')

    def _sig(self):
        if not self._is_signed():
            raise TokenException('Token not signed') # TODO fix
        return self.sig

    @staticmethod
    def urlsafe_b64encode_components(header, payload):
        return header.as_comp() + b'.' + payload.as_comp()

    def build(self):
        """
        Builds a JWT from header, payload, and signature. If signature has not been
        generated, `TokenException` will be raised.
        """
        return self.urlsafe_b64encode_components(self.header, self.payload) + b'.' + self._sig()

    @staticmethod
    def is_valid(verified_sig, token, instance=None):
        """
        Validates that `token` is valid and has not been tampered with.

        Adds clean data to `instance` if `instance` is not `None`.
        """
        # clean_data = BaseToken.clean(token)
        # if hmac.compare_digest(verified_sig, clean_data[2]):
        #     if instance is not None:
        #         instance.validated_data = clean_data

        #     # TODO check each claims .is_valid()
        #     return True
        # return False
        # TODO make work. Returns True for now.
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
        # comps = ()
        # for comp in Token._split(token):
        #     if
        #     comps += (json.loads(urlsafe_b64decode(comp)),)
        # return comps
        header64, payload64, sig = BaseToken._split(token) # TODO check is sig is b64 enc

        try:
            header = json.loads(urlsafe_b64decode(header64).decode())
            payload = json.loads(urlsafe_b64decode(payload64).decode())
            sig = urlsafe_b64decode(payload64)
        except binascii.Error:
            raise TokenMalformedException('Invalid token header. Token padding malformed.', token)
        return (header, payload, sig)

def token_factory(header, payload, kwargs):
    class FactoryToken(BaseToken):
        header_cls = header
        payload_cls = payload
        extra_kwargs = kwargs

    return FactoryToken()
