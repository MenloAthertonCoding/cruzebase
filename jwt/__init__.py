"""JSON Web Token library.

This module creates, signs, builds, and validates JSON Web Tokens,
a RFC standard. JSON Web Tokens (JWTs) are stateless tokens used for
authentication and information exchange.

Examples:
    To create a token, simply create a payload component and create a token::

        >>> from jwt import token_factory
        >>> from jwt.components import HS256HeaderComponent, component_factory
        >>> from jwt import claims
        >>> payload = component_factory(claims.NbfClaim, claims.ExpClaim)
        >>> token_factory(HS256HeaderComponent, payload)
        <jwt.token_factory.<locals>.FactoryToken object at 0x7f74799c7b38>

    To create a component that has instance variables, simply extend `jwt.components.BaseComponent`
    and add extra_kwargs::

        >>> from jwt.components import BaseComponent
        >>> from jwt import claims as jwt_claims
        >>> class Payload(BaseComponent):
        ...     claims = (jwt_claims.IssClaim,)
        ...     extra_kwargs = {jwt_claims.IssClaim: {'iss': 'Issuer'}}
        ...

    To sign and build a token, call .sign() and .build(), supplying a secret
    key and an algorithm class::

        >>> from jwt.algorithms import HMACAlgorithm
        >>> alg = HMACAlgorithm(HMACAlgorithm.SHA256)
        >>> token.build(secret, alg)
        b'eyJhbGciOiAiSFMyNTYifQ==.eyJleHAiO4MTEyfQ==.2-1tzEESguaV2HLXtmf9nQWT-Xc='

    To verify a token, call .compare() with the unverified token string, a token
    instance with equivalent components, the secret key, and a algorithm instance::

        >>> from jwt import compare
        >>>
        >>> # Using token instance from above
        >>> compare(token.build(secret, alg), token, secret, alg)
        True

.. _Extra links:
    https://jwt.io/introduction/
    https://tools.ietf.org/html/rfc7519
"""

import json
import binascii
from base64 import urlsafe_b64encode, urlsafe_b64decode

from jwt import exceptions

from jwt.components import component_factory


class BaseToken:
    """JSON Wen Tokens token class. Signs, builds, and validates JSON Web Tokens.

    To extend BaseToken, create a class and add the following class attributes::

        header_cls
        payload_cls

    Attributes:
        header_cls (BaseComponent): Class that defines the JWT header component.
            Typically use a JOSE header such as `jwt.components.HS256HeaderComponent`.
            Extends `jwt.components.BaseComponent`.
        payload_cls (BaseComponent): Class that defines the JWT payload component.
            Extends `jwt.components.BaseComponent`.
        extra_kwargs (dict, optional): Extra keyword arguments that are passed into
            header_cls and payload_cls for further parsing. Defaults to None.

            Example:
                The dict must have two keys, 'payload' and 'header'. The two keys have
                values of dicts. Inside, are the kwargs passed into the respective component
                when instatntiating::

                {
                    'payload': {'iss': 'Issuer'}
                }

    Raises:
        KeyError: If the header component or payload component requires instantiation arguments,
            however none were provided.

    All token classes should extend BaseToken.
    """
    header_cls = None
    payload_cls = None
    extra_kwargs = {}

    def __init__(self):
        try:
            self.header = self.header_cls()
            self.payload = self.payload_cls()
        except TypeError:
            if not hasattr(self, 'header'):
                if 'header' not in self.extra_kwargs:
                    raise KeyError(
                        'The header class needs to be instantiated with extra kwargs,'
                        'but none were found.'
                    )

                self.header = self.header_cls(**self.extra_kwargs['header'])

            if not hasattr(self, 'payload'):
                if 'payload' not in self.extra_kwargs:
                    raise KeyError(
                        'The header class needs to be instantiated with extra kwargs,'
                        'but none were found.'
                    )

                self.payload = self.payload_cls(**self.extra_kwargs['payload'])


    def _sign(self, signing_input, secret, alg_instance):
        sig = alg_instance.sign(signing_input, secret)
        if not isinstance(sig, bytes):
            raise AssertionError(
                'Expected a `bytes` object to be returned '
                'from the signing method, but received a {0}'.format(type(sig))
            )

        return urlsafe_b64encode(sig)

    def _join(self):
        return self.join(self.header, self.payload)

    @staticmethod
    def join(header, payload):
        """Convert a header component class and a payload component class into a bytes object
        into a json serialized, urlsafe base64 encoded payload concatenated onto a
        json serialized, urlsafe base64 encoded header. The two values are seperated
        by a . (period).

        Example:
            header.payload

        Args:
            header (BaseComponent): The header class to be serialized and base64 encoded.
                Extends `jwt.components.BaseComponent`.
            payload (BaseComponent): The payload class to be serialized and base64 encoded.
                Extends `jwt.components.BaseComponent`.

        Returns:
            bytes: Returns a payload component concatenated onto a header
                component with a seperating . (period).
        """
        return b'.'.join((header.as_comp(), payload.as_comp()))

    def build(self, secret, alg_instance):
        """Cryptographically signs and builds a token string using the header, payload,
        and signature by concatenating the header, payload, and signature.

        Signing a token prevents tampering and modiication of a jwt as comparing
        a 'clean' and a 'dirty' signature will raise InvalidTokenError and considered invalid.

        Args:
            secret (str, bytes): The secret used to sign the token.
                To compare tokens, the same secret is used. The secret can be of type
                str or bytes.
            alg_instance(BaseAlgorithm): An instantiated algorithm class used
                for signing token. Extends `jwt.algorithms.BaseAlgorithm`.

        Returns:
            bytes: A token conforming to RFC 7519 standards
        """
        signing_input = self._join()
        return b'.'.join((signing_input, self._sign(signing_input, secret, alg_instance)))

    @staticmethod
    def is_valid(token, secret, alg_instance):
        """Validates a token. Valdation compares the signatures and validates that the claims
        of each component are correct. The secret and algorithm that was used for encryption or
        hashing must be equivalent in this function.

        Args:
            token (str, bytes): The token to be validated. The token must be of type
                str or bytes.
            secret (str, bytes): The secret key used to sign the token. The secret must
                be of type str or bytes.
            alg_instance (BaseAlgorithm): An instantiated algorithm class used
                for verifying the authenticity of a token's signature. Although there is a
                required alg claim in a JOSE header, the algorithm has not been validated
                and  cannot be trusted (yet). Therefore, alg_instance is required. See
                https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/.
                Extends `jwt.algorithms.BaseAlgorithm`.

        Returns:
            bool: True if the token is cryptographically signed, the authenticity of
                the signature can be verified, and the claims are valid.

        Raises:
            InvalidTokenError: If the authenticity of a signature cannot be verified.
        """
        signing_input, sig = BaseToken.clean_crypto(token)
        if not alg_instance.verify(signing_input, secret, sig):
            raise exceptions.InvalidTokenError('Invalid token signature. Refresh token.', token)
        # TODO check each claims .is_valid()
        return True

    @staticmethod
    def split(token):
        """Splits a token string into individual header and payload claimsets, along with
        the token's signature. This method does not decode or deserialize a token or it's
        claimsets.

         Args:
            token (str, bytes): The token to be split. The token must be of type
                str or bytes.

        Returns:
            tuple: A three tuple of the header and payload claimsets with a decoded
                signature digest.
        """
        signing_input, sig = BaseToken.split_crypto(token)
        header, payload = BaseToken.split_claimsets(signing_input)

        return (header, payload, sig)

    @staticmethod
    def split_claimsets(claimsets):
        """Splits a token's claimsets into individual header and payload claimsets.
        This method does not decode or deserialize a token or it's claimsets.

         Args:
            claimsets (str, bytes): The claimsets to be split. The claimsets must be of type
                str or bytes.

        Returns:
            tuple: A two tuple of the header and payload claimsets.

        Raises:
            MalformedTokenError: If the token's claimsets are not split by a . (period).
        """
        try:
            header, payload = claimsets.rsplit(b'.', 1)
        except ValueError:
            raise exceptions.MalformedTokenError(
                'Invalid token header. Token string should split'
                ' header, payload, and signature by . (period).')

        return (header, payload)


    @staticmethod
    def split_crypto(token):
        """Splits a token's cryptographic elements into the token's claimsets and the
        token's signature. This method does not decode or deserialize the claimsets or
        the signature.

        Useful for verifying a signature digest against the token's claimsets as the claimsets
        can be used as signing input.

        Args:
            token (str, bytes): The token to be cleaned. The token must be of type
                str or bytes.

        Returns:
            tuple: A two tuple of the token's claimsets with a signature digest.

        Raises:
            MalformedTokenError: If the token's claimsets are not split by a . (period).
        """
        try:
            signing_input, sig = token.rsplit(b'.', 1)
        except ValueError:
            raise exceptions.MalformedTokenError(
                'Invalid token header. Token string should split'
                ' header, payload, and signature by . (period).',
                token)

        return (signing_input, sig)

    @staticmethod
    def clean(token):
        """Cleans a token. Cleaning a token will return the token's components
        and signature as decoded base64 data. The token's components will not be decoded.
        After cleaning, the data can then be parsed.

        Args:
            token (str, bytes): The token to be cleaned. The token must be of type
                str or bytes.

        Returns:
            tuple: A three tuple of json deserialized and decoded header and payload components
                with a decoded signature.
        """
        claimsets, sig = BaseToken.clean_crypto(token)
        header, payload = BaseToken.clean_claimsets(claimsets)
        return (header, payload, sig)

    @staticmethod
    def clean_crypto(token):
        """Cleans a token's cryptographic elements. Cleaning the cryptographic elements
        will return the token's signature as decoded base64 data and the header and payload
        claimsets. After cleaning, the data can then be parsed.

        Args:
            token (str, bytes): The token to be cleaned. The token must be of type
                str or bytes.

        Returns:
            tuple: A two tuple of the token's claimsets with a decoded signature digest.

        Raises:
            MalformedTokenError: If the token's base64 padding is defective, abnormal,
                or not parsable.
        """
        signing_input, sig = BaseToken.split_crypto(token)

        try:
            sig = urlsafe_b64decode(sig)
        except binascii.Error:
            raise exceptions.MalformedTokenError(
                'Invalid token header. Token padding malformed.', token
            )

        return (signing_input, sig)

    @staticmethod
    def clean_claimsets(claimsets):
        """Cleans a token's claimsets. Cleaning a token's claimsets will return the token's
        claimsets as deserialized and decoded base64 data. After cleaning, the data can
        then be parsed.

        Args:
            claimsets (str, bytes): The token to be cleaned. The token must be of type
                str or bytes.

        Returns:
            tuple: A two tuple of json deserialized and decoded header and payload components.

        Raises:
            MalformedTokenError: If the token's base64 padding is defective, abnormal,
                or not parsable.
        """
        header, payload = BaseToken.split_claimsets(claimsets)

        try:
            header = json.loads(urlsafe_b64decode(header).decode())
            payload = json.loads(urlsafe_b64decode(payload).decode())
        except binascii.Error:
            raise exceptions.MalformedTokenError(
                'Invalid token header. Token padding malformed.'
            )

        return (header, payload)

def token_factory(header, payload, kwargs=None):
    """Factory method for creating tokens.

    Example:
        To create a token using a token factory::

            >>> from jwt import token_factory
            >>> from jwt.components import HS256HeaderComponent
            >>> # `payload` is previously defined
            >>> token_factory(HS256HeaderComponent, payload)
            <jwt.token_factory.<locals>.FactoryToken object at 0x7f74799c7b38>

    Args:
        header (BaseComponent): The header class to be used as the token's header component.
            Extends `jwt.components.BaseComponent`.
        payload (BaseComponent): The payload class to be used as the token's playload
            component. Extends `jwt.components.BaseComponent`.
        kwargs (dict, optional): Extra keyword arguments that are passed into
            header and payload components for further parsing. Defaults to None.

            Example:
                The dict must have two keys, 'payload' and 'header'. The two keys have
                values of dicts. Inside, are the kwargs passed into the respective component
                when instantiating::

                {
                    'payload': {'iss': 'Issuer'}
                }

    Returns:
        FactoryToken: An intantiated token class with the specified header and
            payload components.
    """
    class FactoryToken(BaseToken):
        header_cls = header
        payload_cls = payload
        if kwargs is not None:
            extra_kwargs = kwargs

    return FactoryToken()

def compare(token, secret, alg_instance):
    """Validates a token. Valdation compares the signatures and validates that the claims
    of each component are correct. The secret and algorithm that was used for encryption or
    hashing must be equivalent in this function.

    Args:
        token (str, bytes): The token to be validated. The token must be of type
            str or bytes.
        instance (BaseToken): An instantiated token instance with header and
            payload classes that are equivalent to those when the token was signed.
            instance must extend BaseToken.
        secret (str, bytes): The secret key used to sign the token. The secret must
            be of type str or bytes.
        alg_instance (BaseAlgorithm): An instantiated algorithm class used
            for verifying the authenticity of a token's signature. Although there is a
            required alg claim in a JOSE header, the algorithm has not been validated
            and  cannot be trusted (yet). Therefore, alg_instance is required. See
            https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/.
            Extends `jwt.algorithms.BaseAlgorithm`.

    Returns:
        bool: True if the token is cryptographically signed, the authenticity of
            the signature can be verified, and the claims are valid.

    Raises:
        InvalidTokenError: If the authenticity of a signature cannot be verified.
    """
    return BaseToken.is_valid(token, secret, alg_instance)
