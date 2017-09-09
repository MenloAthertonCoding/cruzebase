from datetime import datetime, timedelta

from .algo import BaseAlgorithm, HS256
from .exceptions import TokenException, ClaimException

class BaseClaim:
    """
    All claim classes should extend BaseClaim.
    """
    reserved = False
    __optional = True

    def is_valid(self, data):
        """
        Validate `data`.

        Raises `ClaimException` if claim is required and missing. Otherwise returns
        `True` by default.
        """
        if not getattr(self, '__optional') and self.value() not in data:
            raise ClaimException('Claim is required but was not found') # TODO

        return True

    def value(self):
        """
        Return value of claim.

        In the claim `{'typ': 'JWT'}` .value() would return `'typ'`
        """
        return getattr(self, 'claim')

    def key(self):
        """
        Return key of claim.

        In the claim `{'typ': 'JWT'}` .key() would return `'JWT'`
        """
        return getattr(self, 'name')

    def __key(self):
        return (self.reserved, self.__optional, getattr(self, 'name'))

    def __eq__(self, othr):
        return isinstance(othr, self.__class__) and self.__key() == othr.__key()

    def __hash__(self):
        return hash(self.__key())


class BaseDateTimeClaim(BaseClaim):
    """
    All POSIX timestamp claims should extend BaseDateTimeClaim.
    """
    def value(self):
        return getattr(self, 'dt', datetime.utcnow()).timestamp()

    def is_valid(self, data):
        super(BaseDateTimeClaim, self).is_valid(data)
        if getattr(self, 'name') in data:
            if self.is_datetime_invalid(data[getattr(self, 'name')], datetime.now()):
                raise getattr(self, 'invalid_exception', Exception)(getattr(self, 'invalid_except_msg', 'Invalid claim'))#TODO

    def is_datetime_invalid(self, dt, now):
        """
        Children classes must implement .is_datetime_invalid()
        """
        raise NotImplementedError(".is_datetime_invalid() must be overridden.")


class TypClaim(BaseClaim):
    """
    A simple reserved, required claim determining the type of token.
    """
    _reserved = True
    __optional = False
    name = 'typ'
    claim = 'JWT'


class AlgClaim(BaseClaim):
    """
    A simple reserved, required claim determining the encryption algorithm.
    """
    _reserved = True
    __optional = False
    name = 'alg'

    def value(self):
        return str(HS256()) # for now just assume HS256


class IssClaim(BaseClaim):
    """
    A simple reserved claim determining the issuer of the token.
    """
    _reserved = True
    name = 'iss'

    def __init__(self, iss):
        self.claim = iss


class SubClaim(BaseClaim):
    """
    A simple reserved claim determining the subject of the token.
    """
    _reserved = True
    name = 'sub'

    def __init__(self, sub):
        self.claim = sub


class NbfClaim(BaseDateTimeClaim):
    """
    A reserved POSIX timestamp claim determining after what time a token can be used.
    """
    _reserved = True
    name = 'nbf'
    invalid_exception = ClaimException
    invalid_except_msg = 'nbf claim failed' #TODO

    def __init__(self, tmedelta=timedelta(seconds=30)):
        self.dt = datetime.utcnow() + tmedelta

    def is_datetime_invalid(self, dt, now):
        return dt < now


class ExpClaim(BaseDateTimeClaim):
    """
    A reserved POSIX timestamp claim determining the expiration time of a token.
    """
    _reserved = True
    name = 'exp'
    invalid_exception = TokenException('Token is expired') # TODO

    def __init__(self, tmedelta=timedelta(days=7)):
        self.dt = datetime.utcnow() + tmedelta

    def is_datetime_invalid(self, dt, now):
        return dt > now
