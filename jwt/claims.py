from datetime import datetime, timedelta

from jwt.algorithms import BaseAlgorithm 
from jwt import exceptions

class BaseClaim:
    """Claim class. Validates claim data and accesses a claim's name and value.
    A claim has two parts, a name and a value. A claim name is a collision resistant
    identifier for the claim. The value is the information set in the claim.

    To extend BaseClaim, create a class and add the following class attributes::

        name
        claim

    Attributes:
        name (str): The serializable name of the claim. The name would be the key
            in a dictionary.
        claim (str): The serializable value of the claim. The claim value would be the value
            in a dictionary.

    Example:
        After serialization, a claim might look like this, with name and value being data set
        as class attributes::

            {
                name: value
            }

    All claim classes should extend BaseClaim.
    """
    _reserved = False
    __optional = True

    def is_valid(self, data):
        """Validates supplied data. Always call super() when overriding
        this method.

        Args:
            data (str, bytes): The data to validate. data can be of type
                str or bytes.
        Returns:
            bool: True.

        Raises:
            InvalidClaimError: If the data supplied is not valid.
        """
        if not getattr(self, '__optional') and self.value() not in data:
            raise exceptions.InvalidClaimError('Claim is required however was not '\
                                               'found in component.')

        return True

    def value(self):
        """Returns the value of the claim.

        Example:
            In the the following, invoking .value() will return 'JWT'::

            {
                'typ': 'JWT'
            }

        Returns:
            str: The string value of the claim.
        """
        return getattr(self, 'claim')

    def key(self):
        """Returns the key of the claim.

        Example:
            In the the following, invoking .key() will return 'typ'::

            {
                'typ': 'JWT'
            }

        Returns:
            str: The string key of the claim.
        """
        return getattr(self, 'name')

    def __key(self):
        return (self.reserved, self.__optional, getattr(self, 'name'))

    def __eq__(self, othr):
        return isinstance(othr, self.__class__) and self.__key() == othr.__key()

    def __hash__(self):
        return hash(self.__key())


class BaseDateTimeClaim(BaseClaim):
    """Unix timestamp claim class. Validates claim data and accesses a claim's name and value.
    A claim has two parts, a name and a value. A claim name is a collision resistant
    identifier for the claim. The value is the information set in the claim.

    A DateTimeClaim class serializes the current unix timestamp as a claims value. Validation
    of the timestamp is easily preformed by overriding .is_datetime_invalid()

    To extend BaseClaim, create a class and add the following class attributes and
    override .is_datetime_invalid()::

        name
        dt

    Attributes:
        name (str): The serializable name of the claim. The name would be the key
            in a dictionary.
        dt (datetime): the value to be used as the claims value. The value will automatically
            be serialized from a datetime object to a unix timestamp.
        invalid_exception (Exception, optional): An exception to be raised if claim data
            fails validation. Defaults to `jwt.exceptions.InvalidClaimError`.
        invalid_except_msg (str, optional): A string to be passed to invalid_exception
            if claim data fails validation. Defaults to None.

    Example:
        After serialization, a claim might look like this, with name and value being data set
        as class attributes::

            {
                name: value
            }

    All Unix timestamp claims should extend BaseDateTimeClaim.
    """
    def value(self):
        """Returns the value of the claim.

        Example:
            In the the following, invoking .value() will return 'JWT'::

            {
                'typ': 'JWT'
            } Must be of type datetime.

        Returns:
            str: The string value of the claim.
        """
        return getattr(self, 'dt', datetime.utcnow()).timestamp()

    def is_valid(self, data):
        """Validates supplied data against the current timestamp.

        Args:
            data (str, bytes): The data to validate. data can be of type
                str or bytes.
        Returns:
            bool: True.

        Raises:
            Exception: If the data supplied is not valid.
        """
        super(BaseDateTimeClaim, self).is_valid(data)
        if getattr(self, 'name') in data:
            if self.is_datetime_invalid(data[getattr(self, 'name')], datetime.now()):
                raise getattr(self, 'invalid_exception', exceptions.InvalidClaimError)\
                              (getattr(self, 'invalid_except_msg'))

    def is_datetime_invalid(self, dt, now):
        """Returns when the supplied datetime is invalid.

        Args:
            dt (datetime): The supplied datetime object to be compared.
            now (datetime): A datetime object that has the current date and time.

        Raises:
            NotImplementedError: If the method has not been implemented in a child class.

        Children classes must implement .is_datetime_invalid()
        """
        raise NotImplementedError('.is_datetime_invalid() must be overridden.')


class TypClaim(BaseClaim):
    """A simple reserved, required claim that defining the type of token as a JWT.
    For use in a JOSE-compliant header component.
    """
    _reserved = True
    __optional = False
    name = 'typ'
    claim = 'JWT'


class BaseAlgClaim(BaseClaim):
    """A simple reserved, required claim defining the encryption algorithm
    as NoneAlgorithm. For use in a JOSE-compliant header component.

    All algorithm claims should extend BaseAlgClaim.
    """
    _reserved = True
    __optional = False
    name = 'alg'

    def value(self):
        return 'none'

class HS256AlgClaim(BaseAlgClaim):
    """A simple reserved, required claim defining the encryption algorithm
    as SHA256. For use in a JOSE-compliant header component.
    """
    def value(self):
        return 'HS256'

class IssClaim(BaseClaim):
    """A simple reserved claim defining the issuer of the token. For use in a payload.

    Args:
        iss (str): The issuer of the token. Usually, this is a string or URI.
    """
    _reserved = True
    name = 'iss'

    def __init__(self, iss):
        self.claim = iss


class SubClaim(BaseClaim):
    """A simple reserved claim defining the subject of the token. The subject is the
    pricipal idea of a token. For use in a payload.

    Args:
        sub (str): The subject of the token. Usually, this is a string or URI.
    """
    _reserved = True
    name = 'sub'

    def __init__(self, sub):
        self.claim = sub


class AudClaim(BaseClaim):
    """A simple reserved claim defining the audience or recipient of the token.
    For use in a payload.

    Args:
        aud (str): The audience of the token. Usually, this is a user or recipient(s).
    """
    _reserved = True
    name = 'aud'

    def __init__(self, aud):
        self.claim = aud

class NbfClaim(BaseDateTimeClaim):
    """A reserved Unix timestamp claim defining after what time a token can be used.
    For use in a payload.

    Args:
        tmedelta (timedelta): The delta time to be added to the current time; defines
            when the token can be used.
    """
    _reserved = True
    name = 'nbf'

    def __init__(self, tmedelta=timedelta(seconds=30)):
        self.dt = datetime.utcnow() + tmedelta
        self.invalid_except_msg = 'Nbf claim failure. '\
                                  'Token has been used before {0}.'.format(self.dt)

    def is_datetime_invalid(self, dt, now):
        return dt < now


class ExpClaim(BaseDateTimeClaim):
    """A reserved Unix timestamp claim determining the expiration time of a token.
    For use in a payload.

    Args:
        tmedelta (timedelta): The delta time to be added to the current time; defines
            when the token will expire.
    """
    _reserved = True
    name = 'exp'

    def __init__(self, tmedelta=timedelta(days=7)):
        self.dt = datetime.utcnow() + tmedelta
        self.invalid_except_msg = 'Exp claim failure. '\
                                  'Token has been used after {0}.'.format(self.dt)

    def is_datetime_invalid(self, dt, now):
        return dt > now
