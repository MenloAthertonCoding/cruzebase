import json
from base64 import urlsafe_b64encode

from jwt import claims as jwt_claims
from jwt.exceptions import ClaimsetException
from jwt.algorithms import HMACAlgorithm


class BaseClaimset:
    """Claimset class. Serializes claim classes into json objects.

    To extend BaseClaimset, create a class and add the following class attribute::

        claims

    Attributes:
        claims (iterable): Class that defines the JWT header claimset.
            Typically use claims in `jwt.claims`.
        extra_kwargs (dict, optional): Extra keyword arguments that are passed into
            header_cls and payload_cls for further parsing. Defaults to None.

            Example:
                The dict's keys must have classes that extend `jwt.claims.BaseClaim`.
                The values of the dict are of a claim's instantiating parameters as keys
                and arguments as values::

                {
                    claims.IssClaim: {'iss': 'Issuer'}
                }

    All claimset classes should extend BaseClaimset.
    """
    claims = ()
    extra_kwargs = {}

    def as_json(self):
        """Serializes claims into json objects.

        Returns:
            str: Returns the claimset serialized as json.
        """
        claims = {}
        for claim in self._instantiate_claims():
            claims.update({claim.key(): claim.value()})
        return json.dumps(claims)


    def as_claimset(self):
        """Serializes claims into json objects and base64 encodes them.

        Returns:
            str: Returns the base64 encoded claimset.
        """
        return urlsafe_b64encode(self.as_json().encode())

    def _instantiate_claims(self):
        for claim in self._claims():
            try:
                claim = claim(**self._extra_kwargs()[claim])
            except KeyError:
                claim = claim()
            yield claim

    def _extra_kwargs(self):
        return self.extra_kwargs

    def _claims(self):
        return self.claims

    def is_valid(self, data):
        """Validates supplied data. Always call super() when overriding
        this method.

        Args:
            data (dict): The data to validate. data must be a decoded claimset.

        Returns:
            bool: True if the claims are valid.
        """
        for claim in self._instantiate_claims():
            claim.is_valid(data.get(claim.key(), None))
        return True

def claimset_factory(*args):
    """Factory method for creating claimsets. Call add_kwargs to add
    extra kwargs.HS256HeaderClaimset

    Example:
        To create a claimset using a claimset factory::

            >>> from jwt.claimsets import claimset_factory
            >>> from jwt import claims
            >>> claimset_factory(claims.NbfClaim, claims.ExpClaim)
            <class 'jwt.claimsets.claimset_factory.<locals>.FactoryClaimset'>

    Args:
        *args: variable length argument list of claims. each claim must
            extend `jwt.claims.BaseClaim`.

    Returns:
        FactoryClaimset: An claimset class with the specified claims that is
            NOT instantiated.

    Raises:
        ClaimsetException: If no claims were given as arguments.
    """
    if not args:
        # If there are no claims
        raise ClaimsetException('No claims were provided. Claimset class could not be created.')

    class FactoryClaimset(BaseClaimset):
        claims = args

    return FactoryClaimset

def add_kwargs(claimset, kwargs):
    """Adds extra kwargs to a claimset class. The claimset must bne uninstantiated,
    as instantiating also instantiates the claims.

    Args:
        claimset (BaseClaimset): An uninstantiated claimset class to add extra kwargs to.
        kwargs (dict): Extra keyword arguments that are passed into the claimsets claims
            for further parsing.

        Example:
            The dict's keys must have classes that extend `jwt.claims.BaseClaim`.
            The values of the dict are of a claim's instatiating parameters as keys
            and arguments as values::

            {
                claims.IssClaim: {'iss': 'Issuer'}
            }

    Returns:
        BaseClaimset: The claimset with the extra kwargs added.

    Raises:
        TypeError: If the claimset has already been instantiated.
    """
    if isinstance(claimset, BaseClaimset):
        # If claimset is instantiated
        raise TypeError('Claimset has already been instantiated.')
    claimset.extra_kwargs.update(kwargs)
    return claimset


class HMACHeaderClaimset(BaseClaimset):
    """A JOSE-compliant header claimset that uses HMAC to sign a token.

    Args:
        alg (tuple, optional): The algorithm to use to sign the token.
            For example, use HMACAlgorithm.SHA256 value. Check attributes
            of HMACAlgorithm for all hashing algorithms.

    Raises:
        TypeError: If alg is not of type tuple.
    """
    claims = (
        jwt_claims.TypClaim,
        jwt_claims.HMACAlgClaim
    )

    def __init__(self, alg=HMACAlgorithm.SHA256):
        if not isinstance(alg, tuple):
            raise TypeError('Algorithm must be of type tuple.')

        self.alg = alg

    def _extra_kwargs(self):
        return {'alg': self.alg}
