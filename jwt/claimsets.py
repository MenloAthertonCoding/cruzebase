import json
from base64 import urlsafe_b64encode

from jwt import claims as jwt_claims

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
            claims[claim.key()] = claim.value()
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
                claim = claim()
            except TypeError:
                # Will raise KeyError if extra kwargs for claim isn't present.
                claim = claim(**self._extra_kwargs()[claim])
            yield claim

    def _extra_kwargs(self):
        return self.extra_kwargs

    def _claims(self):
        return self.claims

def claimset_factory(*args):
    """Factory method for creating claimsets. Call add_kwargs to add
    extra kwargs.

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
    """

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


class HS256HeaderClaimset(BaseClaimset):
    claims = (
        jwt_claims.TypClaim,
        jwt_claims.HS256AlgClaim
    )