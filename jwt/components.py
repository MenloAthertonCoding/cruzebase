import json
from base64 import urlsafe_b64encode, urlsafe_b64decode

from jwt import claims as jwt_claims

class BaseComponent:
    """Components class. Serializes claim classes into json objects.

    To extend BaseComponent, create a class and add the following class attribute::

        claims

    Attributes:
        claims (iterable): Class that defines the JWT header component.
            Typically use claims in `jwt.claims`.
        extra_kwargs (dict, optional): Extra keyword arguments that are passed into
            header_cls and payload_cls for further parsing. Defaults to None.

            Example:
                The dict's keys must have classes that extend `jwt.claims.BaseClaim`.
                The values of the dict are of a claim's instatiating parameters as keys
                and arguments as values::

                {
                    claims.IssClaim: {'iss': 'Issuer'}
                }

    All component classes should extend BaseComponent.
    """
    claims = ()
    extra_kwargs = {}

    def as_json(self):
        """Serializes claims into json objects.

        Returns:
            str: Returns the component serialized as json.
        """
        claims = {}
        for claim in self._instantiate_claims():
            claims[claim.key()] = claim.value()
        return json.dumps(claims)


    def as_comp(self):
        """Serializes claims into json objects and base64 encodes them.

        Returns:
            str: Returns the base64 encoded component.
        """
        return urlsafe_b64encode(self.as_json().encode())

    def _instantiate_claims(self):
        for claim in self._claims():
            try:
                claim = claim()
            except TypeError:
                # TODO test that key exists
                claim = claim(**self._extra_kwargs()[claim])
        yield claim

    def _extra_kwargs(self):
        return self.extra_kwargs

    def _claims(self):
        return self.claims

def component_factory(*args, kwargs=None):
    """Factory method for creating components.

    Example:
        To create a component using a component factory::

            >>> from jwt.components import component_factory
            >>> from jwt import claims
            >>> component_factory(claims.NbfClaim, claims.ExpClaim)
            <class 'jwt.components.component_factory.<locals>.FactoryComponent'>

    Args:
        *args: variable length argument list of claims.
            each claim must extend `jwt.claims.BaseClaim`.
        kwargs (dict, optional): Extra keyword arguments that are passed into
            header and payload components for further parsing. Defaults to None.

            Example:
                The dict's keys must have classes that extend `jwt.claims.BaseClaim`.
                The values of the dict are of a claim's instatiating parameters as keys
                and arguments as values::

                {
                    claims.IssClaim: {'iss': 'Issuer'}
                }

    Returns:
        FactoryComponent: An component class with the specified claims that is
            NOT instantiated.
    """
    class FactoryComponent(BaseComponent):
        claims = args
        if kwargs is not None:
            extra_kwargs = kwargs

    return FactoryComponent

class HS256HeaderComponent(BaseComponent):
    claims = (
        jwt_claims.TypClaim,
        jwt_claims.HS256AlgClaim
    )
