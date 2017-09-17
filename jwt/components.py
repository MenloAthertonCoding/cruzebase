import json
from base64 import urlsafe_b64encode

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
                The values of the dict are of a claim's instantiating parameters as keys
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
                # Will raise KeyError if key isn't present.
                claim = claim(**self._extra_kwargs()[claim])
            yield claim

    def _extra_kwargs(self):
        return self.extra_kwargs

    def _claims(self):
        return self.claims

def component_factory(*args):
    """Factory method for creating components. Call add_kwargs to add
    extra kwargs.

    Example:
        To create a component using a component factory::

            >>> from jwt.components import component_factory
            >>> from jwt import claims
            >>> component_factory(claims.NbfClaim, claims.ExpClaim)
            <class 'jwt.components.component_factory.<locals>.FactoryComponent'>

    Args:
        *args: variable length argument list of claims. each claim must
            extend `jwt.claims.BaseClaim`.

    Returns:
        FactoryComponent: An component class with the specified claims that is
            NOT instantiated.
    """
    class FactoryComponent(BaseComponent):
        claims = args

    return FactoryComponent

def add_kwargs(component, kwargs):
    """Adds extra kwargs to a component class. The component must bne uninstantiated,
    as instantiating also instantiates the claims.

    Args:
        component (BaseComponent): An uninstantiated component class to add extra kwargs to.
        kwargs (dict): Extra keyword arguments that are passed into the components claims
            for further parsing.

        Example:
            The dict's keys must have classes that extend `jwt.claims.BaseClaim`.
            The values of the dict are of a claim's instatiating parameters as keys
            and arguments as values::

            {
                claims.IssClaim: {'iss': 'Issuer'}
            }

    Returns:
        BaseComponent: The component with the extra kwargs added.

    Raises:
        TypeError: If the component has already been instantiated.
    """
    if isinstance(component, BaseComponent):
        # If component is instantiated
        raise TypeError('Component has already been instantiated.')

    component.extra_kwargs.update(kwargs)
    return component


class HS256HeaderComponent(BaseComponent):
    claims = (
        jwt_claims.TypClaim,
        jwt_claims.HS256AlgClaim
    )
