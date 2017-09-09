import json
from base64 import urlsafe_b64encode, urlsafe_b64decode

from jwt import claims as jwt_claims

class BaseComponent:
    """
    All component classes should extend BaseComponent.
    """
    claims = ()
    extra_kwargs = {}

    def as_json(self):
        """
        Serializes claim classes to json.
        """
        claims = {}
        for claim in self.claims:
            try:
                claim = claim()
            except TypeError:
                # TODO test that key exists 
                claim = claim(**self.extra_kwargs[claim])

            claims[claim.key()] = claim.value()

        return json.dumps(claims)

    def as_comp(self):
        """
        Serializes component into urlsafe base64 json data.
        """
        return urlsafe_b64encode(self.as_json().encode())

def component_factory(claims, kwargs):
    class FactoryComponent(BaseComponent):
        claims = claims
        extra_kwargs = kwargs

    return FactoryComponent()

class HeaderComponent(BaseComponent):
    claims = (
        jwt_claims.TypClaim,
        jwt_claims.AlgClaim
    )
