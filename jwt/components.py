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
        for claim in self._instantiate_claims():
            claims[claim.key()] = claim.value()
        return json.dumps(claims)


    def as_comp(self):
        """
        Serializes component into urlsafe base64 json data.
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

def component_factory(claim_cls, kwargs=None):
    class FactoryComponent(BaseComponent):
        claims = claim_cls
        if kwargs is not None:
            extra_kwargs = kwargs

    return FactoryComponent()

class HS256HeaderComponent(BaseComponent):
    claims = (
        jwt_claims.TypClaim,
        jwt_claims.HS256AlgClaim
    )
