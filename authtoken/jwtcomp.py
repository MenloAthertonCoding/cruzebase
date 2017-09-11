from jwt.components import BaseComponent
from jwt import BaseToken, claims as jwt_claims

class PayloadComponent(BaseComponent):
    """
    Custom payload component.
    """

    def __init__(self, sub):
        if not isinstance(sub, int):
            raise TypeError('Argument `sub` must be of type `int`; specifically,'\
                            'it should reference the `ProfileUser` pk')
        self.sub = sub

    claims = (
        jwt_claims.IssClaim,
        jwt_claims.NbfClaim,
        jwt_claims.ExpClaim,
        jwt_claims.SubClaim
    )

    def _extra_kwargs(self):
        return {
            jwt_claims.IssClaim: {'iss': 'http://www.google.com'},
            jwt_claims.SubClaim: {'sub': self.sub},
        }
