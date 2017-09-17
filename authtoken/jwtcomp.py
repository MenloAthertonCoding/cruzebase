from jwt.components import BaseComponent
from jwt import BaseToken, claims as jwt_claims

class PayloadComponent(BaseComponent):
    """
    Custom payload component.
    """

    def __init__(self, aud):
        if not isinstance(aud, int):
            raise TypeError('Argument `aud` must be of type `int`; specifically,'\
                            'it should reference the `ProfileUser` pk')
        self.aud = aud

    claims = (
        jwt_claims.IssClaim,
        jwt_claims.NbfClaim,
        jwt_claims.ExpClaim,
        jwt_claims.AudClaim
    )

    def _extra_kwargs(self):
        return {
            jwt_claims.IssClaim: {'iss': 'http://www.google.com'},
            jwt_claims.AudClaim: {'aud': self.aud},
        }
