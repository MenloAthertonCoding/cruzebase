from jwt.claimsets import BaseClaimset
from jwt import claims as jwt_claims

from authtoken.settings import api_settings


class PayloadClaimset(BaseClaimset):
    """
    Custom payload claimset.
    """

    def __init__(self, aud):
        if not isinstance(aud, int):
            raise TypeError('Argument `aud` must be of type `int`; specifically,'\
                            'it should reference the `ProfileUser` pk')
        self.aud = aud

    claims = (
        jwt_claims.IssClaim,
        jwt_claims.AudClaim,
        jwt_claims.NbfClaim,
        jwt_claims.ExpClaim,
    )

    def _extra_kwargs(self):
        return {
            jwt_claims.IssClaim: {'iss': 'Iss'},
            jwt_claims.AudClaim: {'aud': self.aud},
            jwt_claims.NbfClaim: {'nbf': api_settings.TOKEN_NOT_BEFORE_TIME_DELTA},
            jwt_claims.ExpClaim: {'exp': api_settings.TOKEN_EXPIRATION_TIME_DELTA},
        }
