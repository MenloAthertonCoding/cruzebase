import unittest
import base64
import json
from datetime import datetime, timedelta

from jwt.claimsets import (
    claimset_factory,
    add_kwargs
)
from jwt import claims as jwt_claims
from jwt.exceptions import InvalidClaimError


class TestClaimsets(unittest.TestCase):

    @classmethod
    def setUp(cls):
        claims = (
            jwt_claims.IssClaim,
            jwt_claims.SubClaim,
            jwt_claims.AudClaim,
            jwt_claims.NbfClaim, # args optional
            jwt_claims.ExpClaim # args optional
        )

        kwargs = {
            jwt_claims.IssClaim: {'iss': 'issuer'},
            jwt_claims.SubClaim: {'sub': 'subject'},
            jwt_claims.AudClaim: {'aud': 'audience'}
        }

        claimset = claimset_factory(*claims)
        add_kwargs(claimset, kwargs)
        cls.claimset = claimset()

    def test_as_claimset(self):
        claimset = self.claimset.as_claimset()
        json_data = self.claimset.as_json()
        self.assertEqual(base64.urlsafe_b64decode(claimset), json_data.encode())

    def test_claimset_valid(self):
        data = json.loads(self.claimset.as_json())
        data.update(nbf=(datetime.utcnow() - timedelta(seconds=5)).timestamp())
        data.update(exp=(datetime.utcnow() + timedelta(days=7)).timestamp())

        self.assertTrue(self.claimset.is_valid(data))

        with self.assertRaises(InvalidClaimError):
            # Replace issuer value
            data.update(iss='other_issuer')
            self.claimset.is_valid(data)
