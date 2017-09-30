import unittest
from datetime import datetime, timedelta

from jwt import claims
from jwt import exceptions


class TestClaims(unittest.TestCase):

    @classmethod
    def setUp(cls):
        cls.typ_claim = claims.TypClaim()
        # Specifically this alg
        cls.alg_claim = claims.HMACAlgClaim()

        cls.nbf_claim = claims.NbfClaim()
        cls.exp_claim = claims.ExpClaim()
        cls.iss_claim = claims.IssClaim('issuer')
        cls.sub_claim = claims.SubClaim('subject')
        cls.aud_claim = claims.IssClaim('audience')

    def test_nbf_claim_validity(self):
        # Not before time. If the token is used before this time,
        # InvalidClaimError should be raised.

        # First set it to set to 5 seconds before present time.
        # Since now is gte to now - 5 seconds, it should pass.
        nbf_time = datetime.utcnow() - timedelta(seconds=5)
        self.nbf_claim.is_valid(nbf_time.timestamp())

        # Then 5 seconds after now.
        # Since now + 5 seconds is lte to now, assert raises.
        nbf_time += timedelta(seconds=10)
        with self.assertRaises(exceptions.InvalidClaimError):
            self.nbf_claim.is_valid(nbf_time.timestamp())

    def test_exp_claim_validity(self):
        # Expiration time. If the token is used after this time,
        # InvalidClaimError should be raised.

        # First set it to set to 7 after present time.
        # Since now is lte to now + 7 days, it should pass.
        exp_time = datetime.utcnow() + timedelta(days=7)
        self.exp_claim.is_valid(exp_time.timestamp())

        # Then 7 days before now.
        # Since now - 7 days is gte to now, assert raises.
        exp_time -= timedelta(days=14)
        with self.assertRaises(exceptions.InvalidClaimError):
            self.exp_claim.is_valid(exp_time.timestamp())

    def test_required_claim_validity(self):
        with self.assertRaises(exceptions.InvalidClaimError):
            self.typ_claim.is_valid(None)

    def test_iss_claim_validity(self):
        with self.assertRaises(exceptions.InvalidClaimError):
            self.iss_claim.is_valid('not_issuer')

        # Test passing None raises InvaildClaimError
        with self.assertRaises(exceptions.InvalidClaimError):
            self.iss_claim.is_valid(None)

    def test_aud_claim_validity(self):
        with self.assertRaises(exceptions.InvalidClaimError):
            self.aud_claim.is_valid('not_audience')

        # Test passing None raises InvaildClaimError
        with self.assertRaises(exceptions.InvalidClaimError):
            self.aud_claim.is_valid(None)

    def test_sub_claim_validity(self):
        with self.assertRaises(exceptions.InvalidClaimError):
            self.sub_claim.is_valid('not_subject')

        # Test passing None raises InvaildClaimError
        with self.assertRaises(exceptions.InvalidClaimError):
            self.sub_claim.is_valid(None)

    def test_alg_claim_validity(self):
        with self.assertRaises(exceptions.InvalidClaimError):
            self.alg_claim.is_valid('other_algorithm')

        # Test passing None raises InvaildClaimError
        with self.assertRaises(exceptions.InvalidClaimError):
            self.alg_claim.is_valid(None)

    def test_typ_claim_validity(self):
        with self.assertRaises(exceptions.InvalidClaimError):
            self.typ_claim.is_valid('other_typ')

        # Test passing None raises InvaildClaimError
        with self.assertRaises(exceptions.InvalidClaimError):
            self.typ_claim.is_valid(None)
