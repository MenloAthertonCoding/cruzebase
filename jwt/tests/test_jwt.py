"""
Tests Token class and JWT main functionality (__init__ file)
"""
import unittest
import json

from jwt import BaseToken, token_factory, compare
from jwt import claims as jwt_claims
from jwt.algorithms import HMACAlgorithm
from jwt.claimsets import BaseClaimset

HMAC_ALGORITHM = HMACAlgorithm(HMACAlgorithm.SHA256)


class TestClaims(unittest.TestCase):

    def _token(self):
        class Header(BaseClaimset):
            claims = (
                jwt_claims.HMACAlgClaim,
                jwt_claims.TypClaim
            )

        class Payload(BaseClaimset):
            claims = (
                jwt_claims.IssClaim,
                jwt_claims.NbfClaim,
                jwt_claims.ExpClaim,
                jwt_claims.AudClaim
            )

            extra_kwargs = {
                jwt_claims.IssClaim: {'iss': 'http://www.github.com'},
                jwt_claims.AudClaim: {'aud': '1'},
            }

        return token_factory(Header, Payload)

    def test_split_token(self):
        token = self._token()
        token_str = token.build('secret', HMAC_ALGORITHM)

        # (header, payload, sig)
        split_token = BaseToken.split(token_str)
        self.assertEqual(len(split_token), 3)
        self.assertEqual(split_token[0], token.header.as_claimset())
        self.assertEqual(split_token[1], token.payload.as_claimset())

        # (claimsets, sig)
        split_token = BaseToken.split_crypto(token_str)
        self.assertEqual(len(split_token), 2)
        self.assertEqual(split_token[0],
                         b'.'.join((token.header.as_claimset(),
                                    token.payload.as_claimset())))

        # (header, payload)
        split_token = BaseToken.split_claimsets(split_token[0])
        self.assertEqual(len(split_token), 2)
        self.assertEqual(split_token[0], token.header.as_claimset())
        self.assertEqual(split_token[1], token.payload.as_claimset())

    def test_clean_token(self):
        token = self._token()
        token_str = token.build('secret', HMAC_ALGORITHM)

        # (header, payload, sig)
        clean_token = BaseToken.clean(token_str)
        self.assertEqual(len(clean_token), 3)
        self.assertDictEqual(clean_token[0], json.loads(token.header.as_json()))
        self.assertDictEqual(clean_token[1], json.loads(token.payload.as_json()))

        # (claimsets, sig)
        clean_token = BaseToken.clean_crypto(token_str)
        self.assertEqual(len(clean_token), 2)
        self.assertEqual(clean_token[0],
                         b'.'.join((token.header.as_claimset(),
                                    token.payload.as_claimset())))

        # (header, payload)
        clean_token = BaseToken.clean_claimsets(clean_token[0])
        self.assertEqual(len(clean_token), 2)
        self.assertDictEqual(clean_token[0], json.loads(token.header.as_json()))
        self.assertDictEqual(clean_token[1], json.loads(token.payload.as_json()))

    def test_compare_token(self):
        # Set verify claims to false as claim verification should
        # be tested in test_claims
        compare(self._token().build('secret', HMAC_ALGORITHM),
                self._token(), 'secret', HMAC_ALGORITHM, verify_claims=False)
