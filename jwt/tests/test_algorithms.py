import unittest
import hashlib
import hmac

from jwt import algorithms


class TestAlgorithms(unittest.TestCase):

    @classmethod
    def setUp(cls):
        cls.hmac_sha256 = ('HS256', hashlib.sha256)
        cls.hmac_sha384 = ('HS384', hashlib.sha384)
        cls.hmac_sha512 = ('HS512', hashlib.sha512)

        cls.hmac_alg = algorithms.HMACAlgorithm
        cls.none_alg = algorithms.NoneAlgorithm

    def _hmac_alg(self):
        return self.hmac_alg(self.hmac_alg.SHA256)

    def test_force_bytes(self):
        byt = algorithms.force_bytes('string')
        self.assertTrue(isinstance(byt, bytes))

    def test_hmac_alg_algorithm(self):
        self.assertEqual(algorithms.HMACAlgorithm.SHA256, self.hmac_sha256)
        self.assertEqual(algorithms.HMACAlgorithm.SHA384, self.hmac_sha384)
        self.assertEqual(algorithms.HMACAlgorithm.SHA512, self.hmac_sha512)

        self.assertEqual(str(self._hmac_alg()), self.hmac_alg.SHA256[0])

    def test_hmac_algorithm_signing_verifying(self):
        hmac_alg = self._hmac_alg()

        key = b'secret'
        msg = b'sign me'
        # Sign twice to ensure that signing is returning similar
        # digests
        sig1 = hmac_alg.sign(msg, key)
        sig2 = hmac_alg.sign(msg, key)

        self.assertTrue(hmac_alg.verify(msg, key, sig1))
        self.assertTrue(hmac.compare_digest(sig1, sig2))

    def test_none_algorithm_signing_verifying(self):
        none_alg = self.none_alg()

        key = b'secret'
        msg = b'sign me'
        # Sign twice to ensure that signing is returning similar
        # digests
        sig1 = none_alg.sign(msg, key)
        sig2 = none_alg.sign(msg, key)

        # NoneAlgorithm must always return '' as its signature
        self.assertEqual(sig1, b'')
        self.assertFalse(none_alg.verify(msg, key, sig1))
        self.assertTrue(hmac.compare_digest(sig1, sig2))

    def test_none_algorithm_string(self):
        self.assertEqual(str(self.none_alg()).lower(), 'none')
