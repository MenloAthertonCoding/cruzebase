import hmac
import hashlib

def force_bytes(value):
    if isinstance(value, str):
        return value.encode('utf-8')
    elif isinstance(value, bytes):
        return value
    else:
        raise TypeError('Expected a string value, got {0} instead.'.format(type(value)))


class BaseAlgorithm:

    def sign(self, msg, key):
        """
        Children classes must implement .sign()
        """
        raise NotImplementedError

    def verify(self, msg, key, sig):
        """
        Children classes must implement .verify()
        """
        raise NotImplementedError

    def prep_key(self, key):
        return force_bytes(key)

    def __str__(self):
        return self.__class__.__name__


class HMACAgorithm(BaseAlgorithm):
    """
    Performs signing and verification operations using HMAC
    and the specified hash function.
    """
    SHA256 = hashlib.sha256
    SHA384 = hashlib.sha384
    SHA512 = hashlib.sha512

    def __init__(self, hash_algo):
        self.hash_algo = hash_algo

    def sign(self, msg, key):
        return hmac.new(
            self.prep_key(key),
            msg,
            digestmod=self.hash_algo
        ).digest()

    def verify(self, msg, key, sig):
        return hmac.compare_digest(sig, self.sign(msg, key))

    def __str__(self):
        return 'HS256' # TODO return hashing alg


class NoneAlgorithm(BaseAlgorithm):
    """
    Placeholder for use when no signing or verification
    operations are required.
    """
    def prep_key(self, key):
        if key == '':
            key = None

        if key is not None:
            raise TypeError('Cannot use `NoneAlgorithm` when key is not'\
                            'of type `None`.')

        return key

    def sign(self, msg, key):
        return b''

    def verify(self, msg, key, sig):
        return False

class RSAAlgorithm(BaseAlgorithm):
    """
    Performs encryption and verification operations using RSA
    public/private secret keys.
    """
    # TODO Implement
    pass
