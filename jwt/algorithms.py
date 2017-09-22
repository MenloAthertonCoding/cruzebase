import hmac
import hashlib

def force_bytes(value):
    """Forces a value to bytes.

    Args:
        value (str, bytes): The value to force to bytes. value must be of type
            str or bytes.

    Returns:
        bytes: value utf-8 encoded as bytes if value is a str; value if vaule is a bytes
        object.

    Raises:
        TypeError: If value is not of type str or bytes.
    """
    if isinstance(value, str):
        return value.encode('utf-8')
    elif isinstance(value, bytes):
        return value
    else:
        raise TypeError('Expected a string value, got {0} instead.'.format(type(value)))


class BaseAlgorithm:
    """Algorithm class. Sign and verify signatures to ensure authenticity.

    To extend BaseAlgorithm, create a class and override the following methods::

        sign()
        verify()

    All algorithm classes should extend BaseAlgorithm.
    """
    def sign(self, msg, key):
        """Signs a message using a key. A signing method should always call
        prep_key(), to ensure that the key is .

        Args:
            msg (bytes): A message to sign.
            key (str, bytes): A secret key used to cryptographically sign msg. key
                must by of type str or bytes.

        Raises:
            NotImplementedError: If the method has not been implemented in a child class.

        Children classes must implement .sign()
        """
        raise NotImplementedError

    def verify(self, msg, key, sig):
        """Verifies a digest. Uses key and msg to sign and compare against sig.

        Args:
            msg (bytes): A message to sign.
            key (str, bytes): A secret key used to cryptographically sign msg. key
                must by of type str or bytes.
            sig (bytes): The signature to verify.

        Raises:
            NotImplementedError: If the method has not been implemented in a child class.

        Children classes must implement .verify()
        """
        raise NotImplementedError

    def prep_key(self, key):
        """Prepares the key for signing. .prep_key() should call force_bytes()
        to ensure that key is of type bytes before key is used.

        Args:
            key (str, bytes): A secret key to prepare for signing. key must be
            of type str or bytes.

        Returns:
            bytes: a bytes object of ke
        """
        return force_bytes(key)

    def __str__(self):
        return self.__class__.__name__


class HMACAlgorithm(BaseAlgorithm):
    """Performs signing and verification operations using HMAC
    and the specified hash function.

    Args:
        hash_algo (func): A hashing function. For example, use HMACAlgorithm.SHA256
            value. Check attributes of HMACAlgorithm for all hashing algorithms.

    Attributes:
        SHA256 (tuple): A two-tuple of 'name' and SHA256 hashing algorithm.
        SHA384 (tuple): A two-tuple of 'name' and SHA384 hashing algorithm.
        SHA512 (tuple): A two-tuple of 'name' and SHA512 hashing algorithm.
    """
    SHA256 = (
        'HS256',
        hashlib.sha256
    )

    SHA384 = (
        'HS384',
        hashlib.sha384
    )

    SHA512 = (
        'HS512',
        hashlib.sha512
    )

    def __init__(self, hash_algo):
        self.hash_algo = hash_algo

    def sign(self, msg, key):
        return hmac.new(
            self.prep_key(key),
            msg,
            digestmod=self.hash_algo[1]
        ).digest()

    def verify(self, msg, key, sig):
        return hmac.compare_digest(sig, self.sign(msg, key))

    def __str__(self):
        return self.hash_algo[0]


class NoneAlgorithm(BaseAlgorithm):
    """Placeholder for use when no signing or verification operations
    are required.
    """
    def prep_key(self, key):
        if key == '':
            key = None

        if key is not None:
            raise TypeError(
                'Cannot use `NoneAlgorithm` when key is not of type `None`.'
            )

        return key

    def sign(self, msg, key):
        return b''

    def verify(self, msg, key, sig):
        return False

    def __str__(self):
        return 'none'

class RSAAlgorithm(BaseAlgorithm):
    """Performs signing and verification operations using RSA
    public/private keys.
    """
    # TODO Implement
    pass
