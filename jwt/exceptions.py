class TokenException(Exception):
    """Raised when a token has a generalized exception.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): BaseToken instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.

    All token, claimset, or claim exceptions should extend TokenException.
    """
    def __init__(self, message=None, token=None):
        super(TokenException, self).__init__(message)
        self.token = token


class MalformedTokenError(TokenException):
    """Raised when a token string is defective, abnormal, or not parsable.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): BaseToken instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
    """
    pass


class InvalidTokenError(TokenException):
    """Raised when a token's signature is invalid.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): BaseToken instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
    """
    pass


class TokenSignatureError(TokenException):
    """Raised when a token signature is not cryptographically signed.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): BaseToken instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
    """
    pass


class ClaimsetException(TokenException):
    """Raised when a claimset has a generalized exception.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): Token instance that raised exception.
            Defaults to None.
        claimset (BaseClaimset, optional): claimset instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        claimset (BaseClaimset): A BaseClaimset instance that raised the exception.

    All claimset or claim exceptions should extend ClaimsetException.
    """
    def __init__(self, message=None, token=None, claimset=None):
        super(ClaimsetException, self).__init__(message, token)
        self.claimset = claimset


class InvalidClaimsetError(ClaimsetException):
    """Raised when claimset data is not valid. Use MalformedClaimsetError
    when claimset data is defective, abnormal, or not parsable.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): Token instance that raised exception.
            Defaults to None.
        claimset (BaseClaimset, optional): claimset instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        claimset (BaseClaimset): A BaseClaimset instance that raised the exception.
    """
    pass


class MalformedClaimsetError(ClaimsetException):
    """Raised when claimset data is defective, abnormal, or not parsable.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): Token instance that raised exception.
            Defaults to None.
        claimset (BaseClaimset, optional): claimset instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        claimset (BaseClaimset): A BaseClaimset instance that raised the exception.
    """
    pass


class ClaimException(ClaimsetException):
    """Raised when a claim has a generalized exception.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): BaseToken instance that raised exception.
            Defaults to None.
        claimset (BaseClaimset, optional): BaseClaimset instance that raised exception.
            Defaults to None.
        claim (BaseClaim, optional): BaseClaim instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        claimset (BaseClaimset): A BaseClaimset instance that raised the exception.
        claim (BaseClaim): A BaseClaim instance that raised the exception.

    All claim exceptions should extend ClaimException.
    """
    def __init__(self, message=None, token=None, claimset=None, claim=None):
        super(ClaimException, self).__init__(message, token, claimset)
        self.claim = claim


class InvalidClaimError(ClaimsetException):
    """Raised when claim data is not valid. Use MalformedClaimError
    when claim data is defective, abnormal, or is not parsable.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): BaseToken instance that raised exception.
            Defaults to None.
        claimset (BaseClaimset, optional): BaseClaimset instance that raised exception.
            Defaults to None.
        claim (BaseClaim, optional): BaseClaim instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        claimset (BaseClaimset): A BaseClaimset instance that raised the exception.
        claim (BaseClaim): A BaseClaim instance that raised the exception.
    """
    pass


class MalformedClaimException(ClaimException):
    """Raised when claim data is defective, abnormal, or not parsable.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): BaseToken instance that raised exception.
            Defaults to None.
        claimset (BaseClaimset, optional): BaseClaimset instance that raised exception.
            Defaults to None.
        claim (BaseClaim, optional): BaseClaim instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        claimset (BaseClaimset): A BaseClaimset instance that raised the exception.
        claim (BaseClaim): A BaseClaim instance that raised the exception.
    """
    pass
