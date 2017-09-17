class TokenException(Exception):
    """Raised when a token has a generalized exception.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): BaseToken instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.

    All token, component, or claim exceptions should extend TokenException.
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


class ComponentException(TokenException):
    """Raised when a component has a generalized exception.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): Token instance that raised exception.
            Defaults to None.
        component (BaseComponent, optional): component instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        component (BaseComponent): A BaseComponent instance that raised the exception.

    All component or claim exceptions should extend ComponentException.
    """
    def __init__(self, message=None, token=None, component=None):
        super(ComponentException, self).__init__(message, token)
        self.component = component


class InvalidComponentError(ComponentException):
    """Raised when component data is not valid. Use MalformedComponentError
    when component data is defective, abnormal, or not parsable.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): Token instance that raised exception.
            Defaults to None.
        component (BaseComponent, optional): component instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        component (BaseComponent): A BaseComponent instance that raised the exception.
    """
    pass


class MalformedComponentError(ComponentException):
    """Raised when component data is defective, abnormal, or not parsable.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): Token instance that raised exception.
            Defaults to None.
        component (BaseComponent, optional): component instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        component (BaseComponent): A BaseComponent instance that raised the exception.
    """
    pass


class ClaimException(ComponentException):
    """Raised when a claim has a generalized exception.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): BaseToken instance that raised exception.
            Defaults to None.
        component (BaseComponent, optional): BaseComponent instance that raised exception.
            Defaults to None.
        claim (BaseClaim, optional): BaseClaim instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        component (BaseComponent): A BaseComponent instance that raised the exception.
        claim (BaseClaim): A BaseClaim instance that raised the exception.

    All claim exceptions should extend ClaimException.
    """
    def __init__(self, message=None, token=None, component=None, claim=None):
        super(ClaimException, self).__init__(message, token, component)
        self.claim = claim


class InvalidClaimError(ComponentException):
    """Raised when claim data is not valid. Use MalformedClaimError
    when claim data is defective, abnormal, or is not parsable.

    Args:
        message (str, optional): Message when exception is raised.
            Defaults to None.
        token (BaseToken, optional): BaseToken instance that raised exception.
            Defaults to None.
        component (BaseComponent, optional): BaseComponent instance that raised exception.
            Defaults to None.
        claim (BaseClaim, optional): BaseClaim instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        component (BaseComponent): A BaseComponent instance that raised the exception.
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
        component (BaseComponent, optional): BaseComponent instance that raised exception.
            Defaults to None.
        claim (BaseClaim, optional): BaseClaim instance that raised exception.
            Defaults to None.

    Attributes:
        token (BaseToken): A BaseToken instance that raised the exception.
        component (BaseComponent): A BaseComponent instance that raised the exception.
        claim (BaseClaim): A BaseClaim instance that raised the exception.
    """
    pass
