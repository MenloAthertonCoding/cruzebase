class TokenException(Exception):
    """Raised when a token has a generalized exception.

    Args:
        message (:obj:`str`, optional): Message when exception is raised.
            Defaults to None.
        token (:obj:`BaseToken`, optional): BaseToken instance that raised exception.
            Defaults to None.

    All token, component, or claim exceptions should extend TokenException.
    """
    def __init__(self, message=None, token=None):
        super(TokenException, self).__init__(message)
        self.token = token


class MalformedTokenError(TokenException):
    """Raised when a token string is abnormal and not parsable.

    Args:
        message (:obj:`str`, optional): Message when exception is raised.
            Defaults to None.
        token (:obj:`BaseToken`, optional): BaseToken instance that raised exception.
            Defaults to None.
    """
    pass


class InvalidTokenError(TokenException):
    """Raised when a token's signature is invalid.

    Args:
        message (:obj:`str`, optional): Message when exception is raised.
            Defaults to None.
        token (:obj:`BaseToken`, optional): BaseToken instance that raised exception.
            Defaults to None.
    """
    pass


class TokenSignatureError(TokenException):
    """Raised when a token signature is not cryptographically signed.

    Args:
        message (:obj:`str`, optional): Message when exception is raised.
            Defaults to None.
        token (:obj:`BaseToken`, optional): BaseToken instance that raised exception.
            Defaults to None.
    """
    pass


class ComponentException(TokenException):
    """Raised when a component has a generalized exception.

    Args:
        message (:obj:`str`, optional): Message when exception is raised.
            Defaults to None.
        token (:obj:`BaseToken`, optional): Token instance that raised exception.
            Defaults to None.
        component (:obj:`BaseComponent`, optional): component instance that raised exception.
            Defaults to None.

    All component or claim exceptions should extend ComponentException.
    """
    def __init__(self, message=None, token=None, component=None):
        super(ComponentException, self).__init__(message, token)
        self.component = component


class InvalidComponentError(ComponentException):
    """Raised when component data is not valid. Use MalformedComponentError
    when component data is abnormal and is not parsable.

    Args:
        message (:obj:`str`, optional): Message when exception is raised.
            Defaults to None.
        token (:obj:`BaseToken`, optional): Token instance that raised exception.
            Defaults to None.
        component (:obj:`BaseComponent`, optional): component instance that raised exception.
            Defaults to None.
    """
    pass


class MalformedComponentError(ComponentException):
    """Raised when component data is abnormal and not parsable.

    Args:
        message (:obj:`str`, optional): Message when exception is raised.
            Defaults to None.
        token (:obj:`BaseToken`, optional): Token instance that raised exception.
            Defaults to None.
        component (:obj:`BaseComponent`, optional): component instance that raised exception.
            Defaults to None.
    """
    pass




class ClaimException(ComponentException):
    """Raised when a claim has a generalized exception.

    Args:
        message (:obj:`str`, optional): Message when exception is raised.
            Defaults to None.
        token (:obj:`BaseToken`, optional): BaseToken instance that raised exception.
            Defaults to None.
        component (:obj:`BaseComponent`, optional): BaseComponent instance that raised exception.
            Defaults to None.
        claim (:obj:`BaseClaim`, optional): BaseClaim instance that raised exception.
            Defaults to None.

    All claim exceptions should extend ClaimException.
    """
    def __init__(self, message=None, token=None, component=None, claim=None):
        super(ClaimException, self).__init__(message, token, component)
        self.claim = claim


class InvalidClaimError(ComponentException):
    """Raised when claim data is not valid. Use MalformedClaimError
    when claim data is abnormal and is not parsable.

    Args:
        message (:obj:`str`, optional): Message when exception is raised.
            Defaults to None.
        token (:obj:`BaseToken`, optional): BaseToken instance that raised exception.
            Defaults to None.
        component (:obj:`BaseComponent`, optional): BaseComponent instance that raised exception.
            Defaults to None.
        claim (:obj:`BaseClaim`, optional): BaseClaim instance that raised exception.
            Defaults to None.
    """
    pass


class MalformedClaimException(ClaimException):
    """Raised when claim data is abnormal and not parsable.

    Args:
        message (:obj:`str`, optional): Message when exception is raised.
            Defaults to None.
        token (:obj:`BaseToken`, optional): BaseToken instance that raised exception.
            Defaults to None.
        component (:obj:`BaseComponent`, optional): BaseComponent instance that raised exception.
            Defaults to None.
        claim (:obj:`BaseClaim`, optional): BaseClaim instance that raised exception.
            Defaults to None.
    """
    pass
