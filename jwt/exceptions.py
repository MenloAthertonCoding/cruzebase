class TokenException(Exception):
    def __init__(self, message, token=None):
        super(TokenException, self).__init__(message)

        self.token = token


class TokenMalformedException(TokenException):
    def __init__(self, message, token=None):
        super(TokenMalformedException, self).__init__(message, token)


class InvalidTokenException(TokenException):
    def __init__(self, message, token=None):
        super(InvalidTokenException, self).__init__(message, token)


class ComponentException(TokenException):
    def __init__(self, message, token=None, component=None):
        super(ComponentException, self).__init__(message, token)

        self.component = component


class ClaimException(ComponentException):
    def __init__(self, message, token=None, component=None, claim=None):
        super(ClaimException, self).__init__(message, token)

        self.claim = claim
