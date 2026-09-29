class ProtocolError(ValueError):
    """A local protocol condition, never an invented server result."""


def require(condition, message):
    if not condition:
        raise ProtocolError(message)
