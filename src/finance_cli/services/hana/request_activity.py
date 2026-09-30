"""Optional, context-local web session policy at the HTTP send boundary.

CLI calls have no observer or idle timeout. No request data is passed to the
observer; certificate authority requests do not extend the bank session.
"""
from contextlib import contextmanager
from contextvars import ContextVar

_observer = ContextVar('hana_request_activity', default=None)


class RequestBlocked(ValueError):
    pass


@contextmanager
def observe(callback):
    token = _observer.set(callback)
    try:
        yield
    finally:
        _observer.reset(token)


def before_request(scope='bank'):
    callback = _observer.get()
    if callback is not None:
        callback(scope)
