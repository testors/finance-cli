"""Offline replay of QueryClient's decoded HTTP-body processing.

receive() accepts text after ResponseBody.string(); receive_bytes() replays the
entity-byte path. No network, cookie storage, UI execution or retries. Optional
offline LoginInfo/UI-stage replay lives in login_state, not this parser.
"""
from dataclasses import dataclass, field

from .compat import loads, read_model
from .crypto import decrypt_text
from .errors import GiroError

SESSION_END_CODES = frozenset(('300', '301', '302'))


@dataclass(frozen=True)
class Received:
    app_success: bool
    code: str | None
    callback: str
    callback_code: str | None
    origin: str
    query: dict | None = field(default=None, repr=False)
    session_update: dict | None = field(default=None, repr=False)
    # LoginInfo.logout clears login metadata, not necessarily cookies/SEED key.
    clear_session: bool = False
    error_html: str = field(default='', repr=False)
    query_source: str = 'response'
    response_text: str | None = field(default=None, repr=False)
    issues: tuple[str, ...] = ()


def error_html(info):
    name = info.get('errorName')
    message = info.get('errorMessage')
    return (f'<b>{name}</b><br/><br/>' if name else '') + (message or '')


def _request_model(name, request_query):
    # request_query is already a typed request object, not server JSON. Do not
    # serialize it back through Gson and invent additional request validation.
    return read_model({}, name) if request_query is None else request_query


def _failure(name, code, origin, request_query=None, *, query_source='request'):
    query = _request_model(name, request_query) if query_source == 'request' else None
    info = query.get('errorInfo') if query is not None else None
    if query is not None and query.get('responseCode') in SESSION_END_CODES:
        return Received(False, code, 'disconnected_session', None, origin, query=query,
                        clear_session=True, query_source=query_source)
    return Received(False, code, 'failure', info.get('errorCode') if info is not None else code,
                    origin, query=query, error_html=error_html(info) if info is not None else '',
                    query_source=query_source)


def receive(name, status, headers, body, *, key=None, request_query=None):
    """Replay response parsing, success and callbacks for a fresh query model.

    Headers are ordered (name, value) pairs: OkHttp returns the LAST match.
    No inferred token, count, page or mandatory-field validation is added.
    request_query optionally supplies the original typed request. On an HTTP or
    decode failure the app retains that request (including its errorInfo).
    ILogin.refresh/UI side effects are handled separately, not synthesized here.
    """
    if not 200 <= status < 300 or body is None:
        code = str(status)
        return _failure(name, code, 'http', request_query)
    encrypted = None
    for header, value in headers:
        if header.lower() == 'mgiro-app-encrypt':
            encrypted = value
    try:
        text = decrypt_text(body, key) if encrypted == '1' else body
    except (GiroError, ValueError, TypeError, AttributeError):
        return _failure(name, '605', 'decrypt', request_query)
    try:
        query = read_model(loads(text), name)
    except (GiroError, ValueError, TypeError):
        return _failure(name, '605', 'model_decode', request_query)
    if query is None:
        # Assignment of the parsed null succeeds before getSessionInfo throws.
        # Unlike malformed JSON, this no longer holds the original ILogin.
        return _failure(name, '605', 'model_decode', query_source='none')
    code = query.get('responseCode')
    session = query.get('sessionInfo')
    if code in SESSION_END_CODES:
        # QueryClient routes to onDisconnectedSession and DOES NOT invoke the
        # ordinary success/failure listener (d.java:208-218).
        return Received(False, code, 'disconnected_session', None, 'response',
                        query=query, session_update=session, clear_session=True, response_text=text)
    if code == '000':
        return Received(True, code, 'success', code, 'response', query=query,
                        session_update=session, response_text=text)
    info = query.get('errorInfo')
    return Received(False, code, 'failure', info.get('errorCode') if info is not None else code,
                    'response', query=query, session_update=session,
                    error_html=error_html(info) if info is not None else '', response_text=text)


def receive_bytes(name, status, headers, body, *, key=None, request_headers=(),
                  method='POST', request_query=None, charset_resolver=None, max_decoded_bytes=None):
    """Offline response entity -> optional gzip -> HTTP charset -> SEED -> Gson.

    Does not consume unsuccessful HTTP bodies (even malformed gzip). Analysis
    limits propagate as such, not fabricated app rejection codes.
    """
    from dataclasses import replace
    from .http_body import decode_body, common_charset, GzipRuntimeError
    if not 200 <= status < 300 or body is None:
        return receive(name, status, headers, None, request_query=request_query)
    try:
        decoded = decode_body(body, headers, request_headers=request_headers, method=method,
                              status=status, charset_resolver=charset_resolver or common_charset,
                              max_decoded_bytes=max_decoded_bytes)
    except OSError:
        return _failure(name, '603', 'body_io', request_query)
    except GzipRuntimeError:
        return _failure(name, '605', 'body_decode', request_query)
    return replace(receive(name, status, decoded.headers, decoded.text, key=key,
                           request_query=request_query), issues=decoded.issues)


def transport_failure(name, *, timeout=False, request_query=None):
    """OkHttp onFailure path; unlike body-read IO, does not refresh the UI timer."""
    query = dict(_request_model(name, request_query))
    code = '601' if timeout else '603'
    # Exception messages can contain private URLs/data. They are deliberately
    # not accepted or reproduced by this offline state-replay API.
    query['errorInfo'] = {'errorCode': code, 'errorName': '예외발생', 'errorMessage': None}
    return Received(False, code, 'failure', code, 'transport_io', query=query,
                    query_source='request')
