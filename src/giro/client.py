"""Authenticated service transport. Login/bootstrap is a separate prerequisite.

The caller supplies the session established by a successful login, including
its cookie jar and last envelope's SEED key. No device identity, security token
or authenticated state is inferred from host information. Secrets stay in RAM.
"""
from dataclasses import dataclass, field, replace
from email.message import Message
import http.client
from http.cookiejar import CookieJar
import socket
import ssl
from threading import RLock
from time import monotonic
from urllib.request import Request

from .compat import read_model
from .crypto import encrypt_text
from .errors import GiroError
from .protocol import BASE_URL, build_query, encrypted_form, endpoint
from .response import Received, receive_bytes, transport_failure


@dataclass(repr=False)
class AuthenticatedSession:
    device_id: str
    key: bytes
    cookies: CookieJar
    user_agent: str
    login_type: str
    info: dict
    active: bool = True
    lock: RLock = field(default_factory=RLock)

    @classmethod
    def from_login(cls, login: Received, *, device_id, key, cookies, user_agent, login_type):
        """Accept an observed login result, never an imported 'logged_in' flag."""
        if login.origin != 'response' or not login.app_success or login.code != '000':
            raise GiroError('성공한 지로 로그인 응답이 필요합니다.')
        if not device_id or not isinstance(key, bytes) or len(key) != 16:
            raise GiroError('로그인에 사용한 기기 식별자와 SEED 세션 키가 필요합니다.')
        if not isinstance(cookies, CookieJar) or not user_agent or any(c in user_agent for c in '\r\n'):
            raise GiroError('로그인에 사용한 쿠키 저장소와 User-Agent가 필요합니다.')
        return cls(device_id, key, cookies, user_agent, login_type, dict(login.session_update or {}))


@dataclass(repr=False)
class WireResponse:
    status: int
    headers: list
    body: bytes

    def info(self):
        headers = Message()
        for key, value in self.headers:
            headers[key] = value
        return headers


def _post(path, body, headers):
    """One verified HTTPS request to the fixed service. No redirect or retry."""
    connection = http.client.HTTPSConnection('m.giro.or.kr', timeout=30,
                                             context=ssl.create_default_context())
    try:
        connection.request('POST', path, body=body, headers=headers)
        response = connection.getresponse()
        return WireResponse(response.status, response.getheaders(), response.read())
    finally:
        try:
            connection.close()
        except OSError:
            pass  # Closing an already-read response cannot erase its verdict.


class AuthenticatedClient:
    def __init__(self, session: AuthenticatedSession):
        self.session = session
        self.events = []

    def _record(self, name, started, status, result):
        try:
            code = result.code
            safe_code = code if isinstance(code, str) and code.isascii() and code.isdigit() and len(code) <= 3 else None
            self.events.append({'endpoint': name, 'http_status': status,
                                'response_code': safe_code, 'origin': result.origin,
                                'callback': result.callback, 'app_success': result.app_success,
                                'elapsed_ms': round((monotonic() - started) * 1000),
                                'processing_issues': list(result.issues)})
        except Exception:
            return replace(result, issues=(*result.issues, 'observation_failed'))
        return result

    def require_active(self):
        if not self.session.active:
            raise GiroError('지로 로그인이 필요합니다. 자동으로 재로그인하지 않습니다.')

    def query(self, name, fields, *, send=False):
        """Read on the existing session; datetime also uses ENCRYPT after login."""
        allowed = {'national.list', 'national.detail', 'accounts.payable',
                   'accounts.registered', 'auth.datetime', 'receipts.list', 'receipts.detail'}
        if name not in allowed:
            raise GiroError('인증된 조회 경로에서 지원하지 않는 요청입니다.')
        if not send:
            raise GiroError('기관 통신에는 명시적인 전송 승인이 필요합니다.')
        with self.session.lock:
            self.require_active()
            query = read_model(fields, name)
            body = encrypted_form(encrypt_text(build_query(name, query,
                device_id=self.session.device_id), self.session.key))
            return self._exchange(name, body, query)

    def _exchange(self, name, body, query=None):
        """Caller holds the session lock; payment caller also owns a reservation."""
        self.require_active()
        started = monotonic()
        path = endpoint(name).path
        request = Request(BASE_URL + path, data=body, method='POST', headers={
            'User-Agent': self.session.user_agent,
            'Content-Type': 'application/x-www-form-urlencoded', 'Accept-Encoding': 'gzip'})
        self.session.cookies.add_cookie_header(request)
        headers = dict(request.header_items())
        try:
            wire = _post(path, body, headers)
        except (socket.timeout, TimeoutError):
            return self._record(name, started, None, transport_failure(name, timeout=True, request_query=query))
        except (OSError, http.client.HTTPException):
            return self._record(name, started, None, transport_failure(name, request_query=query))
        # Cookie bookkeeping is client processing, never the payment verdict.
        cookie_issue = False
        try:
            self.session.cookies.extract_cookies(wire, request)
        except Exception:
            self.session.active = False
            cookie_issue = True
        result = receive_bytes(name, wire.status, wire.headers, wire.body,
                               key=self.session.key, request_headers=list(headers.items()),
                               request_query=query)
        if cookie_issue:
            result = replace(result, issues=(*result.issues, 'cookie_update_failed'))
        if result.session_update is not None:
            self.session.info = result.session_update
        if result.clear_session:
            self.session.active = False
            self.session.info = {}
        return self._record(name, started, wire.status, result)
