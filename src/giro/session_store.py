"""Encrypted local session state with a private, client-owned storage key.

The key and ciphertext both require private filesystem permissions. This does
not protect against an attacker who controls the user's account. PINs and
protection tokens are never persisted. Restoring a session does not assert
current server validity or log in again.
"""
import base64
from contextlib import contextmanager
from http.cookiejar import Cookie, CookieJar
import json
from pathlib import Path
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from finance_cli.core import storage
from finance_cli.core.paths import data_home

from .client import AuthenticatedSession
from .errors import GiroError


FORMAT = 'finance.giro.session.v1'
_COOKIE_FIELDS = ('version', 'name', 'value', 'port', 'port_specified', 'domain', 'domain_specified',
    'domain_initial_dot', 'path', 'path_specified', 'secure', 'expires', 'discard', 'comment',
    'comment_url', 'rfc2109')


class SessionAccessError(GiroError):
    """The exclusive session store could not be entered; no auth was sent."""


def _b64(value): return base64.b64encode(value).decode('ascii')
def _bytes(value): return base64.b64decode(value, validate=True)


class SessionStore:
    def __init__(self, root=None):
        self.root = Path(root) if root is not None else data_home()/'giro'

    def _key(self, *, create):
        path = self.root/'session.key'
        try:
            value = storage.read(path, limit=32)
        except FileNotFoundError:
            if not create or (self.root/'session.json').exists(): raise
            value = secrets.token_bytes(32)
            storage.write_new(path, value)
        if len(value) != 32: raise ValueError('invalid_session_storage_key')
        return value

    def _save(self, session):
        if not isinstance(session, AuthenticatedSession): raise ValueError('authenticated_session_required')
        cookies = [{**{name: getattr(c, name) for name in _COOKIE_FIELDS}, 'rest': dict(c._rest)}
                   for c in session.cookies]
        payload = dict(device_id=session.device_id, key=_b64(session.key), cookies=cookies,
            user_agent=session.user_agent, login_type=session.login_type, info=session.info, active=session.active)
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(self._key(create=True)).encrypt(nonce, json.dumps(payload, ensure_ascii=False).encode(), FORMAT.encode())
        storage.atomic_json(self.root/'session.json', dict(format=FORMAT, nonce=_b64(nonce), sealed=_b64(encrypted)))

    def save(self, session):
        try:
            with self.replacement() as save:
                save(session)
        except Exception:
            raise GiroError('로그인 결과의 세션 저장을 완료하지 못했습니다.') from None

    @contextmanager
    def replacement(self):
        """Exclude queries and other logins before authentication starts.

        The callback saves the new session under the already acquired lock.
        An unsuccessful login leaves the existing encrypted file untouched.
        No process-global reentrancy exemption: another thread using this
        same store must also be excluded.
        """
        try:
            root = storage.directory(self.root)
            lock = storage.lock(root/'session.lock')
            lock.__enter__()
        except Exception:
            raise SessionAccessError('지로 세션을 사용 중이거나 저장소를 열 수 없습니다.') from None
        try:
            def save(session):
                with session.lock:
                    self._save(session)
            yield save
        finally:
            lock.__exit__(None, None, None)

    def _load(self):
        document = storage.read_json(self.root/'session.json')
        if document['format'] != FORMAT: raise ValueError('unsupported_session_format')
        payload = json.loads(AESGCM(self._key(create=False)).decrypt(
            _bytes(document['nonce']), _bytes(document['sealed']), FORMAT.encode()))
        key = _bytes(payload['key'])
        if (len(key) != 16 or type(payload['device_id']) is not str
                or type(payload['active']) is not bool or type(payload['info']) is not dict
                or payload['login_type'] != 'PIN' or type(payload['user_agent']) is not str
                or not payload['user_agent'] or any(c in payload['user_agent'] for c in '\r\n')):
            raise ValueError('invalid_session_state')
        cookies = CookieJar()
        for value in payload['cookies']: cookies.set_cookie(Cookie(**value))
        return AuthenticatedSession(payload['device_id'], key, cookies, payload['user_agent'],
                                    payload['login_type'], payload['info'], payload['active'])

    @contextmanager
    def use(self):
        """Hold one session across a command, persist expiry even on exceptions.

        Save failure is returned as a separate issue and cannot replace a
        response already observed by the caller. No network/retry is performed.
        """
        try:
            root = storage.directory(self.root)
            lock = storage.lock(root/'session.lock')
            lock.__enter__()
        except Exception:
            raise GiroError('지로 세션을 사용 중이거나 저장소를 열 수 없습니다.') from None
        try:
            try: session = self._load()
            except Exception:
                raise GiroError('저장된 지로 세션을 열 수 없습니다. 로그인 상태를 확인하세요.') from None
            issues = []
            try:
                yield session, issues
            finally:
                try: self._save(session)
                except Exception: issues.append('session_save_incomplete')
        finally:
            lock.__exit__(None, None, None)
