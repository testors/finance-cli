"""PIN login coordinator with explicit recipient and protection dependencies.

No default protection runtime or device identity exists. CLI/web must keep live
login unavailable until those dependencies are implemented. This coordinator
connects real service transport, mandatory recipient rules, key rotation and
login state to the existing authenticated query/payment client. Secrets remain
in memory; a coordinator performs at most one attempt and never retries.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from threading import RLock
from time import monotonic

from . import client
from .cert_acquisition import parse_certificate
from .cert_ctl import DEFAULT_CTL_DISTRIBUTION_POINT
from .cert_factory import CertificateBackendLimit
from .cert_pipeline import build_and_validate_steps
from .cert_rules import CertificateRuleError
from .cms import envelop_query
from .compat import loads, omit_null_fields, read_model, string_value
from .crypto import encode_pin, encrypt_text
from .errors import GiroError
from .login_state import LoginState, replay
from .protocol import APP_VERSION, _form_encode, build_query, encrypted_form
from .public_material_io import PublicMaterialExecutor


class ProtectionRuntime(ABC):
    """Persistent normal app protection initialization and CodeGuard callbacks.

    No SDK-success boolean, imported token file, host-ID fallback or clean
    observation substitute. PythonProtectionRuntime composes explicit inputs;
    its declared memory platform does not establish real-device compatibility.
    A token return corresponds to CgManager's callback, including its null/error
    forms; the coordinator does not invent a token-format acceptance gate.
    """
    @abstractmethod
    def initialize(self):
        raise NotImplementedError

    def initialize_for_login(self):
        """Complete the app's update notification before its registration query.

        Synchronous providers complete that notification in initialize().
        Asynchronous providers must override this without joining unrelated
        ZIP work or interpreting the notification as protection success.
        """
        return self.initialize()

    @abstractmethod
    def token(self):
        raise NotImplementedError


@dataclass(repr=False)
class RecipientContext:
    """Explicit trusted anchors and public stores, separate from received certs.

    Validation executes the mandatory discovery/path/KU/EKU/CRL pipeline. An
    unsupported CTL mutation or missing IO remains an exception, never trust.
    This does not discover the installation's trust configuration by itself.
    """
    anchors: tuple
    stores: tuple
    locale_language: str
    cache: object = None
    ldap: object = None

    @classmethod
    def from_public_cache(cls, cache, *, locale_language, stores=(), ldap=None):
        """Load pinned roots without network. Caller owns the open public cache.

        Extra issuer/CRL stores are explicit; otherwise the validation pipeline
        discovers them through this cache and the separately enabled LDAP IO.
        """
        from .recipient_trust import load_anchors
        return cls(load_anchors(cache), tuple(stores), locale_language, cache, ldap)

    def validate(self, text):
        if not isinstance(text, str):
            raise GiroError('수신자 인증서 자료를 확인하지 못했습니다.')
        target = parse_certificate(text.encode('utf-8', errors='replace'))
        executor = PublicMaterialExecutor(stores=self.stores, cache=self.cache, ldap=self.ldap)
        executor.run(build_and_validate_steps(target, anchors=self.anchors,
            store_count=len(self.stores), at=datetime.now(timezone.utc),
            locale_language=self.locale_language,
            ctl_distribution_point=DEFAULT_CTL_DISTRIBUTION_POINT, save_crl=True))
        return target.data


def _token_response(token):
    """QueryClient's Gson Map<String,String>, including duplicate-map rules."""
    if token is None:
        return None
    if not isinstance(token, str):
        raise GiroError('CodeGuard callback 문자열을 확인하지 못했습니다.')
    value = loads(token)
    if isinstance(value, dict):
        pairs = value.pairs if hasattr(value, 'pairs') else value.items()
    elif isinstance(value, list):
        pairs = value
    else:
        raise GiroError('CodeGuard callback 객체를 해석하지 못했습니다.')
    result = {}
    for pair in pairs:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise GiroError('CodeGuard callback 항목을 해석하지 못했습니다.')
        key, item = (string_value(part) for part in pair)
        if key is None:
            raise GiroError('CodeGuard callback 항목의 이름이 없습니다.')
        if result.get(key) is not None:
            raise GiroError('CodeGuard callback에 중복 항목이 있습니다.')
        result[key] = item
    return result.get('CODE_RESPONSE')


@dataclass(repr=False)
class LoginAttempt:
    stage: str
    response: object = None
    session: object = None
    processing_issues: list = field(default_factory=list)
    next_action: str | None = None

    def report(self):
        login = self.response if self.stage == 'auth.pin' else None
        decision = ('unobserved' if login is None or login.origin != 'response' else
                    'success' if login.app_success else 'failure')
        return {'stage': self.stage, 'login_app_success': None if login is None else login.app_success,
                'login_service_decision': decision,
                'session_ready': self.session is not None and self.session.active,
                'automatic_retry': False, 'processing_issues': list(self.processing_issues),
                'next_action': self.next_action}


class PinLogin:
    def __init__(self, *, device_id, user_agent, recipient: RecipientContext,
                 protection: ProtectionRuntime):
        if not isinstance(device_id, str):
            raise GiroError('로그인에 사용할 기기 식별자가 필요합니다.')
        if not isinstance(user_agent, str) or not user_agent or any(c in user_agent for c in '\r\n'):
            raise GiroError('업무 요청에 사용할 User-Agent가 필요합니다.')
        if not isinstance(recipient, RecipientContext) or not isinstance(protection, ProtectionRuntime):
            raise GiroError('수신자 검증과 정상 보호 모듈의 구현이 필요합니다.')
        self.device_id, self.user_agent = device_id, user_agent
        self.recipient, self.protection = recipient, protection
        self.cookies, self.key = CookieJar(), None
        self.state, self.events = LoginState(), []
        self._lock, self._used = RLock(), False

    def _request(self, name, fields, *, recipient_der=None, token=None):
        query = read_model(fields, name)
        if token is not None:
            query['CODE_RESPONSE'] = _token_response(token)
        plain = build_query(name, query, device_id=self.device_id)
        if name == 'auth.server-cert':
            values = omit_null_fields({**query, 'appVersion': APP_VERSION, 'deviceId': self.device_id})
            body = '&'.join(_form_encode(k) + '=' + _form_encode(string_value(v))
                            for k, v in values.items()).encode('ascii')
        elif recipient_der is not None:
            envelope = envelop_query(plain.encode('euc-kr', errors='replace'), recipient_der)
            self.key = envelope.session_key  # Installed before the socket write, also on failure.
            body = encrypted_form(envelope.data)
        else:
            body = encrypted_form(encrypt_text(plain, self.key), token=token)
        started = monotonic()
        status, received = client.exchange(name, body, key=self.key,
            cookies=None if name == 'auth.server-cert' else self.cookies,
            user_agent=self.user_agent, query=query)
        # Preserve the received verdict even when diagnostics or UI replay fail.
        received = client.record(self.events, name, started, status, received)
        return received

    def login(self, *, pin_provider, send=False):
        if not send:
            raise GiroError('기관 통신에는 명시적인 전송 승인이 필요합니다.')
        with self._lock:
            if self._used:
                raise GiroError('이미 사용한 로그인 시도입니다. 자동으로 재시도하지 않습니다.')
            self._used = True
            attempt = LoginAttempt('auth.server-cert')
            try:
                attempt.response = self._request('auth.server-cert', {})
                if not self._continue(attempt):
                    return attempt
                attempt.stage = 'recipient.validate'
                recipient_der = self.recipient.validate(attempt.response.query.get('serverCert'))
                attempt.stage = 'protection.initialize'
                self.protection.initialize_for_login()
                for name, fields in (
                    ('auth.device-status', {'deviceUniqNo': self.device_id}),
                    ('auth.datetime', {}),
                ):
                    attempt.stage = name
                    attempt.response = self._request(name, fields, recipient_der=recipient_der)
                    if not self._continue(attempt):
                        return attempt
                    observed = replay(name, attempt.response, self.state)
                    self.state = observed.state
                    if name == 'auth.device-status' and not self.state.values['isDeviceReg']:
                        # Normal app entry routes to SMS identity verification
                        # before a login screen. This is not a service failure,
                        # nor permission to register/change a device here.
                        attempt.stage = 'device.registration'
                        attempt.next_action = 'sms_identity_verification'
                        return attempt
                attempt.stage = 'pin.input'
                cipher = encode_pin(pin_provider(), self.key)
                # The first callback is discarded by LoginPinPresenter, but
                # its runtime/cookie state must survive the second token call.
                attempt.stage = 'codeguard.presenter'
                self.protection.token()
                attempt.stage = 'codeguard.query'
                token = self.protection.token()
                attempt.stage = 'auth.pin'
                attempt.response = None
                attempt.response = self._request('auth.pin',
                    {'deviceUniqNo': self.device_id, 'pin': cipher}, token=token)
                observed = replay('auth.pin', attempt.response, self.state)
                self.state = observed.state
                if not self._continue(attempt):
                    return attempt
                if not self.state.is_login:
                    attempt.processing_issues.append('login_state_incomplete')
                    return attempt
                attempt.session = client.AuthenticatedSession.from_login(attempt.response,
                    device_id=self.device_id, key=self.key, cookies=self.cookies,
                    user_agent=self.user_agent, login_type='PIN')
                return attempt
            except CertificateRuleError:
                attempt.processing_issues.append('recipient_validation_failed')
                return attempt
            except CertificateBackendLimit:
                attempt.processing_issues.append('recipient_validation_incomplete')
                return attempt
            except Exception:
                # A local/provider error is not a server rejection. No raw
                # exception, credential, token or response is emitted here.
                attempt.processing_issues.append('stage_processing_incomplete')
                return attempt

    @staticmethod
    def _continue(attempt):
        attempt.processing_issues.extend(attempt.response.issues)
        return attempt.response.app_success and 'cookie_update_failed' not in attempt.response.issues
