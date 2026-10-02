"""Explicit, stateful enrollment for an existing personal Giro member.

SMS and PIN requests never retry automatically. The caller supplies a persistent
client identity, recipient validation, a protection runtime and consent/inputs.
No Android identity is discovered or claimed; server acceptance of a new CLI
identity is a separate live observation. KT/certificate and new-member routes
are reported explicitly rather than passed through the existing-member path.
"""
from dataclasses import dataclass, field
from datetime import datetime
from time import monotonic

from .cert_factory import CertificateBackendLimit
from .cert_rules import CertificateRuleError
from .crypto import encode_pin
from .errors import GiroError
from .login import PreloginClient

CARRIERS = {'SKT', 'KTF', 'LGT', 'SKM', 'KTM', 'LGM'}


@dataclass(repr=False, frozen=True)
class IdentityInput:
    name: str
    birthday: str
    nation: str
    gender: str
    phone_corp: str
    phone_number: str

    def fields(self):
        # Personal SMS screen checks. Values are not inferred from the host,
        # protection token, previous login or the CLI device identifier.
        if not isinstance(self.name, str) or self.name == '':
            raise GiroError('본인확인 이름이 필요합니다.')
        if (not isinstance(self.birthday, str) or len(self.birthday) != 8
                or not self.birthday.startswith(('1', '2'))):
            raise GiroError('생년월일 8자리를 확인하세요.')
        try:
            datetime.strptime(self.birthday, '%Y%m%d')
        except ValueError:
            raise GiroError('생년월일을 확인하세요.') from None
        if self.nation not in ('0', '1') or self.gender not in ('0', '1'):
            raise GiroError('내외국인과 성별 선택이 필요합니다.')
        if self.phone_corp not in CARRIERS:
            raise GiroError('지원하는 통신사를 선택하세요.')
        if not isinstance(self.phone_number, str) or not 10 <= len(self.phone_number) <= 12:
            raise GiroError('본인확인 휴대전화번호를 확인하세요.')
        trim = ''.join(chr(i) for i in range(33))  # Java String.trim(), not Unicode strip().
        return dict(userType='0', name=self.name.strip(trim), birthday=self.birthday,
                    nation=self.nation, gender=self.gender, phoneCorp=self.phone_corp,
                    phoneNo=self.phone_number.strip(trim))


@dataclass(repr=False)
class RegistrationStep:
    stage: str
    response_endpoint: str | None = None
    response: object = None
    processing_issues: list = field(default_factory=list)
    next_action: str | None = None
    registration_response: object = None

    def report(self):
        def safe_code(value):
            return value if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 3 else None
        def decision(response):
            if response is None or response.origin != 'response':
                return 'unobserved'
            return 'success' if response.app_success else 'failure'
        return dict(stage=self.stage, response_endpoint=self.response_endpoint,
                    service_decision=decision(self.response),
                    callback=None if self.response is None else self.response.callback,
                    response_origin=None if self.response is None else self.response.origin,
                    response_code=None if self.response is None else safe_code(self.response.code),
                    callback_code=None if self.response is None else safe_code(self.response.callback_code),
                    registration_service_decision=decision(self.registration_response),
                    next_action=self.next_action, processing_issues=list(self.processing_issues),
                    automatic_retry=False, authenticated_session_created=False)


class DeviceRegistration(PreloginClient):
    def __init__(self, *, clock=monotonic, **dependencies):
        super().__init__(**dependencies)
        self.next_action = 'begin'
        self.nonce = None
        self.phone_corp = None
        self.registration_response = None
        self._clock, self._sms_available_at = clock, None

    def _run(self, allowed, send, operation):
        if not send:
            raise GiroError('기관 통신에는 명시적인 전송 승인이 필요합니다.')
        with self._lock:
            if self.next_action not in allowed:
                raise GiroError('현재 등록 단계에서는 이 요청을 실행할 수 없습니다.')
            previous_action = self.next_action
            result = RegistrationStep(previous_action)
            self.next_action = 'stopped'  # Reserve before inputs or side effects.
            try:
                operation(result)
            except CertificateRuleError:
                result.processing_issues.append('recipient_validation_failed')
            except CertificateBackendLimit:
                result.processing_issues.append('recipient_validation_incomplete')
            except GiroError:
                if result.stage in ('sms.input', 'pin.input'):
                    self.next_action = previous_action
                    result.processing_issues.append('local_input_invalid')
                else:
                    result.processing_issues.append('stage_processing_incomplete')
            except Exception:
                result.processing_issues.append('stage_processing_incomplete')
            result.next_action = self.next_action
            result.registration_response = self.registration_response
            return result

    def _call(self, result, name, fields, **options):
        result.stage, result.response_endpoint, result.response = name, name, None
        response = self._request(name, fields, **options)
        result.response = response
        if name == 'registration.pin':
            self.registration_response = response
        result.processing_issues.extend(response.issues)
        if response.clear_session:
            self.next_action = 'session_ended'
        return response.app_success and 'cookie_update_failed' not in response.issues

    @staticmethod
    def _ordinary_failure(result):
        # onDisconnectedSession never invokes the screen's failure callback.
        return result.response is not None and result.response.callback == 'failure'

    def begin(self, *, send=False):
        def operation(result):
            if not self._call(result, 'auth.server-cert', {}): return
            result.stage = 'recipient.validate'
            recipient = self.recipient.validate(result.response.query.get('serverCert'))
            result.stage = 'protection.initialize'
            self.protection.initialize_for_login()
            if not self._call(result, 'auth.device-status',
                              {'deviceUniqNo': self.device_id}, recipient_der=recipient): return
            if result.response.query.get('deviceRegYn') == 'Y':
                self.next_action = 'login_existing_registration'
                return
            if not self._call(result, 'auth.datetime', {}, recipient_der=recipient): return
            self.next_action = 'identity_and_consent'
        return self._run({'begin'}, send, operation)

    def request_sms(self, identity: IdentityInput, *, terms_accepted=False, send=False):
        if not send:
            raise GiroError('기관 통신에는 명시적인 전송 승인이 필요합니다.')
        if terms_accepted is not True:
            raise GiroError('본인확인 개인정보 약관 3종에 대한 동의가 필요합니다.')
        fields = identity.fields()
        with self._lock:
            if self._sms_available_at is not None and self._clock() < self._sms_available_at:
                raise GiroError('인증 재요청은 10초 후 가능합니다.')
            def operation(result):
                result.stage = 'codeguard.user_info'
                token = self.protection.token()  # QryUserInfo alone implements IToken.
                if not self._call(result, 'registration.user-info',
                                  {'qryType': '1', 'userType': '0'}, token=token):
                    if self._ordinary_failure(result):
                        self.next_action = 'identity_and_consent'
                    return
                self.nonce = result.response.query.get('nonce')
                self.phone_corp = identity.phone_corp
                ready = self._call(result, 'registration.sms-send', {**fields, 'nonce': self.nonce})
                if result.response is not None and result.response.callback in ('success', 'failure'):
                    self._sms_available_at = self._clock() + 10
                if ready:
                    self.nonce = result.response.query.get('nonce')
                    self.next_action = 'sms_code'
                elif self._ordinary_failure(result):
                    self.next_action = 'identity_and_consent'
            return self._run({'identity_and_consent', 'sms_code'}, True, operation)

    def verify_sms(self, *, code_provider, send=False):
        def operation(result):
            result.stage = 'sms.input'
            code = code_provider()
            if not isinstance(code, str) or len(code) != 6:
                raise GiroError('인증번호 6자리를 입력하세요.')
            if not self._call(result, 'registration.sms-verify',
                              {'smsNum': code, 'nonce': self.nonce, 'deviceUniqNo': self.device_id}):
                if self._ordinary_failure(result):
                    self.nonce = result.response.query.get('nonce')
                    # The app clears the code and stops its visual timer;
                    # another explicitly entered code is still a user action.
                    self.next_action = 'sms_code'
                return
            values = result.response.query
            self.nonce = values.get('nonce')
            member = values.get('memberStatus')
            if member == '2': self.next_action = 'member_unavailable'
            elif member in ('0', '1') and self.phone_corp in ('KTF', 'KTM'):
                self.next_action = 'carrier_certificate'
            elif member == '1': self.next_action = 'member_join'
            elif member == '0':
                self.next_action = 'existing_pin' if values.get('deviceChgYn') == 'Y' else 'new_pin'
            else: self.next_action = 'member_status_unhandled'
        return self._run({'sms_code'}, send, operation)

    def check_existing_pin(self, *, pin_provider, send=False):
        def operation(result):
            result.stage = 'pin.input'
            pin = encode_pin(pin_provider(), self.key)
            if not self._call(result, 'registration.check-user',
                              {'nonce': self.nonce, 'certType': '1', 'pin': pin}):
                if self._ordinary_failure(result):
                    self.nonce = result.response.query.get('nonce')
                    self.next_action = ('choose_other_authentication' if result.response.callback_code == '82'
                                        else 'existing_pin')
                return
            self.nonce = result.response.query.get('nonce')
            self.next_action = 'new_pin'
        return self._run({'existing_pin'}, send, operation)

    def register_pin(self, *, pin_provider, confirmation_provider, send=False):
        def operation(result):
            result.stage = 'pin.input'
            pin = encode_pin(pin_provider(), self.key)
            confirm = encode_pin(confirmation_provider(), self.key)
            if pin != confirm:
                self.next_action = 'new_pin'
                result.processing_issues.append('pin_confirmation_mismatch')
                return
            if not self._call(result, 'registration.pin', {'nonce': self.nonce,
                    'deviceUniqNo': self.device_id, 'pin': pin, 'pin1': confirm}):
                if self._ordinary_failure(result):
                    self.nonce = result.response.query.get('nonce')
                    self.next_action = 'new_pin'
                # A successful registration remains successful after cookie errors.
                if self.registration_response is not None and self.registration_response.app_success:
                    self.next_action = 'registered'
                return
            self.next_action = 'registered'
        return self._run({'new_pin'}, send, operation)
