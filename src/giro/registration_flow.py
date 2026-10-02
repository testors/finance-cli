"""One explicit enrollment attempt with a persistent, honestly labeled CLI ID.

Providers own terminal/UI input. No platform identity or runtime is inferred.
The durable reservation prevents a restart from silently repeating enrollment;
source-compatible manual retries remain available on DeviceRegistration itself.
"""
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import secrets

from finance_cli.core import storage
from finance_cli.core.paths import data_home

from .errors import GiroError


TERMS = (
    {'name': '개인정보 수집·이용', 'provisionType': '3'},
    {'name': '개인정보 제3자 제공', 'provisionType': '4'},
    {'name': '고유식별정보 처리', 'provisionType': '5'},
)
TERMS_URL = 'https://m.giro.or.kr/girohelp/guide/mobileProvision.m'


def registration_plan():
    return dict(offline=True, network_used=False, live_registration_tested=False,
        implementation='standalone Python CLI enrollment and login with prepared inputs',
        scope='existing personal member, SKT/SKM/LGT/LGM, existing PIN if deviceChgYn=Y',
        identity_source='persistent CLI-generated identifier; not an observed Android ID',
        terms={'url': TERMS_URL, 'method': 'POST', 'items': list(TERMS)},
        sequence=['auth.server-cert', 'recipient.validate', 'protection.initialize',
            'auth.device-status', 'auth.datetime', 'codeguard.token', 'registration.user-info',
            'registration.sms-send', 'registration.sms-verify',
            'registration.check-user if deviceChgYn=Y', 'registration.pin',
            'auth.datetime', 'codeguard.token twice', 'auth.pin', 'encrypted session save'],
        max_business_requests=10, max_codeguard_requests=7,
        retries=0, login=True, payment=False, automatic_alert_number_change=False,
        required_inputs=['current recipient trust/CRLs', 'private prepared protection profile',
            'three reviewed consent terms', 'personal identity and own phone',
            'SMS code', 'existing six-digit login PIN when required', 'new six-digit PIN twice'],
        remaining_live_questions=['CLI ID acceptance', 'existing phone registration effect',
            'SMS/identity acceptance', 'PIN registration acceptance'],
        default_runtime_available=True)


class EnrollmentStore:
    def __init__(self, root=None):
        self.root = Path(root) if root is not None else data_home() / 'giro' / 'enrollment'

    def identity(self):
        """Persist before any request; never replace an existing or corrupt ID."""
        root = storage.directory(self.root)
        path = root / 'identity.json'
        try:
            document = json.loads(storage.read(path, limit=4096))
        except FileNotFoundError:
            document = dict(schema=1, source='cli-generated', device_id=secrets.token_hex(8))
            try:
                storage.write_new(path, (json.dumps(document) + '\n').encode())
            except FileExistsError:
                document = json.loads(storage.read(path, limit=4096))
        if (not isinstance(document, dict) or document.get('schema') != 1
                or document.get('source') != 'cli-generated'
                or not isinstance(document.get('device_id'), str)
                or not re.fullmatch('[0-9a-f]{16}', document['device_id'])):
            raise GiroError('CLI 기기 식별자 기록을 확인할 수 없습니다. 자동으로 새로 만들지 않습니다.')
        return document['device_id']

    def reserve(self):
        path = storage.directory(self.root) / 'attempt.json'
        try:
            storage.write_new(path, b'{"state":"reserved","registration_service_decision":"unobserved"}\n')
        except FileExistsError:
            raise GiroError('이미 기기 등록을 시도한 기록이 있습니다. 기존 결과를 확인하세요.') from None
        return path

    def finish(self, path, report):
        storage.atomic_json(path, {'state': 'finished', **report})


@dataclass(repr=False)
class EnrollmentAttempt:
    steps: list = field(default_factory=list)
    events: list = field(default_factory=list)
    processing_issues: list = field(default_factory=list)
    next_action: str = 'not_started'
    registration_service_decision: str = 'unobserved'
    login_attempt: object = None

    @property
    def session(self):
        return None if self.login_attempt is None else self.login_attempt.session

    def report(self):
        return dict(steps=[step.report() for step in self.steps],
            events=list(self.events),
            processing_issues=list(self.processing_issues), next_action=self.next_action,
            registration_service_decision=self.registration_service_decision,
            identity_source='cli-generated', automatic_retry=False,
            authenticated_session_created=self.session is not None,
            login=None if self.login_attempt is None else self.login_attempt.report())


def enroll_once(*, client_factory, consent_provider, identity_provider, sms_provider,
                existing_pin_provider, new_pin_provider, confirmation_provider,
                store=None, login_pin_provider=None, send=False):
    """Factory(device_id) -> DeviceRegistration; providers are called once at most.

The caller displays the original terms before consent_provider returns True.
An explicit login_pin_provider continues from completion to the PIN screen.
No automatic certificate fallback, member join, restart or payment.
"""
    if not send:
        raise GiroError('기관 통신에는 명시적인 전송 승인이 필요합니다.')
    store = store if store is not None else EnrollmentStore()
    result, reservation, client = EnrollmentAttempt(), None, None
    try:
        device_id = store.identity()
        reservation = store.reserve()
        client = client_factory(device_id)
        def record(step):
            result.steps.append(step)
            result.next_action = step.next_action
            result.registration_service_decision = step.report()['registration_service_decision']
        record(client.begin(send=True))
        if result.next_action == 'identity_and_consent':
            if consent_provider() is not True:
                result.next_action = 'consent_not_given'
            else:
                record(client.request_sms(identity_provider(), terms_accepted=True, send=True))
        if result.next_action == 'sms_code':
            record(client.verify_sms(code_provider=sms_provider, send=True))
        if result.next_action == 'existing_pin':
            record(client.check_existing_pin(pin_provider=existing_pin_provider, send=True))
        if result.next_action == 'new_pin':
            record(client.register_pin(pin_provider=new_pin_provider,
                                       confirmation_provider=confirmation_provider, send=True))
        if login_pin_provider is not None and result.next_action in ('registered', 'login_existing_registration'):
            # Preserve the enrollment verdict before a later login can fail,
            # time out or be interrupted. A diagnostic write never changes it.
            try:
                store.finish(reservation, result.report())
            except Exception:
                result.processing_issues.append('enrollment_receipt_save_incomplete')
            result.login_attempt = client.login(pin_provider=login_pin_provider, send=True)
            result.next_action = client.next_action
    except (Exception, KeyboardInterrupt):
        result.processing_issues.append('enrollment_processing_incomplete')
    if client is not None:
        try:
            result.events = list(client.events)
        except Exception:
            result.processing_issues.append('enrollment_observation_incomplete')
    if reservation is not None:
        try:
            store.finish(reservation, result.report())
        except Exception:
            if 'enrollment_receipt_save_incomplete' not in result.processing_issues:
                result.processing_issues.append('enrollment_receipt_save_incomplete')
    return result
