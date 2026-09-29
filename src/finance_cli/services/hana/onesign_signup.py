"""Domestic phone verification and consent before certificate issuance."""
import hashlib
import time
from . import onesign_signup_protocol as protocol
from .onesign_codec import encode
from .onesign_crypto import ProtocolError, require
REMOTE = ('authenticate', 'request-sms', 'verify-sms')
EXPECTED = {'profile':'new', 'authenticate':'profiled', 'request-sms':'authenticated', 'verify-sms':'sms_sent', 'consent':'eligible'}
NEXT = dict(zip(EXPECTED, ('profiled','authenticated','sms_sent','eligible','consented')))
def ms():
    return int(time.time()*1000)

def consent_digest(signup):
    return hashlib.sha256(encode({'customer': signup['responses']['customer'],
                            'terms_status': signup['responses']['terms-status'],
                            'terms': protocol.signup_terms(signup['responses']['customer'].get('mdtyAgrmCollYn')),
                            'marketing': protocol.marketing_body(signup['responses']['terms-status']),
                            'optional_products': False})).hexdigest()


class Signup:
    """Durable one-attempt state machine, with explicit I/O for offline tests.

    Caller holds the outer store/session locks across this whole operation.
    A crash leaves `pending` durable; no subsequent command may resume it.
    """
    def __init__(self, vault, session, now=ms):
        self.vault, self.session, self.now = vault, str(session), now

    def state(self):
        return self.vault.snapshot()['signup']

    def check(self, command):
        s = self.state()
        require(command in EXPECTED and command not in ('download', 'complete'), 'invalid_signup_command')
        require(s['session'] == self.session, 'signup_session_mismatch')
        require(s['state'] != 'halted' and not s.get('pending'), 'signup_halted_or_pending')
        require(not s.get('replacement_attempt'), 'signup_attempt_replaced')
        require(s['state'] == EXPECTED[command], 'signup_stage_out_of_order')

    def timely(self, sms=False):
        s, now = self.state(), self.now()
        if sms:
            require(0 <= now - s['sms_sent_ms'] < protocol.SMS_LIMIT_MS, 'sms_outside_180_seconds')

    def change(self, **fields):
        with self.vault.transaction() as value:
            value['signup'].update(fields)

    def execute(self, command, run_id, bank=None, *, profile_input=None, agree=None, authenticate=None,
                sms_input=None, download=None, app_hash=None, issue_new=False):
        self.check(command)
        require(self.state().get('purpose', 'download') == ('issue' if issue_new else 'download'), 'signup_purpose_mismatch')
        require(not issue_new or command not in ('download', 'complete'), 'issuance_completion_route_required')
        self.change(pending={'command': command, 'run': run_id, 'at_ms': self.now()})
        try:
            if command in REMOTE and command != 'authenticate':
                self.timely(sms=command == 'verify-sms')

            def call(name, body):
                self.timely(sms=name == 'sms-verify')
                try:
                    response = bank(name, body)
                except (ProtocolError, OSError) as exc:
                    if not protocol.ignores_request_error(name):
                        raise
                    self.change(source_handled_error={'operation': name, 'reason': str(exc) if type(exc) is ProtocolError else 'transport_error'})
                    response = {}
                require(isinstance(response, dict), 'signup_response_object_required')
                with self.vault.transaction() as value:
                    value['signup']['responses'][name] = response
                    value['signup']['last_response_ms'] = self.now()
                return response

            s = self.state()
            device = self.vault.snapshot()['profile']['device_id']
            if command == 'profile':
                p = protocol.phone_profile(profile_input())
                terms = protocol.sms_terms(p['carrier'])
                require(agree(terms, '휴대폰 본인확인 필수 약관 동의') is True, 'phone_consent_not_given')
                self.change(phone=p, sms_consent_digest=hashlib.sha256(encode(terms)).hexdigest())
            elif command == 'authenticate':
                authenticate()
                self.change(authenticated_ms=self.now(), last_response_ms=self.now())
            elif command == 'request-sms':
                p = s['phone']
                require(s['sms_consent_digest'] == hashlib.sha256(encode(protocol.sms_terms(p['carrier']))).hexdigest(), 'phone_consent_changed')
                call('clear', None)
                call('phone-pre', protocol.pre_phone_body(p, device))
                call('sms-send', protocol.sms_body(p, app_hash))
                self.change(sms_sent_ms=self.now())
            elif command == 'verify-sms':
                sms = sms_input()
                try:
                    call('sms-verify', protocol.verify_body(s['phone'], sms))
                finally:
                    del sms
                eligibility = call('eligibility', {})
                protocol.check_eligibility(eligibility)
                customer = call('customer', {'oneSignUseYn': 'Y'})
                number = protocol.check_customer(customer, s['phone'], existing_cloud=not issue_new)
                status = call('terms-status', {'reExcpNtnlYn': 'N'})
                protocol.marketing_body(status)
                with self.vault.transaction() as value:
                    value['profile']['customer_number'] = number
                    value['profile']['customer_source'] = 'phone-signup-eligibility'
            elif command == 'consent':
                terms = protocol.signup_terms(s['responses']['customer'].get('mdtyAgrmCollYn'))
                marketing = protocol.marketing_body(s['responses']['terms-status'])
                title = '가입 필수 약관 동의; 선택 상품 미신청; 마케팅 ' + ('기존 동의 유지' if marketing is None else '미동의 처리')
                require(agree(terms, title) is True, 'signup_consent_not_given')
                self.change(consent_digest=consent_digest(s))
            self.change(state=NEXT[command], pending=None)
            return {'state': NEXT[command], 'network_used': command in REMOTE, 'automatic_retry': False,
                    'transfer_enabled': False, 'normal_signed_login_verified': False}
        except BaseException as exc:
            code = str(exc) if type(exc) is ProtocolError else 'signup_operation_interrupted'
            with self.vault.transaction() as value:
                value['signup'].update(state='halted', reason=code)
                if value['profile']['enrollment']['state'] == 'pending':
                    value['profile']['enrollment']['state'] = 'halted'
            raise
