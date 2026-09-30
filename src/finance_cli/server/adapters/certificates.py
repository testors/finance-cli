"""Certificate setup and one-shot issuance stages. Private inputs travel only in the worker pipe."""
import base64
import hashlib
import json
import re

from finance_cli.core.paths import data_home
from finance_cli.credentials import id_cards
from finance_cli.credentials.registry import Registry, name as credential_name
from finance_cli.services.hana import onesign, onesign_signup_protocol as signup, store
from finance_cli.services.hana.onesign_state import State
from finance_cli.services.hana.onesign_crypto import ProtocolError

from .base import Adapter, InputError, Step, StepResult, Stop, dict_input, pick
from .certificate_diagnostics import identity_diagnostics
from .hana import safe_code, verdict

FILE_LIMIT = 2 * 1024 * 1024
STAGES = (*onesign.PHONE, 'begin-id', 'prepare-id', *onesign.ISSUE[1:])
LABELS = dict(zip(STAGES, ('휴대폰 정보·약관', '앱 인증', 'SMS 요청', 'SMS 확인', '가입 약관',
                          '신분증 확인 시작', '신분증 입력', '신분증 확인', '본인 계좌 확인', '인증서 발급', '가입 완료')))
FIELDS = {'profile': ('phone_profile', 'agreement'), 'verify-sms': ('sms',), 'consent': ('agreement',),
          'prepare-id': ('identity_capture',), 'account': ('account_number', 'account_password'),
          'issue': ('new_pin', 'new_pin_confirmation', 'issue_confirmation')}


def terms_digest(terms):
    return hashlib.sha256(json.dumps(terms, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def decode_file(value, limit):
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise Stop('invalid_certificate_file') from None
    if not raw or len(raw) > limit:
        raise Stop('certificate_file_size_not_accepted')
    return raw


def identity_jpeg(value):
    """Prepare the user's JPEG in memory; never write an unencrypted photo."""
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise Stop('identity_jpeg_invalid') from None
    try:
        return id_cards.prepare_jpeg(raw)
    except ValueError as error:
        raise Stop(safe_code(error, 'identity_jpeg_invalid')) from None


def identity_capture(secret):
    """A directly entered card: reviewed text and photo, confirmed as the user's own."""
    try:
        capture = json.loads(secret)
        if not isinstance(capture, dict) or set(capture) != {'kind', 'fields', 'image', 'confirmation'}:
            raise ValueError()
    except (ValueError, TypeError):
        raise Stop('invalid_identity_capture') from None
    if capture['confirmation'] != '본인 신분증':
        raise Stop('identity_not_confirmed')
    try:
        fields = id_cards.check_fields(capture['kind'], capture['fields'])
    except ValueError as error:
        raise Stop(safe_code(error, 'invalid_identity_capture')) from None
    return {'kind': capture['kind'], 'fields': fields, 'jpeg': identity_jpeg(capture['image'])}


def saved_identity(alias, secret):
    """A card from the ID card store, opened with its passphrase and confirmed as still valid."""
    try:
        choice = json.loads(secret)
        if not isinstance(choice, dict) or set(choice) != {'passphrase', 'confirmation'} \
                or not isinstance(choice['passphrase'], str):
            raise ValueError()
    except (ValueError, TypeError):
        raise Stop('invalid_identity_capture') from None
    if choice['confirmation'] != '본인 신분증':
        raise Stop('identity_not_confirmed')
    try:
        card = id_cards.IdCards().load(alias, choice['passphrase'])
    except (ValueError, OSError) as error:
        raise Stop(safe_code(error, 'id_card_not_opened')) from None
    return {'kind': card['kind'], 'fields': card['fields'], 'jpeg': card['jpeg']}


def next_stage(value):
    phone, issuance = value['signup'], value['issuance']
    if value.get('halted') or phone.get('pending') or phone['state'] == 'halted' or issuance.get('pending') \
            or issuance['state'] == 'halted':
        return None
    stage = dict(zip(('new', 'profiled', 'authenticated', 'sms_sent', 'eligible'), onesign.PHONE)).get(phone['state'])
    if stage:
        return stage
    if phone['state'] != 'consented':
        return None
    return {'new': 'begin-id', 'id_ready': 'identity' if issuance.get('capture') else 'prepare-id',
            'identity_verified': 'account', 'account_verified': 'issue', 'issued': 'complete'}.get(issuance['state'])


def progress(value):
    stage = next_stage(value)
    terms = signup.signup_terms(value['signup']['responses']['customer'].get('mdtyAgrmCollYn')) \
        if stage == 'consent' else []
    return {'next_stage': stage, 'stage_title': LABELS.get(stage),
            'signup_state': value['signup']['state'], 'issuance_state': value['issuance']['state'],
            'certificate_issued': value['issuance'].get('certificate_issued', False),
            'ready': value['profile']['enrollment']['state'] == 'ready',
            'terms': terms, 'terms_digest': terms_digest(terms) if terms else None,
            'automatic_retry': False}


class CertificateImport(Adapter):
    name = 'cert.joint.import'
    title = '공동인증서 가져오기'
    area = 'common'
    requires_login = False
    secret_limits = {'certificate_file': 4 * FILE_LIMIT // 3 + 4, 'private_key_file': 4 * FILE_LIMIT // 3 + 4}
    steps = {'run': Step('run', secrets=('certificate_password', 'certificate_file', 'private_key_file'), sends=False)}

    def validate(self, value, login=None):
        data = dict_input(value, ('name', 'format', 'compatibility', 'pfx_index'), ('name', 'format'))
        credential_name(data['name'])
        if data['format'] not in ('pfx', 'npki') or data.get('compatibility', 'hana') not in ('hana', 'hometax'):
            raise InputError('invalid_certificate_format')
        index = data.get('pfx_index')
        if index is not None and (type(index) is not int or index < 0 or data['format'] != 'pfx'):
            raise InputError('invalid_pfx_index')
        return data

    def run(self, ctx, step):
        data = ctx.input
        raw = decode_file(ctx.secrets['certificate_file'], FILE_LIMIT)
        password = ctx.secrets['certificate_password'].encode('utf-8')
        try:
            if data['format'] == 'pfx':
                if ctx.secrets['private_key_file'] != 'unused':
                    raise Stop('private_key_not_accepted')
                result = Registry().import_pfx(data['name'], raw, password, index=data.get('pfx_index'))
            else:
                encrypted = decode_file(ctx.secrets['private_key_file'], FILE_LIMIT)
                result = Registry().import_npki(data['name'], raw, encrypted, password,
                                               compatibility=data.get('compatibility', 'hana'))
        except ValueError as error:
            raise Stop(safe_code(error, 'certificate_import_failed')) from None
        finally:
            ctx.secrets = None
        return StepResult(outcome='success', result=pick(result, ('name', 'imported', 'certificate_id', 'network_used')),
                          local={'completed': True, 'network_used': False})


class OneSignIssuance(Adapter):
    area = 'banking'
    service = 'hana'
    requires_login = False
    verification = 'live_untested'
    secret_limits = {'identity_capture': 12 * 1024 * 1024}

    def __init__(self, stage):
        self.stage = stage
        self.name = 'hana.onesign.issue.' + stage
        self.title = '하나인증서 ' + ({'init': '저장소 만들기', 'inspect': '발급 상태 확인'}.get(stage) or LABELS[stage])
        self.remote = stage not in ('init', 'inspect', 'profile', 'consent', 'prepare-id')
        self.steps = {'run': Step('run', secrets=('vault_passphrase', *FIELDS.get(stage, ())), sends=self.remote)}

    def validate(self, value, login=None):
        data = dict_input(value, ('name', 'settings', 'send', *(('id_card',) if self.stage == 'prepare-id' else ())),
                          ('name',))
        credential_name(data['name'])
        if 'id_card' in data:
            credential_name(data['id_card'])
        if self.stage == 'init':
            credential_name(data.get('settings'))
        elif 'settings' in data:
            raise InputError('settings_not_accepted')
        if self.remote and data.get('send') is not True:
            raise InputError('send_approval_required')
        if 'send' in data and type(data['send']) is not bool:
            raise InputError('send_approval_required')
        return data

    def resources(self, ctx, step):
        if self.stage == 'init':
            # State creates its directory exclusively; do not pre-create it to acquire a lock.
            return [data_home() / 'server' / 'certificate-locks' / (ctx.input['name'] + '.lock')]
        return [store.root('identities') / ctx.input['name'] / 'operation.lock']

    def run(self, ctx, step):
        if self.stage == 'init':
            result = onesign.initialize(ctx.input['name'], ctx.input['settings'], ctx.secrets['vault_passphrase'])
            return StepResult(outcome='success', result={**result, 'next_stage': 'profile'}, local={'network_used': False})
        try:
            state = State(ctx.input['name'], ctx.secrets['vault_passphrase']).__enter__()
        except ValueError as error:
            raise Stop(safe_code(error, 'onesign_store_not_opened')) from None
        try:
            current = state.snapshot()
            if self.stage == 'inspect':
                shown = progress(current)
                diagnostic = identity_diagnostics(state, current)
                if diagnostic is not None:
                    shown['identity_diagnostic'] = diagnostic
                return StepResult(outcome='success', result=shown, local={'network_used': False})
            if next_stage(current) != self.stage:
                raise Stop('issuance_stage_out_of_order')
            inputs = self.inputs(ctx, current)
            if self.stage == 'prepare-id':
                capture = inputs['capture']
                try:
                    result = onesign.prepare_identity(state, capture['kind'], capture['jpeg'], capture['fields'])
                except ProtocolError as error:
                    raise Stop(safe_code(error, 'invalid_identity_capture')) from None
            else:
                if self.remote:
                    ctx.reserve()
                result = onesign.operate(state, self.stage, 'web-' + ctx.job['id'], send=self.remote, inputs=inputs)
            shown = pick(result, ('accepted', 'service_status', 'processing_status', 'state', 'certificate_issued',
                                  'prepared', 'network_used', 'automatic_retry', 'diagnostic_storage_failed'))
            completed = result.get('processing_status') != 'stopped'
            issued = result.get('certificate_issued') is True
            accepted = result.get('accepted')
            outcome = ('success' if completed else 'partial_success' if issued else
                       'rejected' if accepted is False else 'unknown' if result.get('network_used') else 'not_started')
            evidence = verdict(result) if self.remote else None
            # Record bank/CA evidence before any follow-up read or local processing.
            ctx.observe(service_verdict=evidence, outcome=outcome, result=shown)
            if completed:
                shown.update(progress(state.snapshot()))
            elif self.stage == 'identity':
                try:
                    shown['identity_diagnostic'] = identity_diagnostics(state, state.snapshot())
                except Exception:
                    shown['diagnostic_unavailable'] = True
            return StepResult(service_verdict=evidence, outcome=outcome, result=shown,
                              local={'completed': completed, 'stopped': safe_code(result.get('error'), 'issuance_stopped')}
                              if not completed else {'completed': True})
        finally:
            ctx.secrets = None
            state.__exit__(None, None, None)

    def inputs(self, ctx, current):
        secret = ctx.secrets
        inputs = {}
        if self.stage == 'profile':
            try:
                phone = signup.phone_profile(json.loads(secret['phone_profile']))
            except (ValueError, TypeError):
                raise Stop('invalid_phone_profile') from None
            terms = signup.sms_terms(phone['carrier'])
            if secret['agreement'] != terms_digest(terms):
                raise Stop('phone_consent_not_given')
            inputs = {'phone': lambda: phone, 'agree': lambda rows, title: terms_digest(rows) == secret['agreement']}
        elif self.stage == 'consent':
            expected = progress(current)['terms_digest']
            if secret['agreement'] != expected:
                raise Stop('signup_consent_not_given')
            inputs = {'agree': lambda rows, title: terms_digest(rows) == secret['agreement']}
        elif self.stage == 'verify-sms':
            if not re.fullmatch('[0-9]{6}', secret['sms']):
                raise Stop('sms_six_digits_required')
            inputs = {'sms': lambda: secret['sms']}
        elif self.stage == 'account':
            if not re.fullmatch('[0-9]{4}', secret['account_password']):
                raise Stop('account_password_four_digits_required')
            if not re.fullmatch('[0-9]{8,20}', secret['account_number']):
                raise Stop('invalid_account_number')
            # The business function still checks membership in the bank's observed own-account list.
            inputs = {'account': lambda rows: secret['account_number'],
                      'account_password': lambda *args: secret['account_password']}
        elif self.stage == 'issue':
            from finance_cli.services.hana.onesign_issue_protocol import check_new_pin
            check_new_pin(secret['new_pin'])
            check_new_pin(secret['new_pin_confirmation'])
            if secret['new_pin'] != secret['new_pin_confirmation']:
                raise Stop('new_pin_confirmation_mismatch')
            if secret['issue_confirmation'] != '발급':
                raise Stop('issuance_not_confirmed')
            inputs = {'new_pin': lambda: (secret['new_pin'], secret['new_pin_confirmation']),
                      'confirm_issue': lambda: True}
        elif self.stage == 'prepare-id':
            saved = ctx.input.get('id_card')
            inputs = {'capture': saved_identity(saved, secret['identity_capture']) if saved
                      else identity_capture(secret['identity_capture'])}
        return inputs


class IdCardAdd(Adapter):
    name = 'idcard.add'
    title = '신분증 보관'
    area = 'common'
    requires_login = False
    secret_limits = {'identity_capture': 12 * 1024 * 1024}
    steps = {'run': Step('run', secrets=('idcard_passphrase', 'identity_capture'), sends=False)}

    def validate(self, value, login=None):
        data = dict_input(value, ('name',), ('name',))
        credential_name(data['name'])
        return data

    def run(self, ctx, step):
        try:
            card = identity_capture(ctx.secrets['identity_capture'])
            result = id_cards.IdCards().add(ctx.input['name'], card['kind'], card['fields'], card['jpeg'],
                                            ctx.secrets['idcard_passphrase'])
        except ValueError as error:
            raise Stop(safe_code(error, 'id_card_not_saved')) from None
        finally:
            ctx.secrets = None
        return StepResult(outcome='success', result=pick(result, ('name', 'kind', 'saved', 'network_used')),
                          local={'completed': True, 'network_used': False})


ADAPTERS = [CertificateImport(), IdCardAdd(), *(OneSignIssuance(stage) for stage in ('init', 'inspect', *STAGES))]
