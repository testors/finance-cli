"""Corporate banking jobs over the same single-attempt services as the CLI."""
import json
import re
import secrets
import time

from finance_cli.core import storage
from finance_cli.services.hana_corporate import idpw, login, queries, store, transfers, transfer_protocol

from .base import (Adapter, InputError, Step, StepResult, Stop, choice, dict_input, extension_result, iso_date, scalar,
                   text)
from .hana import account_number, check_credential, digest


VERDICT_FIELDS = ('accepted', 'user_login_verified', 'processing_status', 'session_saved',
                  'session_current_validity', 'reason', 'error', 'business_error_code',
                  'password_failures_reported', 'session_usage', 'external_auth_status', 'transfer_sent')
STAGE_FIELDS = ('stage', 'service_status', 'processing_status', 'http_status', 'reason', 'business_status',
                'business_error_code', 'password_failures_reported')


def pick(value, keys):
    return {k: scalar(value[k]) for k in keys if k in value} if isinstance(value, dict) else {}


def warnings(value):
    return [v for v in value.get('warnings', []) if isinstance(v, str)
            and re.fullmatch('[a-z][a-z0-9_]{1,100}', v)]


def verdict(value):
    result = pick(value, VERDICT_FIELDS)
    result['stages'] = [{**pick(row, STAGE_FIELDS), 'warnings': warnings(row)}
                        for row in value.get('stages', []) if isinstance(row, dict)]
    result['warnings'] = warnings(value)
    return result


def outcome(value):
    if value.get('accepted') is True:
        return 'partial_success' if value.get('complete') is False or value.get('transfer_status') == 'partial' else 'success'
    if value.get('accepted') is False:
        return 'rejected'
    return 'unknown' if value.get('network_used') else 'not_started'


def observed(ctx, value, result=None):
    fields = {'service_verdict': verdict(value), 'outcome': outcome(value)}
    if result is not None:
        fields['result'] = result
    ctx.observe(**fields)
    return fields


def local(value):
    return {'stopped': value['error']} if value.get('error') else {}


class Corporate(Adapter):
    service = 'hana_corporate'
    area = 'corporate'
    verification = 'live_untested'
    methods = ('id_password', 'joint_certificate', 'onesign')

    def ready(self, connection):
        if connection['method'] not in self.methods:
            raise InputError('login_method_not_supported_by_job')


class Login(Corporate):
    purpose = 'login'

    def validate(self, value, login=None):
        value = dict_input(value, ('settings',))
        return {'settings': text(value.get('settings'), 'settings', 64, r'[A-Za-z0-9][A-Za-z0-9_.-]*')}

    def run(self, ctx, step):
        reference = ctx.snapshot['signing']
        name = 'web' + secrets.token_hex(12)
        inputs = ctx.secrets
        ctx.secrets = None
        if self.methods == ('id_password',):
            # Local settings and session preparation are part of login, never extra user steps.
            ctx.reserve(session=name)
            result = idpw.login(name, reference['ref'], ctx.input.get('settings'), send=True,
                                inputs={'password': lambda: inputs['login_password']})
        else:
            credential = check_credential(reference) if self.methods == ('joint_certificate',) else reference['ref']
            store.create(name, store.default_device())
            ctx.reserve(session=name)
            result = login.login(name, '2' if self.methods == ('joint_certificate',) else 'S', credential,
                                 send=True, inputs={'password': lambda: inputs['certificate_password'].encode()
                                 if self.methods == ('joint_certificate',) else inputs['vault_passphrase'],
                                 'pin': lambda: inputs['pin']})
        inputs = None
        fields = observed(ctx, result)
        saved_id = None
        if result.get('accepted') is True and result.get('session_saved') is True \
                and result.get('session_usage') != 'certificate_login_required' \
                and result.get('session_current_validity') != 'logged_out':
            with ctx.db.read() as con:
                from .. import model
                previous = model.current_session(con, ctx.login['id'])
            stated = result.get('server_session_timeout_minutes')
            saved_id = ctx.register_session(store.session_path(name), move_pointer=True, name=name,
                verdict={'accepted': True, **({'server_session_timeout_minutes': stated} if type(stated) is int else {})},
                supersede=previous['id'] if previous else None)
        return StepResult(**fields, result={'session_id': saved_id, 'login_method': self.methods[0],
                          'follow_up': pick(result.get('follow_up'), ('customer_guidance', 'app_fds', 'logout'))},
                          local=local(result))


class PasswordLogin(Login):
    name = 'hana.corporate.login-idpw'
    title = '하나기업뱅킹 ID/PW 로그인'
    methods = ('id_password',)
    verification = 'live_verified'
    steps = {'run': Step('run', secrets=('login_password',))}


class JointLogin(Login):
    name = 'hana.corporate.login'
    title = '하나기업뱅킹 공동인증서 로그인'
    methods = ('joint_certificate',)
    steps = {'run': Step('run', secrets=('certificate_password',))}


class OneSignLogin(Login):
    name = 'hana.corporate.login-onesign'
    title = '하나기업뱅킹 하나인증서 로그인'
    methods = ('onesign',)
    steps = {'run': Step('run', secrets=('vault_passphrase', 'pin'))}


class Session(Corporate):
    uses_session = True

    def session(self, ctx):
        if not ctx.session or not ctx.session.get('name'):
            raise Stop('session_not_fixed')
        return ctx.session['name']

    def resources(self, ctx, step):
        return [store.session_path(self.session(ctx)) / 'operation.lock']


class Accounts(Session):
    name = 'hana.corporate.accounts'
    title = '기업 계좌·잔액 조회'

    def validate(self, value, login=None):
        value = dict_input(value, ('category',))
        return {'category': choice(value.get('category'), 'category', (*queries.TABS, 'all')) or 'withdrawal'}

    def run(self, ctx, step):
        ctx.reserve()
        value = queries.accounts(session=self.session(ctx), send=True, **ctx.input)
        fields = observed(ctx, value)
        candidates, accounts, seen = [], [], set()
        for row in value.get('accounts', []):
            number = row.get('ACCT_NO')
            if not isinstance(number, str) or not re.fullmatch('[0-9]{1,20}', number) or number in seen:
                continue
            seen.add(number)
            row = pick(row, ('ACCT_ALNM', 'PRD_NM', 'SUBJ_NM', 'CUR_CD', 'category', 'BAL', 'PRS_BAL'))
            label = row.get('ACCT_ALNM') or row.get('PRD_NM') or row.get('SUBJ_NM') or '기업 계좌'
            ref = 'account-' + str(len(accounts) + 1)
            identity = {'account_number': number, 'currency': row.get('CUR_CD'), 'name': label,
                        'category': row.get('category'), 'account_type': queries.kind(number)}
            candidates.append({'ref': ref, 'kind': 'account', 'identity_key': 'account:' + number,
                               'label': label, 'identity': identity})
            accounts.append({'ref': ref, 'label': label, **identity, 'balance': row.get('BAL', row.get('PRS_BAL'))})
        ctx.remember(target_candidates=candidates)
        return StepResult(**fields, result={'accounts': accounts, 'complete': value.get('complete'),
                          'categories': [pick(r, ('category', 'received')) for r in value.get('categories', [])]},
                          local=local(value))


class Extend(Session):
    """One login extension on the corporate session. A session the bank reports as ended is marked so."""
    name = 'hana.corporate.session.extend'
    title = '기업뱅킹 로그인 연장'

    def run(self, ctx, step):
        from finance_cli.services.hana_corporate import session as service
        ctx.reserve()
        value = service.extend(session=self.session(ctx), send=True)
        fields = observed(ctx, value)
        return StepResult(**fields, result=extension_result(ctx, value), local=local(value))


class History(Session):
    name = 'hana.corporate.history'
    title = '기업 계좌 거래내역 조회'
    requires_target = True

    def validate(self, value, login=None):
        value = dict_input(value, ('start', 'end', 'direction', 'order', 'search_type', 'search', 'currency', 'sequence'))
        start, end = iso_date(value.get('start'), 'start'), iso_date(value.get('end'), 'end')
        if start and end and (queries.parse_date(end) - queries.parse_date(start)).days not in range(366):
            raise InputError('history_period_must_be_within_one_year')
        return {'start': start, 'end': end,
                'direction': choice(value.get('direction'), 'direction', ('', '1', '2')) or '',
                'order': choice(value.get('order'), 'order', ('latest', 'oldest')) or 'latest',
                'search_type': choice(value.get('search_type'), 'search_type', ('', '04', '03', '05', '02')) or '',
                'search': text(value.get('search'), 'search', 100) or '',
                'currency': text(value.get('currency'), 'currency', 3, '[A-Z]{3}'),
                'sequence': text(value.get('sequence'), 'sequence', 20, '[0-9]+')}

    def run(self, ctx, step):
        ctx.reserve()
        value = queries.history(account_number(ctx.snapshot['target']), session=self.session(ctx), send=True, **ctx.input)
        rows = []
        for row in value.get('transactions', []):
            item = pick(row, queries.HISTORY_FIELDS)
            if isinstance(row.get('display'), dict):
                item['display'] = pick(row['display'], queries.HISTORY_FIELDS)
            rows.append(item)
        result = {'transactions': rows, **pick(value, ('complete', 'account_type', 'currency', 'account_sequence')),
                  'balance': pick(value.get('balance'), ('PRS_BAL', 'CUR_CD')),
                  'loan': pick(value.get('loan'), ('NEW_DT', 'EXPI_DT', 'LON_LIM_AMT', 'PRS_BAL', 'NEXT_INT_PAYT_DT', 'APCL_IRRT', 'curCd')),
                  'pages': [pick(r, ('start', 'end', 'page', 'received', 'past')) for r in value.get('pages', [])]}
        if isinstance(value.get('currencies'), list):
            result['currencies'] = [scalar(v) for v in value['currencies']]
        return StepResult(**observed(ctx, value, result), local=local(value))


def transfer_result(value):
    result = pick(value, ('transfer_sent', 'transfer_status', 'allErrYn', 'errYn', 'sussCnt', 'errCnt',
        'suessTotlTrnsAmt', 'errorTotlTrnsAmt', 'totlTrnsAmt', 'totalRduAfComm', 'comm', 'dlayTrnsYn',
        'dlayTrnsTime', 'SYNC_YN', 'TRNS_EXEC_YN'))
    result['preparation_available'] = bool(value.get('transfer'))
    for key in ('submitted', 'synchronous', 'asynchronous', 'records'):
        if isinstance(value.get(key), list):
            result[key] = [pick(r, (*transfer_protocol.VISIBLE_FIELDS, 'processing_status')) for r in value[key]]
    if isinstance(value.get('preview'), dict):
        preview = value['preview']
        result['preview'] = {**pick(preview, ('acctNo', 'acctNm', 'totlTrnsAmt', 'totalRduAfComm', 'comm', 'dlayTrnsYn', 'toDayTrnListYn')),
                             'items': [pick(r, transfer_protocol.VISIBLE_FIELDS) for r in preview.get('items') or []]}
    return result


def fixed_transfer(ctx):
    owner = json.loads(ctx.parent['attempt']) if ctx.parent else ctx.attempt
    expected = owner.get('corporate_transfer')
    path = store.session_path(ctx.session['name'])
    pending = storage.read_json(path / 'pending-transfer.json')
    if not expected or pending.get('transfer') != expected:
        raise Stop('prepared_transfer_changed')
    return path / 'transfers' / store.name(expected)


class Transfer(Session):
    name = 'hana.corporate.transfer.prepare'
    title = '기업 원화 이체'
    requires_target = True
    confirmation = True
    first_step = 'prepare'
    steps = {name: Step(name, secrets=required) for name, required in (
        ('prepare', ()), ('execute', ()), ('account_password', ('account_password',)), ('otp', ('otp',)),
        ('certificate', ('certificate_password',)), ('choose_certificate', ('signing_credential', 'certificate_password')),
        ('ars', ()))}
    input_masks = ('recipient',)

    def validate(self, value, login=None):
        value = dict_input(value, ('bank', 'recipient', 'amount', 'memo', 'sender_text', 'recipient_text', 'cms_code', 'delayed'),
                           ('bank', 'recipient', 'amount'))
        if type(value.get('delayed', False)) is not bool:
            raise InputError('invalid_delayed')
        return {'bank': text(value['bank'], 'bank', 3, '[0-9]{3}'),
                'recipient': text(value['recipient'], 'recipient', 20, '[0-9]{1,20}'),
                'amount': text(value['amount'], 'amount', 18, '[1-9][0-9]*'),
                'memo': text(value.get('memo'), 'memo', 100) or '',
                'sender_text': text(value.get('sender_text'), 'sender_text', 100),
                'recipient_text': text(value.get('recipient_text'), 'recipient_text', 100),
                'cms_code': text(value.get('cms_code'), 'cms_code', 100, '[A-Za-z0-9-]+') or '',
                'delayed': value.get('delayed', False)}

    def await_step(self, ctx, value, next_step):
        result = transfer_result(value)
        preview = result.get('preview') or ctx.attempt.get('corporate_preview')
        token = digest({'job': ctx.job['id'], 'transfer': ctx.attempt['corporate_transfer'],
                        'next_step': next_step, 'preview': preview, 'nonce': secrets.token_hex(16)})
        return StepResult(**observed(ctx, value, result), awaiting={'kind': 'confirm', 'digest': token,
                          'next_step': next_step, 'requires': list(self.steps[next_step].secrets),
                          'preview': preview, 'verification': self.verification},
                          local={'input_required': next_step})

    def run(self, ctx, step):
        if step == 'prepare':
            ctx.reserve()
            value = transfers.prepare(account_number(ctx.snapshot['target']), session=self.session(ctx), send=True, **ctx.input)
            observed(ctx, value, transfer_result(value))
            ctx.remember(corporate_transfer=value.get('transfer'), corporate_preview=transfer_result(value).get('preview'))
            if value.get('transfer_status') == 'prepared' and value.get('processing_status') == 'completed':
                return self.await_step(ctx, value, 'execute')
        else:
            fixed_transfer(ctx)  # The held CLI lock prevents a different preparation from taking its place.
            inputs = ctx.secrets
            ctx.secrets = None
            selected = ctx.attempt.get('corporate_credential')
            if step == 'choose_certificate':
                from .. import model
                selected = model.credential_ref('joint', inputs['signing_credential'])
                ctx.remember(corporate_credential=selected)
            if selected is None:
                with ctx.db.read() as con:
                    from .. import model
                    selected = model.signing_for(con, ctx.login, ctx.target, 'transfer_sign')
            providers = {k: (lambda key=k: inputs[key]) for k in ('account_password', 'otp') if k in inputs}
            if 'certificate_password' in inputs:
                providers['password'] = lambda: inputs['certificate_password'].encode()
            if step == 'ars':
                ctx.remember(corporate_ars_completed=True)
            ctx.reserve()
            value = transfers.execute(session=self.session(ctx), send=True, inputs=providers,
                credential=check_credential(selected) if selected else None, allow_duplicate=True,
                ars_completed=bool(ctx.attempt.get('corporate_ars_completed')))
            inputs = None
            missing = {'account_password_input_required': 'account_password', 'otp_input_required': 'otp',
                       'invalid_account_password': 'account_password', 'invalid_otp': 'otp',
                       'password_input_required': 'certificate', 'shared_certificate_selection_required': 'choose_certificate',
                       'ars_completed_input_required': 'ars', 'ars_authentication_pending': 'ars'}
            if value.get('error') in missing and not value.get('transfer_sent'):
                return self.await_step(ctx, value, missing[value['error']])
        return StepResult(**observed(ctx, value, transfer_result(value)), local=local(value))


class TransferFollowUp(Session):
    requires_target = True
    session_from_parent = True

    def check_parent(self, parent, value):
        if parent['name'] != Transfer.name or parent['status'] not in ('finished', 'awaiting_input'):
            raise InputError('parent_transfer_job_required')

    def run(self, ctx, step):
        fixed_transfer(ctx)
        ctx.reserve()
        value = self.function(session=self.session(ctx), send=True)
        return StepResult(**observed(ctx, value, transfer_result(value)), local=local(value))


class TransferResult(TransferFollowUp):
    name = 'hana.corporate.transfer.result'
    title = '기업 이체 결과 확인'
    function = staticmethod(transfers.result)


class TransferCancel(TransferFollowUp):
    name = 'hana.corporate.transfer.cancel'
    title = '기업 이체 준비 취소'
    function = staticmethod(transfers.cancel)

    def run(self, ctx, step):
        result = super().run(ctx, step)
        if result.service_verdict.get('accepted') is True:
            with ctx.db.write() as con:
                changed = con.execute("UPDATE jobs SET status='cancelled', awaiting=NULL, updated_at=?, finished_at=? "
                                      "WHERE id=? AND status='awaiting_input'",
                                      (time.time(), time.time(), ctx.parent['id'])).rowcount
                if changed:
                    ctx.db.event(con, ctx.parent['id'], 'cancelled', reason='bank_preparation_cancelled')
        return result


def ars_challenge(job, session):
    awaiting = json.loads(job['awaiting'] or '{}')
    if job['name'] != Transfer.name or job['status'] != 'awaiting_input' or awaiting.get('next_step') != 'ars':
        raise ValueError('ars_challenge_not_available')
    expected = json.loads(job['attempt']).get('corporate_transfer')
    path = store.session_path(session)
    if storage.read_json(path / 'pending-transfer.json').get('transfer') != expected:
        raise ValueError('prepared_transfer_changed')
    received = storage.read_json(path / 'transfers' / store.name(expected) / 'ars-request-received.json')
    code = str(received['data'].get('ARS_APV_NO', ''))
    if not re.fullmatch('[0-9]{2,6}', code):
        raise ValueError('ars_challenge_not_available')
    return {'code': code}


ADAPTERS = [PasswordLogin(), JointLogin(), OneSignLogin(), Accounts(), Extend(), History(), Transfer(), TransferResult(), TransferCancel()]
