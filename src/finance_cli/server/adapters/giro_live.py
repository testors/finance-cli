"""Giro web jobs use the CLI services and its durable payment journal.

Only masked projections leave the worker. Private query/draft files are sealed
to the fixed login session and job. PINs/passwords arrive only through stdin.
"""
from contextlib import contextmanager
from datetime import date
import hashlib
import json
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from finance_cli.core import storage
from finance_cli.core.paths import data_home
from giro import auth_flow, query_flow
from giro.client import AuthenticatedClient
from giro.errors import GiroError
from giro.payment import account_options
from giro.payment_flow import PaymentWorkflow, WorkflowStopped
from giro.session_store import SessionStore

from .base import Adapter, InputError, Step, StepResult, Stop, bounded_int, choice, dict_input, iso_date, pick, text
from .giro import bill_row
from .hana import digest
from .. import model
from ..worker import job_directory

VERDICT = ('app_success', 'response_code', 'callback', 'callback_code', 'origin', 'service_decision',
           'login_service_decision', 'registration_service_decision')
TTL = 600


def observed(ctx, value, result=None):
    decision = value.get('login_service_decision', value.get('service_decision'))
    outcome = {'success': 'success', 'failure': 'rejected', 'partial_success': 'partial_success'}.get(decision, 'unknown')
    if outcome == 'success' and value.get('complete') is False:
        outcome = 'partial_success'
    fields = {'service_verdict': pick(value, VERDICT), 'outcome': outcome}
    if result is not None:
        fields['result'] = result
    ctx.observe(**fields)
    return fields


def local(value):
    return {k: value[k] for k in ('processing_issues', 'session_processing_issues', 'next_action', 'session_saved')
            if k in value}


def seal(session, job_id, value):
    # Separate key domain from the institution's SEED encryption. No PIN stored.
    key = hashlib.sha256(b'finance-giro-web-private-v1\0' + session.key).digest()
    nonce = secrets.token_bytes(12)
    data = AESGCM(key).encrypt(nonce, json.dumps(value, ensure_ascii=False).encode(), job_id.encode())
    storage.write_new(storage.directory(job_directory(job_id)) / 'giro.sealed', nonce + data)


def unseal(session, job_id):
    data = storage.read(job_directory(job_id) / 'giro.sealed')
    key = hashlib.sha256(b'finance-giro-web-private-v1\0' + session.key).digest()
    try:
        return json.loads(AESGCM(key).decrypt(data[:12], data[12:], job_id.encode()))
    except Exception:
        raise Stop('giro_preparation_changed') from None


class Giro(Adapter):
    area = service = 'giro'

    @property
    def verification(self):
        from finance_cli.core.live_verification import giro_job
        return giro_job(self.name)['verification']

    def ready(self, login):
        if login['method'] != 'pin':
            raise InputError('login_method_not_supported_by_job')

    def resources(self, ctx, step):
        # Share the CLI lock before taking a secret or sending any request.
        return [storage.directory(data_home() / 'giro') / 'session.lock']


class Login(Giro):
    name = 'giro.login'
    title = '모바일지로 PIN 로그인'
    steps = {'run': Step('run', secrets=('pin',))}

    def run(self, ctx, step):
        from giro.registration_flow import EnrollmentStore
        try:
            EnrollmentStore().identity(create=False)
        except GiroError:
            raise Stop('giro_device_registration_required') from None
        pin = ctx.secrets['pin']
        ctx.secrets = None
        if len(pin) != 6 or not pin.isascii() or not pin.isdigit():
            raise Stop('giro_invalid_login_pin')
        root = ctx.new_session_path('giro', suffix='')
        ctx.reserve()
        value = auth_flow.authenticate(pin_provider=lambda: pin, send=True, session_store=SessionStore(root))
        pin = None
        fields = observed(ctx, value)
        session_id = None
        if value.get('session_saved'):
            with ctx.db.read() as con:
                previous = model.current_session(con, ctx.login['id'])
            session_id = ctx.register_session(root, move_pointer=True, verdict=fields['service_verdict'],
                                             supersede=previous['id'] if previous else None)
        return StepResult(**fields, result={'session_id': session_id, 'session_saved': value.get('session_saved')},
                          local=local(value))


class Session(Giro):
    uses_session = True

    @contextmanager
    def client(self, ctx):
        if not self.accepts_session(ctx.session):
            raise Stop('fixed_session_not_usable')
        try:
            with SessionStore(ctx.session_file()).use() as (session, issues):
                client = AuthenticatedClient(session)
                try:
                    yield client
                finally:
                    for event in client.events:
                        ctx.event('giro_request', **event)
                    if not session.active:
                        ctx.mark_session(ctx.session['id'], 'expired', 'institution_session_ended')
            if issues:
                ctx.mark_session(ctx.session['id'], 'stale', 'session_save_incomplete')
                ctx.event('giro_session_storage', processing_issues=issues)
        except WorkflowStopped as error:
            value = query_flow.response_report(error.response)
            observed(ctx, value, {'stage': error.stage, 'no_bills_reported': value['no_bills_reported']})
            raise Stop('giro_preparation_stopped', sent=True) from None
        except GiroError:
            raise Stop('giro_operation_stopped', sent=bool(ctx.attempt.get('sent'))) from None

    @contextmanager
    def store(self, ctx):
        # Query helpers own SessionStore.use(); this wrapper records their result
        # before the worker projects it, so subsequent display/storage errors
        # cannot erase the institution's decision.
        if not self.accepts_session(ctx.session):
            raise Stop('fixed_session_not_usable')
        yield SessionStore(ctx.session_file())


class Bills(Session):
    name = 'giro.bills.list'
    title = '국세·지방세·관세 고지 조회'

    def validate(self, value, login=None):
        value = dict_input(value, ('tax_type',))
        return {'tax_type': choice(value.get('tax_type'), 'tax_type', ('national', 'local', 'customs')) or 'national'}

    def run(self, ctx, step):
        with self.client(ctx) as client:
            ctx.reserve()
            value = query_flow.collect_bills(client, ctx.input['tax_type'])
            rows = value.get('bills')
            result = pick(value, ('complete', 'total_count', 'loaded_count', 'tax_type', 'query_region',
                                  'no_bills_reported', 'issues', 'next_action'))
            result['bills'] = None if rows is None else [None if r is None else
                dict(bill_row(r), ref=str(i)) for i, r in enumerate(rows)]
            fields = observed(ctx, value, result)
            seal(client.session, ctx.job['id'], {'bills': rows, 'tax_type': ctx.input['tax_type']})
            return StepResult(**fields, local=local(value))


class FromParent(Session):
    session_from_parent = True
    parent_name = None

    def check_parent(self, parent, value):
        if not parent or parent['name'] != self.parent_name or parent['status'] != 'finished':
            raise InputError('giro_parent_required')
        if parent['outcome'] not in ('success', 'partial_success'):
            raise InputError('giro_parent_not_successful')

    def parent_data(self, ctx, client, *, expiring=False):
        if expiring and time.time() - ctx.parent['finished_at'] > TTL:
            raise Stop('giro_preparation_expired')
        return unseal(client.session, ctx.parent['id'])


class PaymentOptions(FromParent):
    name = 'giro.payment.options'
    title = '지로 고지 상세·납부계좌 조회'
    parent_name = 'giro.bills.list'

    def validate(self, value, login=None):
        value = dict_input(value, ('ref',), ('ref',))
        return {'ref': text(value['ref'], 'ref', 8, r'[0-9]+')}

    def run(self, ctx, step):
        with self.client(ctx) as client:
            parent = self.parent_data(ctx, client)
            rows = parent.get('bills') or []
            index = int(ctx.input['ref'])
            if index >= len(rows) or rows[index] is None:
                raise Stop('giro_item_not_found')
            ctx.reserve()
            value = PaymentWorkflow(client).options(rows[index]['identifiers'], tax_type=parent['tax_type'], send=True)
            options = account_options(value['accounts'])
            detail = value['detail'].get('paymentData') or {}
            result = {'bill': bill_row(rows[index]), 'accounts': options['accounts'],
                      'account_list_state': options['list_state'], 'amount': detail.get('payMny'),
                      'amount_editable': detail.get('mnyEditYn') in ('Y', 'P'),
                      'payment_sent': False}
            fields = observed(ctx, {'app_success': True, 'service_decision': 'success'}, result)
            seal(client.session, ctx.job['id'], value)
            return StepResult(**fields)


class Payment(FromParent):
    name = 'giro.payment.prepare'
    title = '지로 단건 계좌 납부'
    parent_name = 'giro.payment.options'
    confirmation = True
    first_step = 'prepare'
    steps = {'prepare': Step('prepare'), 'execute': Step('execute', secrets=('account_password',)),
             'execute_pin': Step('execute_pin', secrets=('account_password', 'pin'))}

    def validate(self, value, login=None):
        value = dict_input(value, ('account_index', 'amount'), ('account_index',))
        return {'account_index': bounded_int(value['account_index'], 'account_index', 1, 10000),
                'amount': text(value.get('amount'), 'amount', 19, r'[0-9]+')}

    def run(self, ctx, step):
        with self.client(ctx) as client:
            flow = PaymentWorkflow(client)
            if step == 'prepare':
                data = self.parent_data(ctx, client, expiring=True)
                ctx.reserve()
                preview = flow.prepare_selection(data, ctx.input['account_index'], amount=ctx.input['amount'], send=True)
                token = preview.pop('draft_id')
                # Keep large won amounts exact in JavaScript.
                preview['amount'] = str(preview['amount'])
                next_step = 'execute_pin' if preview['additional_pin_required'] else 'execute'
                supported = preview['authentication'] == 'none' or preview['additional_pin_required']
                expires = time.time() + TTL
                # Preparation responses are not a payment verdict. Even when
                # all reads succeed, the payment itself has not started.
                fields = {'service_verdict': {'preparation_service_decision': 'success'},
                          'outcome': 'not_started', 'result': preview}
                ctx.observe(**fields)
                if not supported:
                    return StepResult(**fields, local={'stopped': 'giro_payment_auth_unsupported'})
                review = {'job': ctx.job['id'], 'session': ctx.session['id'], 'preview': preview, 'expires': expires}
                seal(client.session, ctx.job['id'], {'draft': flow.export_draft(token), 'review': review})
                return StepResult(**fields, awaiting={'kind': 'confirm', 'next_step': next_step,
                    'digest': digest(review), 'preview': preview,
                    'requires': list(self.steps[next_step].secrets), 'expires_at': expires})
            saved = unseal(client.session, ctx.job['id'])
            review = saved['review']
            if review['session'] != ctx.session['id'] or digest(review) != ctx.attempt.get('confirmed_digest'):
                raise Stop('giro_preparation_changed')
            if time.time() > review['expires']:
                raise Stop('giro_preparation_expired')
            inputs, ctx.secrets = ctx.secrets, None
            token = flow.restore_draft(saved['draft'])
            ctx.reserve()
            value = flow.pay(token, send=True, account_password_provider=lambda: inputs['account_password'],
                             additional_pin_provider=(lambda: inputs['pin']) if step == 'execute_pin' else None)
            inputs = None
            result = {**pick(value, ('payment_attempted', 'result_saved', 'receipt_state', 'receipt_count',
                                    'automatic_retry')), 'preview': review['preview']}
            fields = observed(ctx, value, result)
            return StepResult(**fields, local=local(value))


class Accounts(Session):
    name = 'giro.accounts.list'
    title = '지로 등록계좌 조회'

    def run(self, ctx, step):
        with self.store(ctx) as store:
            ctx.reserve()
            value = query_flow.registered_accounts(send=True, store=store)
            return query_result(ctx, value, {'accounts': value.get('accounts')})


class Extend(Session):
    """One encrypted server-time query as session activity. Whether the server moves its own
    timeout is not confirmed; the outcome is only that query's decision."""
    name = 'giro.session.extend'
    title = '지로 세션 유지'

    def run(self, ctx, step):
        from giro import session as service
        with self.store(ctx) as store:
            ctx.reserve()
            value = service.extend(send=True, store=store)
            if value.get('session_ended') is True and value.get('callback') != 'disconnected_session':
                ctx.mark_session(ctx.session['id'], 'expired', 'institution_session_ended')
            return query_result(ctx, value, pick(value, ('request_accepted', 'login_extension_accepted', 'extension_effect',
                                                         'session_ended', 'server_expires_at',
                                                         'session_current_validity')))


def query_result(ctx, value, result):
    fields = observed(ctx, value, result)
    for event in value.get('events', []):
        ctx.event('giro_request', **event)
    if value.get('callback') == 'disconnected_session':
        ctx.mark_session(ctx.session['id'], 'expired', 'institution_session_ended')
    elif value.get('session_processing_issues'):
        ctx.mark_session(ctx.session['id'], 'stale', 'session_save_incomplete')
    return StepResult(**fields, local=local(value))


class Receipts(Session):
    name = 'giro.receipts.list'
    title = '지로 납부내역 조회'

    def validate(self, value, login=None):
        value = dict_input(value, ('start_date', 'end_date', 'page'), ('start_date', 'end_date'))
        start, end = iso_date(value['start_date'], 'start_date'), iso_date(value['end_date'], 'end_date')
        if not start or not end or start > end:
            raise InputError('invalid_date_range')
        return {'start_date': start, 'end_date': end, 'page': bounded_int(value.get('page', 1), 'page', 1, 10000)}

    def run(self, ctx, step):
        with self.store(ctx) as store:
            ctx.reserve()
            value = query_flow.list_receipts(date.fromisoformat(ctx.input['start_date']),
                date.fromisoformat(ctx.input['end_date']), page=ctx.input['page'], send=True, store=store)
            rows = value.get('receipts')
            result = {'receipts': None if rows is None else [None if r is None else
                {**pick(r, ('paid_date', 'amount_raw', 'issuer', 'payment_type', 'payment_system', 'cancelled')),
                 'ref': str(i)} for i, r in enumerate(rows)],
                'page_navi': pick(value.get('page_navi'), ('currentPage', 'totalPage', 'totalCount'))}
            answer = query_result(ctx, value, result)
            with store.use() as (session, issues):
                seal(session, ctx.job['id'], {'receipts': rows})
            return answer


class ReceiptDetail(FromParent):
    name = 'giro.receipts.detail'
    title = '지로 납부내역 상세'
    parent_name = 'giro.receipts.list'
    validate = PaymentOptions.validate

    def run(self, ctx, step):
        with self.client(ctx) as client:
            rows = self.parent_data(ctx, client).get('receipts') or []
            index = int(ctx.input['ref'])
            if index >= len(rows) or rows[index] is None:
                raise Stop('giro_item_not_found')
            ctx.reserve()
            response = client.query('receipts.detail', rows[index]['identifiers'], send=True)
            items = response.query.get('receiptItem') if response.app_success else None
            result = {'items': None if items is None else [None if r is None else
                {'name': r.get('n'), 'value': r.get('v')} for r in items], 'payment_reservation_changed': False}
            return StepResult(**observed(ctx, query_flow.response_report(response), result))


ADAPTERS = (Login(), Bills(), PaymentOptions(), Payment(), Accounts(), Extend(), Receipts(), ReceiptDetail())
