"""Hana Bank adapters over the existing business functions (called directly).

The joint-certificate path keeps its one-shot receipts per session; a fresh
balance needs a new login, exactly as in the CLI. Two-step functions are
prepared and then sent inside one locked step without new requests. OneSign
transfers keep one prepared transfer per login session; the account password
arrives with the prepare request and the PIN with the confirmation, so no
step waits for input in the middle of its requests.
"""
import hashlib
import json
import re
import secrets as random
import time

from finance_cli.core import storage

from .base import (Adapter, InputError, Step, StepResult, Stop, bounded_int, choice, dict_input, iso_date, mask_account,
                   pick, text)
from .hometax import scalar_row

PIN = re.compile(r'[0-9]{6}')
ACCOUNT_PASSWORD = re.compile(r'[0-9]{4}')
# The app's native client timer is reset to 600000 ms by a successful login
# extension (services/hana/extend.py); a prepared transfer is not kept longer.
CONFIRM_SECONDS = 600
ROW_LIMIT = 1000


def session_name():
    return 'web' + random.token_hex(8)


def input_file(ctx, name, value):
    path = ctx.directory / name
    if not path.exists():
        storage.write_new(path, json.dumps(value, ensure_ascii=False).encode('utf-8'))
    return path


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def masked_rows(rows):
    return [scalar_row(r) for r in rows[:ROW_LIMIT]] if isinstance(rows, list) else None


def outcome(accepted, *, completed=True):
    if accepted is True and completed:
        return 'success'
    if accepted is False:
        return 'rejected'
    return 'unknown'


def verdict(result, keys=('accepted', 'reason', 'processing_status', 'service_status', 'error_code', 'processing_result',
                          'session_ready', 'user_login_verified', 'error', 'warnings')):
    return pick(result, keys) if isinstance(result, dict) else None


def safe_code(error, fallback='local_processing_error'):
    text_value = str(error)
    return text_value if re.fullmatch(r'[a-z][a-z0-9_]{2,80}', text_value) else fallback


def account_number(target):
    number = ((target or {}).get('identity') or {}).get('account_number')
    if not number:
        raise Stop('account_target_required')
    return number


class HanaAdapter(Adapter):
    service = 'hana'
    area = 'banking'
    capability = 'hana'
    methods = ('joint_certificate',)

    @property
    def verification(self):
        from finance_cli.core.live_verification import hana_job
        return hana_job(self.name)['verification']

    def ready(self, login):
        if login['method'] not in self.methods:
            raise InputError('login_method_not_supported_by_job')


class JointSessionAdapter(HanaAdapter):
    uses_session = True

    def resources(self, ctx, step):
        from finance_cli.services.hana import store
        return [store.child(store.session_path(self.session(ctx)), 'operation.lock')]

    def session(self, ctx):
        if ctx.session is None or not ctx.session.get('name'):
            raise Stop('session_not_fixed')
        return ctx.session['name']

    def headers(self, ctx):
        from finance_cli.services.hana import login, store
        request = login.authenticated_session(store.session_path(self.session(ctx)))
        return {k.lower(): v for k, v in request['headers'].items()}


def check_credential(reference):
    from .hometax import check_credential as joint
    return joint(reference)


# Joint-certificate path -------------------------------------------------

class Login(HanaAdapter):
    name = 'hana.login'
    title = '하나은행 공동인증서 로그인'
    purpose = 'login'
    steps = {'run': Step('run', secrets=('certificate_password',))}

    def ready(self, login):
        super().ready(login)
        registration = json.loads(login['registration'] or '{}')
        if not registration.get('app_profile') or not registration.get('login_input'):
            raise InputError('registration_required:app_profile,login_input')

    def run(self, ctx, step):
        from finance_cli.credentials.registry import Registry
        from finance_cli.services.hana import auth, login
        from ..registration import path_for
        alias = check_credential(ctx.snapshot.get('signing'))
        password = ctx.secrets['certificate_password'].encode('utf-8')
        ctx.secrets = None
        try:
            Registry().material(alias, password)  # A wrong password costs no bank request.
        except ValueError as error:
            raise Stop(safe_code(error, 'certificate_not_usable')) from None
        profile, login_input = path_for(ctx.login, 'app_profile'), path_for(ctx.login, 'login_input')
        if profile is None or login_input is None or not profile.is_file() or not login_input.is_file():
            raise Stop('registration_required')
        name = session_name()
        auth.new_session(name)
        ctx.reserve(session=name)
        try:
            app = auth.authenticate(name, profile, send=True)
        except ValueError as error:
            raise Stop(safe_code(error), sent=True) from None
        result = {'app_auth': verdict(app, ('accepted', 'stopped_at', 'app_auth_accepted'))}
        ctx.observe(service_verdict=result, outcome='rejected' if app.get('accepted') is False else 'unknown')
        if app.get('accepted') is not True:
            return StepResult(service_verdict=result, outcome=outcome(app.get('accepted')))
        try:
            signed = login.login(name, alias, login_input, password, send=True)
        except ValueError as error:
            raise Stop(safe_code(error), sent=True) from None
        finally:
            password = None
        result['login'] = verdict(signed)
        success = signed.get('accepted') is True and signed.get('user_login_verified') is True
        ctx.observe(service_verdict=result, outcome=outcome(signed.get('accepted'), completed=success))
        session_id = None
        if success:
            from finance_cli.services.hana import store
            with ctx.db.read() as con:
                from .. import model
                previous = model.current_session(con, ctx.login['id'])
            session_id = ctx.register_session(store.session_path(name), move_pointer=True, name=name,
                                              verdict={'accepted': True}, supersede=previous['id'] if previous else None)
        return StepResult(service_verdict=result, outcome=outcome(signed.get('accepted'), completed=success),
                          result={'session_id': session_id, 'login_method': 'joint_certificate'})


def account_candidates(ctx, rows):
    candidates, display = [], []
    for index, row in enumerate(rows if isinstance(rows, list) else [], 1):
        if not isinstance(row, dict) or not row.get('acctNo'):
            continue
        label = next((row[k] for k in ('acctNm', 'prdtNm', 'acctPrdtNm', 'goodNm') if isinstance(row.get(k), str)
                      and row[k]), None)
        number = str(row['acctNo'])
        candidates.append({'ref': f'account-{index}', 'kind': 'account', 'identity_key': 'account:' + str(row['acctNo']),
                           'label': label or f'계좌 {number}',
                           'identity': {'account_number': number, 'currency': row.get('curCd'),
                                        'name': label}})
        display.append({'ref': f'account-{index}', 'index': index, 'label': label or f'계좌 {number}',
                        'account_number': number, 'currency': row.get('curCd'), 'balance': row.get('acctBal')})
    ctx.remember(target_candidates=candidates)
    return display


class Accounts(JointSessionAdapter):
    name = 'hana.accounts.list'
    title = '하나은행 계좌 목록·잔액'

    def run(self, ctx, step):
        from finance_cli.services.hana import login, store
        name = self.session(ctx)
        ctx.reserve()
        try:
            result = login.accounts(name, send=True)
        except ValueError as error:
            raise Stop(safe_code(error), sent=True) from None
        accepted = result.get('accepted')
        ctx.observe(service_verdict=verdict(result), outcome=outcome(accepted))
        rows = None
        if accepted is True:
            # The receipt is one-shot per session; history queries keep using this selection.
            try:
                rows = store.read_json(store.child(store.session_path(name), 'account-selection.json'))['accounts']
            except (OSError, ValueError, KeyError):
                rows = None
        return StepResult(service_verdict=verdict(result), outcome=outcome(accepted),
                          result={'accounts': account_candidates(ctx, rows), 'rows': masked_rows(rows),
                                  'account_count': result.get('account_count'),
                                  'session_current_validity': 'unverified'},
                          local={'rows_read': rows is not None})


def account_index(ctx, name):
    """The session's 1-based account index for the fixed target account."""
    from finance_cli.services.hana import store
    number = account_number(ctx.snapshot.get('target'))
    try:
        selection = store.read_json(store.child(store.session_path(name), 'account-selection.json'))
    except (OSError, ValueError):
        raise Stop('accounts_query_required_in_session') from None
    matches = [r for r in selection.get('accounts', []) if isinstance(r, dict) and str(r.get('acctNo')) == number]
    if len(matches) != 1:
        raise Stop('account_not_in_session_accounts')
    return matches[0]['index']


def compact(value):
    return value.replace('-', '')


def validate_history_controls(ctx, *, transfer=False):
    """Validate before the optional account-list request, just as before the clock request."""
    from finance_cli.services.hana import inquiry, ledger_protocol
    config = {**ctx.input, 'start_date': compact(ctx.input['start_date']),
              'end_date': compact(ctx.input['end_date'])}
    if not config.get('search'):
        config.pop('search', None)
    try:
        if transfer:
            inquiry.check_period(config['start_date'], config['end_date'])
        else:
            ledger_protocol.plan(config, inquiry.today_kst().strftime('%Y%m%d'),
                                 account_number(ctx.snapshot.get('target')))
    except ValueError:
        raise Stop('invalid_history_controls') from None


def observe_accounts(ctx, result):
    stages = [{'stage': 'accounts', **verdict(result)}]
    accepted = result.get('accepted')
    ctx.observe(service_verdict={'stages': stages},
                outcome='not_started' if accepted is True else outcome(accepted))
    return stages


def require_accounts_result(result):
    if result.get('accepted') is not True or result.get('processing_status', 'completed') != 'completed':
        raise Stop('accounts_query_incomplete', sent=True)


def ensure_query_accounts(ctx, name):
    """Prime only a fresh session; never replay an existing one-shot account attempt."""
    from finance_cli.services.hana import login, store
    session = store.session_path(name)
    if store.child(session, 'account-selection.json').exists() or store.child(session, 'accounts').exists():
        return []
    ctx.reserve()
    try:
        result = login.accounts(name, send=True, observe=lambda result: observe_accounts(ctx, result))
    except (ValueError, OSError) as error:
        raise Stop(safe_code(error), sent=True) from None
    stages = observe_accounts(ctx, result)
    require_accounts_result(result)
    return stages


def send_two_step(function, *args, **kwargs):
    """Prepare the draft, then send that unchanged draft once."""
    function(*args, send=False, **kwargs)
    return function(*args, send=True, **kwargs)


class History(JointSessionAdapter):
    name = 'hana.history.list'
    title = '거래 내역 조회'
    requires_target = True

    def validate(self, value, login=None):
        value = dict_input(value, ('start_date', 'end_date', 'direction', 'order', 'search'), ('start_date', 'end_date'))
        start, end = iso_date(value['start_date'], 'start_date'), iso_date(value['end_date'], 'end_date')
        if start > end:
            raise InputError('invalid_period')
        return {'start_date': start, 'end_date': end,
                'direction': choice(value.get('direction'), 'direction', ('all', 'deposit', 'withdrawal')) or 'all',
                'order': choice(value.get('order'), 'order', ('desc', 'asc')) or 'desc',
                'search': text(value.get('search'), 'search', 25)}

    def config(self, ctx, name):
        value = {'account_index': account_index(ctx, name), 'start_date': compact(ctx.input['start_date']),
                 'end_date': compact(ctx.input['end_date']), 'direction': ctx.input['direction'],
                 'order': ctx.input['order']}
        if ctx.input.get('search'):
            value['search'] = ctx.input['search']
        return input_file(ctx, 'history-input.json', value)

    def run(self, ctx, step):
        from finance_cli.services.hana import ledger
        name = self.session(ctx)
        validate_history_controls(ctx)
        stages = ensure_query_accounts(ctx, name)
        path = self.config(ctx, name)
        ctx.reserve()
        receipts = {}
        ctx.observe(outcome='unknown')
        try:
            for stage in ('clock', 'account'):
                result = send_two_step(ledger.run, name, stage, path)
                stages.append({'stage': stage, **verdict(result, ('accepted', 'reason'))})
                ctx.observe(service_verdict={'stages': stages}, outcome=outcome(result.get('accepted'), completed=False))
                if result.get('accepted') is not True:
                    return StepResult(service_verdict={'stages': stages}, outcome=outcome(result.get('accepted')))
                receipts[stage] = result['receipt_directory']
            result = send_two_step(ledger.run, name, 'page', path, clock=receipts['clock'],
                                   account_info=receipts['account'])
        except (ValueError, OSError) as error:
            raise Stop(safe_code(error), sent=True, detail={'stages': stages}) from None
        stages.append({'stage': 'page', **verdict(result, ('accepted', 'reason', 'row_count', 'diagnostics'))})
        return page_result(ctx, name, path, receipts, result, stages)


def page_result(ctx, name, path, receipts, result, stages):
    from finance_cli.services.hana import ledger, ledger_protocol as protocol, transport, store
    rows, complete, local = None, None, {}
    ctx.observe(service_verdict={'stages': stages}, outcome=outcome(result.get('accepted')))
    if result.get('accepted') is True:
        receipts['page'] = result['receipt_directory']
        try:
            headers = {k.lower(): v for k, v in transport.read_receipt(store.session_path(name),
                                                                        receipts['page'])[0]['headers'].items()}
            pages, position = ledger.chain(store.session_path(name), receipts['page'], headers)
            request, value, _ = pages[-1]
            rows = [protocol.display_row(r) for r in protocol.rows(request['account_history']['kind'], value)]
            complete = position is None
            ctx.remember(history={'path': str(path), 'receipts': receipts, 'more': position not in (None, 'invalid')})
        except (ValueError, OSError, KeyError, TypeError):
            local['saved_rows_unreadable'] = True  # The accepted verdict stays as observed.
    return StepResult(service_verdict={'stages': stages}, outcome=outcome(result.get('accepted')), local=local,
                      result={'rows': [pick(r, ('date', 'time', 'type', 'name', 'amount', 'balance', 'currency',
                                                'variation', 'extra', 'memo')) for r in (rows or [])[:ROW_LIMIT]]
                              if rows is not None else None,
                              'pagination_complete': complete, 'more_available': complete is False,
                              'transfer_confirmed': False})


class HistoryFollowUp(JointSessionAdapter):
    """Continues a history job on the same session; the cursor never leaves the server."""
    requires_target = True
    session_from_parent = True
    parents = ('hana.history.list', 'hana.history.more')

    def check_parent(self, parent, value):
        if parent['name'] not in self.parents or parent['status'] != 'finished' or parent['outcome'] != 'success':
            raise InputError('parent_history_job_required')
        if not (json.loads(parent['attempt'] or '{}').get('history') or {}).get('receipts', {}).get('page'):
            raise InputError('parent_history_page_required')

    def parent_history(self, ctx):
        history = json.loads(ctx.parent['attempt'] or '{}').get('history') or {}
        if not history.get('receipts', {}).get('page'):
            raise Stop('parent_history_page_required')
        return history


class HistoryMore(HistoryFollowUp):
    name = 'hana.history.more'
    title = '거래 내역 다음 페이지'

    def run(self, ctx, step):
        from finance_cli.services.hana import ledger
        from pathlib import Path
        history = self.parent_history(ctx)
        name = self.session(ctx)
        receipts = dict(history['receipts'])
        ctx.reserve()
        try:
            result = send_two_step(ledger.run, name, 'page', Path(history['path']), clock=receipts['clock'],
                                   account_info=receipts['account'], previous=receipts['page'])
        except (ValueError, OSError) as error:
            raise Stop(safe_code(error), sent=True) from None
        stages = [{'stage': 'page', **verdict(result, ('accepted', 'reason', 'row_count', 'diagnostics'))}]
        return page_result(ctx, name, Path(history['path']), receipts, result, stages)


class HistoryDetail(HistoryFollowUp):
    name = 'hana.history.detail'
    title = '거래 상세'

    def validate(self, value, login=None):
        value = dict_input(value, ('row',), ('row',))
        return {'row': bounded_int(value['row'], 'row', 1, 1000)}

    def run(self, ctx, step):
        from finance_cli.services.hana import ledger, store
        from pathlib import Path
        history = self.parent_history(ctx)
        name, receipts = self.session(ctx), history['receipts']
        options = {'clock': receipts['clock'], 'account_info': receipts['account'], 'previous': receipts['page'],
                   'row': ctx.input['row']}
        try:
            local = ledger.run(name, 'detail', Path(history['path']), send=False, **options)
        except (ValueError, OSError) as error:
            raise Stop(safe_code(error)) from None
        if local.get('source') == 'saved_ledger_row':
            meta = store.read_json(store.child(store.session_path(name), local['detail_file']))
            display = (meta.get('local_detail') or {}).get('display')
            return StepResult(service_verdict=None, outcome='success', observed=False,
                              result={'source': 'saved_ledger_row', 'network_used': False, 'detail': scalar_row(display)})
        ctx.reserve()
        try:
            result = ledger.run(name, 'detail', Path(history['path']), send=True, **options)
        except (ValueError, OSError) as error:
            raise Stop(safe_code(error), sent=True) from None
        detail = None
        ctx.observe(service_verdict=verdict(result), outcome=outcome(result.get('accepted')))
        if result.get('accepted') is True:
            try:
                headers = self.headers(ctx)
                detail = ledger.receipt(store.session_path(name), result['receipt_directory'], headers)[1]
            except (ValueError, OSError, KeyError):
                detail = None
        return StepResult(service_verdict=verdict(result), outcome=outcome(result.get('accepted')),
                          result={'source': 'bank_detail', 'detail': scalar_row(detail) if isinstance(detail, dict)
                                  else None, 'transfer_confirmed': False})


class HistoryExport(HistoryFollowUp):
    name = 'hana.history.export'
    title = '거래 내역 저장'
    steps = {'run': Step('run', sends=False)}

    def run(self, ctx, step):
        from finance_cli.services.hana import ledger
        history = self.parent_history(ctx)
        output = ctx.directory / 'export.json'
        try:
            summary = ledger.export(self.session(ctx), history['receipts']['page'], output)
        except (ValueError, OSError) as error:
            raise Stop(safe_code(error)) from None
        report = json.loads(storage.read(output, 64 * 1024 * 1024))
        fields = ('page', 'row', 'kind', 'date', 'time', 'type', 'name', 'amount', 'balance', 'currency', 'variation',
                  'extra', 'memo')
        filtered = {k: report[k] for k in ('page_count', 'row_count', 'pagination_complete', 'atomic_snapshot_verified',
                                           'transfer_confirmed', 'duplicates_removed', 'issues', 'csv_text_cells_escaped')}
        filtered['rows'] = [pick(r, fields) for r in report['rows']]
        stamp = time.strftime('%Y%m%d-%H%M%S')
        json_id = ctx.add_artifact('hana_history_json', f'history-{stamp}.json', 'application/json',
                                   json.dumps(filtered, ensure_ascii=False, indent=2).encode('utf-8'),
                                   complete=report['pagination_complete'])
        csv_id = ctx.add_artifact('hana_history_csv', f'history-{stamp}.csv', 'text/csv; charset=utf-8',
                                  storage.read(output.with_suffix('.csv'), 64 * 1024 * 1024),
                                  complete=report['pagination_complete'])
        return StepResult(service_verdict=None, outcome='success', observed=False,
                          result={**summary, 'artifact_ids': [json_id, csv_id], 'network_used': False})


class TransferHistory(JointSessionAdapter):
    name = 'hana.inquiry.history'
    title = '이체 내역 조회'
    requires_target = True

    def validate(self, value, login=None):
        value = dict_input(value, ('start_date', 'end_date'), ('start_date', 'end_date'))
        start, end = iso_date(value['start_date'], 'start_date'), iso_date(value['end_date'], 'end_date')
        if start > end:
            raise InputError('invalid_period')
        return {'start_date': start, 'end_date': end}

    def run(self, ctx, step):
        from finance_cli.services.hana import inquiry, store
        name = self.session(ctx)
        validate_history_controls(ctx, transfer=True)
        stages = ensure_query_accounts(ctx, name)
        path = input_file(ctx, 'inquiry-input.json', {'account_index': account_index(ctx, name),
                                                      'start_date': compact(ctx.input['start_date']),
                                                      'end_date': compact(ctx.input['end_date'])})
        ctx.reserve()
        ctx.observe(outcome='unknown')
        try:
            result = send_two_step(inquiry.run, name, 'history', path)
        except (ValueError, OSError) as error:
            raise Stop(safe_code(error), sent=True) from None
        rows, local = None, {}
        service = verdict(result, ('accepted', 'reason', 'row_count', 'warnings'))
        if stages:
            service['stages'] = stages
        ctx.observe(service_verdict=service, outcome=outcome(result.get('accepted')))
        if result.get('accepted') is True:
            try:
                _, payload = inquiry.saved(store.session_path(name), result['receipt_directory'], 'history',
                                           self.headers(ctx))
                rows = payload.get('rec') if isinstance(payload, dict) else None
                ctx.remember(inquiry={'path': str(path), 'receipt': result['receipt_directory']})
            except (ValueError, OSError, KeyError, TypeError):
                local['saved_rows_unreadable'] = True
        return StepResult(service_verdict=service,
                          outcome=outcome(result.get('accepted')), local=local,
                          result={'rows': masked_rows(rows), 'transfer_confirmed': False})


class TransferHistoryDetail(JointSessionAdapter):
    name = 'hana.inquiry.detail'
    title = '이체 상세'
    requires_target = True
    session_from_parent = True

    def validate(self, value, login=None):
        value = dict_input(value, ('row',), ('row',))
        return {'row': bounded_int(value['row'], 'row', 1, 1000)}

    def check_parent(self, parent, value):
        if parent['name'] != 'hana.inquiry.history' or parent['outcome'] != 'success':
            raise InputError('parent_inquiry_job_required')

    def run(self, ctx, step):
        from finance_cli.services.hana import inquiry, store
        from pathlib import Path
        saved = json.loads(ctx.parent['attempt'] or '{}').get('inquiry') or {}
        if not saved.get('receipt'):
            raise Stop('parent_inquiry_job_required')
        name = self.session(ctx)
        ctx.reserve()
        try:
            result = send_two_step(inquiry.run, name, 'detail', Path(saved['path']), previous=saved['receipt'],
                                   row=ctx.input['row'])
        except (ValueError, OSError) as error:
            raise Stop(safe_code(error), sent=True) from None
        rows = None
        ctx.observe(service_verdict=verdict(result, ('accepted', 'reason', 'warnings')),
                    outcome=outcome(result.get('accepted')))
        if result.get('accepted') is True:
            try:
                _, payload = inquiry.saved(store.session_path(name), result['receipt_directory'], 'detail',
                                           self.headers(ctx))
                rows = payload.get('rec') if isinstance(payload, dict) else None
            except (ValueError, OSError, KeyError, TypeError):
                rows = None
        return StepResult(service_verdict=verdict(result, ('accepted', 'reason', 'warnings')),
                          outcome=outcome(result.get('accepted')),
                          result={'rows': masked_rows(rows), 'transfer_confirmed': False})


class Security(JointSessionAdapter):
    name = 'hana.security.query'
    title = '보안매체·한도 조회'

    def validate(self, value, login=None):
        from finance_cli.services.hana.security_protocol import QUERIES
        value = dict_input(value, ('kind',), ('kind',))
        return {'kind': choice(value['kind'], 'kind', tuple(QUERIES))}

    def run(self, ctx, step):
        from finance_cli.services.hana import security, store
        name, run = self.session(ctx), 'web-' + ctx.job['id'] + '-security'
        ctx.reserve(run=run)
        try:
            result = send_two_step(security.query, name, run, ctx.input['kind'])
        except (ValueError, OSError) as error:
            raise Stop(safe_code(error), sent=True) from None
        observation = None
        ctx.observe(service_verdict=verdict(result, ('accepted', 'kind', 'diagnostics', 'warnings')),
                    outcome=outcome(result.get('accepted')))
        try:
            report = store.read_json(store.child(store.run_path(run), 'observation.json'))
            observation = report.get('observation') or {}
        except (OSError, ValueError):
            pass
        view = None
        if isinstance(observation, dict):
            view = {'fields': scalar_row(observation.get('fields')), 'display': scalar_row(observation.get('display')),
                    'rows': masked_rows(observation.get('rows')), 'diagnostics': observation.get('diagnostics')}
        return StepResult(service_verdict=verdict(result, ('accepted', 'kind', 'diagnostics', 'warnings')),
                          outcome=outcome(result.get('accepted')),
                          result={'kind': ctx.input['kind'], 'observation': view, 'state_change_requested': False})


class Extend(JointSessionAdapter):
    name = 'hana.session.extend'
    title = '하나은행 로그인 연장'

    def run(self, ctx, step):
        from finance_cli.services.hana import extend
        name, run = self.session(ctx), 'web-' + ctx.job['id'] + '-extend'
        ctx.reserve(run=run)
        try:
            result = extend.extend(name, run, send=True)
        except (ValueError, OSError) as error:
            raise Stop(safe_code(error), sent=True) from None
        return StepResult(service_verdict=verdict(result, ('accepted', 'login_extension_accepted', 'reason',
                                                           'warnings')),
                          outcome=outcome(result.get('accepted')),
                          result=pick(result, ('login_extension_accepted', 'native_client_timer_reset_ms',
                                               'server_expires_at', 'session_current_validity', 'observed_at')))


# OneSign path -------------------------------------------------------------

def identity(ctx):
    reference = ctx.snapshot.get('signing') if ctx.adapter.purpose else None
    if reference is None and ctx.parent is not None:
        # A follow-up (result lookup) opens the store its transfer was signed with.
        reference = json.loads(ctx.parent['snapshot'] or '{}').get('signing')
    if isinstance(reference, dict) and reference.get('type') != 'onesign':
        reference = None
    login_credential = json.loads(ctx.login['credential'] or 'null')
    value = (reference or login_credential or {}).get('ref')
    if not value:
        raise Stop('onesign_identity_not_configured')
    return value


class OneSignAdapter(HanaAdapter):
    methods = ('onesign',)

    def resources(self, ctx, step):
        from finance_cli.services.hana import store
        return [store.root('identities') / store.name(identity(ctx)) / 'operation.lock']

    def state(self, ctx):
        from finance_cli.services.hana.onesign_state import State
        passphrase = ctx.secrets.get('vault_passphrase')
        try:
            return State(identity(ctx), passphrase).__enter__()
        except ValueError as error:
            raise Stop(safe_code(error, 'onesign_store_not_opened')) from None
        except OSError:
            raise Stop('onesign_store_not_opened') from None

    def session(self, ctx):
        if ctx.session is None or not ctx.session.get('name'):
            raise Stop('session_not_fixed')
        return ctx.session['name']


class OneSignLogin(OneSignAdapter):
    name = 'hana.onesign.login'
    title = '하나은행 하나인증서 로그인'
    steps = {'run': Step('run', secrets=('vault_passphrase', 'pin'))}

    def run(self, ctx, step):
        from finance_cli.services.hana import onesign
        pin = ctx.secrets.get('pin')
        if not PIN.fullmatch(pin or ''):
            raise Stop('pin_six_digits_required')
        state = self.state(ctx)
        try:
            name = session_name()
            onesign.new_session(state, name)
            ctx.reserve(session=name)
            result = onesign.operate(state, 'login', name + '-login', session=name, send=True,
                                     inputs={'pin': lambda: pin})
        finally:
            pin = ctx.secrets = None
            state.__exit__(None, None, None)
        success = result.get('processing_status') == 'completed' and result.get('accepted') is True
        ctx.observe(service_verdict=verdict(result), outcome=outcome(result.get('accepted'), completed=success))
        session_id = None
        if success:
            from finance_cli.services.hana import store
            with ctx.db.read() as con:
                from .. import model
                previous = model.current_session(con, ctx.login['id'])
            session_id = ctx.register_session(store.root('identities') / identity(ctx), move_pointer=True, name=name,
                                              verdict={'accepted': True}, supersede=previous['id'] if previous else None)
        return StepResult(service_verdict=verdict(result), outcome=outcome(result.get('accepted'), completed=success),
                          result={'session_id': session_id, 'login_method': 'onesign'})


class OneSignReadAdapter(OneSignAdapter):
    uses_session = True
    steps = {'run': Step('run', secrets=('vault_passphrase',))}

    def accepts_session(self, session):
        # Consumed by a transfer is different from superseded by a later login.
        return super().accepts_session(session) or (session is not None
            and session['state'] == 'consumed' and session['note'] == 'transfer_prepared')


class OneSignAccounts(OneSignReadAdapter):
    name = 'hana.onesign.accounts'
    title = '하나은행 계좌 목록·잔액'
    uses_session = True
    steps = {'run': Step('run', secrets=('vault_passphrase',))}

    def run(self, ctx, step):
        from finance_cli.services.hana import onesign
        state = self.state(ctx)
        try:
            ctx.reserve()
            result = onesign.operate(state, 'accounts', 'web-' + ctx.job['id'] + '-accounts', session=self.session(ctx),
                                     send=True)
        finally:
            ctx.secrets = None
            state.__exit__(None, None, None)
        reply = result.get('accounts') if isinstance(result.get('accounts'), dict) else {}
        rows = reply.get('mainAcctList')
        return StepResult(service_verdict=verdict(result), outcome=outcome(result.get('accepted'),
                                                                          completed=result.get('processing_status') ==
                                                                          'completed'),
                          result={'accounts': account_candidates(ctx, rows), 'rows': masked_rows(rows),
                                  'session_current_validity': 'unverified'})


class OneSignExtend(OneSignReadAdapter):
    """One native login extension on the OneSign session; the outcome is the bank's own verdict."""
    name = 'hana.onesign.session.extend'
    title = '하나은행 로그인 연장'

    def run(self, ctx, step):
        from finance_cli.services.hana import onesign_session
        state = self.state(ctx)
        try:
            ctx.reserve()
            result = onesign_session.extend(state, session=self.session(ctx), run='web-' + ctx.job['id'] + '-extend',
                                            send=True)
        finally:
            ctx.secrets = None
            state.__exit__(None, None, None)
        return StepResult(service_verdict=verdict(result, ('accepted', 'login_extension_accepted', 'reason',
                                                           'service_status', 'processing_status', 'error', 'warnings')),
                          outcome=outcome(result.get('accepted'), completed=result.get('processing_status') == 'completed'),
                          result=pick(result, ('login_extension_accepted', 'native_client_timer_reset_ms',
                                               'server_expires_at', 'session_current_validity', 'cookies_saved')))


def transfer_preview(preview):
    """Stable confirmation payload. jobs.public projects the full source number
    from the fixed target without changing existing confirmation digests.
    """
    route = preview.get('authentication') if isinstance(preview.get('authentication'), dict) else {}
    return {'recipient_bank_code': preview.get('recipient_bank_code'),
            'recipient_account': preview.get('recipient_account'), 'recipient_name': preview.get('recipient_name'),
            'amount_krw': preview.get('amount_krw'), 'fee_krw': preview.get('fee_krw'),
            'total_krw': preview.get('total_krw'), 'source_account': mask_account(preview.get('source_account')),
            'authentication': pick(route, ('candidate', 'sign_required', 'bridge_type', 'pin_reentry', 'reason')),
            'state': preview.get('state')}


class Transfer(OneSignAdapter):
    """prepare (account password) → confirm (PIN when required) → execute once."""
    name = 'hana.transfer.prepare'
    title = '원화 이체'
    requires_target = True
    uses_session = True
    purpose = 'transfer_sign'
    confirmation = True
    first_step = 'prepare'
    steps = {'prepare': Step('prepare', secrets=('vault_passphrase', 'account_password')),
             'execute': Step('execute', secrets=('vault_passphrase',)),
             'execute_pin': Step('execute_pin', secrets=('vault_passphrase', 'pin'))}

    def validate(self, value, login=None):
        value = dict_input(value, ('recipient_bank_code', 'recipient_account_number', 'amount_krw'),
                           ('recipient_bank_code', 'recipient_account_number', 'amount_krw'))
        return {'recipient_bank_code': text(value['recipient_bank_code'], 'recipient_bank_code', 3, r'[0-9]{3}'),
                'recipient_account_number': text(value['recipient_account_number'], 'recipient_account_number', 30,
                                                 r'[0-9][0-9-]{5,28}[0-9]'),
                'amount_krw': bounded_int(value['amount_krw'], 'amount_krw', 1, 2 ** 53 - 1)}

    def transaction(self, ctx):
        return 'web-' + ctx.job['id']

    def run(self, ctx, step):
        return self.prepare(ctx) if step == 'prepare' else self.execute(ctx)

    def prepare(self, ctx):
        from finance_cli.services.hana import onesign_transfer
        password = ctx.secrets.get('account_password')
        if not ACCOUNT_PASSWORD.fullmatch(password or ''):
            raise Stop('account_password_four_digits_required')
        intent = {'source_account': account_number(ctx.snapshot.get('target')),
                  'recipient_bank_code': ctx.input['recipient_bank_code'],
                  'recipient_account_number': ctx.input['recipient_account_number'],
                  'amount_krw': ctx.input['amount_krw']}
        state = self.state(ctx)
        try:
            ctx.reserve()
            result = onesign_transfer.operate(state, 'prepare', self.transaction(ctx), 'web-' + ctx.job['id'] + '-prepare',
                                              self.session(ctx), send=True, intent=intent,
                                              inputs={'account_password': lambda: password, 'confirm': lambda p: False,
                                                      'pin': lambda: None})
        finally:
            password = ctx.secrets = None
            state.__exit__(None, None, None)
        service = verdict(result, ('accepted', 'processing_status', 'service_status', 'error', 'transfer_sent'))
        ctx.observe(service_verdict=service, outcome='rejected' if result.get('accepted') is False else 'not_started')
        # One transfer per login session: this session is used up either way.
        ctx.mark_session(ctx.session['id'], 'consumed', 'transfer_prepared')
        if result.get('processing_status') == 'stopped' or result.get('state') != 'prepared':
            local = {'transfer_executed': False}
            if result.get('state') == 'authentication_review':
                local['authentication_not_supported'] = True  # The CLI stops here with the same reason.
            # Preparation never moves money: a refusal is the bank's verdict, anything else did not start.
            return StepResult(service_verdict=service, outcome='rejected' if result.get('accepted') is False else
                              'not_started', local=local,
                              result=transfer_preview(result) if result.get('state') else None)
        preview = transfer_preview(result)
        route = preview['authentication'] or {}
        needs_pin = route.get('bridge_type') == 'pinHalf'
        expires = time.time() + CONFIRM_SECONDS
        review = {'job_id': ctx.job['id'], 'target_id': ctx.snapshot['target']['id'],
                  'login_revision': ctx.job['login_revision'], 'preview': preview}
        ctx.remember(transfer={'transaction': self.transaction(ctx), 'preview_digest': digest(preview)})
        awaiting = {'kind': 'confirm', 'next_step': 'execute_pin' if needs_pin else 'execute',
                    'requires': ['vault_passphrase', 'pin'] if needs_pin else ['vault_passphrase'],
                    'digest': digest(review), 'preview': preview, 'verification': self.verification,
                    'expires_at': expires, 'irreversible': True,
                    'expiry_basis': 'native_client_timer_600000ms'}
        # Nothing has been transferred while the confirmation is pending.
        return StepResult(service_verdict=service, outcome='not_started', result=preview, awaiting=awaiting)

    def execute(self, ctx):
        from finance_cli.services.hana import onesign_transfer
        pin = ctx.secrets.get('pin')
        if ctx.step == 'execute_pin' and not PIN.fullmatch(pin or ''):
            raise Stop('pin_six_digits_required')  # Checked before any reservation.
        saved = ctx.attempt.get('transfer') or {}
        expected = saved.get('preview_digest')
        state = self.state(ctx)
        try:
            ctx.reserve()
            confirm = lambda preview: digest(transfer_preview(preview)) == expected  # noqa: E731
            result = onesign_transfer.operate(state, 'execute', saved['transaction'], 'web-' + ctx.job['id'] + '-execute',
                                              self.session(ctx), send=True,
                                              inputs={'confirm': confirm, 'pin': lambda: pin,
                                                      'account_password': lambda: None})
            execution = result.get('execution_result') if isinstance(result.get('execution_result'), dict) else (
                result if 'transfer_sent' in result else None)
            service = {'processing_status': result.get('processing_status'), 'error': result.get('error'),
                       'service_status': result.get('service_status'),
                       'execution_result': pick(execution, ('accepted', 'original_result_success', 'transfer_sent',
                                                            'transfer_confirmed')) if execution else None}
            if execution is not None:
                # The bank's execution verdict is kept before anything else can fail.
                ctx.observe(service_verdict=service, outcome=outcome(execution.get('accepted')))
            try:
                shown = onesign_transfer.operate(state, 'show', saved['transaction'], None, None)
            except Exception:
                shown = {'execution_attempted': True if execution is not None else None}
        finally:
            pin = ctx.secrets = None
            state.__exit__(None, None, None)
        if execution is not None:
            value = outcome(execution.get('accepted'))
        elif shown.get('execution_attempted') is not False:
            value = 'unknown'  # Attempted or not known: never assume it did not leave.
        else:
            value = 'not_started'
        return StepResult(service_verdict=service, outcome=value,
                          result={'execution_attempted': shown.get('execution_attempted'), 'automatic_retry': False,
                                  'next': 'reconcile' if shown.get('execution_attempted') else None},
                          local={'automatic_retry': False})


class TransferReconcile(OneSignAdapter):
    """Result lookup for an executed transfer; recorded apart from the execution verdict."""
    name = 'hana.transfer.reconcile'
    title = '이체 결과 조회'
    requires_target = True
    uses_session = True
    session_from_parent = True
    accepts_consumed_session = True
    steps = {'run': Step('run', secrets=('vault_passphrase',))}

    def check_parent(self, parent, value):
        attempt = json.loads(parent['attempt'] or '{}')
        if parent['name'] != 'hana.transfer.prepare' or parent['status'] != 'finished' \
                or not (attempt.get('transfer') or {}).get('transaction') or parent['step'] not in ('execute',
                                                                                                    'execute_pin'):
            raise InputError('executed_transfer_job_required')

    def run(self, ctx, step):
        from finance_cli.services.hana import onesign_transfer
        transaction = json.loads(ctx.parent['attempt'] or '{}')['transfer']['transaction']
        state = self.state(ctx)
        try:
            ctx.reserve()
            result = onesign_transfer.operate(state, 'reconcile', transaction, 'web-' + ctx.job['id'] + '-reconcile',
                                              self.session(ctx), send=True)
        finally:
            ctx.secrets = None
            state.__exit__(None, None, None)
        reconciliation = {'queried': result.get('network_used', False),
                          'candidate_complete': result.get('candidate_complete', False),
                          'transfer_confirmed': result.get('transfer_confirmed', False), 'match': result.get('match'),
                          'error': result.get('error') if result.get('processing_status') == 'stopped' else None}
        ctx.observe(reconciliation=reconciliation,
                    service_verdict=verdict(result, ('accepted', 'processing_status', 'service_status', 'error')))
        with ctx.db.write() as con:
            # The transfer's execution verdict and outcome stay as observed.
            from ..db import dumps, now
            con.execute('UPDATE jobs SET reconciliation=?, updated_at=? WHERE id=?',
                        (dumps(reconciliation), now(), ctx.parent['id']))
            ctx.db.event(con, ctx.parent['id'], 'reconciliation_recorded', reconcile_job_id=ctx.job['id'],
                         candidate_complete=reconciliation['candidate_complete'])
        completed = result.get('processing_status') == 'completed'
        return StepResult(service_verdict=verdict(result, ('accepted', 'processing_status', 'service_status', 'error')),
                          outcome='success' if completed else outcome(result.get('accepted'), completed=False),
                          reconciliation=reconciliation, result={'reconciliation': reconciliation})


ADAPTERS = (Login(), Accounts(), History(), HistoryMore(), HistoryDetail(), HistoryExport(), TransferHistory(),
            TransferHistoryDetail(), Security(), Extend(), OneSignLogin(), OneSignAccounts(), OneSignExtend(), Transfer(),
            TransferReconcile())
