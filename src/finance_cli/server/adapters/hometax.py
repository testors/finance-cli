"""Hometax adapters over the existing Node commands.

Every Node command reads one session file and writes a new file holding both
the refreshed session (cookies, storage) and the result. Those files stay in
the private session store and are never returned or downloaded; API results
are built from allowlisted fields. The pointer moves only to a file whose
session was saved; otherwise the previous session becomes ``stale``.

Target selection, target confirmation and the business request run in one
step under the institution lock. Service rows are passed as scalar fields
only, with identifier-like values masked; field names are the service's own
and have not been verified against the live service.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess

from finance_cli.core import storage

from .base import (Adapter, InputError, Step, StepResult, Stop, bounded_int, choice, dict_input, iso_date, mask_account,
                   pick, text)

NODE_TIMEOUT = 900
ROW_LIMIT = 1000
FIELD = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,48}')
IDENTIFIER = re.compile(r'(?i)(dscmno|resno|rrn|bsno|mpbno|telno|emladr|crdno|tin|txprno|jmno)$')
EARLY_ISSUE_STOPS = ('original_preview_required', 'previous_issuance_attempt', 'prepared_business_context_changed',
                     'local_certificate_preflight_incomplete', 'original_certificate_not_selectable')
AMEND_REASONS = {'correction': '01', 'amount-change': '02', 'return': '03', 'cancellation': '04',
                 'local-credit': '05', 'duplicate': '06'}


# Node execution -----------------------------------------------------------

def scripts():
    import hometax_cli
    return Path(hometax_cli.__file__).parent


def node(script, config):
    """Run one Node command; only its own stdout pipe is read."""
    from finance_cli.core.runtime import node_environment
    folder = scripts()
    try:
        process = subprocess.run(['node', '--require', str(folder / 'jsdom_compat.cjs'), str(folder / script)],
                                 input=json.dumps(config), text=True, stdout=subprocess.PIPE, check=False,
                                 env=node_environment(), timeout=NODE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, 'node_timeout'
    except OSError:
        return None, 'node_not_started'
    try:
        summary = json.loads(process.stdout.strip().splitlines()[-1]) if process.stdout.strip() else None
    except (ValueError, IndexError):
        return None, 'invalid_result_json'
    if not isinstance(summary, dict):
        return None, 'missing_result_json'
    return summary, None


def load_record(path):
    try:
        value = json.loads(storage.read(path, limit=256 * 1024 * 1024))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def verdict_of(record, summary=None):
    """The service's own verdict fields: from the saved record, else the stdout summary."""
    source = record if isinstance(record, dict) else summary if isinstance(summary, dict) else None
    if source is None:
        return None
    value = pick(source, ('branch', 'reason', 'action_id', 'login_request_observed', 'session_binding_observed',
                          'refresh_started'))
    data = source.get('data') if isinstance(source.get('data'), dict) else {}
    pagination = data.get('pagination')
    if isinstance(pagination, dict):
        value['pagination'] = pick(pagination, ('requested_all', 'complete', 'reason'))
        pages = data.get('pages')
        if isinstance(pages, list):
            value['page_branches'] = [p.get('branch') for p in pages if isinstance(p, dict)]
    if record is None:
        value['source'] = 'stdout_summary'
    return value


def outcome_of(verdict):
    """Mapping table: success → success; failure → rejected (partial if some pages
    succeeded); no_action or no verdict → unknown. Never inferred from exit codes."""
    if not verdict:
        return 'unknown'
    branch = verdict.get('branch')
    if branch == 'success':
        return 'success'
    if branch == 'failure':
        return 'partial_success' if 'success' in (verdict.get('page_branches') or []) else 'rejected'
    return 'unknown'


def issue_outcome(verdict, data):
    """Invoice issue mapping: early local stops were never sent; a stored invoice
    with an approval number whose completion was not observed is partial."""
    branch, reason = (verdict or {}).get('branch'), (verdict or {}).get('reason')
    if branch == 'success':
        return 'success'
    if branch == 'failure':
        return 'rejected'
    if reason in EARLY_ISSUE_STOPS:
        return 'not_started'
    if isinstance(data, dict) and data.get('storage_branch') == 'success' and (
            data.get('approval_number') or data.get('replacement_approval_number')):
        return 'partial_success'
    return 'unknown'


# Allowlisted user data ----------------------------------------------------

def scalar_row(row):
    if not isinstance(row, dict):
        return None
    result = {}
    for key, value in row.items():
        if not isinstance(key, str) or not FIELD.fullmatch(key):
            continue
        if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
            result[key] = mask_account(value) if IDENTIFIER.search(key) and value is not None else value
        elif isinstance(value, str) and len(value) <= 300:
            result[key] = mask_account(value) if IDENTIFIER.search(key) else value
    return result


def rows(value):
    return [scalar_row(r) for r in value[:ROW_LIMIT]] if isinstance(value, list) else None


def account_view(account):
    if not isinstance(account, dict):
        return None
    return {'name': account.get('userNm') if isinstance(account.get('userNm'), str) else None,
            'tin': mask_account(account.get('tin')), 'switched': account.get('smprYn') == 'Y'}


def origin_tin(account):
    return account.get('rprsTin') or account.get('tin')


# Session chain ----------------------------------------------------------

class Chain:
    """Runs Node commands one after another on the fixed session."""

    def __init__(self, ctx, session=True):
        self.ctx = ctx
        self.session_id = self.path = None
        self.checks = []
        self.expired = False
        self.session_error = False
        if session:
            recheck = ctx.adapter.accepts_stale_session and ctx.session is not None and ctx.session['state'] == 'stale'
            if ctx.session is None or (ctx.session['state'] != 'usable' and not recheck):
                raise Stop('fixed_session_not_usable')
            if ctx.session['login_revision'] != ctx.job['login_revision'] and not recheck:
                raise Stop('session_login_revision_changed')
            self.session_id, self.path = ctx.session['id'], ctx.session_file()
            if not self.path.is_file():
                raise Stop('fixed_session_file_missing')

    def run(self, script, config, *, register=True, output=None, record_name=None):
        if self.ctx.attempt.get('reserved_step') != self.ctx.step:
            self.ctx.reserve()
        out = output or self.ctx.new_session_path('hometax')
        config = {**config, 'output': str(out)}
        if self.path is not None and 'session' not in config and 'capture' not in config:
            config['session'] = str(self.path)
        self.ctx.event('institution_command', command=config.get('command'), operation=config.get('operation'))
        summary, output_error = node(script, config)
        record_path = out / record_name if record_name else out
        record = load_record(record_path)
        if register:
            self.safe_advance(record_path, record)
        return record, summary, output_error

    def safe_advance(self, path, record):
        """The service already answered: a local registration error must not hide that answer."""
        try:
            self.advance(path, record)
        except Exception:
            self.session_error = True
            previous, self.session_id, self.path = self.session_id, None, None
            if previous:
                try:
                    self.ctx.mark_session(previous, 'stale', 'session_registration_failed')
                except Exception:
                    pass

    def local(self, output_error=None):
        value = {'session_saved': self.path is not None}
        if self.session_error:
            value['session_registration_failed'] = True
        if output_error:
            value['output_error'] = output_error
        return value

    def advance(self, path, record):
        if saved(record):
            account = (record.get('data') or {}).get('account') if isinstance(record.get('data'), dict) else None
            validation = record.get('session_validation')
            check = validation if isinstance(validation, dict) else record
            self.session_id = self.ctx.register_session(
                path, move_pointer=True, verdict=pick(check, ('branch', 'reason')), supersede=self.session_id,
                state='expired' if check.get('branch') == 'failure' else 'usable',
                current_target={'tin': account.get('tin')} if isinstance(account, dict) else None)
            self.expired = check.get('branch') == 'failure'
            self.path = None if self.expired else path
        elif self.session_id:
            self.ctx.mark_session(self.session_id, 'stale', 'session_file_not_saved')
            self.session_id = self.path = None

    def require_session(self):
        if self.path is None:
            raise Stop('session_expired' if self.expired else 'session_not_saved', sent=True,
                       detail={'target_check': self.checks})

    def ensure_target(self):
        """Confirm the fixed target in this session, switching once if needed."""
        target = self.ctx.snapshot.get('target')
        if not target:
            raise Stop('target_required')
        wanted = (target.get('identity') or {}).get('tin')
        record, summary, _ = self.run('business.mjs', {'command': 'account', 'operation': 'show', 'domain': 'pp',
                                                       'timeout': 60.0})
        verdict = verdict_of(record, summary) or {}
        self.checks.append({'operation': 'account.show', **verdict})
        account = ((record or {}).get('data') or {}).get('account') if verdict.get('branch') == 'success' else None
        self.require_session()
        if not isinstance(account, dict) or not account.get('tin'):
            raise Stop('target_unverified', sent=True, detail={'target_check': self.checks})
        if account.get('tin') == wanted:
            return account
        select = 'ORIGIN' if target['kind'] == 'personal' else wanted
        record, summary, _ = self.run('business.mjs', {'command': 'business', 'operation': 'select', 'tin': select,
                                                       'timeout': 60.0})
        verdict = verdict_of(record, summary) or {}
        self.checks.append({'operation': 'business.select', **verdict})
        self.require_session()
        account = ((record or {}).get('data') or {}).get('account') if verdict.get('branch') == 'success' else None
        if not isinstance(account, dict) or account.get('tin') != wanted:
            raise Stop('target_unverified', sent=True, detail={'target_check': self.checks})
        return account


def saved(record):
    """A session is usable as the next input only when the file holds it."""
    return isinstance(record, dict) and record.get('session_file_saved', True) is not False \
        and isinstance(record.get('cookie_jar'), (dict, list))


def document_path(output, artifact):
    """A saved standalone HTML file strictly inside the job's report directory, or None."""
    if not isinstance(artifact, dict) or not artifact.get('saved'):
        return None
    file = artifact.get('file')
    if not isinstance(file, str) or not file.endswith('.html'):
        return None
    base = output.resolve()
    path = (output / file).resolve()
    if not path.is_relative_to(base) or not path.is_file():
        return None
    return storage.no_symlinks(path)


def check_runtime():
    from finance_cli.core import runtime
    status = runtime.status()
    if not status['node']:
        raise Stop('node_not_found')
    if not status['installed']:
        raise Stop('hometax_runtime_not_installed')


def check_credential(reference):
    from finance_cli.credentials.registry import Registry
    if not reference or reference.get('type') != 'joint':
        raise Stop('signing_not_configured')
    try:
        entry = Registry().entry(reference['ref'])
    except ValueError:
        raise Stop('credential_not_found') from None
    if entry['certificate_id'] != reference.get('fingerprint'):
        raise Stop('credential_changed')  # Never select another certificate.
    return reference['ref']


def compact_date(value):
    return value.replace('-', '') if value else None


# Adapters ---------------------------------------------------------------

class HometaxAdapter(Adapter):
    service = 'hometax'
    area = 'tax'
    capability = 'hometax'
    verification = 'live_untested'
    uses_session = True

    def resources(self, ctx, step):
        from hometax_cli import serial
        return [serial.lock_path()]


class Login(HometaxAdapter):
    name = 'hometax.login'
    title = '홈택스 공동인증서 로그인'
    uses_session = False
    purpose = 'login'
    steps = {'run': Step('run', secrets=('certificate_password',))}

    def run(self, ctx, step):
        from finance_cli.credentials.registry import Registry
        from hometax_cli.certificate import SignedCertificate, sign_empty, vid_random
        check_runtime()
        alias = check_credential(ctx.snapshot.get('signing'))
        try:
            cert, private, notes = Registry().material(alias, ctx.secrets['certificate_password'].encode('utf-8'))
            callback = SignedCertificate(sign_empty(cert, private), vid_random(private), notes).callback()
        except ValueError as error:
            code = str(error) if re.fullmatch(r'[a-z_]{3,64}', str(error)) else 'certificate_not_usable'
            raise Stop(code) from None
        finally:
            private = None
        ctx.secrets = None
        with ctx.db.read() as con:
            from .. import model
            previous = model.current_session(con, ctx.login['id'])
        chain = Chain(ctx, session=False)
        output = ctx.new_session_path('hometax')
        record, summary, output_error = chain.run('browserless.mjs', {'callback': callback, 'appVersion': '14.3',
                                                                       'timeout': 180.0}, output=output, register=False)
        callback = None
        verdict = verdict_of(record, summary)
        ctx.observe(service_verdict=verdict, outcome=outcome_of(verdict))
        if (verdict or {}).get('branch') == 'success' and saved(record):
            # A new login supersedes the previous pointer; a failed one leaves it alone.
            chain.session_id = previous['id'] if previous is not None else None
            chain.safe_advance(output, record)
        local = chain.local(output_error)
        return StepResult(service_verdict=verdict, outcome=outcome_of(verdict), local=local,
                          result={'login_request_observed': (verdict or {}).get('login_request_observed'),
                                  'session_binding_observed': (verdict or {}).get('session_binding_observed'),
                                  'session_id': chain.session_id if chain.path else None})


class SessionRefresh(HometaxAdapter):
    """Re-checks the current session, including one marked stale by a settings change."""
    name = 'hometax.session.refresh'
    title = '홈택스 세션 확인·갱신'
    accepts_stale_session = True

    def validate(self, value, login=None):
        value = dict_input(value, ('mode',))
        return {'mode': choice(value.get('mode'), 'mode', ('resume', 'refresh')) or 'resume'}

    def run(self, ctx, step):
        check_runtime()
        chain = Chain(ctx)
        record, summary, output_error = chain.run('session.mjs', {'command': 'session', 'operation': ctx.input['mode'],
                                                                   'timeout': 60.0})
        verdict = verdict_of(record, summary)
        return StepResult(service_verdict=verdict, outcome=outcome_of(verdict), local=chain.local(output_error),
                          result={'session_id': chain.session_id if chain.path else None})


class DiscoverTargets(HometaxAdapter):
    """Verification job: candidates come from the service, never from the browser."""
    name = 'hometax.targets.discover'
    title = '홈택스 사용자·사업장 확인'

    def validate(self, value, login=None):
        value = dict_input(value, ('include_closed',))
        if not isinstance(value.get('include_closed', False), bool):
            raise InputError('invalid_include_closed')
        return {'include_closed': value.get('include_closed', False)}

    def run(self, ctx, step):
        check_runtime()
        chain = Chain(ctx)
        record, summary, _ = chain.run('business.mjs', {'command': 'account', 'operation': 'show', 'domain': 'pp',
                                                        'timeout': 60.0})
        account_verdict = verdict_of(record, summary)
        account = ((record or {}).get('data') or {}).get('account') if (account_verdict or {}).get('branch') == 'success' \
            else None
        candidates = []
        if isinstance(account, dict) and origin_tin(account):
            origin = origin_tin(account)
            candidates.append({'ref': 'personal', 'kind': 'personal', 'identity_key': 'personal:' + origin,
                               'label': account.get('userNm') or '개인',
                               'identity': {'tin': origin, 'name': account.get('userNm')},
                               'display': {'tin': mask_account(origin), 'name': account.get('userNm')}})
        verdict = {'account_show': account_verdict}
        if chain.path is not None:
            config = {'command': 'business', 'operation': 'list', 'timeout': 60.0}
            if ctx.input['include_closed']:
                config['status'] = '1'
            record, summary, _ = chain.run('business.mjs', config)
            verdict['business_list'] = verdict_of(record, summary)
            items = ((record or {}).get('data') or {}).get('items') if (verdict['business_list'] or {}).get('branch') \
                == 'success' else None
            for index, item in enumerate(items if isinstance(items, list) else []):
                if not isinstance(item, dict) or not isinstance(item.get('tin'), str) or not item['tin']:
                    continue
                label = next((item[k] for k in ('tnmNm', 'txprNm', 'bmanNm', 'bsnsNm') if isinstance(item.get(k), str)
                              and item[k]), None)
                number = next((item[k] for k in ('txprDscmNo', 'bsno', 'bmanNo') if item.get(k)), None)
                candidates.append({'ref': f'business-{index + 1}', 'kind': 'business',
                                   'identity_key': 'business:' + item['tin'],
                                   'label': label or ('사업장 ' + (mask_account(item['tin']) or '')),
                                   'identity': {'tin': item['tin'], 'name': label,
                                                'business_number': mask_account(number)},
                                   'display': {'tin': mask_account(item['tin']), 'name': label,
                                               'business_number': mask_account(number)}})
        branches = [(v or {}).get('branch') for v in (verdict['account_show'], verdict.get('business_list'))]
        outcome = 'success' if branches == ['success', 'success'] else \
            'partial_success' if 'success' in branches else outcome_of(account_verdict)
        ctx.observe(service_verdict=verdict, outcome=outcome)
        # Full identities stay in the job's private attempt data; browsers get masked candidates.
        ctx.remember(target_candidates=[{k: c[k] for k in ('ref', 'kind', 'identity_key', 'label', 'identity')}
                                        for c in candidates])
        return StepResult(service_verdict=verdict, outcome=outcome,
                          result={'candidates': [{'ref': c['ref'], 'kind': c['kind'], 'label': c['label'],
                                                  **c['display']} for c in candidates],
                                  'current': account_view(account)},
                          local=chain.local())


class TargetQuery(HometaxAdapter):
    """Target check, then one business query, inside one locked step."""
    requires_target = True
    command = operation = None
    fields = ()

    def config(self, value):
        return {}

    def run(self, ctx, step):
        check_runtime()
        chain = Chain(ctx)
        target = ctx.snapshot['target']
        config = {'command': self.command, 'operation': self.operation, 'timeout': 60.0, **self.config(ctx.input)}
        if self.command == 'tax':
            config.update(target={'tin': target['identity']['tin'], 'kind': target['kind']}, timings=True)
            record, summary, output_error = chain.run('business.mjs', config)
            source = {**(summary or {}), **(record or {})}
            checks = source.get('target_check')
            chain.checks = [pick(item, ('operation', 'branch', 'reason', 'action_id'))
                            for item in checks if isinstance(item, dict)] if isinstance(checks, list) else []
            if source.get('target_verified') is False:
                chain.require_session()
                raise Stop('target_unverified', sent=True, detail={'target_check': chain.checks})
            confirmed = {'tin': target['identity']['tin']} if source.get('target_verified') is True else {}
            if confirmed:
                ctx.observe(confirmed_target={'tin': mask_account(confirmed.get('tin')), 'target_id': target['id']})
        else:
            confirmed = chain.ensure_target()
            ctx.observe(confirmed_target={'tin': mask_account(confirmed.get('tin')), 'target_id': target['id']})
            record, summary, output_error = chain.run('business.mjs', config)
        verdict = verdict_of(record, summary)
        verdict = {**(verdict or {}), 'target_check': chain.checks} if verdict else {'target_check': chain.checks}
        data = (record or {}).get('data') if isinstance((record or {}).get('data'), dict) else {}
        local = chain.local(output_error)
        if self.command == 'tax':
            timings = source.get('timings')
            local['timings'] = [pick(item, ('stage', 'duration_ms')) for item in
                                timings if isinstance(item, dict)
                                and item.get('stage') in ('session.open', 'business.select', 'tax.' + self.operation)
                                and type(item.get('duration_ms')) in (int, float)
                                and 0 <= item['duration_ms'] < float('inf')] if isinstance(timings, list) else []
        account = data.get('account')
        mismatch = (self.command == 'tax' and not confirmed) or (
            isinstance(account, dict) and account.get('tin') != target['identity'].get('tin'))
        confirmed_view = {'tin': mask_account(confirmed.get('tin')), 'target_id': target['id']} if confirmed else None
        ctx.observe(service_verdict=verdict, outcome='unknown' if mismatch else outcome_of(verdict))
        if mismatch:
            # The answer's taxpayer differs or is unconfirmed: keep the verdict, withhold the data.
            local['target_mismatch_after_query'] = True
            return StepResult(service_verdict=verdict, outcome='unknown', local=local,
                              confirmed_target=confirmed_view)
        outcome = outcome_of(verdict)
        return StepResult(service_verdict=verdict, outcome=outcome, local=local, result=self.result(data),
                          confirmed_target=confirmed_view)

    def result(self, data):
        pagination = data.get('pagination')
        return {'items': rows(data.get('items')), 'item_count': len(data['items']) if isinstance(data.get('items'),
                                                                                                  list) else None,
                'pagination': pick(pagination, ('requested_all', 'complete', 'reason')) if isinstance(pagination, dict)
                else None,
                'page_info': [pick(p.get('page_info'), ('pageNum', 'pageSize', 'totalCount'))
                              for p in data.get('pages', []) if isinstance(p, dict) and isinstance(p.get('page_info'), dict)]
                if isinstance(data.get('pages'), list) else None}


def period_input(value, extra=(), *, pages=True):
    allowed = ('from', 'to', *(('page', 'all_pages') if pages else ()), *extra)
    value = dict_input(value, allowed)
    result = {'from': iso_date(value.get('from'), 'from'), 'to': iso_date(value.get('to'), 'to')}
    if result['from'] and result['to'] and result['from'] > result['to']:
        raise InputError('invalid_period')
    if pages:
        result['page'] = bounded_int(value.get('page'), 'page', 1, 10000)
        if not isinstance(value.get('all_pages', False), bool):
            raise InputError('invalid_all_pages')
        result['all_pages'] = value.get('all_pages', False)
    return result, value


def period_config(value):
    config = {k: v for k, v in (('from', compact_date(value.get('from'))), ('to', compact_date(value.get('to'))))
              if v}
    if value.get('page'):
        config['page'] = str(value['page'])
    if value.get('all_pages'):
        config['all_pages'] = True
    return config


class TaxDues(TargetQuery):
    name, title, command, operation = 'hometax.tax.dues', '납부할 세액', 'tax', 'dues'


class TaxPayments(TargetQuery):
    name, title, command, operation = 'hometax.tax.payments', '납부 내역', 'tax', 'payments'

    def validate(self, value, login=None):
        result, value = period_input(value, ('payment_type',))
        result['payment_type'] = choice(value.get('payment_type'), 'payment_type', ('01', '03'))
        return result

    def config(self, value):
        return {**period_config(value), **({'payment_type': value['payment_type']} if value.get('payment_type') else {})}


class TaxRefunds(TargetQuery):
    name, title, command, operation = 'hometax.tax.refunds', '환급금', 'tax', 'refunds'

    def validate(self, value, login=None):
        result, value = period_input(value, ('refund_status',))
        status = value.get('refund_status')
        result['refund_status'] = choice(status, 'refund_status', ('1', '2', '3')) if status != '' else ''
        return result

    def config(self, value):
        config = period_config(value)
        if value.get('refund_status') is not None:
            config['refund_status'] = value['refund_status']
        return config


class TaxNotices(TargetQuery):
    name, title, command, operation = 'hometax.tax.notices', '전자고지', 'tax', 'notices'

    def validate(self, value, login=None):
        result, value = period_input(value, ('notice_type', 'read_status', 'tax_code'), pages=False)
        result['notice_type'] = choice(value.get('notice_type'), 'notice_type', ('01', '02'))
        result['read_status'] = choice(value.get('read_status'), 'read_status', ('all', '01', '02'))
        result['tax_code'] = text(value.get('tax_code'), 'tax_code', 10, r'[0-9A-Za-z]+')
        return result

    def config(self, value):
        return {**period_config(value), **{k: value[k] for k in ('notice_type', 'read_status', 'tax_code') if value.get(k)}}


class ReturnsList(TargetQuery):
    name, title, command, operation = 'hometax.returns.list', '신고 내역', 'returns', 'list'

    def validate(self, value, login=None):
        result, value = period_input(value, ('tax_code',))
        result['tax_code'] = text(value.get('tax_code'), 'tax_code', 10, r'[0-9A-Za-z]+')
        return result

    def config(self, value):
        return {**period_config(value), **({'tax_code': value['tax_code']} if value.get('tax_code') else {})}

    def result(self, data):
        value = super().result(data)
        value['taxpayer_choices'] = [pick(c, ('label',)) for c in data.get('taxpayer_choices') or []
                                     if isinstance(c, dict)][:100]
        return value


class ReturnsStatus(ReturnsList):
    name, title, operation = 'hometax.returns.status', '신고 접수 결과', 'status'

    def validate(self, value, login=None):
        value = dict_input(value, ('year', 'month', 'page', 'all_pages', 'tax_code'))
        if not isinstance(value.get('all_pages', False), bool):
            raise InputError('invalid_all_pages')
        return {'year': bounded_int(value.get('year'), 'year', 2000, 2100),
                'month': bounded_int(value.get('month'), 'month', 1, 12),
                'page': bounded_int(value.get('page'), 'page', 1, 10000), 'all_pages': value.get('all_pages', False),
                'tax_code': text(value.get('tax_code'), 'tax_code', 10, r'[0-9A-Za-z]+')}

    def config(self, value):
        config = {k: str(value[k]) for k in ('year', 'page') if value.get(k)}
        if value.get('month'):
            config['month'] = f"{value['month']:02d}"
        if value.get('all_pages'):
            config['all_pages'] = True
        if value.get('tax_code'):
            config['tax_code'] = value['tax_code']
        return config


def return_reference(value):
    value = dict_input(value, ('return_id', 'query_source', 'year', 'month', 'tax_code', 'form_code', 'all_forms'),
                       ('return_id',))
    result = {'return_id': text(value['return_id'], 'return_id', 60, r'[0-9A-Za-z_-]+'),
              'query_source': choice(value.get('query_source'), 'query_source', ('list', 'status')) or 'list',
              'year': bounded_int(value.get('year'), 'year', 2000, 2100),
              'month': bounded_int(value.get('month'), 'month', 1, 12),
              'tax_code': text(value.get('tax_code'), 'tax_code', 10, r'[0-9A-Za-z]+')}
    return result, value


def return_config(value):
    config = {'return_id': value['return_id'], 'query_source': value['query_source']}
    if value.get('year'):
        config['year'] = str(value['year'])
    if value.get('month'):
        config['month'] = f"{value['month']:02d}"
    if value.get('tax_code'):
        config['tax_code'] = value['tax_code']
    return config


class ReturnsForms(ReturnsList):
    name, title, operation = 'hometax.returns.forms', '제출서식', 'forms'

    def validate(self, value, login=None):
        return return_reference(value)[0]

    def config(self, value):
        return return_config(value)

    def result(self, data):
        return {'items': rows(data.get('items')), 'return': scalar_row(data.get('return'))}


class ReturnsReport(HometaxAdapter):
    """Receipt or return document saved as standalone HTML; only the HTML is registered."""
    requires_target = True
    operation = None

    def validate(self, value, login=None):
        result, value = return_reference(value)
        if self.operation == 'document':
            result['form_code'] = text(value.get('form_code'), 'form_code', 20, r'[0-9A-Za-z_-]+')
            if not isinstance(value.get('all_forms', False), bool):
                raise InputError('invalid_all_forms')
            result['all_forms'] = value.get('all_forms', False)
            if result['form_code'] and result['all_forms']:
                raise InputError('form_selection_conflict')
        return result

    def run(self, ctx, step):
        check_runtime()
        chain = Chain(ctx)
        confirmed = chain.ensure_target()
        target = ctx.snapshot['target']
        output = ctx.directory / 'report'
        config = {'command': 'returns', 'operation': self.operation, 'timeout': 60.0, **return_config(ctx.input)}
        if self.operation == 'document':
            if ctx.input.get('form_code'):
                config['form_code'] = ctx.input['form_code']
            if ctx.input.get('all_forms'):
                config['all_forms'] = True
        record, summary, output_error = chain.run('returns_report.mjs', config, output=output, record_name='result.json')
        verdict = {**(verdict_of(record, summary) or {}), 'target_check': chain.checks}
        ctx.observe(service_verdict=verdict, outcome=outcome_of(verdict))
        data = (record or {}).get('data') or {}
        documents = []
        for index, item in enumerate(data.get('documents') or []):
            if not isinstance(item, dict):
                continue
            artifact = item.get('artifact') if isinstance(item.get('artifact'), dict) else {}
            entry = {'form': pick(item.get('form'), ('frmlCd', 'frmlNm')), 'batch': item.get('batch'),
                     'branch': item.get('branch'), 'reason': item.get('reason'),
                     'render_complete': item.get('render_complete'),
                     'artifact': pick(artifact, ('saved', 'complete', 'page_count', 'image_count', 'missing_images',
                                                 'invalid_images', 'external_references')), 'artifact_id': None}
            path = document_path(output, artifact)
            if path is not None:
                name = (entry['form'] or {}).get('frmlNm') or '접수증'
                try:
                    entry['artifact_id'] = ctx.add_artifact('hometax_report', f'{name}-{index + 1}.html',
                                                            'text/html; charset=utf-8', storage.read(path, 64 * 1024 * 1024),
                                                            complete=artifact.get('complete'))
                except (OSError, ValueError):
                    entry['artifact_registration_failed'] = True
            documents.append(entry)
        collection = (record or summary or {}).get('collection')
        local = chain.local(output_error)
        return StepResult(service_verdict=verdict, outcome=outcome_of(verdict), local=local,
                          result={'documents': documents,
                                  'collection': pick(collection, ('requested_all_forms', 'complete', 'artifacts_complete'))
                                  if isinstance(collection, dict) else None,
                                  'selected': scalar_row(data.get('selected'))},
                          confirmed_target={'tin': mask_account(confirmed.get('tin')), 'target_id': target['id']})


class ReturnsReceipt(ReturnsReport):
    name, title, operation = 'hometax.returns.receipt', '신고 접수증 저장', 'receipt'


class ReturnsDocument(ReturnsReport):
    name, title, operation = 'hometax.returns.document', '신고서 저장', 'document'


class ReportResave(HometaxAdapter):
    """Re-render a captured report again; it never re-runs the original query."""
    name = 'hometax.report.resave'
    title = '보고서 다시 저장'
    uses_session = False

    def validate(self, value, login=None):
        value = dict_input(value, ('document',), ('document',))
        return {'document': bounded_int(value.get('document'), 'document', 1, 999)}

    def check_parent(self, parent, value):
        if parent['name'] not in ('hometax.returns.receipt', 'hometax.returns.document') or parent['status'] != 'finished':
            raise InputError('parent_report_job_required')

    def run(self, ctx, step):
        from ..worker import job_directory
        check_runtime()
        if ctx.parent is None:
            raise Stop('parent_report_job_required')
        source = job_directory(ctx.parent['id']) / 'report' / f"document-{ctx.input['document']:03d}" / 'source' / \
            'capture.json'
        if not source.is_file():
            raise Stop('capture_not_found')
        chain = Chain(ctx, session=False)
        output = ctx.directory / f"resave-{ctx.input['document']:03d}"
        record, summary, output_error = chain.run('report.mjs', {'capture': str(source), 'timeout': 60.0},
                                                  output=output, record_name='result.json', register=False)
        verdict = verdict_of(record, summary)
        ctx.observe(service_verdict=verdict, outcome=outcome_of(verdict))
        artifact = (summary or {}).get('artifact') or (record or {}).get('artifact') or {}
        artifact_id = None
        path = document_path(output, artifact) if isinstance(artifact, dict) else None
        if path is not None:
            try:
                artifact_id = ctx.add_artifact('hometax_report', f"report-{ctx.input['document']}.html",
                                               'text/html; charset=utf-8', storage.read(path, 64 * 1024 * 1024),
                                               complete=artifact.get('complete'))
            except (OSError, ValueError):
                artifact_id = None
        return StepResult(service_verdict=verdict, outcome=outcome_of(verdict),
                          local={'reprocessing': True, **({'output_error': output_error} if output_error else {})},
                          result={'render_complete': (record or summary or {}).get('render_complete'),
                                  'artifact': pick(artifact, ('saved', 'complete', 'page_count', 'image_count',
                                                              'missing_images')) if isinstance(artifact, dict) else None,
                                  'artifact_id': artifact_id})


class InvoiceList(TargetQuery):
    name, title, command, operation = 'hometax.invoice.list', '전자세금계산서 조회', 'invoice', 'list'

    def validate(self, value, login=None):
        result, value = period_input(value, ('direction', 'invoice_type', 'classification'))
        result['direction'] = choice(value.get('direction'), 'direction', ('sales', 'purchases')) or 'sales'
        result['invoice_type'] = choice(value.get('invoice_type'), 'invoice_type', ('01', '03'))
        result['classification'] = choice(value.get('classification'), 'classification', ('all', '01', '02', '03', '04'))
        return result

    def config(self, value):
        return {**period_config(value), 'direction': value['direction'],
                **{k: value[k] for k in ('invoice_type', 'classification') if value.get(k)}}

    def result(self, data):
        value = super().result(data)
        value['totals'] = scalar_row(data.get('totals'))
        return value


APPROVAL = r'[0-9]{8}-?[0-9A-Za-z]{8}-?[0-9A-Za-z]{8}'


class InvoiceDetail(TargetQuery):
    name, title, command, operation = 'hometax.invoice.detail', '전자세금계산서 상세', 'invoice', 'detail'

    def validate(self, value, login=None):
        value = dict_input(value, ('approval_number',), ('approval_number',))
        return {'approval_number': text(value['approval_number'], 'approval_number', 30, APPROVAL)}

    def config(self, value):
        return {'approval_number': value['approval_number']}

    def result(self, data):
        return {'invoice': scalar_row(data.get('invoice')), 'items': rows(data.get('items')),
                'settlement': scalar_row(data.get('settlement'))}


# Invoice drafts and issuance ---------------------------------------------

PARTY = {'name': 60, 'representative': 30, 'address': 150, 'business_type': 40, 'business_item': 40,
         'branch_number': 4, 'email': 80}
ITEM = {'month': 2, 'day': 2, 'name': 100, 'specification': 60, 'remark': 100}
AMOUNTS = ('quantity', 'unit_price', 'supply_amount', 'tax_amount')


def party_input(value, name, extra=()):
    fields = {**PARTY, **{k: 80 for k in extra}}
    value = dict_input(value, (*fields, 'business_number') if name == 'buyer' else fields)
    result = {k: text(value.get(k), f'{name}_{k}', limit) for k, limit in fields.items() if value.get(k) is not None}
    if name == 'buyer' and value.get('business_number') is not None:
        result['business_number'] = text(value['business_number'], 'buyer_business_number', 12, r'[0-9]{3}-?[0-9]{2}-?[0-9]{5}')
    return result


def draft_input(value, *, required=True):
    value = dict_input(value, ('supplier', 'buyer', 'date', 'remark', 'items', 'settlement'))
    result = {}
    if value.get('supplier') is not None:
        result['supplier'] = party_input(value['supplier'], 'supplier')
    if value.get('buyer') is not None:
        result['buyer'] = party_input(value['buyer'], 'buyer', ('secondary_email',))
    if required and not (result.get('buyer') or {}).get('business_number'):
        raise InputError('input_required:buyer.business_number')
    if value.get('date') is not None:
        result['date'] = compact_date(iso_date(value['date'], 'date')) if '-' in str(value['date']) else \
            text(value['date'], 'date', 8, r'[0-9]{8}')
    if value.get('remark') is not None:
        result['remark'] = text(value['remark'], 'remark', 150)
    if value.get('items') is not None:
        items = value['items']
        if not isinstance(items, list) or not 1 <= len(items) <= 4:
            raise InputError('invalid_items')
        result['items'] = []
        for item in items:
            item = dict_input(item, (*ITEM, *AMOUNTS))
            row = {k: text(item.get(k), 'item_' + k, limit) for k, limit in ITEM.items() if item.get(k) is not None}
            for key in AMOUNTS:
                if item.get(key) is not None:
                    row[key] = bounded_int(item[key], 'item_' + key, -99999999999, 99999999999)
            result['items'].append(row)
    if value.get('settlement') is not None:
        settlement = dict_input(value['settlement'], ('cash', 'check', 'note', 'credit', 'type'))
        result['settlement'] = {k: text(str(settlement[k]), 'settlement_' + k, 15, r'-?[0-9]*')
                                for k in ('cash', 'check', 'note', 'credit') if settlement.get(k) not in (None, '')}
        if settlement.get('type') is not None:
            result['settlement']['type'] = choice(settlement['type'], 'settlement_type', ('claim', 'receipt'))
    return result


def draft_preview(draft):
    """Allowlisted review fields of the service draft (supplier, buyer, items, amounts)."""
    if not isinstance(draft, dict):
        return None
    supplier = pick(draft.get('splrInfrBizSVO'), ('splrTxprDscmNo', 'splrTnmNm', 'splrRprsFnm', 'splrPfbAdr', 'splrBcNm',
                                                  'splrItmNm', 'splrChrgEmlAdr'))
    buyer = pick(draft.get('dmnrInfrBizSVO'), ('dmnrTxprDscmNo', 'dmnrTnmNm', 'dmnrRprsFnm', 'dmnrPfbAdr', 'dmnrBcNm',
                                               'dmnrItmNm', 'dmnrMchrgEmlAdr', 'dmnrSchrgEmlAdr'))
    items = [pick(i, ('lsatSplDt', 'lsatSplMm', 'lsatSplDd', 'lsatNm', 'lsatRszeNm', 'lsatQty', 'lsatUtprc', 'lsatSplCft',
                      'lsatTxamt', 'lsatRmrkCntn')) for i in (draft.get('lsatInfrBizSVOList') or []) if isinstance(i, dict)]
    return {'kind': pick(draft.get('etxivObj'), ('etxivClsfCd', 'etxivKndCd')), 'supplier': supplier, 'buyer': buyer,
            'items': items[:10],
            'totals': pick(draft.get('sncInfrBizSVO'), ('wrtDt', 'sumAmt', 'splCft', 'txamt', 'rmrkCntn')),
            'settlement': pick(draft.get('sncClInfrBizSVO'), ('csh', 'chck', 'note', 'crit', 'recApeClCd', 'sumAmt'))}


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class InvoiceDraft(HometaxAdapter):
    """prepare → (confirm with the issuing certificate password) → issue once."""
    requires_target = True
    purpose = 'invoice_sign'
    confirmation = True
    first_step = 'prepare'
    steps = {'prepare': Step('prepare'), 'issue': Step('issue', secrets=('certificate_password',))}

    def run(self, ctx, step):
        return self.prepare(ctx) if step == 'prepare' else self.issue(ctx)

    def node_config(self, ctx):
        raise NotImplementedError

    def prepare(self, ctx):
        check_runtime()
        check_credential(ctx.snapshot.get('signing'))
        chain = Chain(ctx)
        confirmed = chain.ensure_target()
        target = ctx.snapshot['target']
        config = {'timeout': 60.0, **self.node_config(ctx)}
        record, summary, output_error = chain.run('business.mjs', config)
        verdict = {**(verdict_of(record, summary) or {}), 'target_check': chain.checks}
        # Nothing is issued by preparing; the service's preview verdict is kept as observed.
        ctx.observe(service_verdict=verdict, outcome='not_started' if verdict.get('branch') == 'success'
                    else outcome_of(verdict))
        data = (record or {}).get('data') or {}
        local = chain.local(output_error)
        confirmed_target = {'tin': mask_account(confirmed.get('tin')), 'target_id': target['id']}
        ready = verdict.get('branch') == 'success' and verdict.get('reason') == 'original_preview_ready' \
            and chain.path is not None and isinstance(data.get('draft'), dict)
        preview = {'draft': draft_preview(data.get('draft')), 'issued': data.get('issued'),
                   'stage': data.get('stage') if isinstance(data.get('stage'), str) else None,
                   **{k: data.get(k) for k in ('kind', 'original_approval_number', 'amendment_reason', 'document_count')
                      if k in data}}
        if not ready:
            return StepResult(service_verdict=verdict, outcome=outcome_of(verdict), local=local, result=preview,
                              confirmed_target=confirmed_target)
        prepared = chain.path
        signing = ctx.snapshot['signing']
        review = {'job_id': ctx.job['id'], 'target': target, 'login_revision': ctx.job['login_revision'],
                  'signing': {'ref': signing['ref'], 'fingerprint': signing['fingerprint']},
                  'prepared_sha256': hashlib.sha256(storage.read(prepared, 256 * 1024 * 1024)).hexdigest(),
                  'preview': preview}
        ctx.remember(prepared_session_id=chain.session_id, prepared_sha256=review['prepared_sha256'])
        awaiting = {'kind': 'confirm', 'next_step': 'issue', 'requires': ['certificate_password'],
                    'digest': digest(review), 'preview': preview, 'signing_credential': signing['ref'],
                    'verification': self.verification, 'document_count': data.get('document_count', 1),
                    'irreversible': True}
        # Nothing has been issued while the confirmation is pending.
        return StepResult(service_verdict=verdict, outcome='not_started', local=local, result=preview,
                          awaiting=awaiting, confirmed_target=confirmed_target)

    def issue(self, ctx):
        from .. import model
        check_runtime()
        alias = check_credential(ctx.snapshot.get('signing'))
        session_id = ctx.attempt.get('prepared_session_id')
        with ctx.db.read() as con:
            row = con.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
            login = model.get_login(con, ctx.login['id'], raw=True)
        if login['revision'] != ctx.job['login_revision']:
            raise Stop('login_revision_changed')
        if row is None or row['state'] != 'usable':
            raise Stop('prepared_session_superseded')  # The same draft file path is required; prepare again.
        from ..worker import resolve_private
        prepared = resolve_private(row['location'])
        if hashlib.sha256(storage.read(prepared, 256 * 1024 * 1024)).hexdigest() != ctx.attempt.get('prepared_sha256'):
            raise Stop('prepared_draft_changed')
        chain = Chain(ctx, session=False)
        chain.session_id, chain.path = session_id, prepared
        password = base64.b64encode(ctx.secrets['certificate_password'].encode('utf-8')).decode('ascii')
        ctx.secrets = None
        record, summary, output_error = chain.run('business.mjs', {
            'command': 'invoice', 'operation': 'issue', 'prepared': str(prepared), 'session': str(prepared),
            'timeout': 60.0, 'credential': alias, 'password': password})
        password = None
        verdict = verdict_of(record, summary)
        data = (record or {}).get('data') if isinstance((record or {}).get('data'), dict) else {}
        issued = pick(data, ('storage_branch', 'notification_branch', 'approval_number', 'kind',
                             'original_approval_number', 'cancellation_approval_number', 'replacement_approval_number',
                             'automatic_retry', 'issued'))
        if isinstance(data.get('certificate'), dict):
            issued['certificate'] = pick(data['certificate'], ('selectable', 'policy_matches', 'expired_in_original_list',
                                                                'not_after'))
        verdict = {**(verdict or {}), 'storage_branch': data.get('storage_branch'),
                   'notification_branch': data.get('notification_branch')}
        ctx.observe(service_verdict=verdict, outcome=issue_outcome(verdict, data), result=issued)
        local = {**chain.local(output_error), 'session_saved': chain.path is not None and chain.path != prepared,
                 'automatic_retry': False}
        return StepResult(service_verdict=verdict, outcome=issue_outcome(verdict, data), local=local, result=issued)


class InvoicePrepare(InvoiceDraft):
    name = 'hometax.invoice.prepare'
    title = '전자세금계산서 작성·발급'

    def validate(self, value, login=None):
        return draft_input(value)

    def node_config(self, ctx):
        path = ctx.directory / 'draft-input.json'
        if not path.exists():
            storage.write_new(path, json.dumps(ctx.input, ensure_ascii=False).encode('utf-8'))
        return {'command': 'invoice', 'operation': 'prepare', 'input': str(path)}


class InvoiceAmend(InvoiceDraft):
    name = 'hometax.invoice.amend'
    title = '수정 전자세금계산서 작성·발급'

    def validate(self, value, login=None):
        value = dict_input(value, ('approval_number', 'reason', 'changes'), ('approval_number', 'reason'))
        return {'approval_number': text(value['approval_number'], 'approval_number', 30, APPROVAL),
                'reason': choice(value['reason'], 'reason', tuple(AMEND_REASONS)),
                'changes': draft_input(value['changes'], required=False) if value.get('changes') else None}

    def node_config(self, ctx):
        config = {'command': 'invoice', 'operation': 'amend', 'approval_number': ctx.input['approval_number'],
                  'reason': ctx.input['reason']}
        if ctx.input.get('changes'):
            path = ctx.directory / 'amend-input.json'
            if not path.exists():
                storage.write_new(path, json.dumps(ctx.input['changes'], ensure_ascii=False).encode('utf-8'))
            config['input'] = str(path)
        return config


ADAPTERS = (Login(), SessionRefresh(), DiscoverTargets(), TaxDues(), TaxPayments(), TaxRefunds(), TaxNotices(),
            ReturnsList(), ReturnsStatus(), ReturnsForms(), ReturnsReceipt(), ReturnsDocument(), ReportResave(),
            InvoiceList(), InvoiceDetail(), InvoicePrepare(), InvoiceAmend())
