"""Giro bill data interpretation. Offline: no login, no network, no payment state.

The uploaded file is the user's own decrypted response data. Due dates and
payment completion are never inferred; ``complete`` and ``issues`` are kept.
"""
from datetime import date, datetime
from zoneinfo import ZoneInfo

from .base import Adapter, InputError, Step, StepResult, Stop, bounded_int, choice, dict_input, iso_date, mask_account

MAX_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64


def nesting_depth(text):
    """Deepest [ or { nesting outside strings; the parser itself has no limit."""
    depth = deepest = 0
    quote = None
    escaped = False
    for character in text:
        if quote:
            if escaped:
                escaped = False
            elif character == '\\':
                escaped = True
            elif character == quote:
                quote = None
        elif character in '"\'':
            quote = character
        elif character in '[{':
            depth += 1
            deepest = max(deepest, depth)
        elif character in ']}':
            depth = max(depth - 1, 0)
    return deepest


def bill_row(item):
    if not isinstance(item, dict):
        return None
    identifiers = item.get('identifiers') or {}
    return {'tax_type': item.get('tax_type'), 'issuer': item.get('issuer'), 'tax_name': item.get('tax_name'),
            'amount': item.get('amount'), 'amount_raw': item.get('amount_raw'), 'due_date': item.get('due_date'),
            'due_date_raw': item.get('due_date_raw'), 'days_until_due': item.get('days_until_due'),
            'electronic_number': mask_account(identifiers.get('elecNo'))}


class BillsParse(Adapter):
    name = 'giro.bills.parse'
    title = '고지서 자료 해석'
    area = 'giro'
    service = 'giro'
    capability = 'bills'
    verification = 'offline'
    requires_login = False
    steps = {'run': Step('run', sends=False)}

    def validate(self, value, login=None):
        value = dict_input(value, ('upload_id', 'tax_type', 'mode', 'today', 'within_days', 'include_overdue'),
                           ('upload_id', 'tax_type'))
        if not isinstance(value['upload_id'], str) or not value['upload_id'].startswith('up_'):
            raise InputError('invalid_upload_id')
        mode = choice(value.get('mode'), 'mode', ('list', 'due')) or 'list'
        include = value.get('include_overdue', False)
        if not isinstance(include, bool):
            raise InputError('invalid_include_overdue')
        return {'upload_id': value['upload_id'],
                'tax_type': choice(value['tax_type'], 'tax_type', ('national', 'local', 'customs')),
                'mode': mode, 'today': iso_date(value.get('today'), 'today'),
                'within_days': bounded_int(value.get('within_days'), 'within_days', 0, 36500)
                if mode == 'due' else None,
                'include_overdue': include if mode == 'due' else False}

    def run(self, ctx, step):
        from giro.bills import due_bills, normalize_pages
        from giro.compat import loads
        from giro.errors import GiroError, ResponseError
        from ..uploads import read_upload
        data = read_upload(ctx.db, ctx.input['upload_id'], 'giro_bills')
        if len(data) > MAX_BYTES:
            raise Stop('input_too_large')
        try:
            text = data.decode('utf-8')
        except UnicodeError:
            raise Stop('input_not_utf8') from None
        if nesting_depth(text) > MAX_DEPTH:
            raise Stop('input_too_deep')
        processed_at = datetime.now(ZoneInfo('Asia/Seoul'))
        base = {'input': {'upload_id': ctx.input['upload_id'], 'tax_type': ctx.input['tax_type']},
                'processed_at': processed_at.isoformat(timespec='seconds'), 'network_used': False,
                'payment_state_inferred': False}
        try:
            result = normalize_pages(loads(text), ctx.input['tax_type'])
            if ctx.input['mode'] == 'due':
                today = date.fromisoformat(ctx.input['today']) if ctx.input['today'] else processed_at.date()
                days = ctx.input['within_days']
                result = due_bills(result, today=today, within_days=7 if days is None else days,
                                   include_overdue=ctx.input['include_overdue'])
        except ResponseError as error:
            verdict = {'app_success': False, 'response_code': error.code, 'callback_code': error.callback_code}
            return StepResult(service_verdict=verdict, outcome='rejected', result=base,
                              local={'source': 'uploaded_response_error'})
        except (GiroError, ValueError, RecursionError):
            return StepResult(service_verdict=None, outcome='not_started', result=base,
                              local={'input_error': 'bill_data_not_readable'}, observed=False)
        verdict = {'app_success': result.get('app_success'), 'response_code': result.get('response_code'),
                   'complete': result.get('complete'), 'filter_complete': result.get('filter_complete')}
        bills = result.get('bills')
        payload = {**base, 'complete': result.get('complete'), 'issues': list(result.get('issues') or [])[:200],
                   'total_count': result.get('total_count'), 'loaded_count': result.get('loaded_count'),
                   'missing_page_count': result.get('missing_page_count'),
                   'bills': None if bills is None else [bill_row(b) for b in bills[:5000]],
                   'as_of': result.get('as_of'), 'through': result.get('through'),
                   'include_overdue': result.get('include_overdue'),
                   'unparsed_count': len(result.get('unparsed_bills') or []) if 'unparsed_bills' in result else None,
                   'mode': ctx.input['mode']}
        complete = result.get('complete') and result.get('filter_complete', True)
        return StepResult(service_verdict=verdict, result=payload, outcome='success' if complete else 'partial_success')


class GiroReadiness(Adapter):
    """Offline support information; never a login."""
    name = 'giro.readiness'
    title = '지로 연결 준비 정보'
    area = 'giro'
    service = 'giro'
    capability = 'auth-plan'
    verification = 'offline'
    requires_login = False
    steps = {'run': Step('run', sends=False)}

    def run(self, ctx, step):
        from giro.protocol import auth_plan, request_plan
        plan = auth_plan()
        steps = [{k: s.get(k) for k in ('endpoint', 'operation', 'mode', 'effect')} for s in plan.get('steps', [])
                 if isinstance(s, dict)]
        requests = []
        for name in ('national.list', 'local.list', 'customs.list'):
            item = request_plan(name)
            requests.append({'name': name, 'network_enabled': item.get('network_enabled'), 'stage': item.get('stage')})
        return StepResult(service_verdict={'live_login_ready': plan.get('live_login_ready')},
                          result={'live_login_ready': plan.get('live_login_ready'), 'steps': steps,
                                  'blockers': list(plan.get('blockers') or []), 'requests': requests,
                                  'network_used': False},
                          outcome='success')


ADAPTERS = (BillsParse(), GiroReadiness())
