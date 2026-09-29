"""Read-only transfer history, detail and ledger queries with a recorded login.

Each query is prepared first and sent only with --send, and only if the
prepared draft is unchanged. No login refresh, signing, automatic pagination or
retry. A historical login success is not evidence of a current session.
"""
from datetime import datetime, timedelta
import math
import re
from zoneinfo import ZoneInfo

from . import login, store, transport
from .compat import bank_business_headers, truthy, web_value
from .evidence import account, amount, identifiers, nonblank
from .hana_protocol import API
from .ledger_protocol import cursor as ledger_cursor, number

PATHS = {
    'history': '/api/pcm/trns01/capi/trnsPtclInq/retrievetxnOurTrns',
    'detail': '/api/pcm/trns01/capi/trnsPtclInq/retrievedtlOurTrnsPtcl',
    'ledger': '/api/pcm/slct01/capi/trscPtclInq/retrievetxnNrstTrsc',
    'accounts': login.ACCOUNTS_PATH,
}
KINDS = ('history', 'detail', 'ledger')
INPUT_KEYS = {'account_index', 'start_date', 'end_date'}
CURSOR = ('wdrwDstnDt', 'dtlsSeqNo', 'trscSeqNo', 'nextTrscYn')


def date_value(value):
    if not isinstance(value, str) or len(value) != 8 or not value.isascii() or not value.isdigit():
        raise ValueError('expected_yyyyMMdd')
    datetime.strptime(value, '%Y%m%d')
    return value


def today_kst():
    return datetime.now(ZoneInfo('Asia/Seoul')).date()


def check_period(start, end):
    today = today_kst()
    try:
        oldest = today.replace(year=today.year - 2)
    except ValueError:  # February 29 falls back to the calendar-year boundary.
        oldest = today.replace(year=today.year - 2, day=28)
    oldest += timedelta(days=1)
    if start > end or start < oldest.strftime('%Y%m%d') or end > today.strftime('%Y%m%d'):
        raise ValueError('only_a_recent_two_year_period_through_the_local_kst_date_is_supported')


def next_page(kind, request, payload):
    """The page's own continuation; data quality is reported as warnings."""
    if not isinstance(payload, dict):
        raise ValueError('accepted_response_has_no_usable_pagination_object')
    if kind == 'history':
        rows = payload.get('rec')
        if not rows:
            return None
        if not isinstance(rows, list):
            raise ValueError('accepted_response_rows_cannot_be_paginated')
        # strPost and rqstNcnt are integer strings produced by this command.
        page, size = int(request['strPost']), int(request['rqstNcnt'])
        count = payload.get('recNcnt')
        observed = (page - 1) * size + len(rows)
        return ({'strPost': str(page + 1)} if truthy(count) and observed < number(count)
                and len(rows) >= size else None)
    if kind == 'ledger':
        value = ledger_cursor('recent', payload)
        if value is not None and any(type(v) is float and not math.isfinite(v) for v in value.values()):
            raise ValueError('accepted_response_has_an_unusable_continuation_cursor')
        return value
    return None


def assess(kind, status, headers, body, request=None, previous_total=None):
    result = {'accepted': False, 'reason': 'unconfirmed_query_response', 'warnings': [],
              'transfer_confirmed': False, 'resend_allowed': False}
    try:
        if not 200 <= status < 300:
            raise ValueError('http_error')
        result['processing_result'] = bank_business_headers(headers, web=True)
    except (KeyError, TypeError, ValueError, UnicodeError, AttributeError):
        result['reason'] = 'http_or_business_error'
        return result
    result.update(accepted=True, reason='read_only_query_response_accepted')
    payload = web_value(body)
    try:
        if kind not in KINDS or not isinstance(payload, dict):
            raise ValueError('unexpected_response')
        rows = payload.get('grid1' if kind == 'ledger' else 'rec')
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise ValueError('missing_or_malformed_rows')
        result['row_count'] = len(rows)
        count = amount(payload.get('recNcnt1' if kind == 'ledger' else 'recNcnt'))
        if kind == 'ledger' and count != len(rows):
            result['warnings'].append('row_count_differs_from_array')
        if kind == 'history' and request:
            observed = (int(request['strPost']) - 1) * int(request['rqstNcnt']) + len(rows)
            if count is None or observed > count or (len(rows) < int(request['rqstNcnt']) and observed < count):
                result['warnings'].append('history_count_inconsistent')
        if kind != 'detail' and request:
            cursor = next_page(kind, request, payload)
            if cursor and kind == 'ledger' and store.digest(cursor) == store.digest({k: request[k] for k in CURSOR}):
                result['warnings'].append('repeated_cursor')
        if kind == 'history' and previous_total is not None and amount(payload.get('recNcnt')) != previous_total:
            result['warnings'].append('history_total_changed')
    except (KeyError, TypeError, ValueError, UnicodeError, AttributeError, OverflowError):
        result['warnings'].append('response_data_unavailable_or_inconsistent')
    return result


def saved(session, receipt, kind, headers):
    """Reassess the saved bytes instead of trusting an editable assessment flag."""
    request, response, raw = transport.read_receipt(session, receipt)
    if request.get('method') != 'POST' or request.get('url') != API + PATHS[kind]:
        raise ValueError('wrong_receipt_endpoint')
    old = {k.lower(): v for k, v in request['headers'].items()}
    if any(not nonblank(old.get(k)) or old[k] != headers[k] for k in login.IDENTITY):
        raise ValueError('receipt_belongs_to_a_different_recorded_login')
    previous_total = (request.get('inquiry', {}).get('previous') or {}).get('history_total')
    assessment = (login.assess('accounts', response['status'], response['headers'], raw) if kind == 'accounts'
                  else assess(kind, response['status'], response['headers'], raw, request['body'], previous_total))
    if not assessment['accepted']:
        raise ValueError('saved_query_was_not_accepted')
    return request, web_value(raw)


def authenticated_account(session, value):
    """Recorded login plus the main-account provenance of the selected account."""
    if type(value['account_index']) is not int or value['account_index'] < 1:
        raise ValueError('expected_a_positive_account_index')
    request = login.authenticated_session(session)
    headers = {k.lower(): v for k, v in request['headers'].items()}
    selection = store.read_json(store.child(session, 'account-selection.json'))
    if selection.get('source') != 'accounts/body.bin':
        raise ValueError('selection_must_refer_to_this_session_main_account_receipt')
    _, accounts = saved(session, 'accounts', 'accounts', headers)
    selected = [r for r in selection['accounts'] if r.get('index') == value['account_index']]
    if len(selected) != 1:
        raise ValueError('account_selection_is_not_unique')
    selected = selected[0]
    matches = [r for r in accounts['mainAcctList'] if r.get('acctNo') == selected.get('acctNo')]
    if len(matches) != 1 or any(matches[0].get(k) != v for k, v in selected.items() if k != 'index'):
        raise ValueError('account_selection_differs_from_the_recorded_response')
    if account(selected.get('acctNo')) is None or selected.get('curCd') != 'KRW':
        raise ValueError('expected_a_krw_account')
    return request, selected


def read_query(path):
    value = store.read_input(path)
    if not isinstance(value, dict) or set(value) != INPUT_KEYS:
        raise ValueError('unexpected_inquiry_input_fields: ' + ', '.join(sorted(INPUT_KEYS)))
    return value


def prepare(session, kind, value, previous=None, row=None, snapshot=None):
    if kind not in KINDS:
        raise ValueError('only_read_only_inquiry_stages_are_supported')
    if snapshot is not None and (not isinstance(snapshot, str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,39}', snapshot) is None):
        raise ValueError('snapshot_must_be_a_non_secret_lowercase_label_of_at_most_40_characters')
    start, end = date_value(value['start_date']), date_value(value['end_date'])
    check_period(start, end)
    if kind == 'detail':
        if previous is None or type(row) is not int or row < 1:
            raise ValueError('detail_requires_a_saved_history_receipt_and_a_positive_row')
    elif row is not None:
        raise ValueError('row_is_only_for_detail')
    request, selected = authenticated_account(session, value)
    headers = {k.lower(): v for k, v in request['headers'].items()}
    number_ = account(selected['acctNo'])
    history = {'rqstNcnt': '20', 'strPost': '1', 'trnsRsltBizDvCd': '', 'trnsInqDvCd': '',
               'wdrwAcctNo': number_, 'inqBascStrDt': start, 'inqBascEndDt': end,
               'srchDvCd': '0', 'srchWdNm': '', 'trscSeqInqDvCd': '2'}
    ledger = {'inqEndDt': end, 'rvSeqInqYn': 'Y', 'rcvWdrwDvCd': '0', 'srchStrnCtt': '',
              'acctNo': number_, 'curCd': 'KRW', 'inqStrDt': start, 'dtlsSeqNo': 0, 'trscSeqNo': 0,
              'fastInqYn': 'N', 'wdrwDstnDt': '', 'nextTrscYn': '', 'inqRqreNcnt': 100, 'trscPtclSrchDvCd': ''}
    body = dict(ledger if kind == 'ledger' else history)
    predecessor = None
    if previous is not None:
        prior_kind = 'history' if kind == 'detail' else kind
        old, payload = saved(session, previous, prior_kind, headers)
        cursors = CURSOR if prior_kind == 'ledger' else ('strPost',)
        if set(old['body']) != set(body) or store.digest({k: v for k, v in old['body'].items() if k not in cursors}) \
                != store.digest({k: v for k, v in body.items() if k not in cursors}):
            raise ValueError('previous_query_scope_differs')
        predecessor = {'receipt': previous, 'request_sha256': store.digest(old), 'body_sha256': store.digest(payload)}
        if kind == 'history':
            predecessor['history_total'] = amount(payload.get('recNcnt'))
        if kind == 'detail':
            if row > len(payload['rec']):
                raise ValueError('detail_row_is_outside_saved_history')
            body = identifiers(payload['rec'][row - 1])
            if body is None or sum(identifiers(r) == body for r in payload['rec']) != 1:
                raise ValueError('detail_identifiers_are_missing_or_not_unique_in_the_saved_page')
        else:
            cursor = next_page(kind, old['body'], payload)
            if cursor is None:
                raise ValueError('no_next_page_in_saved_response')
            body.update(cursor)
    request.update(url=API + PATHS[kind], body=body, live_verified=False,
                   mode='prepared read-only inquiry; no request sent',
                   inquiry={'kind': kind, 'input_sha256': store.digest(value), 'previous': predecessor,
                            'session_current_validity': 'unverified', 'transfer_confirmed': False})
    name = 'inquiry-' + kind + '-' + store.digest(body)[:20]
    if snapshot is not None:
        request['inquiry']['snapshot'] = snapshot
        name += '-' + snapshot
    return request, name


def run(name, kind, input_path, *, previous=None, row=None, send=False, snapshot=None):
    session = store.session_path(name)
    value = read_query(input_path)
    with store.lock(session):
        request, receipt = prepare(session, kind, value, previous, row, snapshot)
        draft = store.child(session, receipt + '-prepared.json')
        if not send:
            if not draft.exists():
                store.write_new(draft, request)
            elif store.digest(store.read_json(draft)) != store.digest(request):
                raise ValueError('an_earlier_draft_differs_review_inputs_and_session')
            return {'network_used': False, 'kind': kind, 'prepared_request': draft.name,
                    'receipt_directory': receipt, 'session_current_validity': 'unverified',
                    'transfer_confirmed': False, 'next': 'same_command_with_send'}
        if store.digest(store.read_json(draft)) != store.digest(request):
            raise ValueError('prepared_request_changed_review_inputs_and_session')
        previous_total = (request['inquiry']['previous'] or {}).get('history_total')
        result = transport.send(session, receipt, request, lambda stage, status, headers, body: assess(
            kind, status, headers, body, request['body'], previous_total))
        result['receipt_directory'] = receipt
        result['automatic_retry'] = False
        return result
