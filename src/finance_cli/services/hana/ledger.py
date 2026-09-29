"""Ordinary KRW account ledger: explicit single-query drafts, offline details and CSV.

No login, session refresh, signing, transfer, automatic pagination or retry.
The server clock, account information, each page and each detail are sent only
with --send and only for an unchanged draft. Pages form a receipt chain whose
scope, order and cursors are checked again from the saved bytes.
"""
import csv
from datetime import datetime
import io
import math
import re

from . import inquiry, login, ledger_protocol as protocol, store, transport
from .compat import bank_business_headers, kotlin_object, web_value
from .hana_protocol import API, decode_header, encode_header

KINDS = ('clock', 'account', 'page', 'detail')
CONFIG_KEYS = {'account_index', 'start_date', 'end_date', 'direction', 'order', 'search'}
REQUIRED_KEYS = {'account_index', 'start_date', 'end_date'}


def assess(kind, status, headers, raw):
    result = {'accepted': False, 'network_used': True, 'automatic_retry': False,
              'transfer_confirmed': False, 'resend_allowed': False, 'warnings': []}
    try:
        if not (status == 200 if kind == 'clock' else 200 <= status < 300):
            raise ValueError('http_failure')
        bank_business_headers(headers, web=kind != 'clock')
    except (ValueError, TypeError, KeyError, AttributeError):
        result['reason'] = 'http_or_business_error'
        return result
    result.update(accepted=True, reason='read_only_response_accepted')
    try:
        value = payload(kind, raw)
        if not isinstance(value, dict):
            raise ValueError('response_object_required')
        if kind in ('recent', 'past'):
            result.update(row_count=len(protocol.rows(kind, value)), diagnostics=protocol.diagnostics(kind, value))
        elif kind in ('account', 'loan-account') and not protocol.nonempty(value.get('acctInfo')):
            raise ValueError('account_info_absent')
        result['warnings'].extend(result.get('diagnostics', []))
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        result['warnings'].append('response_data_unavailable')
    return result


def payload(kind, raw):
    if kind == 'clock':
        value = kotlin_object(raw, string_fields=('dt', 'tm', 'bussDdYn'))
        if not all(k in value for k in ('dt', 'tm', 'bussDdYn')):
            raise ValueError('missing_native_clock_fields')
        return protocol.normalize_server_clock(value)
    return web_value(raw)


def receipt(session, name, headers, *, expected=None):
    request, response, raw = transport.read_receipt(session, name)
    kind = request.get('account_history', {}).get('kind')
    if kind not in protocol.PATHS or expected is not None and kind not in expected:
        raise ValueError('unexpected_account_history_receipt')
    if request.get('method') != 'POST' or request.get('url') != API + protocol.PATHS[kind]:
        raise ValueError('receipt_endpoint_differs')
    old = {k.lower(): v for k, v in request['headers'].items()}
    if any(not old.get(k) or old.get(k) != headers.get(k) for k in login.IDENTITY):
        raise ValueError('receipt_belongs_to_another_recorded_login')
    result = assess(kind, response['status'], response['headers'], raw)
    if not result['accepted']:
        raise ValueError('receipt_did_not_contain_an_accepted_response')
    value = payload(kind, raw)
    return request, value, {'receipt': name, 'request_sha256': store.digest(request), 'body_sha256': store.digest(value)}


def next_position(plan, segment, request_body, value):
    kind = plan['segments'][segment]['kind']
    cursor = protocol.cursor(kind, value)
    if cursor is not None:
        if not cursor or any(type(v) is float and not math.isfinite(v) for v in cursor.values()):
            raise ValueError('continuation_cursor_is_missing_or_nonfinite')
        body = {**plan['segments'][segment]['body'], **cursor}
        if store.digest(body) == store.digest(request_body):
            raise ValueError('repeated_continuation_cursor')
        return segment, body
    if segment + 1 < len(plan['segments']):
        return segment + 1, plan['segments'][segment + 1]['body']
    return None


def chain(session, last, headers):
    pages, seen, expected_link, name = [], set(), None, last
    while True:
        if name in seen:
            raise ValueError('cyclic_receipt_chain')
        seen.add(name)
        request, value, link = receipt(session, name, headers, expected=('recent', 'past'))
        if expected_link and expected_link != link:
            raise ValueError('predecessor_receipt_changed')
        pages.append((request, value, link))
        previous = request['account_history'].get('previous')
        if previous is None:
            break
        expected_link, name = previous, previous['receipt']
    pages.reverse()
    scope = pages[0][0]['account_history']['scope']
    expected_position = (0, scope['plan']['segments'][0]['body'])
    bodies = set()
    for index, (request, value, _) in enumerate(pages):
        metadata = request['account_history']
        if store.digest(metadata['scope']) != store.digest(scope) or metadata['index'] != index:
            raise ValueError('scope_or_page_order_differs')
        if expected_position is None:
            raise ValueError('page_follows_completed_range')
        segment, body = expected_position
        if (metadata['segment'] != segment or metadata['kind'] != scope['plan']['segments'][segment]['kind']
                or store.digest(body) != store.digest(request['body'])):
            raise ValueError('saved_page_is_not_the_expected_continuation')
        key = store.digest([metadata['kind'], body])
        if key in bodies:
            raise ValueError('repeated_page_in_chain')
        bodies.add(key)
        # A bad cursor is a diagnostic on the last accepted page, not a query failure.
        try:
            expected_position = next_position(scope['plan'], segment, body, value)
        except ValueError:
            if index != len(pages) - 1:
                raise
            expected_position = 'invalid'
    if expected_position not in (None, 'invalid'):
        segment, body = expected_position
        if store.digest([scope['plan']['segments'][segment]['kind'], body]) in bodies:
            expected_position = 'invalid'
    return pages, expected_position


def read_config(path):
    config = store.read_input(path)
    if not isinstance(config, dict) or not set(config) <= CONFIG_KEYS or not REQUIRED_KEYS <= set(config):
        raise ValueError('unexpected_history_input_fields: ' + ', '.join(sorted(CONFIG_KEYS)))
    return config


def prepare(session, stage, config, *, clock=None, account_info=None, previous=None, row=None, snapshot=None):
    if stage not in KINDS:
        raise ValueError('read_only_history_stages_only')
    if snapshot is not None and (not isinstance(snapshot, str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,39}', snapshot) is None):
        raise ValueError('expected_a_non_secret_observation_label')
    request, selected = inquiry.authenticated_account(session, config)
    headers = {k.lower(): v for k, v in request['headers'].items()}
    # Validate user controls before even preparing an auxiliary query.
    protocol.plan(config, inquiry.today_kst().strftime('%Y%m%d'), selected['acctNo'])
    kind, body = stage, None
    meta = {'kind': kind, 'input_sha256': store.digest(config), 'snapshot': snapshot,
            'session_current_validity': 'unverified'}
    if stage == 'clock':
        body = {'bussDt': '', 'tgtDt': ''}
    elif stage == 'account':
        body = {'acctNo': selected['acctNo']}
        if protocol.truthy(selected.get('acctSeqNo')):
            kind = 'loan-account'
            body['acctSeqNo'] = selected['acctSeqNo']
    else:
        if clock is None or account_info is None:
            raise ValueError('clock_and_account_info_receipts_are_required')
        _, clock_data, clock_link = receipt(session, clock, headers, expected=('clock',))
        info_req, info_data, info_link = receipt(session, account_info, headers, expected=('account', 'loan-account'))
        if info_req['body']['acctNo'] != selected['acctNo']:
            raise ValueError('account_info_selection_differs')
        info = info_data['acctInfo']
        if not isinstance(info, dict) or info.get('acctNo') != selected['acctNo']:
            raise ValueError('account_info_identity_differs')
        if protocol.account_screen(info) != 'inout' or info.get('curCd') != 'KRW':
            raise ValueError('this_account_uses_a_different_ledger_screen')
        query_plan = protocol.plan(config, clock_data['dt'], selected['acctNo'],
                                   local_day=inquiry.today_kst().strftime('%Y%m%d'))
        scope = {'input_sha256': store.digest(config), 'clock': clock_link, 'account_info': info_link,
                 'plan': query_plan, 'snapshot': snapshot}
        if stage == 'page':
            segment, body, index, predecessor = 0, query_plan['segments'][0]['body'], 0, None
            if previous:
                pages, position = chain(session, previous, headers)
                if store.digest(pages[-1][0]['account_history']['scope']) != store.digest(scope):
                    raise ValueError('previous_page_query_scope_differs')
                if position is None:
                    raise ValueError('ledger_range_is_complete')
                if position == 'invalid':
                    raise ValueError('inspect_the_cursor_before_any_further_query')
                segment, body = position
                predecessor, index = pages[-1][2], len(pages)
            kind = query_plan['segments'][segment]['kind']
            meta.update(scope=scope, segment=segment, index=index, previous=predecessor)
        else:
            if previous is None or type(row) is not int or row < 1:
                raise ValueError('detail_requires_an_accepted_ledger_receipt_and_a_one_based_row')
            pages, _ = chain(session, previous, headers)
            source_request, source_data, source_link = pages[-1]
            if store.digest(source_request['account_history']['scope']) != store.digest(scope):
                raise ValueError('detail_query_scope_differs')
            items = protocol.rows(source_request['account_history']['kind'], source_data)
            if row > len(items):
                raise ValueError('detail_row_out_of_range')
            selected_row = items[row - 1]
            kind, body = protocol.detail_request(info, selected_row)
            meta.update(scope=scope, previous=source_link, row=row,
                        local_detail={'display': protocol.display_row(selected_row), 'raw': selected_row},
                        transfer_history_navigation={'screen': 'TRNB0701001001', 'date': selected_row.get('trscDt')})
    if kind != 'clock':
        common = decode_header(headers['hana-com-header'])
        common['CNL_HDPT']['SCRN_ID'] = 'INQB0201001001'
        headers['hana-com-header'] = encode_header(common)
    meta['kind'] = kind
    request.update(method='POST', url=API + protocol.PATHS[kind] if kind != 'local' else None,
                   headers=headers, body=body, account_history=meta,
                   mode='prepared read-only account history; no request sent', live_verified=False)
    return request, 'account-history-' + kind + '-' + store.digest([body, meta])[:20]


def run(name, stage, input_path, *, send=False, **options):
    session = store.session_path(name)
    config = read_config(input_path)
    with store.lock(session):
        request, receipt_name = prepare(session, stage, config, **options)
        meta = request['account_history']
        if meta['kind'] == 'local':
            if send:
                raise ValueError('a_saved_ledger_detail_needs_no_bank_query')
            detail = store.child(session, receipt_name + '-detail.json')
            store.write_new(detail, meta)
            return {'network_used': False, 'detail_file': detail.name, 'source': 'saved_ledger_row',
                    'transfer_confirmed': False}
        draft = store.child(session, receipt_name + '-prepared.json')
        halt = store.child(session, 'account-history-' + store.digest(meta.get('scope', meta))[:20] + '-halt.json')
        if halt.exists():
            raise ValueError('this_observation_was_halted_inspect_the_existing_records')
        if not send:
            if not draft.exists():
                store.write_new(draft, request)
            elif store.digest(store.read_json(draft)) != store.digest(request):
                raise ValueError('an_earlier_draft_differs_review_inputs_and_session')
            return {'network_used': False, 'kind': meta['kind'], 'prepared_request': draft.name,
                    'receipt_directory': receipt_name, 'session_current_validity': 'unverified',
                    'automatic_retry': False, 'next': 'same_command_with_send'}
        if store.digest(store.read_json(draft)) != store.digest(request):
            raise ValueError('prepared_query_changed')
        if store.child(session, receipt_name).exists():
            raise FileExistsError('a_recorded_attempt_already_exists')
        try:
            result = transport.send(session, receipt_name, request,
                                    lambda _, status, headers, raw: assess(meta['kind'], status, headers, raw))
        except (ValueError, OSError):
            if store.child(session, receipt_name, 'attempt.json').exists() and not halt.exists():
                store.write_new(halt, {'reason': 'query_outcome_unknown', 'automatic_retry': False,
                                       'receipt': receipt_name})
            raise
        if not result['accepted']:
            store.write_new(halt, {'reason': result['reason'], 'automatic_retry': False, 'receipt': receipt_name})
        result['receipt_directory'] = receipt_name
        return result


def export(name, last, output):
    """Export accepted pages without contacting the bank; keep duplicates and wire order."""
    from pathlib import Path
    from finance_cli.core import storage
    session = store.session_path(name)
    final = transport.read_receipt(session, last)[0]
    headers = {k.lower(): v for k, v in final['headers'].items()}
    pages, position = chain(session, last, headers)
    exported, issues, seen = [], [], {}
    for request, value, link in pages:
        meta = request['account_history']
        issues.extend({'page': meta['index'] + 1, 'issue': issue} for issue in protocol.diagnostics(meta['kind'], value))
        for index, row in enumerate(protocol.rows(meta['kind'], value), 1):
            identity = store.digest(row)
            if identity in seen:
                issues.append({'page': meta['index'] + 1, 'row': index, 'issue': 'identical_row_preserved',
                               'previous': seen[identity]})
            seen[identity] = [meta['index'] + 1, index]
            exported.append({'page': meta['index'] + 1, 'row': index, 'kind': meta['kind'],
                             **protocol.display_row(row), 'raw': row})
    if position == 'invalid':
        issues.append({'issue': 'continuation_cursor_requires_review'})
    report = {'network_used': False, 'page_count': len(pages), 'row_count': len(exported),
              'pagination_complete': position is None, 'atomic_snapshot_verified': False,
              'transfer_confirmed': False, 'duplicates_removed': False, 'issues': issues,
              'scope': pages[0][0]['account_history']['scope'], 'pages': [p[2] for p in pages], 'rows': exported}
    fields = ['page', 'row', 'kind', 'date', 'time', 'type', 'name', 'amount', 'balance', 'currency',
              'variation', 'extra', 'memo']
    buffer = io.StringIO(newline='')
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    escaped = 0
    for row in exported:
        cells = {}
        for field in fields:
            value = row[field]
            # Only text cells: numeric negative amounts stay numeric.
            if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r', '\n')):
                value = "'" + value
                escaped += 1
            cells[field] = value
        writer.writerow(cells)
    report['csv_text_cells_escaped'] = escaped
    output = storage.no_symlinks(Path(output).expanduser())
    if output.suffix != '.json':
        raise ValueError('export_output_must_end_in_json')
    csv_path = output.with_suffix('.csv')
    if output.exists() or csv_path.exists():
        raise ValueError('export_already_exists')
    store.write_new(output, report)
    storage.write_new(csv_path, ('﻿' + buffer.getvalue()).encode('utf-8'))
    return {k: report[k] for k in ('network_used', 'page_count', 'row_count', 'pagination_complete',
                                   'atomic_snapshot_verified', 'transfer_confirmed')}
