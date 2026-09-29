"""One explicit read-only limit, security-medium or OTP-status query with a recorded login.

Default: prepare locally. --send: one unchanged request, with no authentication
refresh, OTP or PIN input, registration, recovery, limit change or automatic retry.
"""
from datetime import datetime, timezone

from . import login, security_protocol as protocol, store, transport
from .compat import bank_business_headers, web_value
from .hana_protocol import API, decode_header, encode_header


def assess(kind, status, headers, raw):
    result = {'accepted': False, 'network_used': True, 'automatic_retry': False,
              'state_change_requested': False, 'resend_allowed': False, 'warnings': []}
    try:
        if kind not in protocol.QUERIES or not 200 <= status < 300:
            raise ValueError('http_failure')
        bank_business_headers(headers, web=True)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        result['reason'] = 'http_or_business_response_failure'
        return result
    result.update(accepted=True, reason='read_only_response_accepted')
    try:
        observation = protocol.observe(kind, web_value(raw))
        result.update(diagnostics=observation['diagnostics'], warnings=observation['diagnostics'])
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError):
        result.update(diagnostics=['response_display_unavailable'], warnings=['response_display_unavailable'])
    return result


def prepare(session, kind):
    if kind not in protocol.QUERIES:
        raise ValueError('unknown_inquiry')
    request = login.authenticated_session(session)
    headers = {k.lower(): v for k, v in request['headers'].items()}
    for key in login.IDENTITY:
        headers[key] = headers[key].strip()  # The web interceptor trims these values.
    path, omitted, screen = protocol.QUERIES[kind]
    common = decode_header(headers['hana-com-header'])
    common['CNL_HDPT']['SCRN_ID'] = screen
    headers['hana-com-header'] = encode_header(common)
    if omitted:
        headers.pop('content-type', None)
    else:
        headers['content-type'] = 'application/json;charset=utf-8'
    request.update(method='POST', url=API + path, headers=headers, body=None if omitted else {},
                   omit_body=omitted, security_inquiry={'kind': kind, 'screen': screen},
                   mode='prepared read-only security inquiry; no request sent', live_verified=False)
    return request


def report(session, run, receipt_name, kind):
    """Reassess the saved bytes; a hand-edited accepted flag is never trusted."""
    draft = store.read_json(store.child(run, 'prepared.json'))
    actual, response, raw = transport.read_receipt(session, receipt_name)
    actual = dict(actual, mode=draft['mode'], live_verified=False)
    if store.digest(actual) != store.digest(draft) or draft['url'] != API + protocol.QUERIES[kind][0]:
        raise ValueError('receipt_differs_from_prepared_query')
    assessment = assess(kind, response['status'], response['headers'], raw)
    value = web_value(raw)
    try:
        observation = protocol.observe(kind, value)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError):
        observation = {'fields': {}, 'rows': [], 'display': {}, 'diagnostics': ['response_display_unavailable']}
    result = {'kind': kind, 'observed_at': response['observed_at'], 'assessment': assessment,
              'observation': observation, 'raw_value': value, 'receipt': receipt_name,
              'session_current_validity': 'unverified', 'state_change_confirmed': False}
    store.write_new(store.child(run, 'observation.json'), result)
    return result


def query(session_name, run_name, kind, *, send=False):
    session = store.session_path(session_name)
    if kind not in protocol.QUERIES:
        raise ValueError('unsupported_inquiry')
    run = store.run_path(run_name)
    with store.lock(session):
        request = prepare(session, kind)
        receipt_name = 'security-inquiry-' + store.digest(run_name)[:20]
        if not send:
            store.make_directory(run)
            store.write_new(store.child(run, 'prepared.json'), request)
            store.write_new(store.child(run, 'receipt-link.json'), {'session': session_name, 'receipt': receipt_name})
            return {'network_used': False, 'kind': kind, 'automatic_retry': False, 'run': run_name,
                    'prepared_request': 'prepared.json', 'session_current_validity': 'unverified',
                    'next': 'same_command_with_send'}
        if any(store.child(run, n).exists() for n in ('halt.json', 'attempt.json')) \
                or store.child(session, receipt_name).exists():
            raise ValueError('recorded_attempt_exists_inspect_records_do_not_replay')
        if store.digest(store.read_json(store.child(run, 'prepared.json'))) != store.digest(request):
            raise ValueError('prepared_query_changed')
        if store.read_json(store.child(run, 'receipt-link.json')) != {'session': session_name, 'receipt': receipt_name}:
            raise ValueError('receipt_link_changed')
        store.write_new(store.child(run, 'attempt.json'), {
            'started_at': datetime.now(timezone.utc).isoformat(), 'automatic_retry': False})
        try:
            result = transport.send(session, receipt_name, request,
                                    lambda _, status, headers, raw: assess(kind, status, headers, raw))
            observation = report(session, run, receipt_name, kind)
            if not result['accepted']:
                store.write_new(store.child(run, 'halt.json'), {'reason': result['reason'], 'automatic_retry': False})
            return {'kind': kind, 'accepted': result['accepted'], 'network_used': True,
                    'automatic_retry': False, 'resend_allowed': False, 'state_change_requested': False,
                    'diagnostics': observation['observation']['diagnostics'],
                    'warnings': observation['assessment']['warnings'], 'run': run_name,
                    'report': 'observation.json'}
        except (ValueError, OSError, KeyError, TypeError, AttributeError):
            if not store.child(run, 'halt.json').exists():
                store.write_new(store.child(run, 'halt.json'), {
                    'reason': 'query_outcome_requires_inspection', 'automatic_retry': False})
            raise
