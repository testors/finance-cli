"""Prepare or send one native extendLgin request for a recorded login.

No PIN, keychain, new login, periodic heartbeat or automatic retry. Historical
login receipts are never rewritten and the server expiry is not inferred from
the app's local timer.
"""
from datetime import datetime, timezone
import hashlib

from finance_cli.core import storage
from . import login, store, transport
from .compat import bank_business_headers
from .hana_protocol import API

PATH = '/api/pcm/lgin01/capi/lginMgnt/extendLgin'
CLIENT_TIMER_MS = 600_000


def cookie_hash(session):
    path = store.child(session, 'cookies.txt')
    return hashlib.sha256(storage.read(path)).hexdigest() if path.exists() else None


def assess(status, headers, raw):
    """Native result mapper and logout repository, not the web predicates.

    The response body object exists even for empty HTTP 200 bytes. The native
    mapper routes 404 and 500 through the business headers although the body is
    null there; other statuses never produce native success. The repository does
    not parse the body or require a flag.
    """
    result = {'accepted': False, 'login_extension_accepted': False, 'warnings': [],
              'native_client_timer_reset_ms': None, 'server_expires_at': None,
              'session_current_validity': 'unverified', 'automatic_retry': False, 'resend_allowed': False}
    if status != 200:
        return dict(result, reason='native_http_failure', original_app_stops_local_session=True)
    try:
        bank_business_headers(headers, web=False)
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
        return dict(result, reason='native_business_or_header_failure', original_app_stops_local_session=True)
    # A non-JSON or empty body is valid here, including the literal "false".
    return dict(result, accepted=True, login_extension_accepted=True,
                native_client_timer_reset_ms=CLIENT_TIMER_MS, reason='login_extension_accepted',
                original_app_stops_local_session=False)


def prepare(session):
    request = login.authenticated_session(session)
    headers = {name.lower(): value for name, value in request['headers'].items()}
    # A native POST without a body sends an empty JSON body; do not use the web omit rule.
    headers.update({'accept': 'application/json', 'content-type': 'application/json'})
    request.update(method='POST', url=API + PATH, headers=headers, body=None,
                   omit_body=False, mode='prepared native login extension; no request sent')
    return request


def observe(session, run, receipt_name, request):
    actual, response, raw = transport.read_receipt(session, receipt_name)
    actual['mode'] = request['mode']
    expected = {k: v for k, v in request.items() if k != 'live_verified'}
    if store.digest(actual) != store.digest(expected):
        raise ValueError('extension_receipt_request_changed')
    outcome = assess(response['status'], response['headers'], raw)
    returned = transport.headers_by_name(response['headers'])
    # The saved login proof is kept; a different returned value is only a diagnostic.
    for name in ('nonce', 'access-token', 'one-access-token'):
        if name in returned and returned[name] != request['headers'].get(name):
            outcome['warnings'].append('response_' + name.replace('-', '_') + '_differs_from_saved_session')
    record = {'operation': 'extend-login', 'network_used': True, **outcome, 'receipt': receipt_name,
              'observed_at': response['observed_at'], 'http_status': response['status'],
              'request_sha256': store.digest(expected), 'response_body_sha256': hashlib.sha256(raw).hexdigest(),
              'response_body_bytes': len(raw), 'login_receipt_rewritten': False,
              'auth_tokens_replaced': False, 'cookies_updated_by_transport': True}
    store.write_new(store.child(run, 'observation.json'), record)
    return {'operation': 'extend-login', 'network_used': True, **outcome, 'observed_at': response['observed_at'],
            'report': 'observation.json', 'receipt_directory': receipt_name}


def extend(session_name, run_name, *, send=False):
    session = store.session_path(session_name)
    run = store.run_path(run_name)
    with store.lock(session):
        request = prepare(session)
        receipt_name = 'login-extension-' + store.digest(run_name)[:20]
        # --send on a new run prepares and sends under the same session lock. An
        # existing run needs a complete matching draft; a partial run is never
        # repaired and a request that was attempted is never replayed.
        if not send or not run.exists():
            if store.child(session, receipt_name).exists():
                raise ValueError('existing_extension_receipt_do_not_replay')
            store.make_directory(run)
            store.write_new(store.child(run, 'run.json'), {
                'version': 1, 'command': 'session extend', 'session': session_name, 'receipt': receipt_name,
                'request_sha256': store.digest(request), 'cookie_sha256': cookie_hash(session),
                'prepared_at': datetime.now(timezone.utc).isoformat(), 'automatic_retry': False})
            store.write_new(store.child(run, 'prepared.json'), request)
            if not send:
                return {'operation': 'extend-login', 'network_used': False, 'run': run_name,
                        'prepared_request': 'prepared.json', 'next': 'same_command_with_send',
                        'automatic_retry': False, 'session_current_validity': 'unverified'}
        if any(store.child(run, n).exists() for n in ('attempt.json', 'halt.json', 'observation.json')) \
                or store.child(session, receipt_name).exists():
            raise ValueError('recorded_extension_attempt_do_not_replay')
        meta = store.read_json(store.child(run, 'run.json'))
        draft = store.read_json(store.child(run, 'prepared.json'))
        if (meta.get('version') != 1 or meta.get('command') != 'session extend'
                or meta['session'] != session_name or meta['receipt'] != receipt_name
                or meta['request_sha256'] != store.digest(request) or store.digest(draft) != store.digest(request)
                or meta['cookie_sha256'] != cookie_hash(session)):
            raise ValueError('extension_session_or_draft_changed')
        store.write_new(store.child(run, 'attempt.json'), {
            'started_at': datetime.now(timezone.utc).isoformat(), 'automatic_retry': False})
        try:
            transport.send(session, receipt_name, request, lambda stage, status, headers, raw: assess(status, headers, raw))
            result = observe(session, run, receipt_name, request)
            if not result['accepted']:
                store.write_new(store.child(run, 'halt.json'), {
                    'reason': result['reason'], 'bank_acceptance': False, 'automatic_retry': False,
                    'resend_allowed': False})
            return result
        except (Exception, KeyboardInterrupt) as error:
            if not store.child(run, 'halt.json').exists():
                store.write_new(store.child(run, 'halt.json'), {
                    'reason': 'extension_outcome_requires_inspection', 'error_type': type(error).__name__,
                    'bank_acceptance': 'inspect_receipt', 'automatic_retry': False, 'resend_allowed': False})
            raise
