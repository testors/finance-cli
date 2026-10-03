"""One explicit native login extension using the encrypted OneSign session."""
import uuid

from . import extend as native, onesign_crypto as pin, request_activity, store
from .onesign_io import Client, send_http


def extend(state=None, *, session=None, run=None, send=False, exchange=send_http):
    result = {'operation': 'extend-login', 'accepted': None, 'login_extension_accepted': None,
              'service_status': 'unconfirmed', 'processing_status': 'planned', 'network_used': False,
              'automatic_retry': False, 'server_expires_at': None, 'session_current_validity': 'unverified',
              'cookies_saved': False, 'warnings': []}
    if not send:
        return result
    client = control = None
    try:
        sessions = state.snapshot()['sessions']
        if session is None:
            candidates = [name for name, value in sessions.items() if value.get('signed_login') is True]
            pin.require(bool(candidates), 'onesign_signed_login_required')
            pin.require(len(candidates) == 1, 'multiple_onesign_sessions_use_session')
            session = candidates[0]
        store.name(session)
        pin.require(session in sessions and sessions[session].get('signed_login') is True,
                    'onesign_signed_login_required')
        run = store.name(run) if run is not None else 'extend-' + uuid.uuid4().hex
        result.update(session=session, run=run)
        control = state.begin_run(run, 'extend-login')
        client = Client(state, run, session, send=True, exchange=exchange)
        headers = {k.lower(): v for k, v in client.headers().items()}
        headers.update({'accept': 'application/json', 'content-type': 'application/json'})

        def assess(status, head, raw):
            outcome = native.assess(status, head, raw)
            returned = {k.lower(): v for k, v in head}
            for key in ('nonce', 'access-token', 'one-access-token'):
                if key in returned and returned[key] != headers.get(key):
                    outcome['warnings'].append('response_' + key.replace('-', '_') + '_differs_from_saved_session')
            return outcome

        client.request('bank', 'POST', native.PATH, headers, b'', assessor=assess, ignore_body=True)
        result.update(client.last, processing_status='completed')
    except (Exception, KeyboardInterrupt) as exc:
        if client is not None:
            result.update(client.last)
        code = ('interrupted' if isinstance(exc, KeyboardInterrupt) else str(exc)
                if isinstance(exc, (pin.ProtocolError, request_activity.RequestBlocked)) else 'local_processing_error')
        result.update(processing_status='stopped', error=code)
    finally:
        if client is not None:
            result['network_used'] = client.sent > 0
        if control is not None:
            try:
                with control.transaction() as value:
                    value.update(outcome=result['processing_status'], result=result)
            except Exception:
                result['warnings'].append('outcome_storage_failed')
    return result
