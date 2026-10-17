"""Explicit PIN authentication, nonce signing and certificate login workflow."""
from datetime import datetime
import hashlib
import hmac
import json
import re

from finance_cli.core import storage
from finance_cli.credentials.registry import decode
from finance_cli.credentials.shinhan import Registry, SelectionRequired
from . import crypto, e2e, login_protocol, setup
from .exchange import Exchange
from .enrollment import Pending


def select(reference=None):
    registry = Registry()
    if reference is not None:
        return registry.select(reference)
    path = setup.root() / 'session.json'
    state = storage.read_json(path) if path.exists() else {}
    disabled = state.get('disabled_credentials', [])
    active = [row['name'] for row in registry.list() if row['name'] not in disabled]
    preferred = state.get('credential')
    if preferred in active:
        return preferred
    if len(active) == 1:
        return active[0]
    raise SelectionRequired(len(active))


def run(reference, password, pin_input):
    settings = setup.load()
    registry = Registry()
    reference = select(reference)
    credential = registry.load(reference, password)
    if credential.get('state') != 'issued':
        raise ValueError('issued_certificate_required')
    if credential.get('device_id') != settings['device']['device_id']:
        raise ValueError('certificate_device_mismatch')
    if not isinstance(settings.get('e2e_key'), str):
        raise ValueError('e2e_settings_required')
    folder = setup.prepare_directory()
    with storage.lock(folder / '.lock'):
        path = folder / 'session.json'
        state = storage.read_json(path) if path.exists() else {}
        if reference in state.get('disabled_credentials', []):
            raise ValueError('certificate_reissue_required')
        exchange = Exchange(settings, state, 'login')
        report = exchange.report
        report['authentication'] = 'unverified'
        try:
            unique = authenticate_pin(exchange, credential, pin_input)
            plaintext = 'login'+datetime.now().strftime('%y%m%d%H%M%S')
            step, document = exchange.bank('nonce', 'RSMCM0800C12', {}, path='/serviceEndpoint/httpDigital/')
            nonce = ''
            if step['result'] == 'success' and isinstance(document.get('dataBody'), dict):
                nonce = document['dataBody'].get('randomUid') or ''
            # The repository's empty fallback is passed to signing, which rejects it.
            if not credential['alias'] or not unique:
                return finish(exchange, 'local_signing_input_unavailable')
            if not hmac.compare_digest(hashlib.sha256(unique.encode()).hexdigest(), credential['access_key_digest']):
                return finish(exchange, 'local_key_access_rejected')
            signature = crypto.sign(decode(credential['certificate']), decode(credential['private_key']),
                                    plaintext.encode(), nonce.encode()).hex()
            transaction, body, identity = login_protocol.login_request(
                credential, unique, plaintext, signature, settings, state)
            step, document = exchange.bank('bank_login', transaction, body, device_id=identity)
            report['bank_result'] = step['result']
            if step['result'] != 'success':
                return finish(exchange, 'bank_login_unavailable')
            report['authentication'] = 'bank_accepted'
            state.pop('transfer_pending', None)
            data = document.get('dataBody')
            if not isinstance(data, dict):
                return finish(exchange, 'login_body_unavailable')
            user = data.get('user')
            if user is None:
                user = {}
            if not isinstance(user, dict):
                return finish(exchange, 'login_user_unavailable')
            state['group_failure'] = {name: user.get(field) == 'Y' for name, field in (
                ('card', 'cardErrYn'), ('invest', 'investErrYn'), ('life', 'lifeErrYn'))}
            state.update(authenticated=True, credential=reference, login=data, login_failed_count=0,
                         login_header=document['dataHeader'], last_login_type='G', last_operation='login')
            report['processing_status'] = 'complete'
            exchange.save()
            return report
        except Pending as error:
            return finish(exchange, error.action)
        except (KeyboardInterrupt, EOFError):
            return finish(exchange, 'interrupted')
        except Exception:
            # Keep observed PIN/bank results when signing, decoding or local IO fails.
            return finish(exchange, 'local_login_processing_error')


def finish(exchange, error):
    exchange.report.update(processing_status='incomplete', error=error)
    exchange.save()
    return exchange.report


def authenticate_pin(exchange, credential, pin_input):
    """Authenticate once on the existing bank/CA session, without bank login."""
    settings, state, report = exchange.settings, exchange.state, exchange.report
    step, raw = exchange.ca('e2e_init', '/v2.0/skeypad/init', e2e.initial(settings['e2e_key']))
    if step['result'] != 'http_success':
        raise Pending('e2e_init_unavailable')
    handshake = e2e.Handshake.challenge(raw)
    step['processing_status'] = 'complete'
    step, raw = exchange.ca('e2e_complete', '/v2.0/skeypad/init', handshake.request)
    if step['result'] != 'http_success':
        raise Pending('e2e_response_unavailable')
    if not handshake.finish(raw):
        step.update(result='failure', processing_status='complete')
        raise Pending('e2e_rejected')
    step.update(result='success', processing_status='complete')
    step, raw = exchange.ca('e2e_health', '/v2.0/skeypad/init', handshake.health_request())
    if step['result'] != 'http_success':
        raise Pending('e2e_health_unavailable')
    if e2e.health_error(raw):
        raise Pending('e2e_reinitialization_required')
    step.update(result='success', processing_status='complete')
    if not handshake.kr1:
        raise Pending('keypad_material_unavailable')
    # PIN is requested only when the protected channel is available.
    pin = pin_input()
    if not isinstance(pin, bytes) or not re.fullmatch(rb'[0-9]{6}', pin):
        raise Pending('six_digit_pin_required')
    unique = crypto.unique_value(pin, decode(credential['pin_salt']))
    encrypted = handshake.encrypt(unique)
    step, raw = exchange.ca('pin_auth', '/v1.1/prsn-cert/sec/auth',
                            login_protocol.pin_request(credential, settings['device'], encrypted))
    if step['result'] != 'http_success':
        raise Pending('pin_auth_unavailable')
    document = json.loads(raw)
    verdict = login_protocol.pin_verdict(document)
    step.update(verdict)
    step['processing_status'] = verdict.get('processing_status', 'complete')
    if verdict['increment_failure_count']:
        count = (state.get('login_failed_count') or 0)+1
        state['login_failed_count'] = (count+2**31) % 2**32-2**31
    if verdict['clear_local']:
        # Make the app connection unusable without deleting shared credential archives.
        state['disabled_credentials'] = [row['name'] for row in Registry().list()]
        state['authenticated'] = False
        step['local_cleanup'] = 'disabled'
    exchange.save()
    if verdict['result'] != 'success':
        report['pin_authentication'] = verdict['result']
        raise Pending('pin_auth_rejected')
    report['pin_authentication'] = 'success'
    return unique
