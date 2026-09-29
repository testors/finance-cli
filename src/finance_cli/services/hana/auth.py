"""App authentication (three GET requests) and the certificate login nonce.

The device profile is a user-supplied JSON file with exactly system_header,
channel_header, secure_token and profile_provenance. Nothing about the device is
guessed or shipped. Only the transport allowlisted below is ever requested.
"""
import hashlib
import secrets

from finance_cli.core import storage
from . import store, transport
from .compat import bank_business_headers, kotlin_object
from .hana_protocol import API, auth_request, encode_header

STAGES = ('register', 'first-access', 'access-token')
CERT_NONCE = 'cert-nonce'
NONCE_PATH = '/public/pcm/lgin01/capi/certsMgnt/createDelfinoNonce'
PROFILE_KEYS = {'system_header', 'channel_header', 'profile_provenance', 'secure_token'}
IDENTITY_NOTE = 'Random, isolated CLI identity; not the Android ID of any real device'


def new_session(name):
    from Crypto.PublicKey import RSA
    session = store.session_path(name, new=True)
    private = RSA.generate(2048).export_key(format='DER', pkcs=8)
    store.write_new(store.child(session, 'app-key.der'), private)
    store.write_new(store.child(session, 'identity.json'), {
        'android_id': secrets.token_hex(8), 'provenance': IDENTITY_NOTE,
        'key_sha256': hashlib.sha256(private).hexdigest(), 'user_agent': transport.USER_AGENT,
        'device_profile_observed': False})
    return {'session': name, 'directory': store.relative(session), 'identity': 'new isolated CLI identity',
            'rsa_bits': 2048, 'network_used': False}


def load_profile(path):
    profile = store.read_input(path)
    if not isinstance(profile, dict) or set(profile) != PROFILE_KEYS:
        raise ValueError('profile_must_contain_exactly: ' + ', '.join(sorted(PROFILE_KEYS)))
    if not isinstance(profile['profile_provenance'], dict) or not profile['profile_provenance']:
        raise ValueError('profile_provenance_required')
    return profile


def classify(stage, status, headers, body_present):
    """Auth result mapper and repository checks; not the business API mapper.

    body_present refers to the response-body object, not the byte length: an
    empty HTTP 200 still yields a body, while 204 and 205 yield none.
    """
    headers = transport.headers_by_name(headers)
    if not 200 <= status < 300:
        return {'accepted': False, 'reason': 'http_error'}
    if not body_present:
        return {'accepted': False, 'reason': 'missing_response_body'}
    name, expected = {'register': ('key-save-status', 'Successful'),
                      'first-access': ('nonce', None),
                      'access-token': ('access-token', None)}[stage]
    value = headers.get(name, '')
    accepted = value == expected if expected else bool(value.strip())
    return {'accepted': accepted, 'reason': 'accepted' if accepted else 'invalid_' + name}


def classify_nonce(status, headers, body):
    if status != 200:
        return {'accepted': False, 'reason': 'http_error'}, None
    try:
        processing = bank_business_headers(headers, web=False)
        payload = kotlin_object(body)
    except (ValueError, KeyError, TypeError, UnicodeError):
        return {'accepted': False, 'reason': 'malformed_or_missing_nonce_response_fields'}, None
    nonce = payload.get('nnce')
    ready = isinstance(nonce, str) and bool(nonce.strip())
    return {'accepted': True, 'reason': 'nonce_response_accepted', 'processing_result': processing,
            'continuation_ready': ready, 'warnings': [] if ready else ['nonce_unavailable']}, nonce if ready else None


def identity(session):
    value = store.read_json(store.child(session, 'identity.json'))
    private = storage.read(store.child(session, 'app-key.der'))
    if hashlib.sha256(private).hexdigest() != value['key_sha256']:
        raise ValueError('cli_key_changed_after_identity_creation')
    if value['user_agent'] != transport.USER_AGENT:
        raise ValueError('unexpected_user_agent')
    return value, private


def app_session(session):
    value = store.read_json(store.child(session, 'app-session.json'))
    if value.get('app_auth_accepted') is not True:
        raise ValueError('app_authentication_not_confirmed')
    return value


def prepare(session, stage, profile=None):
    """Build one allowlisted request without sending it."""
    if stage == CERT_NONCE:
        saved = app_session(session)
        result = store.read_json(store.child(session, 'access-token', 'request.json'))
        result['method'] = 'POST'
        result['url'] = API + NONCE_PATH
        result['headers'].pop('enc-nonce')
        result['headers'].update({'nonce': saved['nonce'], 'access-token': saved['access_token'],
                                  'hana-1q-env': 'Prod'})
        result['mode'] = 'prepared certificate nonce request; no user signature included'
        return result
    ident, private = identity(session)
    index = STAGES.index(stage)
    previous = None
    if index:
        previous = store.read_json(store.child(session, STAGES[index - 1], 'response.json'))
        if not previous['assessment']['accepted']:
            raise ValueError('previous_app_auth_stage_not_accepted')
        if profile is None:
            raise ValueError('device_profile_required')
    value = {'android_id': ident['android_id']}
    if index:
        value.update(system_header=profile['system_header'], channel_header=profile['channel_header'])
        if stage == 'first-access':
            value['secure_token'] = profile['secure_token']
        else:
            value['nonce'] = transport.headers_by_name(previous['headers'])['nonce']
            first = store.read_json(store.child(session, 'first-access', 'request.json'))
            if (first['headers']['hana-sys-header'] != encode_header(value['system_header'])
                    or first['headers']['hana-com-header'] != encode_header(value['channel_header'])):
                raise ValueError('common_headers_changed_between_app_auth_stages')
    result = auth_request(stage, private, value)
    result['headers'].update({'Accept': 'application/json', 'Content-Type': 'application/json',
                              'User-Agent': transport.USER_AGENT, 'Accept-Encoding': 'identity'})
    result['identity_provenance'] = ident['provenance']
    if index:
        result['profile_provenance'] = profile['profile_provenance']
    result['transport_differences'] = [
        'Python urllib, not Android OkHttp; TLS/HTTP fingerprint differs',
        'Accept-Encoding identity; no compression requested',
        'Fresh standard CookieJar, not the phone WebView cookie store',
        'No redirects, automatic retries or vendor callbacks']
    return result


def send_stage(session, stage, request):
    if stage == CERT_NONCE:
        found = {}

        def assess(_, status, headers, body):
            assessment, nonce = classify_nonce(status, headers, body)
            found['nonce'] = nonce
            return assessment
        result = transport.send(session, stage, request, assess)
        if result['accepted'] and result.get('continuation_ready'):
            store.write_new(store.child(session, 'joint-cert-nonce.json'), {'nnce': found['nonce']})
        return result
    result = transport.send(session, stage, request,
                            lambda name, status, headers, body: classify(name, status, headers, status not in (204, 205)))
    if stage == 'access-token' and result['accepted']:
        first = transport.headers_by_name(store.read_json(store.child(session, 'first-access', 'response.json'))['headers'])
        token = transport.headers_by_name(store.read_json(store.child(session, 'access-token', 'response.json'))['headers'])
        store.write_new(store.child(session, 'app-session.json'), {
            'nonce': first['nonce'], 'access_token': token['access-token'], 'one_access_token': '',
            'app_auth_accepted': True, 'user_login_verified': False,
            'identity_provenance': request['identity_provenance'],
            'expires_at': None, 'expiry_source': 'not established'})
    return result


def authenticate(name, profile_path, *, send=False):
    """register -> first-access -> access-token, stopping at the first stage not accepted."""
    session = store.session_path(name)
    profile = load_profile(profile_path)
    with store.lock(session):
        if store.child(session, 'app-session.json').exists():
            raise ValueError('app_authentication_already_recorded_use_a_new_session')
        if not send:
            request = prepare(session, 'register')
            return {'network_used': False, 'session': name, 'stages': list(STAGES),
                    'request_header_names': sorted(request['headers']), 'next': 'same_command_with_send',
                    'user_login_verified': False}
        results = []
        for stage in STAGES:
            if store.child(session, stage).exists():
                raise ValueError('recorded_attempt_exists_do_not_replay: ' + stage)
            result = send_stage(session, stage, prepare(session, stage, profile))
            results.append({key: result[key] for key in ('stage', 'http_status', 'accepted', 'reason')})
            if not result['accepted']:
                return {'network_used': True, 'session': name, 'accepted': False, 'stopped_at': stage,
                        'stages': results, 'automatic_retry': False, 'user_login_verified': False}
        return {'network_used': True, 'session': name, 'accepted': True, 'stages': results,
                'app_auth_accepted': True, 'user_login_verified': False, 'automatic_retry': False}
