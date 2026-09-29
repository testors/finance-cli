"""Joint-certificate login and the main-account query for a recorded app session.

The nonce, the local signature and the login run in one command only when
--send is given. Each request is a separate recorded attempt and none is ever
repeated. Whether the login is still valid on the server is never inferred.
"""
import base64
import re

from finance_cli.core import storage
from . import auth, store, transport
from .compat import bank_business_headers, kotlin_object
from .hana_protocol import API, decode_header, joint_cert_body, joint_cert_tbs

LOGIN_PATH = '/public/pcm/lgin01/capi/lginMgnt/loginOfclCerts'
ACCOUNTS_PATH = '/api/pcm/lgin01/capi/mainInfoMgnt/retrieveMainAcctInfo'
LOGIN_INPUT_KEYS = {'push_token', 'fakefinder_install_id', 'input_provenance'}
IDENTITY = ('uuid', 'nonce', 'access-token', 'one-access-token')
ALLOWED_HEADERS = {'app-version', 'package-name', 'uuid', 'hana-sys-header', 'hana-com-header', 'nonce',
                   'access-token', 'one-access-token', 'hana-1q-env', 'accept', 'content-type',
                   'user-agent', 'accept-encoding'}
METHOD = 'joint certificate'


def assess(stage, status, headers, body):
    """The service's business acceptance; extra profile checks are only warnings."""
    header_map = transport.headers_by_name(headers)
    result = {'accepted': False, 'reason': 'unconfirmed_response', 'warnings': [],
              'http_status': status, 'processing_result': None, 'error_code': None, 'session_ready': False}
    try:
        # A decoded body exists for HTTP 200 and the native success code is 0.
        if status != 200:
            raise ValueError('http_error')
        result['processing_result'] = bank_business_headers(headers, web=False)
        payload = kotlin_object(body)
    except (KeyError, TypeError, ValueError, UnicodeError, IndexError, AttributeError):
        result['reason'] = 'http_business_or_native_decode_error'
        return result
    result.update(accepted=True, reason='login_accepted' if stage == 'login' else 'query_accepted')
    try:
        first = (decode_header(header_map['hana-com-header']).get('STD_MSGPT') or [{}])[0]
        error = first.get('OGN_ERR_CD')
        if isinstance(error, str) and re.fullmatch(r'[A-Z0-9_]{1,40}', error):
            result['error_code'] = error
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        result['warnings'].append('message_metadata_unavailable')
    if stage == 'login':
        result['session_ready'] = bool(header_map.get('one-access-token', '').strip())
        if not result['session_ready']:
            result['warnings'].append('login_token_unavailable')
        if not isinstance(payload.get('custNo'), str) or not payload['custNo']:
            result['warnings'].append('customer_number_unavailable')
        if payload.get('lginCertMethCd') != '2':
            result['warnings'].append('login_method_differs_from_joint_profile')
    else:
        accounts = payload.get('mainAcctList')
        if payload.get('lginYn') != 'Y':
            result['warnings'].append('login_flag_differs_from_profile')
        if not isinstance(accounts, list):
            result['warnings'].append('account_list_unavailable')
        elif not all(isinstance(item, dict) and isinstance(item.get('acctNo'), str)
                     and isinstance(item.get('curCd'), str) and type(item.get('acctBal')) in (int, float)
                     for item in accounts):
            result['warnings'].append('account_fields_differ_from_profile')
    return result


def login_input(path):
    value = store.read_input(path)
    if not isinstance(value, dict) or set(value) != LOGIN_INPUT_KEYS:
        raise ValueError('login_input_must_contain_exactly: ' + ', '.join(sorted(LOGIN_INPUT_KEYS)))
    if not isinstance(value['input_provenance'], dict) or not value['input_provenance']:
        raise ValueError('input_provenance_required')
    return value


def login_request(session, value, signed_data):
    saved = auth.app_session(session)
    request = store.read_json(store.child(session, 'cert-nonce', 'request.json'))
    request['mode'] = 'prepared request; no request sent'
    request['headers'].update({'nonce': saved['nonce'], 'access-token': saved['access_token']})
    request['url'] = API + LOGIN_PATH
    request['body'] = joint_cert_body({'signed_data': signed_data, 'push_token': value['push_token'],
                                       'fakefinder_install_id': value['fakefinder_install_id']})
    request['login_input_provenance'] = value['input_provenance']
    return request


def login(name, credential, input_path, password, *, send=False):
    """nonce -> local CMS signature from the vault -> login, stopping at the first refusal."""
    from Crypto.PublicKey import RSA
    from finance_cli.credentials.joint import cms
    from finance_cli.credentials.registry import Registry
    session = store.session_path(name)
    value = login_input(input_path)
    with store.lock(session):
        auth.app_session(session)
        if store.child(session, 'login-session.json').exists() or store.child(session, 'login').exists():
            raise ValueError('login_already_recorded_use_a_new_session')
        request = auth.prepare(session, auth.CERT_NONCE)
        if not send:
            return {'network_used': False, 'session': name, 'stages': [auth.CERT_NONCE, 'sign', 'login'],
                    'request_header_names': sorted(request['headers']), 'next': 'same_command_with_send',
                    'user_login_verified': False}
        # Open the certificate before the nonce is requested so a wrong password costs nothing.
        certificate, private = Registry().material(credential, password)[:2]
        if store.child(session, auth.CERT_NONCE).exists():
            raise ValueError('recorded_attempt_exists_do_not_replay: ' + auth.CERT_NONCE)
        nonce_result = auth.send_stage(session, auth.CERT_NONCE, request)
        if not nonce_result['accepted'] or not nonce_result.get('continuation_ready'):
            return {'network_used': True, 'session': name, 'accepted': False, 'stopped_at': auth.CERT_NONCE,
                    'reason': nonce_result['reason'], 'automatic_retry': False, 'user_login_verified': False}
        nonce = store.read_json(store.child(session, 'joint-cert-nonce.json'))['nnce']
        expected = joint_cert_tbs(nonce)
        signature = cms.sign_cms(certificate, RSA.import_key(private), expected.encode())
        del private
        if certificate not in signature:
            raise ValueError('selected_certificate_absent_from_signature')
        result = transport.send(session, 'login',
                                login_request(session, value, base64.b64encode(signature).decode('ascii')), assess)
        if result['accepted'] and result['session_ready']:
            response = store.read_json(store.child(session, 'login', 'response.json'))
            token = transport.headers_by_name(response['headers'])['one-access-token']
            store.write_new(store.child(session, 'login-session.json'), {
                'one_access_token': token, 'user_login_verified': True, 'login_method': METHOD,
                'account_query_verified': False, 'expiry_source': 'not established'})
        result['user_login_verified'] = store.child(session, 'login-session.json').exists()
        result['automatic_retry'] = False
        return result


def account_request(session):
    saved = auth.app_session(session)
    state = store.read_json(store.child(session, 'login-session.json'))
    if state.get('login_method') != METHOD:
        raise ValueError('joint_certificate_login_required')
    if not state.get('user_login_verified') or not str(state.get('one_access_token', '')).strip():
        raise ValueError('successful_user_login_is_required')
    request = store.read_json(store.child(session, 'cert-nonce', 'request.json'))
    request['mode'] = 'prepared request; no request sent'
    request['headers'].update({'nonce': saved['nonce'], 'access-token': saved['access_token'],
                               'one-access-token': state['one_access_token']})
    request['url'] = API + ACCOUNTS_PATH
    request['body'] = None
    return request


def authenticated_session(session):
    """Reuse a recorded login without querying or refreshing it."""
    for filename, flag in (('app-session.json', 'app_auth_accepted'), ('login-session.json', 'user_login_verified')):
        if store.read_json(store.child(session, filename)).get(flag) is not True:
            raise ValueError('successful_recorded_app_and_user_authentication_required')
    request = account_request(session)
    request['method'] = 'POST'
    headers = {k.lower(): v for k, v in request['headers'].items()}
    if len(headers) != len(request['headers']) or not set(headers) <= ALLOWED_HEADERS:
        raise ValueError('duplicate_or_unexpected_request_headers')
    if any(not isinstance(headers.get(k), str) or not headers[k].strip()
           for k in (*IDENTITY, 'hana-sys-header', 'hana-com-header')):
        raise ValueError('missing_saved_authentication_headers')
    if any(not isinstance(v, str) or any(ord(c) < 32 or ord(c) > 126 for c in v) for v in headers.values()):
        raise ValueError('invalid_http_header_value')
    if (headers.get('hana-1q-env') != 'Prod' or headers.get('app-version') != '1.0.27'
            or headers.get('package-name') != 'com.hanabank.oqf'):
        raise ValueError('unexpected_environment')
    return request


def accounts(name, *, send=False):
    session = store.session_path(name)
    with store.lock(session):
        request = authenticated_session(session)
        if not send:
            return {'network_used': False, 'session': name, 'stage': 'accounts',
                    'request_header_names': sorted(request['headers']), 'next': 'same_command_with_send',
                    'session_current_validity': 'unverified'}
        if store.child(session, 'accounts').exists():
            raise ValueError('recorded_attempt_exists_do_not_replay: accounts')
        result = transport.send(session, 'accounts', request, lambda stage, *rest: assess('accounts', *rest))
        result['session_current_validity'] = 'unverified'
        if result['accepted']:
            rows = kotlin_object(storage.read(store.child(session, 'accounts', 'body.bin'))).get('mainAcctList')
            if isinstance(rows, list) and all(isinstance(row, dict) for row in rows):
                store.write_new(store.child(session, 'account-selection.json'), {
                    'source': 'accounts/body.bin',
                    'accounts': [{**row, 'index': index} for index, row in enumerate(rows, 1)]})
                result['account_count'] = len(rows)
        result['transfer_enabled'] = False
        result['automatic_retry'] = False
        return result
