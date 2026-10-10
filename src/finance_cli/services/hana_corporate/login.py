"""Certificate login orchestration; no automatic replay, enrollment or ID mapping."""
import base64
from contextlib import ExitStack
from datetime import datetime
from zoneinfo import ZoneInfo

from Crypto.PublicKey import RSA
from finance_cli.core import storage
from finance_cli.credentials.registry import Registry
from finance_cli.credentials.joint import cms
from finance_cli.services.hana.onesign_state import State
from finance_cli.services.hana.onesign_io import send_http
from finance_cli.services.hana.onesign_crypto import ProtocolError
from . import protocol, store
from .transport import Client
from .onesign import External


def plan(method):
    protocol.require(method in ('2', 'S'), 'unsupported_corporate_login_method')
    return {'channel': 'corporate', 'login_method': method, 'network_used': False, 'accepted': None,
            'processing_status': 'planned', 'next': 'same_command_with_send', 'shared_credentials': True,
            'automatic_retry': False, 'live_tested': False}


def login(session, method, credential, *, send=False, inputs=None, exchange=send_http, now=None):
    if not send:
        return plan(method)
    protocol.require(method in ('2', 'S'), 'unsupported_corporate_login_method')
    inputs = inputs or {}
    result = {'channel': 'corporate', 'session': session, 'login_method': method, 'accepted': None,
              'user_login_verified': False, 'network_used': False, 'automatic_retry': False,
              'processing_status': 'preparing', 'stages': [], 'session_saved': False,
              'session_current_validity': 'unverified', 'external_auth_status': 'not_started'}
    external = None
    try:
        directory = store.session_path(session)
        with storage.lock(directory / 'operation.lock'), ExitStack() as stack:
            protocol.require(not (directory / 'login-attempt.json').exists(), 'login_already_attempted_use_new_session')
            profile = store.device(storage.read_json(directory / 'device.json'))
            if method == '2':
                certificate, private, _ = Registry().material(credential, inputs['password']())
                key = RSA.import_key(private)
                del private
                cms.require_matching_key(certificate, key)
                reference = {'type': 'joint', 'ref': credential, 'certificate_id': Registry().entry(credential)['certificate_id']}
            else:
                state = stack.enter_context(State(credential, inputs['password']()))
                external = External(state, result, exchange=exchange)
                reference = {'type': 'onesign', 'ref': credential, 'certificate_id': external.entry['fingerprint']}
            store.record(directory / 'login-attempt.json', {'credential': reference, 'login_method': method, 'automatic_retry': False})
            client = Client(directory, profile, result, exchange=exchange)
            client.saved['credential'] = reference
            client.saved['login_method'] = method
            try:
                for stage in ('emergency', 'app-info'):
                    data = client.request(stage, native=True, assessor=protocol.assess_data)
                    warnings = protocol.check_bootstrap(stage, data)
                    if warnings:
                        result['stages'][-1]['warnings'] = warnings
                    stated = protocol.session_timeout_minutes(data) if stage == 'app-info' else None
                    if stated is not None:
                        client.saved['server_session_timeout_minutes'] = result['server_session_timeout_minutes'] = stated
                nonce = client.request('nonce', native=method == '2').get('delfinoNonce')
                protocol.require(isinstance(nonce, str), 'nonce_unavailable')
                if method == '2':
                    signature = base64.b64encode(cms.sign_cms(certificate, key, protocol.joint_tbs(nonce))).decode()
                else:
                    moment = now or datetime.now(ZoneInfo('Asia/Seoul'))
                    request = {'tbsData': protocol.onesign_tbs(nonce, moment), 'SVC_DV_CD': '1',
                               'nextUrl': '', 'reLoginYn': 'N', 'cbSuccessName': 'function(data) {}'}
                    response = client.request('onesign-request', request)
                    # RSLT_NM is not a reliable gate in this flow; the transaction
                    # ID starts external authentication, not a successful login.
                    external.authenticate(response.get('txid'), inputs['pin'])
                    confirmed = client.request('onesign-confirm')
                    protocol.require(confirmed.get('ACPN_PROC_RSLT_CD') in ('2', 2), 'external_confirmation_pending')
                    protocol.require(confirmed.get('GO_HANA_CERT_REG') != 'Y', 'corporate_id_link_required')
                    protocol.require(confirmed.get('CB_SUCCESS_NAME') is None, 'external_callback_unhandled')
                    signature = confirmed.get('ELEC_SIGN_VLU_DAT')

                def observe(receipt, data):
                    accepted, reason = protocol.login_verdict(receipt, data)
                    result.update(accepted=accepted, user_login_verified=accepted is True, reason=reason)
                    if accepted is True:
                        client.saved.update(login_verified=True, login_response=data)

                client.request('login', protocol.login_body(method, signature, profile['push']), observe=observe)
                result['session_saved'] = True
                protocol.require(result['accepted'] is True, result['reason'])
                # Follow-up observations never overwrite the confirmed login.
                client.request('withdrawal-info', {'exceptSignedMsgYn': 'Y',
                    'COMM_HEAD': {'SIGNED_MSG': '', 'VID_MSG': '', 'LGIN_CERT_METH_CD': ''}})
                customer = client.request('customer-check', {'INQ_TYPE': '1'})
                client.saved['customer_check'] = customer
                storage.atomic_json(directory / 'session.json', client.saved)
                result['follow_up'] = {'customer_check_received': True, 'app_fds': 'not_implemented',
                                       'customer_guidance': 'not_interpreted'}
                result['processing_status'] = 'completed'
            except KeyboardInterrupt:
                result.update(processing_status='stopped', error='interrupted')
            except Exception as exc:
                result.update(processing_status='stopped', error=str(exc) if isinstance(exc, (protocol.Stop, ProtocolError)) else 'local_processing_error')
            finally:
                if external:
                    external.finish()
                try:
                    store.record(directory / 'outcome.json', result)
                except (OSError, ValueError):
                    result['diagnostic_storage_failed'] = True
    except KeyboardInterrupt:
        result.update(processing_status='stopped', error='interrupted')
        if external:
            external.finish()
    except Exception as exc:
        result.update(processing_status='stopped', error=str(exc) if isinstance(exc, (protocol.Stop, ProtocolError)) else 'local_input_or_processing_error')
        if external:
            external.finish()
    return result
