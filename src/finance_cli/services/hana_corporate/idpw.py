"""Single-attempt corporate ID/password login; secrets come from an input provider."""
from finance_cli.core import storage
from finance_cli.services.hana.nfilter_crypto import OpenSSL, encrypt_character_password
from finance_cli.services.hana.onesign_io import send_http
from . import keypad, protocol, store
from .transport import Client


def plan():
    return {'channel': 'corporate', 'login_method': '1', 'network_used': False, 'accepted': None,
            'processing_status': 'planned', 'next': 'same_command_with_send', 'certificate_required': False,
            'automatic_retry': False, 'live_tested': True, 'verification_source': 'user_reported_cli_output'}


def follow_up(client, result):
    detail = {'app_fds': 'not_implemented', 'customer_guidance': 'unconfirmed'}
    result['follow_up'] = detail
    for stage, body in (
        ('withdrawal-info', {'exceptSignedMsgYn': 'Y', 'COMM_HEAD': {'SIGNED_MSG': '', 'VID_MSG': '', 'LGIN_CERT_METH_CD': ''}}),
        ('customer-check', {'INQ_TYPE': '1'}),
    ):
        try:
            data = client.request(stage, body)
        except Exception as exc:
            detail[stage] = str(exc) if isinstance(exc, protocol.Stop) else 'follow_up_processing_error'
            continue  # These callback failures do not revoke the observed login.
        detail[stage] = 'received'
        if stage == 'customer-check':
            client.saved['customer_check'] = data
            detail['customer_guidance'] = protocol.customer_guidance(data)
    guidance = detail['customer_guidance']
    if guidance == 'certificate_login_required':
        client.saved['session_usage'] = result['session_usage'] = 'certificate_login_required'
        detail['logout'] = 'unconfirmed'

        def logged_out(receipt, data):
            if receipt['service_status'] == 'accepted':
                detail['logout'] = 'accepted'
                client.saved['login_verified'] = False
                result['session_current_validity'] = 'logged_out'

        try:
            client.request('logout', observe=logged_out)
        except Exception as exc:
            detail['logout_processing'] = str(exc) if isinstance(exc, protocol.Stop) else 'logout_processing_error'
    client.saved['follow_up'] = detail
    try:
        storage.atomic_json(client.directory / 'session.json', client.saved)
    except (OSError, ValueError):
        result['session_saved'] = False
        raise protocol.Stop('session_storage_failed') from None


def login(session, identity, settings, *, send=False, inputs=None, exchange=send_http):
    if not send:
        return plan()
    inputs = inputs or {}
    result = {'channel': 'corporate', 'session': session, 'login_method': '1', 'accepted': None,
              'user_login_verified': False, 'network_used': False, 'automatic_retry': False,
              'processing_status': 'preparing', 'stages': [], 'session_saved': False,
              'session_current_validity': 'unverified'}
    try:
        identity = protocol.user_id(identity)
        settings, mac = keypad.resolve(settings)
        OpenSSL()
        session, directory = store.prepare_idpw(session)
        result.update(session=session, settings=settings)
        with storage.lock(directory / 'operation.lock'):
            protocol.require(not (directory / 'login-attempt.json').exists(), 'login_already_attempted_use_new_session')
            profile = store.device(storage.read_json(directory / 'device.json'))
            # Validate push consistency and local crypto/settings before reading a secret or sending.
            protocol.idpw_body(identity, 'validation-only', profile['push'])
            password = protocol.id_password(inputs['password']())
            store.record(directory / 'login-attempt.json', {'login_method': '1', 'settings': settings, 'automatic_retry': False})
            client = Client(directory, profile, result, exchange=exchange)
            client.saved.update(login_method='1', user_id=identity, settings=settings)
            try:
                for stage in ('emergency', 'app-info'):
                    data = client.request(stage, native=True, assessor=protocol.assess_data)
                    warnings = protocol.check_bootstrap(stage, data)
                    if warnings:
                        result['stages'][-1]['warnings'] = warnings
                    stated = protocol.session_timeout_minutes(data) if stage == 'app-info' else None
                    if stated is not None:
                        client.saved['server_session_timeout_minutes'] = result['server_session_timeout_minutes'] = stated
                public = client.request('keypad-key', native=True, assessor=protocol.assess_data).get('publicKey')
                protocol.require(isinstance(public, str) and bool(public), 'keypad_public_key_unavailable')
                try:
                    encrypted = encrypt_character_password(public, password, mac)
                except (ValueError, TypeError):
                    raise protocol.Stop('keypad_encryption_failed') from None
                finally:
                    password = None

                def observe(receipt, data):
                    status = receipt['service_status']
                    accepted = True if status == 'accepted' else False if status == 'rejected' else None
                    result.update(accepted=accepted, user_login_verified=accepted is True,
                                  reason='login_accepted' if accepted else receipt['reason'])
                    for name in ('business_error_code', 'password_failures_reported'):
                        if name in receipt:
                            result[name] = receipt[name]
                    if accepted is True:
                        client.saved.update(login_verified=True, login_response=data)

                body = protocol.idpw_body(identity, encrypted, profile['push'])
                client.request('login-idpw', body, native=True, assessor=protocol.assess_native, observe=observe,
                               redact=('USER_ID', 'LOGIN_PW', 'C2DM_IDNM'))
                encrypted = body = None
                result['session_saved'] = True
                follow_up(client, result)
                result['processing_status'] = 'completed'
            except KeyboardInterrupt:
                result.update(processing_status='stopped', error='interrupted')
            except Exception as exc:
                result.update(processing_status='stopped', error=str(exc) if isinstance(exc, protocol.Stop) else 'local_processing_error')
            finally:
                password = None
                try:
                    store.record(directory / 'outcome.json', result)
                except (OSError, ValueError):
                    result['diagnostic_storage_failed'] = True
    except KeyboardInterrupt:
        result.update(processing_status='stopped', error='interrupted')
    except Exception as exc:
        result.update(processing_status='stopped', error=str(exc) if isinstance(exc, protocol.Stop) else 'local_input_or_processing_error')
    return result
