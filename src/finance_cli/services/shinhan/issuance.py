"""Interactive first certificate enrollment through the account/security route."""
from finance_cli.core import storage
from . import device_phone, enrollment, issuance_auth, issue, keypad, pin_registration, security_media, session, setup
from .enrollment import Pending
from .exchange import Exchange


def perform(exchange, ask):
    state, report = exchange.state, exchange.report
    if state.get('authenticated'):
        raise Pending('first_issuance_logged_out_session_required')
    context = state['enrollment'] = {}
    phone_state = state.get('device_phone', {})
    if phone_state.get('verified') is True:
        phone = phone_state.get('phone_number')
        report['device_phone_verification'] = 'previously_verified'
    else:
        phone = device_phone.verify(exchange, lambda destination, message:
                                    ask('send_phone_sms', {'destination': destination, 'message': message}))
    documents = enrollment.terms(exchange)
    if ask('terms', documents) is not True:
        raise Pending('terms_declined')
    context.update(terms=documents, terms_accepted=True)
    values = ask('identity', {'phone': phone})
    phone = enrollment.digits(phone)
    if len(phone) not in (10, 11) or not phone.startswith('01'):
        raise Pending('device_phone_format_required')
    identity = {name: values[name] for name in ('name', 'birth', 'gender', 'telecom')}
    identity['phoneNumber'] = phone[:3]+'-'+phone[3:-4]+'-'+phone[-4:]
    enrollment.request_sms(exchange, identity)
    enrollment.verify_sms(exchange, ask('identity_sms', {}))
    route = enrollment.prepare_authentication(exchange,
        confirm=lambda name, value: ask(name, value), age_for_rrn=lambda birth, gender: enrollment.age(exchange, birth, gender))
    report['authentication_route'] = route
    if route != 'SELECT_AUTH':
        raise Pending({'CLOUD_DOWNLOAD': 'cloud_certificate_download_required',
                       'NO_FACE_AUTH': 'no_face_authentication_required',
                       'SECURITY_MEDIA': 'mobile_otp_authentication_required'}.get(route, 'issuance_route_unavailable'))
    if ask('account_security_route', {'kind': context['security_media']['securityMediaType']}) is not True:
        raise Pending('authentication_route_cancelled')
    channel = keypad.Channel(exchange)
    encrypted = channel.read(lambda: ask('resident_identity', {}), 7)
    issuance_auth.resident_identity(exchange, encrypted)
    device = exchange.settings['device']
    issuance_auth.fds(exchange, {'APP_VERSION': exchange.settings['version'], 'OS_TYPE': 'A',
                                'PHONE_OS': device['os_version'], 'PHONE_MODEL': device['model']}, ask('network_info', {}))
    candidates = [account for account in context['authentication_accounts'] if account.get('bankCode') == '088']
    account = ask('account', candidates)
    # The screen also accepts direct entry, including when its remembered list
    # is empty. The bank verifies ownership/password in the following request.
    if not isinstance(account, str) or not account:
        raise Pending('issuance_account_input_required')
    security_media.account_authentication(exchange, account, ask, channel=channel)
    issuance_auth.additional_authentication(exchange, select=lambda value: ask('additional_select', value),
        respond=lambda method, seconds: ask('additional_response', {'method': method, 'seconds': seconds}))
    reference = issuance_auth.reference(exchange, account=enrollment.digits(account), bank='088')
    unique, salt = pin_registration.prepare(exchange, ask, channel=channel)
    password = ask('storage_password', {})
    return issue.complete(exchange, reference, password, unique, salt)


def run(input_factory):
    settings = setup.load()
    if not all(isinstance(settings.get(name), str) for name in ('pin_check_key', 'keypad_alphabet', 'e2e_key')):
        return {'operation': 'certificate_issue', 'network_used': False, 'processing_status': 'incomplete',
                'bank_result': 'unknown', 'error': 'issuance_settings_update_required'}
    folder = setup.prepare_directory()
    path = folder/'session.json'
    previous = storage.read_json(path) if path.exists() else {}
    startup = None
    if not previous.get('cookie'):
        startup = session.execute('start')
        if startup['bank_result'] != 'success':
            return {'operation': 'certificate_issue', 'startup': startup, 'network_used': startup['network_used'],
                    'bank_result': startup['bank_result'], 'processing_status': 'incomplete', 'error': 'startup_incomplete'}
    exchange = None
    try:
        with storage.lock(folder/'.lock'):
            state = storage.read_json(path) if path.exists() else {}
            exchange = Exchange(settings, state, 'certificate_issue')
            if startup:
                exchange.report.update(startup=startup, bank_result=startup['bank_result'], network_used=startup['network_used'])
            try:
                if not state.get('cookie'):
                    raise Pending('startup_session_unavailable')
                perform(exchange, input_factory(exchange))
            except Pending as error:
                exchange.report.update(processing_status='incomplete', required_action=error.action)
            except (KeyboardInterrupt, EOFError):
                exchange.report.update(processing_status='incomplete', error='interrupted')
            except Exception:
                exchange.report.update(processing_status='incomplete', error='issuance_processing_error')
            state['last_operation'] = 'certificate_issue'
            exchange.save()
            return exchange.report
    except (Exception, KeyboardInterrupt) as error:
        if exchange is not None:
            exchange.report.update(processing_status='incomplete', error='issuance_prepare_error')
            exchange.warning('issuance_local_processing_error')
            return exchange.report
        # Creating the report or acquiring the lock can fail after startup was
        # accepted. Preserve that result even when no issuance Exchange exists.
        return {'operation': 'certificate_issue', **({'startup': startup} if startup else {}),
                'network_used': startup['network_used'] if startup else False,
                'bank_result': startup['bank_result'] if startup else 'unknown',
                'processing_status': 'incomplete', 'local_status': 'incomplete',
                'error': 'interrupted' if isinstance(error, (KeyboardInterrupt, EOFError)) else 'issuance_prepare_error'}
