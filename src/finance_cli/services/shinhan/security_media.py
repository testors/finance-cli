"""Certificate issuance security card and physical OTP authentication."""
import re

from . import issuance_auth, keypad, web
from .enrollment import Pending, field


def options(media, *, login_info=None, challenges=None):
    """Select the full security-media dialog from the issuance screen's values."""
    logged_in = not web.nullish(login_info)
    if logged_in:
        info = dict(login_info)
        for index in (1, 2):
            info[f'COM_SEC_CHAL{index}'] = (challenges or {}).get(f'COM_SEC_CHAL{index}') or ''
    else:
        info = {'secrityMdiaInfS1': ('1' if media.get('secrityCdBnkGS1') == 'S' else '2')
                if media.get('secrityMdiaGS1') == '1' else '5'}
        for index in (1, 2):
            if f'comSecChal{index}' in media:
                info[f'COM_SEC_CHAL{index}'] = media[f'comSecChal{index}']
    questions = {}
    for index in (1, 2):
        key = f'COM_SEC_CHAL{index}'
        source, name = (media, f'comSecChal{index}') if web.nullish(info.get(key)) else (info, key)
        if f'secretChar{index}' in info:
            source, name = info, f'secretChar{index}'
        if name in source:
            questions['firstNumber' if index == 1 else 'secondNumber'] = source[name]
    kind = info.get('secrityMdiaInfS1')
    if kind in ('1', '2', '3', '4'):
        return {'kind': 'card', 'cardType': '3' if kind == '1' else '4', **questions,
                'serialNumberArray': [media.get(f'secrityCdSerQry{index}S1') for index in (1, 2, 3)],
                'nextServiceCode': 'RSMCM1100A09'}
    if kind == '5':
        if questions.get('firstNumber') == '31':
            return {'kind': 'mobile_otp'}
        if (logged_in and (web.nullish(info.get('otpSerS12')) or info.get('otpSerS12') == 'XXXX')
                and info.get('smartOtpVndrS3') == '512'):
            return {'kind': 'reissue'}
        return {'kind': 'otp', 'serviceCode': 'RSMCM1100A04' if media.get('secrityMdiaGS1') == '1' else 'RSMCM1100A02',
                'nextServiceCode': 'RSMCM1100A09'}
    return {'kind': 'reissue' if kind == '0' else 'unavailable'}


def serial_numbers(values):
    # The native bridge converts JSON array strings with Kotlin toInt(), then
    # the activity requires exactly three numbers. This is local consumption.
    result = []
    for value in values:
        value = str(value) if type(value) in (int, float) else value
        if not isinstance(value, str) or not re.fullmatch(r'[+-]?[0-9]+', value):
            raise ValueError('security_card_serial_query_invalid')
        number = int(value)
        if not -2**31 <= number < 2**31:
            raise ValueError('security_card_serial_query_invalid')
        result.append(str(number))
    if len(result) != 3:
        raise ValueError('security_card_serial_queries_missing')
    return result


def card_input(channel, selected, input_provider):
    queries = serial_numbers(selected['serialNumberArray'])
    # Both JSONObject.getString calls occur before creating the native keypad.
    selected = {**selected, 'firstNumber': selected['firstNumber'], 'secondNumber': selected['secondNumber']}
    channel.prepare()
    serial = input_provider('card_serial', selected)
    channel.encrypt(serial, 3)  # Native encrypts this too, then consumes decodeAll.
    first = channel.encrypt(input_provider('card_first', selected), 2)
    second = channel.encrypt(input_provider('card_second', selected), 2)
    return {'cardType': 'TYPE_'+selected['cardType'], 'requestSerialNumberArray': queries,
            'responseSerialNumberArray': list(serial.decode('ascii')),
            'firstPassword': first, 'secondPassword': second}


def verify_otp(exchange, encrypted, *, service='RSMCM1100A02', next_service='RSMCM1100A09'):
    if service not in ('RSMCM1100A02', 'RSMCM1100A04'):
        raise ValueError('otp_service_invalid')
    if encrypted is None:
        raise Pending('otp_input_unavailable')
    step, document = exchange.bank('security_otp_verify', service,
        {'otpCdPswdS200': encrypted, 'nxtSvcCS20': next_service}, path='/serviceEndpoint/httpDigital/')
    exchange.report['security_media_verification'] = step['result']
    if step['result'] == 'failure':
        code = field(field(document, 'dataHeader'), 'resultCode')
        if code in ('RIB05540', 'RIB05550'):
            exchange.report['otp_error'] = {'maximum_count_exceeded': True}
        elif isinstance(code, str) and code.startswith(('RIB0554', 'RIB0555')):
            # digitToInt may throw for a malformed bank code after the FAIL.
            if code[-1] not in '0123456789':
                raise ValueError('otp_error_count_invalid')
            exchange.report['otp_error'] = {'count': int(code[-1]), 'correction_required': code.startswith('RIB0555')}
    if step['result'] != 'success':
        raise Pending('security_media_unverified')
    # NetworkResponse.Success maps to Unit; no dataBody/isOk test is added.
    return {'state': 'done', 'secureType': 'OTP'}


def authenticate(exchange, input_provider, *, channel=None, login_info=None):
    context = exchange.state['enrollment']
    media = context['security_media']
    if media.get('securityMediaType') == 'MOBILE_OTP':
        raise Pending('mobile_otp_authentication_required')
    challenges = {f'COM_SEC_CHAL{index+1}': value for index, value in
                  enumerate(exchange.state.get('web_challenges', []))}
    selected = options(media, login_info=login_info, challenges=challenges)
    kind = selected['kind']
    exchange.report['security_media_kind'] = kind
    if kind not in ('card', 'otp'):
        raise Pending('security_media_'+kind)
    channel = channel or keypad.Channel(exchange)
    if kind == 'card':
        result = card_input(channel, selected, input_provider)
        issuance_auth.security_card_serial(exchange, result)
    else:
        encrypted = channel.read(lambda: input_provider('otp', selected), 6)
        verify_otp(exchange, encrypted, service=selected['serviceCode'], next_service=selected['nextServiceCode'])
    context['security_media_verified'] = True
    exchange.save()


def account_authentication(exchange, account, input_provider, *, channel=None, login_info=None):
    """The selected account password precedes its security-media authentication."""
    channel = channel or keypad.Channel(exchange)
    encrypted = channel.read(lambda: input_provider('account_password', {'account': account}), 4)
    issuance_auth.account_password(exchange, account, encrypted)
    authenticate(exchange, input_provider, channel=channel, login_info=login_info)
