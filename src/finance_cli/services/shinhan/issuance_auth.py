"""Resident/account verification and the bank-issued certificate reference."""
from . import web
from .enrollment import Pending, field, request

RRN_PROGRAM = 'CA0902H0043P01'
ACCOUNT_PROGRAM = 'CA0751S0011P06'


def observed(header):
    result = field(header, 'result')
    return 'success' if result == 'SUCCESS' else 'failure' if result == 'FAIL' else 'unknown'


def resident_identity(exchange, encrypted, *, login_info=None):
    context = exchange.state['enrollment']
    identity, customer = context['identity'], context['customer']
    birth, ci = identity['birth'], identity.get('customerCI')
    if len(birth) != 6 or not web.truthy(encrypted):
        raise Pending('resident_identity_input_required')
    logged_in = not web.nullish(login_info)
    if logged_in:
        request(exchange, 'resident_identity_ci', 'RSMCM9000A32', {'inqrNoS100': ci}, program=RRN_PROGRAM)
    _, body, header = request(exchange, 'resident_identity_verify', 'RSMCM0000A05', {
        'trxGS2': '01', 'biryrMmddS6': birth, 'silno2': encrypted,
        'silnoBigyoYnS1': 'N' if customer['isNewCIF'] else 'Y'}, program=RRN_PROGRAM)
    exchange.report['resident_identity_verification'] = observed(header)
    if field(header, 'result') != 'SUCCESS':
        raise Pending('resident_identity_unverified')
    if not logged_in:
        # Original refreshes the customer context; it does not reject on the
        # helper's ordinary business failure or request identity kind again.
        request(exchange, 'resident_identity_customer_refresh', 'RSMCM9000A08',
                {'inqrGS2': '09' if web.truthy(ci) else '01', 'inqrNoS100': '' if ci is None else ci},
                program=RRN_PROGRAM)
    info = {'birth': birth, 'secret': encrypted, 'transactionNumber': field(body, 'trxnoS8')}
    context['resident_identity'] = info
    exchange.save()
    return info


def fds(exchange, device_info, network_info, *, program=RRN_PROGRAM):
    body = {'trxG': '07'}
    for output, source in [('appVersion', 'APP_VERSION'), ('osType', 'OS_TYPE'),
                           ('osVersion', 'PHONE_OS'), ('phoneModel', 'PHONE_MODEL')]:
        if source in device_info:
            body[output] = device_info[source]
    body['vpnYn'] = 'Y' if web.truthy(network_info.get('useVPN')) else 'N'
    if 'countryCode' in network_info:
        body['networkCntryCd'] = network_info['countryCode']
    _, _, header = request(exchange, 'issuance_fds', 'RSMCM1005A02', body, program=program)
    exchange.report['issuance_fds'] = observed(header)
    if field(header, 'result') != 'SUCCESS':
        raise Pending('issuance_fds_unavailable')


def account_password(exchange, account, encrypted):
    context = exchange.state['enrollment']
    rrn = context['resident_identity']
    if encrypted is None:
        raise Pending('account_password_cancelled')
    if account[:3] in ('180', '181', '185'):
        transaction = 'RSMFO0001A02'
        body = {'bnkG': '1', 'trxG': '2', 'imptdoc': '1', 'acno': account,
                'scno6': encrypted, 'biryrMmddS6': rrn['birth'], 'silno': rrn['secret']}
    else:
        transaction = 'RSMDE0301B01'
        body = {'jiAcno': account, 'jiAcScno': encrypted, 'biryrMmddS6': rrn['birth'], 'silnoS13': rrn['secret']}
    _, _, header = request(exchange, 'issuance_account_password', transaction, body, program=ACCOUNT_PROGRAM)
    exchange.report['account_password_verification'] = observed(header)
    if field(header, 'result') != 'SUCCESS':
        raise Pending('account_password_unverified')
    context['verified_account'] = account
    exchange.save()


def security_card_serial(exchange, result):
    """Consume the secure-card callback's encrypted values, not plaintext."""
    media = exchange.state['enrollment']['security_media']
    queries, responses = result.get('requestSerialNumberArray'), result.get('responseSerialNumberArray')
    if (queries is not None and len(queries) < 3 or responses is not None and len(responses) < 3 or
            not web.truthy(result.get('firstPassword')) or not web.truthy(result.get('secondPassword'))):
        raise Pending('security_card_input_required')
    body = {'icheScnoGS1': '1'}
    for key in ('secrityCdMdiaGS1', 'secrityCdBnkGS1'):
        source = 'secrityMdiaGS1' if key == 'secrityCdMdiaGS1' else key
        if source in media:
            body[key] = media[source]
    for prefix, values in [('secrityCdSerQry', queries), ('secrityCdSerResp', responses)]:
        if values is not None:
            body.update({prefix+str(index+1)+'S1': values[index] for index in range(3)})
    body.update(secrityCdPswd1S24=result['firstPassword'], secrityCdPswd2S24=result['secondPassword'])
    _, _, header = request(exchange, 'issuance_security_card', 'RSMCM1100A09', body, program=ACCOUNT_PROGRAM)
    exchange.report['security_media_verification'] = observed(header)
    if field(header, 'result') != 'SUCCESS':
        raise Pending('security_media_unverified')


def additional_authentication(exchange, authenticate, *, program=ACCOUNT_PROGRAM):
    customer = exchange.state['enrollment']['customer']
    _, body, header = request(exchange, 'issuance_additional_auth_check', 'RSMCM1005A04',
                              {'cusnoS10': customer['customerNumber']}, program=program)
    exchange.report['additional_auth_check'] = observed(header)
    if field(header, 'result') != 'SUCCESS':
        raise Pending('additional_auth_check_unavailable')
    sequence = field(body, 'svcSeqS3')
    required = field(body, 'addAuthDsYnS1') == 'Y' and not web.nullish(sequence)
    exchange.report['additional_auth_required'] = required
    if required:
        result = authenticate({'serviceSeq': sequence, '고객번호': customer['customerNumber'],
                               '고객성명': customer['customerName']})
        if field(result, '인증여부') != 'Y':
            raise Pending('additional_authentication_incomplete')
        exchange.report['additional_authentication'] = 'success'
    exchange.state['enrollment']['additional_auth_complete'] = True
    exchange.save()


def reference(exchange, *, account='', bank='', recommendation=None, no_face=None,
              rrn_expiration='', program=ACCOUNT_PROGRAM):
    context = exchange.state['enrollment']
    identity, rrn, customer = context['identity'], context['resident_identity'], context['customer']
    if not all(web.truthy(identity.get(name)) for name in ('birth', 'gender', 'telecom', 'phoneNumber')):
        raise Pending('issuance_identity_input_required')
    recommendation, no_face = recommendation or {}, no_face or {}
    request_key = no_face.get('reqKey', '')
    expiry, client = identity.get('rrnExpirationDate'), identity.get('clientId')
    body = {'cvtYnS1': '1', 'biryrMmddS8': identity['birth'], 'silnoBkstS7': rrn['secret'],
            'sex': identity['gender'], 'oigukinIdcdYhtm': expiry if web.truthy(expiry) else rrn_expiration,
            'commCoG': identity['telecom'], 'hpnoS14': identity['phoneNumber']}
    for output, source in [('suggHwnno', 'hwnnoNormal'), ('mngBrnoS4', 'brnoS4'), ('ssiSuggGrpC', 'corpCode')]:
        if source in recommendation:
            body[output] = recommendation[source]
    body.update(clientId=client if web.truthy(client) else '', reqKey=request_key, reqKey2=request_key,
                imgKey=no_face.get('imgKey', ''), accountNo=account, bankCd=bank)
    _, data, header = request(exchange, 'issuance_reference', 'RSMCM0890A01', body, program=program)
    exchange.report['issuance_reference'] = observed(header)
    if field(header, 'result') != 'SUCCESS':
        raise Pending('issuance_reference_unavailable')
    enrollment = {'customerNumber': customer['customerNumber'], 'customerName': customer['customerName'],
                  'referenceNumber': field(data, 'refNoS20'), 'authCode': field(data, 'ingaCS20')}
    # A missing value does not change the bank success. The CMP consumer will
    # record its own incomplete processing instead of fabricating reference data.
    context['certificate_enrollment'] = enrollment
    exchange.save()
    return enrollment
