"""Certificate enrollment web stages. Identity data stays in private workflow state.

These functions are not a certificate import or a substitute for device phone
verification. The caller supplies the original screen's inputs and callbacks;
the complete device/security-media frontend is still being connected.
"""
import re

from . import web


TERMS_PROGRAM = 'CA0902H0081P01'
PHONE_PROGRAM = 'CA0903H7000F01'
TERM_IDS = ('910000129', '2022042600000035', '900000047', '980000001',
            '980000002', '980000003')


class Pending(Exception):
    """A navigation, input, or response boundary, never an inferred bank failure."""
    def __init__(self, action):
        self.action = action


def field(value, key):
    return value.get(key) if isinstance(value, dict) else None


def request(exchange, stage, transaction, body, *, program=PHONE_PROGRAM):
    verdict, document = exchange.web(stage, transaction, body, program=program)
    if not verdict['callback_ready']:
        raise Pending(verdict['required_action'])
    return verdict, field(document, 'dataBody'), field(document, 'dataHeader')


def terms(exchange):
    _, body, header = request(exchange, 'enrollment_terms', 'RSMCM9000C10',
                               {'stplInqrVS1000': ','.join(TERM_IDS)}, program=TERMS_PROGRAM)
    rows = field(body, 'grid01')
    if field(header, 'result') != 'SUCCESS' or not web.truthy(rows):
        raise Pending('terms_unavailable')
    # Original helpers call map/find directly: malformed or missing documents
    # stop processing after the observed bank result; no invented empty terms.
    if not isinstance(rows, list):
        raise ValueError('terms_response_shape')
    result = []
    for term_id in TERM_IDS:
        row = next((row for row in rows if row['stplDocIdS22'].startswith(term_id+'_')), None)
        if row is None:
            raise ValueError('term_document_missing')
        result.append({'id': term_id, 'document_id': row['stplDocIdS22'],
                       'title': row.get('stplTtlS200'), 'url': row.get('stplApdfUrlS200')})
    return result


def request_sms(exchange, identity):
    parts = identity['phoneNumber'].split('-')
    parts += [''] * max(0, 3-len(parts))
    _, body, header = request(exchange, 'identity_sms_request', 'RSMCM0801A07', {
        'subChanG': '03', 'cusnm': identity['name'].strip(),
        'rrgsNo1S6': identity['birth'], 'rrgsNo2S7': identity['gender'],
        'commCoGS1': identity['telecom'], 'hpGNoS4': parts[0],
        'hpMainNoS4': parts[1], 'hpSubNoS4': parts[2]})
    if field(header, 'result') != 'SUCCESS':
        raise Pending('identity_sms_not_sent')
    context = exchange.state.setdefault('enrollment', {})
    context.update(identity=dict(identity), sms_reference=field(body, 'authNatvNoS24'), sms_verified=False)
    exchange.report['identity_sms_request'] = 'success'
    exchange.save()
    return context['sms_reference']


def verify_sms(exchange, code):
    context = exchange.state['enrollment']
    identity, reference = context['identity'], context['sms_reference']
    if len(code) < 6 or not web.truthy(reference):
        raise Pending('identity_sms_input_required')
    verdict, body, header = request(exchange, 'identity_sms_verify', 'RSMCM0801A08', {
        'subChanG': '03', 'rrgsNo1S6': identity['birth'], 'rrgsNo2S7': identity['gender'],
        'smsAuthNoS8': code, 'authNatvNoS24': reference})
    # This screen explicitly checks both fields, independently of bridge isOk.
    verified = field(header, 'result') == 'SUCCESS' and field(body, 'authConfRstS4') == '0000'
    if not verified:
        exchange.report['identity_verification'] = ('failure' if verdict['bank_result'] == 'failure' or
            verdict['bank_result'] == 'success' and field(body, 'authConfRstS4') is not None else 'unknown')
        raise Pending('identity_sms_unverified')
    identity = {**identity, 'phoneNumber': identity['phoneNumber'].replace('-', ''),
                'customerCI': field(body, 'ciS88')}
    context.update(identity=identity, sms_verified=True)
    exchange.report['identity_verification'] = 'success'
    exchange.save()
    return identity


def identify(exchange, identity, consent, sms_code):
    """Terms and SMS after the device-phone step; no implicit consent/retry."""
    documents = terms(exchange)
    if not consent(documents):
        raise Pending('terms_declined')
    context = exchange.state.setdefault('enrollment', {})
    context['terms'] = documents
    context['terms_accepted'] = True
    request_sms(exchange, identity)
    return verify_sms(exchange, sms_code())


def customer(exchange, identity, *, login_info=None):
    # getLoginInfo is the mapped app user, not the raw bank login envelope.
    login = login_info
    if login:
        info = {'isNewCIF': field(login, 'newcifYn') == 'Y',
                'isSOLCustomer': field(login, 'smartBnkgEntSangtaeS1') == '1',
                'customerNumber': field(login, 'cusnoS10'),
                'customerName': field(login, 'cusSungNmS30'),
                'customerCI': field(login, 'ciNoS88'), 'isLoggedIn': True}
        transaction = 'RSMCM0303A01'
    else:
        ci = identity.get('customerCI')
        _, body, _ = request(exchange, 'enrollment_customer', 'RSMCM9000A08',
                              {'inqrGS2': '09' if web.truthy(ci) else '01',
                               'inqrNoS100': '' if ci is None else ci})
        rows = field(body, 'grid01')
        first = rows[0] if isinstance(rows, list) and rows else None
        number = field(first, 'cusno')
        info = {'isNewCIF': first is None or field(first, 'drCusBL10') == 20,
                'isSOLCustomer': web.truthy(number) and field(body, 'sbankEntYnS1') == '1',
                'customerNumber': str(number).zfill(10) if web.truthy(number) else '',
                'customerName': field(first, 'cusnm'), 'customerCI': None, 'isLoggedIn': False}
        transaction = 'RSMCM0303A03'
    # The app requests this even when customer inquiry returned an ordinary FAIL.
    verdict, body, _ = request(exchange, 'enrollment_identity_kind', transaction, {})
    info['silnoG'] = field(body, 'silnoG') if verdict['bridge_success'] else None
    exchange.state.setdefault('enrollment', {})['customer'] = info
    exchange.save()
    return info


def contact(exchange, customer_info, identity):
    number = customer_info['customerNumber']
    number = str(number).zfill(10) if not web.nullish(number) else ''
    phone = identity['phoneNumber']
    body = ({'upmuGN1': 1, 'srchGN1': 1, 'bnkG': 1, 'srchNoS30': '',
             'hpNoS12': phone, 'loginType': 'CERT'} if web.nullish(number) else
            {'srchNoS30': number, 'hpNoS12': phone})
    _, data, header = request(exchange, 'enrollment_contact', 'RSMCM0301B07', body)
    registered = field(data, 'hpNoS12')
    result = {'registeredPhoneNumber': registered,
              'isPhoneNumberDifferent': web.truthy(registered) and phone != registered,
              'isTransactionSuccess': field(header, 'result') == 'SUCCESS'}
    exchange.state.setdefault('enrollment', {})['contact'] = result
    exchange.save()
    return result


def digits(value):
    return re.sub('[^0-9]', '', '' if value is None else str(value))


def number_is(value, expected):
    return type(value) in (int, float) and value == expected


def authentication_accounts(exchange):
    """The issue screen's eligible account candidates, not the loan list."""
    verdict, body, _ = request(exchange, 'enrollment_accounts', 'RSMDE0106A03', {'loginTrxGN1': '5'})
    body = body if verdict['bridge_success'] else None
    rows, other = field(body, 'sub01'), field(body, 'sub02')
    if not web.truthy(rows) or not web.truthy(other):
        return []
    if not isinstance(rows, list):
        raise ValueError('accounts_response_shape')
    shinhan = []
    for row in rows:
        prefix = (row.get('acno') or '')[:3]
        eligible = (number_is(row.get('depK'), 1) or number_is(row.get('depK'), 5) and prefix in ('180', '181'))
        if number_is(row.get('ipGnyn'), 1) and eligible and row.get('prdtC') != '110003101':
            old, new = digits(row.get('guAcno')), row.get('acno_originalValue')
            shinhan.append({'productName': row.get('prdtHngNmS50'), 'oldAccountNumber': old,
                            'newAccountNumber': new, 'accountNumber': old if web.truthy(row.get('guAcno')) else new,
                            'bankName': '신한', 'bankCode': '088'})
    verdict, body, _ = request(exchange, 'enrollment_registered_accounts', 'RSMCM0800C01', {})
    registered = field(body, 'accountList') if verdict['bridge_success'] else None
    if not web.truthy(registered) or len(registered) == 0:
        return []
    verdict, body, _ = request(exchange, 'enrollment_bank_names', 'RSMCM9009A01', {'codeGS30': 'bank_code_smart'})
    rows = field(body, 'grid01') if verdict['bridge_success'] else None
    banks = {str(row.get('codeVS10')).zfill(3): row for row in rows or []}
    result = []
    for row in registered:
        bank = str(row.get('bankCd')).zfill(3)
        name = field(banks.get(bank), 'codeHngNmS100') or ''
        if bank not in ('088', '021', '026') and name:
            account = digits(row.get('accountNumber'))
            result.append({'productName': name, 'oldAccountNumber': account, 'newAccountNumber': account,
                           'accountNumber': account, 'bankName': name, 'bankCode': bank})
        else:
            matched = next((item for item in shinhan if row.get('accountNumber') in
                            (item['newAccountNumber'], item['oldAccountNumber'])), None)
            if matched is not None:
                result.append(matched)
    return result


def cloud_certificates(exchange):
    _, body, header = request(exchange, 'enrollment_cloud_certificates', 'RSMCM0906A02', {})
    if field(header, 'result') != 'SUCCESS':
        raise Pending('cloud_certificate_query_incomplete')
    rows = field(body, 'certList')
    if web.nullish(rows):
        return []
    if not isinstance(rows, list):
        raise ValueError('cloud_certificate_response_shape')
    return [{'shSignSequenceNumber': row.get('certSeqNo'), 'shSignExpirationTimestamp': row.get('certExpireTs')}
            for row in rows if field(row, 'existCloudCertYn') == 'Y']


def security_media(exchange, *, mobile_issue_info=None, mobile_precheck=None):
    _, body, _ = request(exchange, 'enrollment_security_media', 'RSMCM1100A07', {})
    kind = field(body, 'secrityMdiaGS1')
    if kind == '1':
        return {**body, 'securityMediaType': 'SECURITY_CARD'}
    if kind != '2':
        return None
    verdict, _, _ = request(exchange, 'enrollment_security_status', 'RSMCM1100B03', {})
    if not verdict['bridge_success']:
        return None
    if field(body, 'comSecChal1') != '31':
        return {**body, 'securityMediaType': 'OTP'}
    if mobile_issue_info is None:
        raise Pending('mobile_otp_state_required')
    info = mobile_issue_info()
    if not web.truthy(field(info, 'isOk')) or not web.truthy(field(field(info, 'params'), 'serialNumber')):
        return None
    if mobile_precheck is None:
        raise Pending('mobile_otp_precheck_required')
    if not web.truthy(field(mobile_precheck(), 'isSuccess')):
        return None
    return {**body, 'securityMediaType': 'MOBILE_OTP'}


def prepare_authentication(exchange, *, confirm, age_for_rrn, login_info=None,
                           mobile_issue_info=None, mobile_precheck=None):
    """Follow the verified phone screen through the original auth-route choice.

    UI/device callbacks are injected, not inferred from an empty native store.
    The returned route still requires its account/security or no-face steps.
    """
    context = exchange.state['enrollment']
    if context.get('sms_verified') is not True:
        raise Pending('identity_sms_unverified')
    identity = context['identity']
    info = customer(exchange, identity, login_info=login_info)
    if not info['isSOLCustomer']:
        raise Pending('sol_membership_required')
    if not info['isNewCIF'] and not any(number_is(info['silnoG'], value) for value in (1, 5, 6)):
        # xn returns an earlier SUCCESS object here but without customerInfo.
        # Preserve the bank result and stop the subsequent missing-info consumer.
        raise Pending('customer_identity_kind_unavailable')
    if info['isLoggedIn'] and info['customerCI'] != identity.get('customerCI'):
        raise Pending('customer_identity_update_required')
    if identity['name'] != info['customerName'] and not confirm('name_changed', {
            'entered_name': identity['name'], 'registered_name': info['customerName']}):
        raise Pending('name_change_declined')
    if age_for_rrn(identity['birth'], identity['gender']) < 14:
        raise Pending('guardian_branch_visit_required')
    if identity['gender'] in ('5', '6', '7', '8'):
        raise Pending('foreign_identity_required')
    contact_info = contact(exchange, info, identity)
    if not web.truthy(identity['phoneNumber']):
        raise Pending('phone_number_required')
    if contact_info['isPhoneNumberDifferent'] and not confirm('phone_changed', contact_info):
        raise Pending('phone_change_declined')
    accounts = authentication_accounts(exchange)
    context['authentication_accounts'] = accounts
    registered = contact_info['registeredPhoneNumber']
    same_phone = web.truthy(registered) and identity['phoneNumber'] == registered
    if same_phone:
        certificates = cloud_certificates(exchange)
        context['cloud_certificates'] = certificates
        if certificates and confirm('download_cloud_certificate', certificates):
            context['authentication_route'] = 'CLOUD_DOWNLOAD'
            exchange.save()
            return 'CLOUD_DOWNLOAD'
    route, media = 'NO_FACE_AUTH', None
    if not info['isNewCIF'] and same_phone:
        # This is a separate original inquiry with a different body; do not
        # deduplicate it with the preceding account-auth candidate inquiry.
        _, body, header = request(exchange, 'enrollment_route_accounts', 'RSMDE0106A03', {})
        rows = field(body, 'sub01')
        if field(header, 'result') == 'SUCCESS' and web.truthy(rows) and len(rows) != 0:
            media = security_media(exchange, mobile_issue_info=mobile_issue_info, mobile_precheck=mobile_precheck)
            if media:
                route = 'SECURITY_MEDIA' if media['securityMediaType'] == 'MOBILE_OTP' else 'SELECT_AUTH'
    context.update(authentication_route=route, security_media=media)
    exchange.save()
    return route
