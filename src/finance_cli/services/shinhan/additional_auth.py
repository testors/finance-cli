"""ARS/SMS steps with caller-supplied selection and hidden input callbacks."""
import math
import re
import time

from . import legacy_web as legacy, web
from .enrollment import Pending

SELECT_PROGRAM = 'CO0703S0010P01'
AUTH_PROGRAM = 'CO0703S0011P01'
TRANSFERS = ('9', '30', '31')
PHONE_FIELDS = (('휴대폰번호', '휴대폰상이'), ('자택전화번호', '자택전화상이'), ('회사전화번호', '회사전화상이'))
MISSING = object()


def js_text(value):
    if value is MISSING:
        return 'undefined'
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, list):
        return ','.join('' if item is None else js_text(item) for item in value)
    if isinstance(value, dict):
        return '[object Object]'
    if isinstance(value, float):
        if math.isnan(value):
            return 'NaN'
        if value.is_integer():
            return str(int(value))
    return str(value)


def contact_number(data, prefix):
    parts = [data.get(prefix+str(i)+'no', MISSING) for i in (1, 2, 3)]
    value = parts[0]
    for other in parts[1:]:
        left = js_text(value) if isinstance(value, (dict, list)) else value
        right = js_text(other) if isinstance(other, (dict, list)) else other
        if isinstance(left, str) or isinstance(right, str):
            value = js_text(left)+js_text(right)
        else:
            value = float('nan') if left is MISSING or right is MISSING else (left or 0)+(right or 0)
    return value


def optional(body, params, mapping):
    for output, source in mapping:
        if source in params:
            body[output] = params[source]


def contacts(exchange, params):
    sequence = str(params.get('serviceSeq') or '')
    if sequence in ('1', '2'):
        transaction = 'RSMCM0301B04'
        body = {'upmuG': '4', 'srchGL1': '1', 'bnkG': '1', 'trxGL1': '02'}
    else:
        transaction = 'RSMCM0301B06' if sequence in ('72', '75') else 'RSMCM0301A02'
        body = {'upmuGN1': '4', 'srchGN1': '1', 'bnkG': '1', 'trxGS2': '02'}
    body['macAdr1S32'] = exchange.settings['device']['device_id']
    header = {'certTp': params['certTp'], 'serviceType': 'AA'} if str(params.get('certTp')) == '1' else {}
    data = legacy.request(exchange, 'additional_auth_contacts', transaction, body,
                          program=SELECT_PROGRAM, header=header)
    if not isinstance(data, dict):
        raise ValueError('additional_auth_contacts_shape')
    result = dict(params)
    mapping = [('휴대폰번호', 'hpNoS12'), ('휴대폰상이', 'hpDifrN1'),
               ('자택전화번호', 'homeTelnoS12'), ('자택전화상이', 'homeTelTmDifrN1'),
               ('회사전화번호', 'ofcTelnoS12'), ('회사전화상이', 'ofcTelTmDifrN1')]
    extras = [('중요거래통지휴대폰번호', 'imptTrxNotiHpNoS12', 'imptTrxNotiYnHpno'),
              ('해외체류확인여부', 'ovseaStayHiynS1', 'ovseaStayConfYn'),
              ('해외IP체크여부', 'ovseaIpCheckYnS1', 'ovseaIpChkYn'), ('해외IP여부', 'ovseaIpYnS1', 'ovseaIpYn'),
              ('외국인여부', 'oigukinYnS1', 'oigukinYn'), ('모바일승인신청여부', 'mblApscYnS1', 'mblAprvSincYn'),
              ('SMS허용', 'smsRecvYn', 'smsNalwYn'), ('OTP사용여부', 'otpUsynS1', 'otpUsyn'),
              ('인증서추가인증신청여부', 'certificateAddAuthSincYnS1', 'certiAddAuthAprvSincYn'),
              ('이체추가인증신청여부', 'icheAddAuthSincYnS1', 'icheAddAuthAprvSincYn'),
              ('심야여부', 'donYnS1', 'nightYn'), ('이체추가인증기준금액', 'icheAddAuthBasAmtN10', 'icheAddAuthBasAmt'),
              ('고객성명', 'cusnmS30', 'cusnmS30')]
    if transaction == 'RSMCM0301B04':
        mapping = [('휴대폰상이', 'hpDfyn'), ('자택전화상이', 'homeTmDfynL1'), ('회사전화상이', 'ofcTmDfynL1')]
        for output, prefix in [('휴대폰번호', 'hpT'), ('자택전화번호', 'homeTel'), ('회사전화번호', 'ofcTel')]:
            # The contact response contains three text fields. Missing/null
            # values retain their JavaScript concatenation, not a made-up number.
            result[output] = contact_number(data, prefix)
        mapping += [(out, old) for out, _, old in extras]
    elif transaction == 'RSMCM0301B06':
        result['해외IP여부'] = ''
    else:
        mapping += [(out, new) for out, new, _ in extras] + [('고객번호', 'cusno')]
    for output, source in mapping:
        result.pop(output, None)  # An absent response field overrides an earlier value with undefined.
        if source in data:
            result[output] = data[source]
    return result


def methods(params):
    sequence = str(params.get('serviceSeq') or '')
    if sequence in ('81', '84'):
        return ('face',)
    if sequence == '99':
        return ('phone_registration',)
    if sequence == '73':
        return ('sms',) if params.get('인증type') == 'S' else ('ars',) if params.get('인증type') == 'A' else ()
    # This client installs an Android context; the SMS button is Android-only.
    return ('ars', 'sms') if sequence in ('1', '2', '9', '30', '31', '62', '63') else ('ars',)


def phones(params):
    return [{'kind': str(index), 'number': params[number]} for index, (number, different) in enumerate(PHONE_FIELDS)
            if not legacy.nullish(params.get(number)) and str(params.get(different)) != '1']


def business_hours(exchange, group='A1'):
    group = group.upper()
    value = legacy.request(exchange, 'additional_auth_server_time', 'RSMCM9000A03',
                           {'bdtInqrGS20': 'getCurrentDateFmt', 'dtFrmtS20': 'yyyyMMdd HHmmss'},
                           program=AUTH_PROGRAM, show_message=False)
    parts = value['getCurrentDateFmt']['valueS20'].split(' ')
    date, clock = parts[0], parts[1] if len(parts) > 1 else None
    value = legacy.request(exchange, 'additional_auth_business_day', 'RSMCM9000A03',
                           {'bdtInqrGS20': 'isOpDate', 'rfdtS14': date, 'dcnt': 0},
                           program=AUTH_PROGRAM, show_message=False)
    working_day = value['isOpDate'].get('valueS20')
    if group in ('D2', 'E4', 'E5', 'F1'):
        return True
    if group not in ('A1', 'A2', 'A3', 'B1', 'B2', 'B3', 'C1', 'C2', 'C3',
                     'D1', 'D3', 'E1', 'E6', 'E7', 'F2', 'G1', 'G2', 'H1', 'H2'):
        raise Pending('additional_auth_business_hours_route')
    return web.truthy(working_day) and clock is not None and '090000' <= clock < '180000'


def request_body(params, method, phone, logged_in, in_hours):
    sequence = str(params.get('serviceSeq'))
    body = {'영업시간내외': '1' if in_hours else '0', 'authTypeS1': '0' if method == 'ars' else '1'}
    optional(body, params, [('upmuSeqS5', 'serviceSeq'), ('title', 'title'), ('svcCS6', '서비스코드'), ('nextSvcCS6', 'NEXT_서비스코드')])
    if sequence not in TRANSFERS:
        transaction = 'RSMCM1200A08' if logged_in else 'RSMCM1200A06'
        if sequence in ('6', '7', '20', '21') and method == 'ars' and '계좌번호_상품코드' in params:
            body['acnoPrdtCS12'] = params['계좌번호_상품코드'].replace('-', '')
        if sequence == '37':
            if legacy.nullish(params.get('계좌번호')):
                raise Pending('additional_auth_account_required')
            body['acnoPrdtCS12'] = params['계좌번호']
        optional(body, params, [('tramtS12' if logged_in else 'tramtN12', '거래금액')])
        if not logged_in:
            optional(body, params, [('rrno', '주민번호'), ('cusSungNmS30', '고객명')])
        elif '등록계좌목록' in params:
            rows = params['등록계좌목록']
            first = rows[0]
            body['opbDrCntS5'] = len(rows)
            optional(body, first, [('opbDrBnkNmS50', 'bankNm'), ('opbDrBnkCS3', 'bankCd')])
            body['opbDrAcnoS16'] = re.sub('[^0-9]', '', js_text(first.get('acno', MISSING)))
    else:
        transaction = 'RSMCM1201A04' if method == 'ars' else 'RSMCM1202A01'
        if method == 'ars':
            body['telnoS12'] = phone['number']
            optional(body, params, [('addIpbnkNmS50', '추가_입금은행명'), ('ipbnkNmS50', '입금은행명')])
        else:
            body.update(upmuByAuthTimesN2='3', upmuByErrCntN2='3')
        body['addIcheYnS1'] = 'Y' if params.get('추가이체여부') == 'Y' else 'N'
        if body['addIcheYnS1'] == 'Y':
            optional(body, params, [('addIpbnkCS3', '추가_입금은행코드'), ('addIpbnkNmS100', '추가_입금은행명'),
                ('addIpAcnoS16', '추가_입금계좌번호'), ('addIpAcSungNmS20', '추가_입금계좌성명'), ('addIcheamtN18', '추가_이체금액'),
                ('icheCntS5' if method == 'ars' else 'addIcheCntN2', '이체건수')])
        else:
            optional(body, params, [('ipbnkNmS100', '입금은행명')])
    body['hpNoS20' if transaction == 'RSMCM1202A01' else 'hpNoS12'] = phone['number']
    available = phones(params)
    fallback = available[0]['kind'] if available else '0'
    body['addAuthTelGbn'] = fallback if fallback != '0' else phone['kind']
    body['isLogin'] = logged_in
    return transaction, body


def verify_body(params, method, logged_in, reference, code, remaining):
    if method == 'ars' and legacy.nullish(reference.get('sincNoS8')):
        raise Pending('additional_auth_reference_missing')
    if method == 'sms':
        if remaining <= 0:
            raise Pending('additional_auth_code_expired')
        if not isinstance(code, str) or len(code) != 6:
            raise Pending('additional_auth_code_required')
    body = {'authTypeS1': '0' if method == 'ars' else '1'}
    optional(body, params, [('upmuSeqS5', 'serviceSeq'), ('svcCS6', '서비스코드'), ('nextSvcCS6', '서비스코드')])
    body.update(reference)  # Missing SMS request number is omitted; explicit null stays null.
    if method == 'sms':
        body.update(authNoS30=code, authNoS24=code)
    sequence = str(params.get('serviceSeq'))
    transaction = 'RSMCM1200A09' if logged_in or method == 'sms' and sequence == '24' else 'RSMCM1200A07'
    if sequence not in TRANSFERS:
        optional(body, params, [('tramtN12', '거래금액')])
        if transaction == 'RSMCM1200A07':
            optional(body, params, [('rrno', '주민번호')])
    elif method == 'sms':
        transaction = 'RSMCM1200A03'
        if params.get('추가이체여부') == 'Y':
            body['addIcheYnS1'] = 'Y'
            optional(body, params, [('addIpAcnoS16', '추가_입금계좌번호')])
    body['isLogin'] = logged_in
    return transaction, body


def authenticate(exchange, params, select, respond, *, login_info=None, monotonic=time.monotonic, sleep=time.sleep):
    """Select receives private options; respond receives method and 180 seconds.

    Callbacks return a selection {method, kind}, then SMS text or ARS True.
    None cancels. Only one request and one user-confirmed verification are sent.
    """
    params = contacts(exchange, params)
    allowed, available = methods(params), phones(params)
    if select is None or respond is None:
        raise Pending('additional_auth_input_required')
    # The page counts phone-only services separately from its list builder.
    sequence = str(params.get('serviceSeq'))
    if sequence in ('5', '36', '41', '62', '71', '72'):
        available = [phone for phone in available if phone['kind'] == '0']
    choice = select({'methods': allowed, 'phones': available})
    if choice is None:
        raise Pending('additional_auth_cancelled')
    method = choice.get('method')
    if method not in allowed:
        raise Pending('additional_auth_method_unavailable')
    if method not in ('ars', 'sms'):
        raise Pending('additional_auth_'+method+'_required')
    if not re.sub('[^0-9]', '', params.get('휴대폰번호') or ''):
        raise Pending('additional_auth_registered_phone_required')
    if method == 'sms':
        # SMS has no phone-selection control; it consumes the initial fallback.
        phone = next(iter(phones(params)), None)
    else:
        phone = next((phone for phone in available if phone['kind'] == choice.get('kind')), None)
    if phone is None:
        raise Pending('additional_auth_phone_selection_required')
    logged_in = not legacy.nullish(login_info)
    hours = business_hours(exchange, params.get('telConselType', 'A1'))
    transaction, body = request_body(params, method, phone, logged_in, hours)
    header = {'isNative': True, 'addMsg': '1'}
    if str(params.get('certTp')) == '1':
        header.update(certTp=params['certTp'], serviceType='AA')
    data = legacy.request(exchange, 'additional_auth_request', transaction, body, program=AUTH_PROGRAM, header=header)
    reference = {}
    if method == 'ars':
        optional(reference, data, [('sincNoS8', 'sincNoS8')])
    else:
        optional(reference, params, [('sincNoS8', '신청번호')])
    context = {'params': params, 'method': method, 'phone': phone, 'reference': reference, 'verification': 'unknown'}
    exchange.state['additional_auth'] = context
    exchange.report['additional_auth_request'] = 'success'
    exchange.report['additional_authentication'] = 'unknown'
    started = monotonic()
    exchange.save()
    answer = respond(method, 180)
    if answer is None or method == 'ars' and answer is not True:
        raise Pending('additional_auth_cancelled')
    if method == 'ars':
        sleep(max(0, 3-(monotonic()-started)))
    transaction, body = verify_body(params, method, logged_in, reference, answer, 180-(monotonic()-started))
    data = legacy.request(exchange, 'additional_auth_verify', transaction, body, program=AUTH_PROGRAM, header=header)
    flag = data.get('addAuthCpltYnS1')
    verdict = 'success' if flag == 'Y' else 'failure'
    context['verification'] = exchange.report['additional_authentication'] = verdict
    result = {**params, '휴대폰번호': phone['number'], 'trdtC8': '', 'ltrtmC6': ''}
    optional(result, data, [('인증여부', 'addAuthCpltYnS1')])
    if not legacy.nullish(data.get('trdtC8')) and not legacy.nullish(data.get('ltrtmC6')):
        result.update(trdtC8=data['trdtC8'], ltrtmC6=data['ltrtmC6'])
    context['result'] = result
    exchange.save()
    return result
