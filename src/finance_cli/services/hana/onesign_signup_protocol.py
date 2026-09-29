"""Phone signup protocol for the supported service version. Pure, no network or credentials.

Supports ordinary domestic SMS / regTyp A, including direct issuance.
Other original screens are reported as stops, never treated as completed checks.
"""
import base64
from datetime import date
import hashlib
import re

from .hana_protocol import LOGIN_FIELDS, decode_header, encode_header
from .onesign_codec import encode
from .onesign_crypto import require
from .onesign_compat import truthy

PREFIX = '/public/pcm/lgin01/capi/'
WEB_PATHS = {
    'clear': '/public/pcm/etcs01/capi/comSvc/deleteSessTmpDat',
    'phone-pre': PREFIX + 'addCert/preMbphCert',
    'sms-send': PREFIX + 'addCert/requestMbphCertNoSndg',
    'sms-verify': PREFIX + 'addCert/requestMbphCertNoVrfc',
    'eligibility': PREFIX + 'bkngMmbNtry/retrieveHanaCertsIssuPossYn',
    'customer': PREFIX + 'bkngMmbNtry/retrieveDmpyAcctList',
    'terms-status': PREFIX + 'bkngMmbNtry/retrieveMmbInfoGthrUtlzDpsAgrm',
    'terms-save': PREFIX + 'bkngMmbNtry/setMmbInfoGthrUtlzDpsAgrm',
    'instant-number': PREFIX + 'otmCertNo/retrieveOtmCertNo',
    'download-notify': PREFIX + 'hanaSrvrCertsMgnt/downloadHanaSrvrCerts',
    'complete': PREFIX + 'bkngMmbNtry/completeMmbNtry',
}
# These call sites await success but do not consume the returned body in the
# supported (no optional marketing selection) branch. Identity checks do.
OPTIONAL_RESPONSE_BODY = frozenset(WEB_PATHS[name] for name in
    ('clear', 'phone-pre', 'sms-send', 'terms-save', 'instant-number', 'download-notify'))
SCREENS = {name: ('COMC1002001001' if name == 'clear' else
                 'COMC1002001003' if name in ('phone-pre', 'sms-send', 'sms-verify') else
                 'COMC1301001002' if name == 'complete' else 'COMC0501001501')
           for name in WEB_PATHS}
CARRIERS = {'4': 'SKT', '6': 'KT', '5': 'LGU+', '7': 'SKT 알뜰폰', '8': 'KT 알뜰폰', 'A': 'LGU+ 알뜰폰'}
STATIC = 'https://cdnoqf.hanabank.com/oqf/static/cont/pdf/etc/'
SMS_LIMIT_MS = 180000  # Source popup timer, not an assertion about server TTL.
IDLE_LIMIT_MS = 300000  # Historical v3 parser-stop replacement delay only; not a server TTL.


def empty_success_body(path, body, raw):
    if path in OPTIONAL_RESPONSE_BODY:
        return raw.strip() in (b'', b'null')
    # HanaPhoneValidate consumes rtnVlu only for old-number comparison (Y).
    # The normal N branch accepts the observed zero-byte success response.
    return (path == WEB_PATHS['sms-verify'] and isinstance(body, dict)
            and body.get('oldTelNoCprYn') == 'N' and raw == b'')


def ignores_response_body(path, body):
    return path in OPTIONAL_RESPONSE_BODY or (path == WEB_PATHS['sms-verify']
            and isinstance(body, dict) and body.get('oldTelNoCprYn') == 'N')


def ignores_request_error(operation):
    # oe.catch offers existing cloud; download notification is fire-and-forget.
    return operation in ('instant-number', 'download-notify')


def sms_hash(signer):
    raw = hashlib.sha256(('com.hanabank.oqf ' + signer.hex()).encode()).digest()
    return base64.b64encode(raw).decode()[:11]


def web_headers(base, operation):
    require(operation in WEB_PATHS, 'signup_endpoint_not_allowed')
    require(not base.get('one-access-token'), 'anonymous_signup_session_required')
    result = dict(base)
    common = decode_header(base['hana-com-header'])
    require(isinstance(common.get('CNL_HDPT'), dict), 'invalid_common_header')
    common['CNL_HDPT']['SCRN_ID'] = SCREENS[operation]
    result.update({'hana-com-header': encode_header(common), 'one-access-token': '',
                   'content-type': 'application/json;charset=utf-8'})
    return result


def web_body(body):
    # Axios JSON transform: explicit JS null is four bytes, unlike native @POST.
    require(body is None or isinstance(body, dict), 'unexpected_signup_body')
    return b'null' if body is None else encode(body)


def phone_profile(value, today=None):
    require(isinstance(value, dict) and set(value) == {'name', 'birth7', 'phone', 'carrier'}, 'phone_profile_fields')
    require(all(isinstance(v, str) for v in value.values()), 'phone_profile_types')
    require(re.fullmatch(r'[가-힣A-Za-z ]{2,60}', value['name']) is not None
            and len(value['name'].encode()) <= 90 and value['name'] == value['name'].strip(), 'invalid_customer_name')
    require(re.fullmatch(r'[0-9]{6}[1-4]', value['birth7']) is not None, 'domestic_birth7_required')
    b = value['birth7']
    try:
        born = date((1900 if b[6] in '12' else 2000) + int(b[:2]), int(b[2:4]), int(b[4:6]))
    except ValueError:
        require(False, 'invalid_birth_date')
    today = today or date.today()
    age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    require(age >= 14, 'guardian_or_invalid_age_branch')
    require(re.fullmatch(r'0[0-9]{9,10}', value['phone']) is not None, 'invalid_phone_number')
    require(value['carrier'] in CARRIERS, 'unsupported_carrier')
    return dict(value, name=value['name'].upper())


def pre_phone_body(profile, device):
    profile = phone_profile(profile)
    return {'custNm': profile['name'], 'resRegNo1': profile['birth7'][:6], 'resRegNo2': profile['birth7'][6],
            'resRegNo': '', 'tmpResRegNo': '', 'tmpCustNo': '', 'mbphNo': profile['phone'],
            'noFace': 'Y', 'uUId': device, 'c2dmRegIdNm': ''}


def sms_body(profile, app_hash):
    return {'mbphEnprDvCd': profile['carrier'], 'mbphNo': profile['phone'],
            'custNm': profile['name'], 'niceMsgHash': app_hash}


def verify_body(profile, sms):
    require(isinstance(sms, str) and re.fullmatch(r'[0-9]{6}', sms) is not None, 'sms_six_digits_required')
    return {'mbphEnprDvCd': profile['carrier'], 'mbphNo': profile['phone'], 'mbleCertNo': sms,
            'myDevcYn': 'Y', 'oldTelNoCprYn': 'N'}


def check_eligibility(value):
    require(value.get('smsVrfcRslt') == 'Y', 'sms_not_verified_by_eligibility')
    require(value.get('frnrYn') != 'Y', 'foreign_customer_branch')


def check_customer(value, profile, *, existing_cloud=True):
    code = value.get('regTyp')
    if code in ('Q', 'QA'):
        require(False, 'additional_identity_screen_COMC0101001502')
    if code in ('B', 'D', 'F', 'H', 'P'):
        require(False, 'additional_signup_screen_COMC1001001001')
    if code in ('C', 'E', 'G'):
        require(False, 'additional_signup_screen_COMC0101001501')
    require(isinstance(code, str) and code in 'A|Q|QA', 'unsupported_signup_customer_branch')
    require(value.get('acnmNoDvCd') != '02', 'unsupported_real_name_type')
    require(value.get('oneSignUseYn') != 'Y', 'onesign_registration_disabled')
    if existing_cloud:
        require(truthy(value.get('cludCertsExitYn')), 'existing_cloud_certificate_not_confirmed')
    return value.get('custNo')  # X copies the server field without a format gate.


def marketing_body(status):
    # COMC0501001501 ae/dt: only strict string "1" sets pe. Every other
    # value leaves it false; the user's unselected choices produce N/N.
    # This is an optional-consent UI value, not authentication evidence.
    value = status.get('unfyMktgGthrAgrmYn')
    if value == '1':
        return None
    return {'reExcpNtnlYn': 'N', 'custAttAcdtCd': '', 'unfyMktgGthrAgrmYn': 'N', 'unfyMktgOffrAgrmYn': 'N'}


def complete_body(device):
    return {'appIdSeqNo': device, 'custInfoOffrAgrmYn': 'N', 'hanaMonyRegYn': '', 'hanaMyDatAgrmYn': '',
            'reExcpNtnlYn': 'N', 'agrmYn10': 'N', 'agrmYn3': 'N', 'smsRecvAgrmYn8': 'N',
            'emalRecvAgrmYn8': 'N', 'tmktRecvAgrmYn8': 'N', 'agrmYn4': 'N'}


def completion_login_body(profile):
    # Native COMPLETE_SIGN_UP -> LoginInput mask14 -> LoginRequest mask1998.
    # Valid only after completeMmbNtry. This is not normal signed PIN login.
    body = dict.fromkeys(LOGIN_FIELDS, '')
    body['telNo'] = profile['phone']
    return body


def sms_terms(carrier):
    require(carrier in CARRIERS, 'unsupported_carrier')
    base = {'7': '4', '8': '6', 'A': '5'}.get(carrier, carrier)
    nice = {'4': 'skm', '6': 'ktm', '5': 'lgm'}[base]
    kcb = {'4': 'skt', '6': 'kt', '5': 'lgu'}[base]
    names = ['개인정보 수집·이용·제공 동의', '고객식별정보 처리 동의', '서비스 이용약관 동의',
             '통신사 이용약관 동의', '개인정보 제3자 제공 동의(알뜰폰)']
    nice_codes = ('01', '02', '04', '03', '05')
    kcb_files = ('kcb_agrmt_hs_info_' + kcb, 'kcb_agrmt_hs_info', 'kcb_agrmt_hs_tos',
                 'kcb_agrmt_hs_tos_' + kcb, 'kcb_agrmt_hs_offer_' + kcb + 'mvno')
    return [{'title': names[i], 'urls': ['https://cert.vno.co.kr/app/agree/app_agree_m_' + nice + '.jsp?gubun=' + nice_codes[i],
             'https://safe.ok-name.co.kr/eterms/' + kcb_files[i] + '.jsp']}
            for i in range(5 if carrier in ('7', '8', 'A') else 4)]


def signup_terms(mandatory_collected):
    rows = [
        ('com_00022.pdf', '하나원큐 앱 이용약관'), ('com_00016.pdf', '돈통 이용약관'),
        ('0000000220510_20220510.pdf', '하나인증서 서비스 이용약관'),
        ('0000000220510_20220511.pdf', '개인(신용)정보 수집이용제공 동의 (하나인증서 서비스)'),
        ('https://image.kebhana.com/cont/download/documents/etc/7-99-0105.pdf', '개인정보 제3자 제공 동의(사단법인 금융결제원 신원확인용)'),
        ('7-99-0114.pdf', '개인정보 수집이용 제공 동의(자동로그인 서비스)'),
        ('com_00023.pdf', '개인(신용)정보 수집이용 동의서(비 여신 금융거래)'),
        ('7-99-0061.pdf', '개인(신용)정보 수집이용 동의서(하나 원큐 앱 서비스 이용)'),
    ]
    return [{'title': title, 'urls': [file if file.startswith('https://') else STATIC + file]}
            for file, title in rows if mandatory_collected != 'Y' or file != 'com_00023.pdf']
