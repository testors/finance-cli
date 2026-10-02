"""Corporate login wire contracts. Pure functions, no I/O."""
import json
import re
from urllib.parse import quote, quote_from_bytes, quote_plus

ORIGIN = 'https://cmb.hanabank.com'
VERSION = '6.2.2'
PATHS = {
    'emergency': '/cont/html/adm/cmb_emergency.json',
    'app-info': '/CCOM/COM01/APP_INFO.do',
    'nonce': '/CCOM/COM01/DELFINO_NONCE.do',
    'login': '/CLGN/LGN01/CLGN010100102.do',
    'keypad-key': '/CCOM/COM01/NFILTER_KEY.do',
    'login-idpw': '/CLGN/LGN01/CLGN010100101.do',
    'logout': '/CLGN/LGN02/CLGN020100101.do',
    'onesign-request': '/CCOM/COM01/HANA_ONESIGN_REQUEST.do',
    'onesign-confirm': '/CCOM/COM01/HANA_ONESIGN_CONFIRM.do',
    'withdrawal-info': '/CCOM/COM03/WDRW_ACCT_INFO_PTCL.do',
    'customer-check': '/CUSR/USR11/CUSR110100101.do',
    'accounts': '/BIAT/INQ01/BINQ010100101_T01.do',
    'account-info': '/BINQ/IAT00/BIAT000000020.do',
    'balance': '/CCOM/COM03/POSSIBLE_TRANSFER_MONEY.do',
    'fund-balance': '/CCOM/COM03/FUND_POSSIBLE_TRANSFER_MONEY.do',
    'customer-type': '/CCOM/COM03/USER_SPRT_YN_INFO.do',
    'currencies': '/CCOM/COM03/CURRENCY_CODE_INQUIRY.do',
    'loan-sequences': '/BIAT/BIAT000000003.do',
    'loan-detail': '/BIAT/INQ01/BINQ010100401.do',
    'history-krw': '/BIAT/INQ02/BINQ020200201.do',
    'history-fund': '/BIAT/INQ02/BINQ020200301.do',
    'history-foreign': '/BIAT/INQ02/BINQ020200501.do',
    'history-loan': '/BIAT/INQ02/BINQ020100401.do',
    'server-time': '/CCOM/COM01/SYSTEM_TIME.do',
    'transfer-init': '/BIAT/TRN01/BTRN010100101.do',
    'transfer-withdrawal': '/BIAT/BIAT000000019.do',
    'transfer-recipient': '/BIAT/BIAT000000016.do',
    'transfer-amount': '/BIAT/BIAT000000011.do',
    'transfer-prepare': '/BIAT/TRN01/BTRN010100102.do',
    'transfer-confirm': '/BIAT/TRN01/BTRN010100201.do',
    'transfer-execute': '/BIAT/TRN01/BTRN010100203.do',
    'transfer-result': '/BIAT/TRN01/BTRN010100301.do',
    'transfer-clear': '/CCOM/COM01/TEMP_CLEAR.do',
    'unified-auth': '/CCOM/COM01/UNFY_CERT_MEAN_MGNT.do',
    'account-password': '/CCOM/COM03/WDRW_ACCT_PW_VRFC.do',
    'otp': '/CCOM/COM01/VALID_SCRT_MDCL_DCTC_CHECK.do',
    'ars-phones': '/CCOM/COM03/ARS_PAGE.do',
    'ars-request': '/CCOM/COM03/ARS_APC_NO_REQ.do',
    'ars-check': '/CCOM/COM03/ARS_RESULT_CHECK.do',
}
KNOWN_ERRORS = {'FRU0001': 'session_required', 'FRU00031': 'service_stopped',
                'FORCE_PW_REG': 'password_change_required', 'AUTH_58': 'permission_required'}
PASSWORD_ERRORS = dict(zip(('OCOM16209', 'OCOM16210', 'OCOM16211', 'OCOM16212', 'BCOM16069'), range(1, 6)))
ID_ERRORS = {**dict.fromkeys(PASSWORD_ERRORS, 'login_password_mismatch'),
             'UNFY_AGREE_URL': 'agreement_required', 'BCBI10114': 'corporate_notice_required'}


class Stop(ValueError):
    """A stable, non-sensitive processing reason, separate from bank acceptance."""


def require(condition, code):
    if not condition:
        raise Stop(code)


def form(value):
    """jQuery-style nested form encoding, including %20 spaces and empty objects."""
    pairs = []

    def add(key, item):
        if isinstance(item, dict):
            for child, content in item.items():
                add(key + '[' + child + ']', content)
        elif isinstance(item, list):
            for index, content in enumerate(item):
                suffix = str(index) if isinstance(content, (dict, list)) else ''
                add(key + '[' + suffix + ']', content)
        else:
            text = '' if item is None else 'true' if item is True else 'false' if item is False else str(item)
            pairs.append(quote(key, safe="~!*'()-._") + '=' + quote(text, safe="~!*'()-._"))

    for key, item in value.items():
        add(key, item)
    return '&'.join(pairs).encode('utf-8')


def native_form(value):
    """Flat UTF-8 FormBody: null omitted, spaces '+', '~' escaped, '*' retained."""
    def encode(text):
        require(isinstance(text, str), 'invalid_native_form')
        return quote_plus(text, safe='*').replace('~', '%7E')
    return '&'.join(encode(k) + '=' + encode(v) for k, v in value.items() if v is not None).encode('utf-8')


def user_id(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9]{4,20}', value) is not None, 'invalid_corporate_user_id')
    return value.upper()


def id_password(value):
    require(isinstance(value, str) and 6 <= len(value) <= 16 and all(32 <= ord(c) <= 126 for c in value),
            'invalid_login_password')
    return value


def idpw_body(identity, encrypted, push):
    require(isinstance(encrypted, str) and bool(encrypted), 'encrypted_password_unavailable')
    is_push = 'Y' if push['management_number'] else 'N'
    require(push['is_push'] == is_push, 'inconsistent_push_profile')
    return {'LGIN_CERT_METH_CD': '1', 'VRTL_LGIN_YN': 'N', 'USER_ID': user_id(identity),
            'LOGIN_PW': encrypted, 'IS_PUSH': is_push, 'C2DM_IDNM': push['token']}


def assess_native(status, value):
    """Only the native String status '200' selects the success branch."""
    result = {'http_status': status, 'service_status': 'unconfirmed', 'reason': 'response_unconfirmed'}
    if not 200 <= status < 300 or not isinstance(value, dict):
        return result
    header = value.get('headerData')
    if not isinstance(header, dict):
        return result
    code = header.get('status')
    # Gson String fields accept scalar numbers and booleans, but not containers.
    if code is None or code == '' or not isinstance(code, (str, int, float, bool)):
        return result
    code = ('true' if code else 'false') if isinstance(code, bool) else str(code)
    if code == '200':
        result.update(service_status='accepted', reason='native_login_callback', business_status='200')
    else:
        error = header.get('errorCode')
        error = error if isinstance(error, str) else ''
        result.update(service_status='rejected', reason=ID_ERRORS.get(error, KNOWN_ERRORS.get(error, 'business_error')))
        if error in ID_ERRORS or error in KNOWN_ERRORS:
            result['business_error_code'] = error
        if error in PASSWORD_ERRORS:
            result['password_failures_reported'] = PASSWORD_ERRORS[error]
    return result


def assess_data(status, value):
    """Preparation repositories consume data without checking a business status."""
    result = {'http_status': status, 'service_status': 'unconfirmed', 'reason': 'response_unconfirmed'}
    if 200 <= status < 300 and isinstance(value, dict) and isinstance(value.get('data'), dict):
        result.update(service_status='accepted', reason='data_received')
    return result


def customer_guidance(value):
    if value.get('CRPN_REG_NO') in ('1101110672538', 1101110672538) and value.get('LGIN_CERT_METH_CD') in ('1', 1):
        return 'certificate_login_required'
    if value.get('eddCddPopUpYn') in ('Y', 'Y1', 'Y2'):
        return 'customer_verification_choice_required' if value.get('CUST_QUAL_CD') in ('014', 14) else 'visit_branch_notice'
    return 'none'


def joint_tbs(nonce):
    require(isinstance(nonce, str), 'nonce_unavailable')
    # Java URLEncoder's safe set excludes ~ and spaces become +. EUC-KR replaces
    # unmappable characters, unlike Python's default strict encoder.
    escaped = quote_from_bytes(nonce.encode('euc-kr', errors='replace'), safe='*-._')
    escaped = escaped.replace('~', '%7E').replace('%20', '+')
    return ('login=certLogin&delfinoNonce=' + escaped).encode('euc-kr')


def onesign_tbs(nonce, moment):
    require(isinstance(nonce, str), 'nonce_unavailable')
    value = {'하나인증서 로그인[LOGIN]': 'CERT',
             '전자서명데이터생성시간[sign_sslsignctime]': moment.strftime('%Y-%m-%d %H:%M:%S')}
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '&delfinoNonce=' + quote(nonce, safe="~!*'()-._")


def login_body(method, signature, push):
    require(method in ('2', 'S') and isinstance(signature, str) and bool(signature), 'signature_unavailable')
    head = {'LGIN_CERT_METH_CD': method, 'SIGNED_MSG': signature}
    if method == '2':
        head.update(TKN_ISS_NO1='', TKN_ISS_NO2='')
    return {'IS_PUSH': push['is_push'], 'C2DM_IDNM': push['token'],
            'PUSH_USR_MGNT_NO': push['management_number'], 'LGIN_CERT_METH_CD': method,
            'VRTL_LGIN_YN': 'N', 'COMM_HEAD': head}


def assess(status, value):
    """HTTP receipt and business envelope are distinct; absent evidence stays unknown."""
    result = {'http_status': status, 'service_status': 'unconfirmed', 'reason': 'response_unconfirmed'}
    if status != 200 or not isinstance(value, dict):
        return result
    header = value.get('headerData')
    if not isinstance(header, dict) or 'status' not in header:
        return result
    code = header['status']
    if code in ('200', '210', 200, 210):
        result.update(service_status='accepted', reason='business_callback', business_status=str(code))
    elif code is not None and code != '':
        result.update(service_status='rejected', reason=KNOWN_ERRORS.get(header.get('errorCode'), 'business_error'))
    return result


def login_verdict(receipt, data):
    if receipt['service_status'] == 'rejected':
        return False, receipt['reason']
    if receipt['service_status'] != 'accepted' or not isinstance(data, dict):
        return None, 'login_unconfirmed'
    if data.get('SMT_PHBK_NTRY_YN') == 'N':
        return None, 'corporate_enrollment_required'
    if data.get('LOGIN_RESULT') == 'OK':
        return True, 'login_accepted'
    return None, 'login_unconfirmed'


def check_bootstrap(stage, value):
    require(isinstance(value, dict), 'bootstrap_data_unavailable')
    if stage == 'emergency':
        require(value.get('emergency_yn') != 'Y', 'emergency_notice')
        # The nullable Gson String flag gates the next request only for exact Y.
        require(value.get('emergency_yn') is None or isinstance(value['emergency_yn'], (str, int, float, bool)),
                'emergency_status_unavailable')
        return [] if value.get('emergency_yn') == 'N' else ['emergency_status_unusual']
    info = value.get('appInfo')
    require(isinstance(info, dict), 'app_version_unavailable')
    warnings = []
    # Only the minimum version is mandatory. Optional update dismissal continues.
    for key, reason in (('minVerNo', 'app_update_required'), ('prsVerNo', 'app_update_notice')):
        version = info.get(key)
        require(version is None or isinstance(version, (str, int, float, bool)), 'app_version_unavailable')
        number = str(version).replace('.', '')
        if not (number.isascii() and number.isdecimal()):
            # IntroVM.checkVersion returns false for absent/non-numeric versions.
            warnings.append('app_version_unavailable')
            continue
        require(int(number) <= 2147483647, 'app_version_parse_failed')
        if int(VERSION.replace('.', '')) < int(number):
            require(key != 'minVerNo', reason)
            warnings.append(reason)
    notice = value.get('noticeInfo')
    require(notice is None or isinstance(notice, dict), 'app_notice_data_unavailable')
    if notice is not None and notice.get('tite') not in (None, ''):
        # Informational confirmation leads to checkedNotice, not login rejection.
        warnings.append('app_notice')
    return list(dict.fromkeys(warnings))
