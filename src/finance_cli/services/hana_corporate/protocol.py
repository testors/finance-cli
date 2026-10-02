"""Corporate certificate-login wire contracts. Pure functions, no I/O."""
import json
from urllib.parse import quote, quote_from_bytes

ORIGIN = 'https://cmb.hanabank.com'
VERSION = '6.2.2'
PATHS = {
    'emergency': '/cont/html/adm/cmb_emergency.json',
    'app-info': '/CCOM/COM01/APP_INFO.do',
    'nonce': '/CCOM/COM01/DELFINO_NONCE.do',
    'login': '/CLGN/LGN01/CLGN010100102.do',
    'onesign-request': '/CCOM/COM01/HANA_ONESIGN_REQUEST.do',
    'onesign-confirm': '/CCOM/COM01/HANA_ONESIGN_CONFIRM.do',
    'withdrawal-info': '/CCOM/COM03/WDRW_ACCT_INFO_PTCL.do',
    'customer-check': '/CUSR/USR11/CUSR110100101.do',
}
KNOWN_ERRORS = {'FRU0001': 'session_required', 'FRU00031': 'service_stopped',
                'FORCE_PW_REG': 'password_change_required', 'AUTH_58': 'permission_required'}


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
        require(isinstance(value.get('emergency_yn'), str), 'emergency_status_unavailable')
        return
    info = value.get('appInfo')
    require(isinstance(info, dict), 'app_version_unavailable')
    # Service compares versions after removing dots; preserve that ordering.
    for key, reason in (('minVerNo', 'app_update_required'), ('prsVerNo', 'app_update_notice')):
        version = info.get(key)
        require(isinstance(version, str), 'app_version_unavailable')
        number = version.replace('.', '')
        if number.isascii() and number.isdecimal():
            require(int(VERSION.replace('.', '')) >= int(number), reason)
    require(value.get('noticeInfo') is None, 'app_notice_requires_review')
