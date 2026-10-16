"""Typed request construction and PIN-auth result branches."""
import re


def pin_request(credential, device, encrypted_value):
    return {'RA_CERT_DCD': '001', 'RQST_CHNL_DCD': 'SOL',
            'CERT_SEQ_NO': credential['alias'], 'MSB_VRSN_VL': credential['msb_version'],
            'CUST_CCTN_MCTL_ID': device['uuid2'], 'CRTC_PTRN_DCD': '10',
            'CRTC_PTRN_DATA_CON': encrypted_value, 'BIO_CRTC_SUCC_YN': ''}


def login_request(credential, unique_value, plaintext, signature, settings, state, *, device=None):
    device = device or (lambda: settings['device']['device_id'])
    sign_data = {'deviceId': device(), 'pkcs7SignedData': '', 'fidoKey': '', 'fidoTrxId': '',
                 'fidoUuid': '', 'fidoVrfyYn': '', 'certSeqNo': credential['alias'],
                 'msbVrsnVl': credential['msb_version'], 'custCctnMctlId': device(),
                 'crtcPtrnDcd': '10', 'crtcPtrnDataCon': unique_value,
                 'tranElsgOnttCon': plaintext, 'tranElsgDataCon': signature, 'bioCrtcSuccYn': ''}
    metadata = settings.get('login_metadata', {})
    body = {'loginMthS1': 'G', 'cusnoS10': '', 'autoLoginCretYnS1': '0', 'encDataS2000': '',
            'mcmInptSignData': sign_data, 'smpIcheIdS64': state.get('simple_transfer_id', ''),
            'pkeyVerS30': '', 'rsaKeyS512': '', 'rsaTmplHashS96': '', 'rsaTmplS50000': '',
            'clientOsS64': '', 'mASKYnS1': '', 'appVersion': settings['version'],
            'phoneNo': metadata.get('phoneNo', ''), 'phoneModel': settings['device']['model'],
            'phoneCom': metadata.get('phoneCom', ''), 'phoneInfo': metadata.get('phoneInfo', ''),
            'vpnYn': metadata.get('vpnYn', 'X'), 'pushToken': metadata.get('pushToken', ''),
            'loginFailCnt': state.get('login_failed_count', 0), 'osVer': settings['device']['os_version'], 'osType': 'A'}
    if body['vpnYn'] == 'UNKNOWN':
        body['vpnYn'] = 'X'
    if body['pushToken'] is None:
        body['pushToken'] = ''
    if body['loginFailCnt'] is None:
        body['loginFailCnt'] = 0
    if not all(isinstance(value, str) for value in sign_data.values()):
        raise ValueError('invalid_sign_data')
    if not all(isinstance(value, str) for field, value in body.items() if field not in ('loginFailCnt', 'mcmInptSignData')):
        raise ValueError('invalid_login_metadata')
    count = body['loginFailCnt']
    if not isinstance(count, int) or isinstance(count, bool) or not -(2**31) <= count < 2**31:
        raise ValueError('invalid_login_count')
    return ('RSMCM0201D08' if state.get('emergency', False) else 'RSMCM0201C08', body, device())


def pin_verdict(document):
    if (not isinstance(document, dict) or not isinstance(document.get('ERR_CD'), str)
            or not isinstance(document.get('ERR_MSG'), (str, bool, int, float))
            or document.get('data') is not None and not isinstance(document['data'], dict)):
        return {'result': 'unknown', 'branch': 'response_decode_error', 'clear_local': False,
                'increment_failure_count': False, 'processing_status': 'incomplete'}
    code = document.get('ERR_CD')
    if code == 'RA0000':
        return {'result': 'success', 'branch': 'authenticated', 'clear_local': False, 'increment_failure_count': False}
    branch, clear, increment = 'rejected', False, False
    if code in ('RA3100', 'RA3200'):
        increment = True
        data = document.get('data') or {}
        if not isinstance(data, dict):
            return {'result': 'failure', 'branch': 'count_decode_error', 'clear_local': False,
                    'increment_failure_count': True, 'processing_status': 'incomplete'}
        count = data.get('PIN_EROR_CNT' if code == 'RA3100' else 'PTN_EROR_CNT')
        # Preserve null and parse errors, without replacing the bank's rejection.
        try:
            if count is not None:
                if isinstance(count, bool) or not re.fullmatch('[+-]?[0-9]+', str(count)):
                    raise ValueError('invalid_count')
                count = int(count)
                if not -(2**31) <= count < 2**31:
                    raise ValueError('invalid_count')
        except (TypeError, ValueError):
            return {'result': 'failure', 'branch': 'count_decode_error', 'clear_local': False,
                    'increment_failure_count': True, 'processing_status': 'incomplete'}
        clear = count == 5
        branch = 'failed_five_times' if clear else 'pin_wrong' if code == 'RA3100' else 'pattern_wrong'
    elif code in ('RA3150', 'RA3250'):
        branch, clear = 'reissue_required', True
    elif code in ('RA2010', 'RA3900', 'RA4000', 'RA4100', 'RA5000', 'RE2010', 'RE3900'):
        branch, clear = 'invalid_certificate', True
    elif code in ('RA5100', 'RA5110'):
        branch = 'device_mismatch'
    return {'result': 'failure' if isinstance(code, str) else 'unknown', 'branch': branch,
            'clear_local': clear, 'increment_failure_count': increment}
