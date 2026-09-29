"""Offline contracts for new OneSign issuance, distinct from cloud download.

Image functions accept an already captured card crop / native OCR result. They
do not perform OCR, establish identity, or fabricate a successful verification.
"""
import base64
import calendar
import hmac
import re
import secrets
from datetime import date

from Crypto.Cipher import AES

from .onesign_compat import get_string, string, truthy
from .onesign_crypto import b64url, ra_success, require, text

PREFIX = '/public/pcm/lgin01/capi/'
PATHS = {
    'pre-issue': PREFIX + 'hanaCertsIssu/preHanaCertsIssu',
    'pre-terms': PREFIX + 'hanaCertsIssu/preHanaCertsStpl',
    'instant-number': PREFIX + 'otmCertNo/retrieveOtmCertNo',
    'instant-verify': PREFIX + 'otmCertNo/verifyOtmCertNo',
    'application': PREFIX + 'idcdTnfCnfm/getApcNo',
    'image': '/public/pcm/lgin01/upload/idcdTnfCnfm/uploadIdcdImg',
    'identity': PREFIX + 'idcdTnfCnfm/confirmIdcdTnf',
    'own-account': PREFIX + 'acctVrfc/verifyOurAcctPw',
    'other-account': PREFIX + 'acctVrfc/verifyObkAcctPw',
    'one-won-send': PREFIX + 'acctVrfc/transferObkAcctRmrkCert',
    'one-won-verify': PREFIX + 'acctVrfc/verifyObkAcctRmrkCert',
    'pin-check': PREFIX + 'hanaCertsIssu/checkPinNoEfctv',
    'registration': PREFIX + 'hanaCertsIssu/issuHanaCerts',
    'complete': PREFIX + 'hanaCertsIssu/completeHanaCertsIssu',
    'signup-accounts': PREFIX + 'bkngMmbNtry/retrieveDmpyAcctList',
    'signup-account': PREFIX + 'bkngMmbNtry/verifyOurAcctPw',
    'complete-signup': PREFIX + 'bkngMmbNtry/completeMmbNtry',
    'keypad': PREFIX + 'lginMgnt/executeNFilterKey',
    'clock': '/public/pcm/etcs01/capi/dtInq/retrieveCurrDtm',
}
CA_URL = 'https://hanacert.hanabank.com/pinsign30-ca/cmp/subca'
CA_MIME = 'application/pkixcmp'


def ocr_key(application):
    # Java substring counts UTF-16 code units, then String.getBytes(UTF-8).
    value = (text(application, empty=True) + '0' * 16).encode('utf-16-be', 'surrogatepass')[:32]
    return value.decode('utf-16-be', 'surrogatepass').encode('utf-8', 'replace')


def encrypt_ocr(value, application, *, nonce=None):
    """STLabgr.STLabgz: standard Base64(nonce || cipher || tag), no AAD."""
    require(isinstance(value, bytes), 'ocr_bytes_required')
    nonce = secrets.token_bytes(12) if nonce is None else nonce
    require(isinstance(nonce, bytes) and len(nonce) == 12, 'ocr_nonce_length')
    key = ocr_key(application)
    require(len(key) in (16, 24, 32), 'ocr_aes_key_length')
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    encrypted, tag = cipher.encrypt_and_digest(value)
    return base64.b64encode(nonce + encrypted + tag).decode()


def encrypt_ocr_field(value, application, *, nonce=None):
    # STLabgg returns empty for a null/empty char array.
    return '' if value is None or value == '' else encrypt_ocr(text(value).encode(), application, nonce=nonce)


def id_body(application, kind, ocr):
    """The native result -> web JSON mapping, including undefined vs null."""
    require(kind in ('resident', 'driver'), 'unsupported_identity_document')
    require(isinstance(ocr, dict), 'ocr_result_required')
    body = {'apcNo': application, 'idcdDvCd': '01' if kind == 'resident' else '02', 'saveYn': 'Y'}
    # Optional chaining on issueDate produces undefined for null and missing.
    if ocr.get('issueDate') is not None:
        body['issuDt'] = re.sub(r'[^0-9]', '', text(ocr['issueDate'], empty=True))
    name = ocr.get('name')
    body['custNm'] = '' if name is None else text(name, empty=True).strip(' \t\r\n\v\f\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff')
    for source, target in (('birthDate', 'resRegNo1'), ('encResidentNo', 'resRegNo2')):
        if source in ocr:
            body[target] = ocr[source]
    if kind == 'driver':
        for source, target in (('regionCode', 'drlcNo1'), ('encDriverLicenseExceptAreaNo1', 'crypDrlcNo1'),
                               ('encDriverLicenseExceptAreaNo2', 'crypDrlcNo2'), ('encDriverLicenseExceptAreaNo3', 'crypDrlcNo3')):
            body[target] = ocr[source] if truthy(ocr.get(source)) else ''
    return body


def image_upload(application, encrypted_image, *, milliseconds, boundary=None):
    """Multipart text file, followed by apcNo. Browser boundary is arbitrary."""
    text(encrypted_image)
    require(type(milliseconds) is int, 'image_timestamp_required')
    boundary = boundary or ('----HanaCLI' + secrets.token_hex(18))
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,70}', boundary) is not None, 'invalid_multipart_boundary')
    filename = 'idcdImg-' + str(milliseconds)
    raw = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
           'Content-Type: text/plain\r\n\r\n' + encrypted_image + '\r\n'
           f'--{boundary}\r\nContent-Disposition: form-data; name="apcNo"\r\n\r\n'
           + string(application) + f'\r\n--{boundary}--\r\n').encode()
    return 'multipart/form-data; boundary=' + boundary, raw


def accept_image(response):
    require(isinstance(response, dict) and truthy(response.get('scss')), 'identity_image_upload_failed')


def accept_identity(response, body):
    require(isinstance(response, dict) and (response.get('rspsCd') == '000' or
            response.get('rspsCd') == '200' and body.get('idcdDvCd') == '03'), 'identity_verification_failed')


def account_body(bank, account, encrypted_password):
    return ('own-account', {'acctNo': account, 'acctPw': encrypted_password}) if bank == '081' else (
        'other-account', {'rcvAcctNo': account, 'rcvBnkCd': bank, 'rcvAcctPw': encrypted_password})


def pin_check_body(first_cipher, confirmation_cipher):
    # NFilter E2E NUM ciphertext, never AESEncData or a plaintext PIN.
    return {'pinNo': text(first_cipher), 'pinNoCnfm': text(confirmation_cipher)}


def check_new_pin(pin):
    require(isinstance(pin, str) and re.fullmatch('[0-9]{6}', pin) is not None, 'six_digit_pin_required')
    digits = '01234567890'
    forbidden = [c * 3 for c in digits] + [digits[i:i + 3] for i in range(len(digits) - 2)]
    require(not any(s in pin for s in forbidden), 'pin_repeated_or_ascending_three_digits')


def validate_ocr(ocr, kind):
    """Domestic Zod form constraints; do not add a past-date or RR checksum rule."""
    require(kind in ('resident', 'driver') and isinstance(ocr, dict), 'unsupported_identity_document')
    require(isinstance(ocr.get('name'), str) and bool(id_body('', kind, {'name': ocr['name']})['custNm']), 'identity_name_required')
    value = ocr.get('issueDate')
    require(isinstance(value, str) and re.fullmatch('[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}', value) is not None, 'identity_date_format')
    try:
        year, month, day = map(int, value.split('.'))
        require(year >= 100, 'identity_date_invalid')  # JS new Date(0..99,...) uses 1900..1999.
        date(year, month, day)
    except ValueError:
        require(False, 'identity_date_invalid')
    for name in ('birthDate', 'maskedResidentNo', 'encResidentNo', 'encImage', 'maskedImage'):
        require(name not in ocr or isinstance(ocr[name], str), 'identity_optional_field_type')
    if kind == 'driver':
        for name in ('regionCode', 'encDriverLicenseExceptAreaNo1', 'encDriverLicenseExceptAreaNo2', 'encDriverLicenseExceptAreaNo3'):
            require(isinstance(ocr.get(name), str) and len(ocr[name]) > 0, 'identity_driver_field_required')
        for i, length in enumerate((2, 6, 2), 1):
            value = ocr.get('encDriverLicenseExceptAreaNoMasking' + str(i))
            require(isinstance(value, str) and len(value) == length, 'identity_driver_mask_length')
    # After successful form validation the callback returns without any request
    # if encImage is absent or empty. The CLI reports that stop explicitly.
    require(truthy(ocr.get('encImage')), 'identity_image_required')


def registration_body(*, overseas=False):
    require(type(overseas) is bool, 'overseas_boolean_required')
    return {'reExcpNtnl': overseas}


def normalize_server_clock(value):
    """Native LocalDate yyyyMMdd / LocalTime HHmmss, SMART resolver profile.

    ServerDateTimeResponse requires dt/tm/bussDdYn. Java SMART clamps day31
    at a shorter month and parses 24:00:00 as midnight (LocalTime only).
    """
    day, time = value['dt'], value['tm']
    require(re.fullmatch('[0-9]{8}', day) is not None and re.fullmatch('[0-9]{6}', time) is not None,
            'issuance_server_clock_format')
    year, month, number = int(day[:4]), int(day[4:6]), int(day[6:])
    hour, minute, second = int(time[:2]), int(time[2:4]), int(time[4:])
    require(1 <= year <= 9999 and 1 <= month <= 12 and 1 <= number <= 31, 'issuance_server_date_invalid')
    number = min(number, calendar.monthrange(year, month)[1])
    if hour == 24 and minute == second == 0:
        hour = 0
    require(0 <= hour < 24 and 0 <= minute < 60 and 0 <= second < 60, 'issuance_server_time_invalid')
    return {**value, 'dt': f'{year:04d}{month:02d}{number:02d}', 'tm': f'{hour:02d}{minute:02d}{second:02d}'}


def certificate_pem(certificate):
    # The wire field is named PEM, but u.o.getEncoded calls WBase64.encode(DER):
    # standard Base64, no armor and no line breaks.
    return base64.b64encode(certificate).decode()


def register_certificate_body(certificate, mac_key, material, *, overseas=False):
    pem = certificate_pem(certificate)
    return {'certificatePem': pem, 'certificatePemHmac': b64url(hmac.digest(text(mac_key).encode(), pem.encode(), 'sha256')),
            'hashedPin': material.pin_hash,
            'certExtraInfos': {'osInfo': 'ANDROID', 'storage': 'INAPP', 'citizenshipCd': '1' if overseas else '0'}}


def registration_secret(response):
    ra_success(response)
    return get_string(response, 'pinSecret'), string(response['pinVersion']) if 'pinVersion' in response else ''


def complete_body(*, reissue=False, uploaded=False):
    return {'rissYn': reissue, 'certsUpld': uploaded, 'isDownloadToCloud': False, 'scss': True}
