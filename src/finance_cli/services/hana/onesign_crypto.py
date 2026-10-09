"""Offline OneSign/PINsign V30 primitives for service version 1.0.27.

No transport, credential enrollment, device-store access or password persistence.
PIN derivation, wrapped keys and CMS signatures for the supported service version.
"""
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import re
from urllib.parse import quote_plus

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Util.Padding import unpad
from Crypto.Util.asn1 import DerObjectId, DerOctetString, DerSequence, DerSetOf

from .hana_protocol import LOGIN_FIELDS
from .nfilter_format import der
from .signing_text import signing_text

PROFILE = 'onesign-v30-x509-pin-offline-v2'
BANK_NONCE_PATH = '/public/pcm/lgin01/capi/hanaCertsCert/pinsignNonce'
LOGIN_PATH = '/public/pcm/lgin01/capi/lginMgnt/loginPwCerts'
RA_BASE_PATH = '/pinsign30-ra/service'
SHA256_OID = '2.16.840.1.101.3.4.2.1'
ECDSA_SHA256_OID = '1.2.840.10045.4.3.2'
DATA_OID = '1.2.840.113549.1.7.1'
SIGNED_DATA_OID = '1.2.840.113549.1.7.2'


class ProtocolError(ValueError):
    """Only fixed diagnostic codes; never include secret values in exceptions."""


def require(condition, code):
    if not condition:
        raise ProtocolError(code)


def text(value, *, empty=False):
    require(isinstance(value, str) and (empty or bool(value)), 'invalid_text')
    return value


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64url(value):
    text(value)
    require(re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', value) is not None,
            'invalid_base64url')
    try:
        return base64.b64decode(value + '=' * (-len(value) % 4),
                                altchars=b'-_', validate=True)
    except ValueError:
        raise ProtocolError('invalid_base64url') from None


def repeated_sha256(rounds, *parts):
    """t/b.a(int, byte[]...): hash the concatenation, then rehash the digest."""
    require(type(rounds) is int and 1 <= rounds <= 4096, 'invalid_hash_rounds')
    digest = hashlib.sha256(b''.join(parts)).digest()
    for _ in range(1, rounds):
        digest = hashlib.sha256(digest).digest()
    return digest


@dataclass(frozen=True)
class PinMaterial:
    # PIN-derived strings are credentials too: keep them out of repr/logs/files.
    pin_hash: str = field(repr=False)
    secret: str = field(repr=False)
    secret_hash: str = field(repr=False)
    nonce_key: bytes = field(repr=False)
    effective_salt: str = field(repr=False)
    spec_version: int


def derive_pin(pin, *, device_id, pin_salt, pin_spec_version, device_fallback=True):
    """h/b + h/f, for the six ASCII digit OneSign PIN profile.

    Stored pinSpecVersion is 0/1/2, not the enum's ordinal+1 passed to l/a.c.
    getDeviceId(alias) selects stored pinSalt before config.deviceId.
    """
    require(isinstance(pin, str) and re.fullmatch(r'[0-9]{6}', pin) is not None,
            'six_digit_pin_required')
    require(type(pin_spec_version) is int and pin_spec_version in (0, 1, 2),
            'unsupported_pin_spec_version')
    salt = text(pin_salt, empty=True)
    if not salt and device_fallback:
        salt = text(device_id)
    effective = salt if pin_spec_version > 0 else ''
    raw = pin.encode('ascii')
    label = b'WIZVERA ID2'
    pin_hash = b64url(repeated_sha256(1024, label, raw, effective.encode()))
    secret = b64url(repeated_sha256(512, label, raw))
    secret_hash = b64url(repeated_sha256(512, label, raw, effective.encode()))
    nonce_key = b64url(repeated_sha256(1024, (label.decode() + pin_hash).encode()))
    return PinMaterial(pin_hash, secret, secret_hash, nonce_key.encode(),
                       salt, pin_spec_version)


def ra_success(response):
    from .onesign_compat import integer
    require(isinstance(response, dict), 'ra_response_object_required')
    # JSONObject.getInt accepts the integer and its string representation.
    code = response.get('resultCode')
    require(integer(code, 'ra_business_error') == 0, 'ra_business_error')
    return response


def ra_nonce(response):
    from .onesign_compat import get_string
    return get_string(ra_success(response), 'nonce')


def seq(*values):
    return DerSequence(values).encode()


def oid(value):
    return DerObjectId(value).encode()


def certificate_parts(cert_der):
    """Return serial/issuer/subject/public key; does not establish registration."""
    try:
        certificate = DerSequence().decode(cert_der, strict=True)
        require(len(certificate) == 3, 'x509_certificate_required')
        tbs = DerSequence().decode(certificate[0], strict=True)
        offset = int(isinstance(tbs[0], bytes) and tbs[0][0] == 0xa0)
        serial, issuer, subject = tbs[offset], tbs[offset + 2], tbs[offset + 4]
        public = ECC.import_key(cert_der)
        require(type(serial) is int and serial > 0 and public.curve == 'NIST P-256'
                and not public.has_private(), 'p256_certificate_required')
        return serial, issuer, subject, public
    except (ValueError, IndexError, TypeError):
        raise ProtocolError('p256_x509_certificate_required') from None


def request_secret_body(material, cert_der, nonce, pin_version=''):
    """x/r requestSecretE: subject DER and HMAC with the *encoded* PIN key."""
    _, _, subject, _ = certificate_parts(cert_der)
    body = {'subjectDer': b64url(subject),
            'nonceHmac': b64url(hmac.digest(material.nonce_key, text(nonce).encode(), 'sha256')),
            'authType': 'PIN'}
    if text(pin_version, empty=True):
        body['pinVersion'] = pin_version
    return body


def decrypt_ra_secret(nonce, response):
    """x/s with enableEncSecret=true. The returned secret stays in memory."""
    from .onesign_compat import get_string
    from .onesign_codec import segment
    data = segment(get_string(ra_success(response), 'requestSecret'))
    require(len(data) >= 32 and len(data) % 16 == 0, 'invalid_secret_envelope')
    salt, ciphertext = data[:16], data[16:]
    key = repeated_sha256(1024, text(nonce, empty=True).encode(), salt)
    iv = hashlib.sha256(salt).digest()[:16]
    try:
        value = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16).decode('utf-8', errors='replace')
        return value
    except (ValueError, UnicodeError):
        raise ProtocolError('ra_secret_decryption_failed') from None


def master_secret(material, alias, server_secret):
    """h/e.a or h/e.b, selected by stored pinSpecVersion >= 2."""
    salt = material.effective_salt
    component = material.secret_hash if material.spec_version >= 2 else material.pin_hash
    server_part = repeated_sha256(256, ('PINsign30' + text(server_secret, empty=True) + salt).encode())
    pin_part = repeated_sha256(128, ('PINsign30' + component + text(alias) + salt).encode())
    return repeated_sha256(384, server_part, pin_part)


def unwrap_master_password(secret, encrypted):
    """j/c encrypted master password (PIN or SecretB); no key extraction."""
    require(isinstance(secret, bytes) and len(secret) == 32, 'invalid_master_secret')
    ciphertext = unb64url(encrypted)
    require(len(ciphertext) > 0 and len(ciphertext) % 16 == 0, 'invalid_master_envelope')
    # Hash both byte arrays as one concatenated message.
    # The same Java method name also has a two-argument HMAC overload.
    iv = hashlib.sha256(b'WIZVERA ID2 IV' + secret).digest()[:16]
    try:
        encoded = unpad(AES.new(secret, AES.MODE_CBC, iv).decrypt(ciphertext), 16)
        value = base64.b64decode(encoded, validate=True)
        require(len(value) == 32, 'unsupported_master_password_length')
        return value
    except ValueError:
        raise ProtocolError('master_password_decryption_failed') from None


def external_master_secret(sc_b_cert_key, *, device_id):
    """g/a + j/c X509 external-auth branch, using the registered config deviceId.

    This does not establish that EXTERNAL_AUTH is enrolled. The caller must use
    the stored encryptedMasterPasswordBySecretB and the same registered key.
    Unlike the PIN path, this uses config.deviceId, never a stored pinSalt.
    """
    device = text(device_id)
    require(device.isascii(), 'ascii_registered_device_id_required')
    encoded = device.encode('ascii')
    ciphertext = unb64url(sc_b_cert_key)
    require(len(ciphertext) > 0 and len(ciphertext) % 16 == 0, 'invalid_secret_b_envelope')
    salt = repeated_sha256(1058, encoded)
    key = hashlib.pbkdf2_hmac('sha1', encoded, salt, 2002, 32)
    iv = repeated_sha256(552, encoded)[:16]
    try:
        secret_b = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)
    except ValueError:
        raise ProtocolError('secret_b_decryption_failed') from None
    require(bool(secret_b), 'empty_secret_b')
    return repeated_sha256(8, repeated_sha256(1024, b'PINsign30' + encoded), secret_b)


def login_tbs(customer_number, moment):
    text(customer_number, empty=True)
    require(isinstance(moment, datetime) and moment.utcoffset() is not None,
            'explicit_login_timezone_required')
    return customer_number + moment.strftime('%Y%m%d%H%M%S') + 'login'


def bind_bank_nonce(tbs, nonce):
    """android/t.a(BerryInfo,String,String), X509 branch (Java URLEncoder)."""
    text(tbs, empty=True)
    text(nonce, empty=True)
    if 'delfinoNonce=' in tbs:
        return tbs
    encoded = quote_plus(nonce, safe='*-._', encoding='utf-8').replace('~', '%7E')
    return tbs + ('&' if tbs else '') + 'delfinoNonce=' + encoded


def validate_cloud_registration(value):
    from .onesign_compat import string
    # HanaCertPublicApi.getCloudRegistrationCode uses the four-field CLOUD
    # model. Network Json ignores unknown keys; required fields stay strict.
    fields = ('berryName', 'keyId', 'macKey', 'scBCertKey')
    require(isinstance(value, dict) and set(fields) <= set(value), 'unexpected_pre_register_fields')
    for name in fields:
        require(type(value[name]) in (str, int, float, bool), 'invalid_cloud_registration_string')
        value[name] = string(value[name])
    return value


def bank_nonce_body(customer_number):
    text(customer_number, empty=True)
    return {'custNo': customer_number, 'mbleSvcDvCd': 'Q', 'machUnqNo': ''}


def login_body(signed_data, *, phone_number='', push_token='', fakefinder_install_id=''):
    # Caller must bind/verify CMS and establish registration before any transport.
    base64.b64decode(text(signed_data), validate=True)
    body = dict.fromkeys(LOGIN_FIELDS, '')
    body.update(signDat=signed_data, telNo=text(phone_number, empty=True),
                c2dmRegIdNm=text(push_token, empty=True),
                rskAppIstId=text(fakefinder_install_id, empty=True))
    return body


def assess_transfer_auth(response, login_info, *, auto_sign_yn='Y'):
    """Single PIN or enrolled external-auth branch; no permission to transmit."""
    require(isinstance(response, dict) and isinstance(login_info, dict), 'auth_objects_required')
    if response.get('otpCertYn') == 'Y':
        return {'candidate': False, 'reason': 'server_requires_otp'}
    if (response.get('lginMdclCd'), login_info.get('lginCertMethCd'),
            login_info.get('hanaCertLginYn')) != ('S', 'S', 'Y'):
        return {'candidate': False, 'reason': 'onesign_pin_session_required'}
    if any(response.get(k) == 'Y' for k in ('scrtCrdYn', 'faceCertYn', 'fptCertYn', 'ptrnCertYn')):
        return {'candidate': False, 'reason': 'unsupported_authentication_combination'}
    if any(response.get(k) == 'Y' for k in
           ('smtCertYn', 'arsCertYn', 'smsCertYn', 'otmCertYn', 'depInfoYn',
            'pnCertTrnsYn')):
        return {'candidate': False, 'reason': 'additional_authentication_required'}
    if response.get('fdsRspsCd') in ('EATP', 'ITBL', 'EAAM'):
        return {'candidate': False, 'reason': 'fds_response_requires_review'}
    if response.get('pinCertYn') == 'Y':
        return {'candidate': True, 'reason': 'single_onesign_pin_branch',
                'sign_required': True, 'bridge_type': 'pinHalf', 'pin_reentry': True}
    # yM tests Y only; iy forces signYn=Y for OneSign regardless of certYn.
    if (auto_sign_yn or 'Y') == 'Y':
        return {'candidate': True, 'reason': 'onesign_external_auth_branch',
                'sign_required': True, 'bridge_type': 'noAuth', 'pin_reentry': False,
                'requires_registered_external_auth': True}
    return {'candidate': False, 'reason': 'unsupported_auto_sign_combination'}


def transfer_form(form, server_date, server_time, *, bridge_type, prvt_cert_yn=''):
    """Zi single-transfer form; input is ordered/formatted, before '_1' suffixes."""
    return transfer_forms([form], server_date, server_time, bridge_type=bridge_type, prvt_cert_yn=prvt_cert_yn)


def transfer_forms(forms, server_date, server_time, *, bridge_type, prvt_cert_yn=''):
    """Flatten ordered transaction forms, suffix each row, append one signing timestamp."""
    require(isinstance(forms, list) and bool(forms), 'transfer_forms_required')
    result = []
    for index, form in enumerate(forms, 1):
        _check_transfer_form(form)
        require(form[0]['name'] == forms[0][0]['name'], 'inconsistent_transfer_form_start')
        result.extend(dict(item, name=item['name'] + '_' + str(index)) for item in form)
    require(re.fullmatch(r'[0-9]{8}', text(server_date)) is not None and
            re.fullmatch(r'[0-9]{6}', text(server_time)) is not None, 'invalid_server_time')
    stamp = datetime.strptime(server_date + server_time, '%Y%m%d%H%M%S')
    require(bridge_type in ('pinHalf', 'noAuth'), 'unsupported_sign_bridge')
    private_type = '0' if bridge_type == 'pinHalf' else ''
    private_skip = 'A' if bridge_type == 'pinHalf' else text(prvt_cert_yn, empty=True)
    result.extend([
        {'signid': '사설인증종류코드', 'name': 'sign_privateCertType', 'value': private_type},
        {'signid': '사설인증SKIP여부', 'name': 'sign_prvtCertYn', 'value': private_skip},
        {'signid': '전자서명데이터생성시간', 'name': 'sign_sslsignctime',
         'value': stamp.strftime('%Y-%m-%d %H:%M:%S')},
    ])
    return result


def _check_transfer_form(form):
    signing_text(form)  # Validate field types using the existing web TBS contract.
    names = [item['name'] for item in form]
    require(len(set(names)) == len(names), 'only_one_transfer_form_supported')
    reserved = {'sign_privateCertType', 'sign_prvtCertYn', 'sign_sslsignctime', 'elecSignVluDat'}
    require(not reserved.intersection(names) and all(not name.endswith('_1') for name in names),
            'unsuffixed_transfer_form_required')


def sign_cms(cert_der, key, content, signing_time=None):
    """Offline X509/ECDSA CMS primitive. Key loading/registration is not implied.

    s/d + w/a + DefaultSignedAttributeTableGenerator; synthetic SDK comparison.
    The transfer adapter separately validates bank receipts and user execution.
    """
    require(isinstance(content, bytes), 'explicit_cms_bytes_required')
    serial, issuer, _, public = certificate_parts(cert_der)
    require(isinstance(key, ECC.EccKey) and key.has_private() and key.curve == public.curve
            and key.pointQ == public.pointQ, 'certificate_private_key_mismatch')
    moment = signing_time or datetime.now(timezone.utc)
    require(isinstance(moment, datetime) and moment.utcoffset() is not None,
            'explicit_signing_timezone_required')
    moment = moment.astimezone(timezone.utc)
    time_der = der(0x17, moment.strftime('%y%m%d%H%M%SZ').encode()) if 1950 <= moment.year < 2050 else \
        der(0x18, moment.strftime('%Y%m%d%H%M%SZ').encode())
    digest_alg = seq(oid(SHA256_OID), b'\x05\x00')
    signature_alg = seq(oid(ECDSA_SHA256_OID))  # ECDSA parameters must be absent.

    def attribute(name, value):
        return seq(oid(name), DerSetOf([value]).encode())

    attrs = DerSetOf([
        attribute('1.2.840.113549.1.9.3', oid(DATA_OID)),
        attribute('1.2.840.113549.1.9.5', time_der),
        attribute('1.2.840.113549.1.9.4', DerOctetString(SHA256.new(content).digest()).encode()),
        attribute('1.2.840.113549.1.9.52', seq(digest_alg, b'\xa1' + signature_alg[1:])),
    ]).encode()
    signature = DSS.new(key, 'fips-186-3', encoding='der').sign(SHA256.new(attrs))
    DSS.new(public, 'fips-186-3', encoding='der').verify(SHA256.new(attrs), signature)
    signer = seq(1, seq(issuer, serial), digest_alg, b'\xa0' + attrs[1:],
                 signature_alg, DerOctetString(signature).encode())
    signed = seq(1, DerSetOf([digest_alg]).encode(),
                 seq(oid(DATA_OID), der(0xa0, DerOctetString(content).encode())),
                 der(0xa0, cert_der), DerSetOf([signer]).encode())
    return seq(oid(SIGNED_DATA_OID), der(0xa0, signed))
