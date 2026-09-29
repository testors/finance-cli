"""Portable deployment diagnostics, NOT CodeGuard's environment checks.

Synthetic memory-only crypto, packaged data, codec and timezone checks. No
network, identity discovery, subprocess or platform services.
These results must never be fed into an OSCheck/security response or used to
overrule an app response. Missing capabilities are diagnostic warnings only.
"""
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo


def deployment_plan():
    return {
        'target': 'non_android_headless_server',
        'capability_scope': 'implemented_offline_core_not_complete_authentication',
        'android_runtime_required': False,
        'adb_required': False,
        'jvm_required': False,
        'original_sdk_execution_required': False,
        'host_identity_autofill': False,
        'protocol_abi_source': 'explicit_protocol_selection_not_host_cpu',
        'protocol_locale_source': 'explicit_not_host_locale',
        'live_login_ready': False,
        'unresolved': [
            'codeguard_process_package_and_environment_input_contract',
            'registered_device_identity_and_account_state',
            'current_recipient_trust_path_crl_and_installation',
            'stateful_authentication_transport_and_server_acceptance',
            'noninteractive_secret_input_and_session_lifecycle',
        ],
    }


def _models():
    from .compat import loads, read_model
    from .protocol import ENDPOINTS
    # Exercise packaged schema lookup for every catalogued request.
    for name in ENDPOINTS:
        read_model({}, name)
    return read_model(loads('{"responseCode":"000"}'), 'national.list')['responseCode'] == '000'


def _nonce():
    from .codeguard_nonce import cg_auth_code, load_programs
    # Existing offline vector. Inputs are synthetic, NOT device observations.
    key = bytes(range(32)).hex().encode('ascii')
    codes = [bytes([i] * 32).hex().encode('ascii') for i in range(6)]
    return (len(load_programs()['functions']) == 100 and cg_auth_code(key, codes)
            == '5223183D3B4B4B733742A465610E92E71B9633E0B8D1EA8B5C9F9F4C15155BB5')


def _seed_pin():
    from .crypto import PIN_IV, _cbc, decrypt_body, encode_pin, encrypt_body
    key, plain = bytes(range(16)), b'SYNTHETIC DEPLOYMENT CHECK'
    if decrypt_body(encrypt_body(plain, key), key) != plain:
        return False
    blocks = bytes.fromhex(encode_pin('012345', key))
    return len(blocks) == 96 and all(
        _cbc(key, PIN_IV, blocks[i * 16:(i + 1) * 16], decrypt=True)
        == bytes((5, position)) + bytes(14)
        for i, position in enumerate((10, 1, 2, 3, 4, 5)))


def _cms():
    from asn1crypto import cms
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from .cms import envelop_query
    from .crypto import decrypt_body

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'SYNTHETIC OFFLINE ONLY')])
    at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(private.public_key()).serial_number(128)
            .not_valid_before(at).not_valid_after(at + timedelta(days=1))
            .sign(private, hashes.SHA256()))
    plain = b'SYNTHETIC DEPLOYMENT CHECK'
    envelope = envelop_query(plain, cert.public_bytes(serialization.Encoding.DER))
    parsed = cms.ContentInfo.load(envelope.data)['content']
    wrapped = parsed['recipient_infos'][0].chosen['encrypted_key'].native
    key = private.decrypt(wrapped, padding.PKCS1v15())
    encrypted = parsed['encrypted_content_info']['encrypted_content'].native
    # Encoding round trip only. No recipient trust/path/CRL validation claim.
    return key == envelope.session_key and decrypt_body(encrypted, key) == plain


def _charset():
    sample = '국세 지방세 관세'
    return sample.encode('euc-kr').decode('euc-kr') == sample


def _timezone():
    # Explicit service calendar, independent of the server's local timezone.
    at = datetime(2026, 1, 1, 16, tzinfo=timezone.utc).astimezone(ZoneInfo('Asia/Seoul'))
    return at.day == 2 and at.hour == 1 and at.utcoffset() == timedelta(hours=9)


def check_runtime():
    checks = []
    for name, check, warning in (
        ('packaged_models', _models, 'model_resource_unavailable_or_incompatible'),
        ('packaged_nonce_arithmetic', _nonce, 'nonce_resource_or_arithmetic_unavailable'),
        ('seed_pin_codec', _seed_pin, 'crypto_extra_and_seed_backend_required'),
        ('rsa_cms_roundtrip', _cms, 'crypto_extra_and_rsa_cms_backend_required'),
        ('euc_kr_codec', _charset, 'euc_kr_codec_unavailable_or_incompatible'),
        ('seoul_calendar', _timezone, 'system_zoneinfo_or_tzdata_required'),
    ):
        try:
            passed = check() is True
        except Exception:
            # Keep paths, exception messages and any material out of reports.
            # This catch belongs only to diagnostics, never protocol handling.
            passed = False
        checks.append({'component': name, 'status': 'passed' if passed else 'warning',
                       **({} if passed else {'issue': warning})})
    return {
        'offline': True,
        'analysis_status': 'local_capability_check_only',
        'deployment': deployment_plan(),
        'network_attempted': False,
        'host_identity_collected': False,
        'device_checks_performed': False,
        'certificate_validation_performed': False,
        'server_token_generated': False,
        'live_login_ready': False,
        'checks': checks,
        'warning_count': sum(check['status'] == 'warning' for check in checks),
    }
