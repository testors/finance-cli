"""Read PKCS#12 without discarding NPKI PKCS#8 attributes.

The system OpenSSL library is used. All decrypted
data stays in memory. Source/format references are documented in docs/12.
"""
import ctypes as ct
import ctypes.util
from functools import lru_cache

from asn1crypto import pkcs12
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .certificate import (CertificateError, UnsupportedProfile, SignedCertificate,
                          SEED_SHA1, SEED_CBC, decrypt_key, sign_empty, vid_random)
from finance_cli.core.native import crypto_library


@lru_cache(maxsize=1)
def crypto():
    name = crypto_library()
    if not name:
        raise UnsupportedProfile("PFX 처리에 시스템 OpenSSL libcrypto가 필요합니다.")
    lib = ct.CDLL(name)
    pointer = ct.c_void_p
    functions = {
        "d2i_PKCS12": (pointer, [ct.POINTER(pointer), ct.POINTER(pointer), ct.c_long]),
        "PKCS12_free": (None, [pointer]),
        "PKCS12_verify_mac": (ct.c_int, [pointer, ct.c_char_p, ct.c_int]),
        "d2i_X509_ALGOR": (pointer, [ct.POINTER(pointer), ct.POINTER(pointer), ct.c_long]),
        "X509_ALGOR_free": (None, [pointer]),
        "PKCS12_pbe_crypt": (pointer, [pointer, ct.c_char_p, ct.c_int, ct.c_char_p,
                                      ct.c_int, ct.POINTER(pointer), ct.POINTER(ct.c_int), ct.c_int]),
        "CRYPTO_clear_free": (None, [pointer, ct.c_size_t, ct.c_char_p, ct.c_int]),
    }
    try:
        for function, (result, arguments) in functions.items():
            getattr(lib, function).restype = result
            getattr(lib, function).argtypes = arguments
        if hasattr(lib, "OSSL_PROVIDER_load"):
            lib.OSSL_PROVIDER_load.restype = pointer
            lib.OSSL_PROVIDER_load.argtypes = [pointer, ct.c_char_p]
            # Retain providers for the process lifetime; old PFX uses RC2/3DES.
            lib._providers = [lib.OSSL_PROVIDER_load(None, b"default"),
                              lib.OSSL_PROVIDER_load(None, b"legacy")]
    except AttributeError as error:
        raise UnsupportedProfile("필요한 PKCS#12 OpenSSL API가 없습니다.") from error
    return lib


def _decode(function, der):
    buffer = ct.create_string_buffer(der)
    cursor = ct.c_void_p(ct.addressof(buffer))
    result = function(None, ct.byref(cursor), len(der))
    if not result:
        raise CertificateError("PFX ASN.1 구조를 읽을 수 없습니다.")
    return result


def _verify_mac(data, password):
    lib = crypto()
    pfx = _decode(lib.d2i_PKCS12, data)
    try:
        if lib.PKCS12_verify_mac(pfx, password, len(password)) != 1:
            raise CertificateError("PFX MAC 검증에 실패했습니다. 비밀번호 또는 파일을 확인하세요.")
    finally:
        lib.PKCS12_free(pfx)


def _decrypt(algorithm, encrypted, password):
    lib = crypto()
    alg = _decode(lib.d2i_X509_ALGOR, algorithm.dump())
    output, size = ct.c_void_p(), ct.c_int()
    try:
        result = lib.PKCS12_pbe_crypt(alg, password, len(password), encrypted, len(encrypted),
                                    ct.byref(output), ct.byref(size), 0)
        if not result:
            raise CertificateError("PFX 복호화를 완료하지 못했습니다. 비밀번호·암호 프로파일을 확인하세요.")
        return ct.string_at(output, size.value)
    finally:
        if output:
            lib.CRYPTO_clear_free(output, max(size.value, 0), None, 0)
        lib.X509_ALGOR_free(alg)


def read_pfx(data: bytes, password: bytes):
    if not data or not password:
        raise CertificateError("빈 PFX 파일 또는 빈 비밀번호는 지원하지 않습니다.")
    pfx = pkcs12.Pfx.load(data)
    if pfx["version"].native != "v3" or pfx["auth_safe"]["content_type"].native != "data":
        raise UnsupportedProfile("현재 PFX 입력은 v3 password privacy 형식을 지원합니다.")
    warnings = []
    if pfx["mac_data"].native is not None:
        _verify_mac(data, password)
    else:
        warnings.append("PFX에 MAC이 없습니다. 계속 읽습니다.")
    certificates, private_keys = [], []

    def bags(contents):
        for bag in contents:
            kind, value = bag["bag_id"].native, bag["bag_value"]
            if kind == "cert_bag" and value["cert_id"].native == "x509":
                certificates.append(value["cert_value"].parsed.dump())
            elif kind == "key_bag":
                private_keys.append(value.untag().dump())
            elif kind == "pkcs8_shrouded_key_bag":
                algorithm = value["encryption_algorithm"]
                if algorithm["algorithm"].dotted in (SEED_SHA1, SEED_CBC):
                    private, notes = decrypt_key(value.untag().dump(), password)
                    warnings.extend(notes)
                else:
                    private = _decrypt(algorithm, value["encrypted_data"].native, password)
                private_keys.append(private)
            elif kind == "safe_contents":
                bags(value)
            else:
                warnings.append("로그인 키·인증서 이외의 PFX bag은 선택에 사용하지 않습니다.")

    for content in pkcs12.AuthenticatedSafe.load(pfx["auth_safe"]["content"].native):
        kind = content["content_type"].native
        if kind == "data":
            plain = content["content"].native
        elif kind == "encrypted_data":
            encrypted = content["content"]["encrypted_content_info"]
            plain = _decrypt(encrypted["content_encryption_algorithm"],
                             encrypted["encrypted_content"].native, password)
        else:
            raise UnsupportedProfile("이 PFX SafeContents 보호 방식은 아직 구현하지 않았습니다.")
        bags(pkcs12.SafeContents.load(plain))
    pairs = []
    encoding, form = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    for private in private_keys:
        key = serialization.load_der_private_key(private, password=None)
        public = key.public_key().public_bytes(encoding, form)
        for certificate in certificates:
            cert = x509.load_der_x509_certificate(certificate)
            if cert.public_key().public_bytes(encoding, form) == public:
                pairs.append((certificate, private))
    if not pairs:
        raise CertificateError("PFX에서 서로 일치하는 인증서와 개인키를 찾지 못했습니다.")
    return pairs, warnings


def select_signing_pair(pairs, index=None):
    if index is None:
        # Korean PFX often bundles separate signing and encryption identities.
        # Apply the existing original keyUsage rule, preserving missing-usage
        # acceptance, to identify the unique signing pair without choosing an
        # arbitrary identity among multiple signing certificates.
        signing = []
        for number, (certificate, _) in enumerate(pairs):
            cert = x509.load_der_x509_certificate(certificate)
            try:
                if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
                    continue
            except x509.ExtensionNotFound:
                pass
            signing.append(number)
        if len(signing) == 1:
            index = signing[0]
        elif len(pairs) == 1:
            index = 0  # sign_empty reports the original keyUsage rejection.
        else:
            raise CertificateError("PFX에 인증서 쌍이 여럿입니다. --pfx-index로 사용할 항목을 선택하세요.")
    if index < 0 or index >= len(pairs):
        raise CertificateError("선택한 PFX 인증서 인덱스가 없습니다.")
    return pairs[index]


def prepare_pfx(data, password, index=None, signing_time=None):
    pairs, warnings = read_pfx(data, password)
    certificate, private = select_signing_pair(pairs, index)
    # Raw DER retains PKCS#8 attributes; never serialize a generic RSA key here.
    return SignedCertificate(sign_empty(certificate, private, signing_time), vid_random(private), warnings)
