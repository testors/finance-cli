"""Offline NPKI signing at the selected-certificate boundary. See docs/06.

The cryptography package supplies cipher/RSA primitives.
No trust-store, expiry or policy checks are invented at this boundary.
"""

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib

from asn1crypto import algos, cms, core, keys, x509
from cryptography import x509 as crypto_x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import SEED

from .auth import certificate_callback

VID_RANDOM_OID = "1.2.410.200004.10.1.1.3"
SEED_SHA1 = "1.2.410.200004.1.15"
SEED_CBC = "1.2.410.200004.1.4"
PBES2 = "1.2.840.113549.1.5.13"
AES128_CBC = "2.16.840.1.101.3.4.1.2"


class CertificateError(ValueError):
    """Local processing error; never a server authentication verdict."""


class UnsupportedProfile(CertificateError):
    """An unimplemented profile, not an original-app rejection."""


class Algorithm(core.Sequence):
    _fields = [("oid", core.ObjectIdentifier), ("parameters", core.Any, {"optional": True})]


class EncryptedKey(core.Sequence):
    _fields = [("algorithm", Algorithm), ("encrypted", core.OctetString)]


class PBEParameters(core.Sequence):
    _fields = [("salt", core.OctetString), ("iterations", core.Integer)]


class PBES2Parameters(core.Sequence):
    _fields = [("kdf", Algorithm), ("cipher", Algorithm)]


def legacy_material(password: bytes, salt: bytes, iterations: int, oid: str):
    digest = hashlib.sha1(password + salt).digest()
    # Native PBKDF1 hashes once even for iterations <= 1.
    for _ in range(1, iterations):
        digest = hashlib.sha1(digest).digest()
    iv = b"0123456789012345" if oid == SEED_CBC else hashlib.sha1(digest[16:]).digest()[:16]
    return digest[:16], iv


def native_unpad(plain: bytes, block_size: int = 16) -> bytes:
    # PPKCS8 passes padding=2 -> getECSP_Padding(2)=0. MagicCrypto's
    # MCM_DetachPad case 0 checks all bytes, but also accepts a zero last byte.
    if not plain:
        raise CertificateError("개인키 복호화 결과가 비어 있습니다.")
    count = plain[-1]
    if count > block_size or count > len(plain):
        raise CertificateError("올바르지 않은 개인키 패딩입니다.")
    if count and plain[-count:] != bytes([count]) * count:
        raise CertificateError("올바르지 않은 개인키 패딩입니다.")
    return plain[:-count] if count else plain


def decrypt_key(encrypted: bytes, password: bytes) -> tuple[bytes, list[str]]:
    if not encrypted or not password:
        raise CertificateError("빈 개인키 또는 빈 비밀번호는 지원하지 않습니다.")
    info = EncryptedKey.load(encrypted)
    algorithm = info["algorithm"]
    oid = algorithm["oid"].dotted
    warnings = []
    if oid in (SEED_SHA1, SEED_CBC):
        params = PBEParameters.load(algorithm["parameters"].dump())
        key, iv = legacy_material(password, params["salt"].native, params["iterations"].native, oid)
        cipher = SEED(key)
    elif oid == PBES2:
        params = PBES2Parameters.load(algorithm["parameters"].dump())
        # Native parseKeyDerivationFunc reads parameters, not the KDF OID.
        kdf = algos.Pbkdf2Params.load(params["kdf"]["parameters"].dump())
        if kdf["salt"].name != "specified":
            raise UnsupportedProfile("PBKDF2 otherSource salt 경로는 아직 구현하지 않았습니다.")
        if kdf["prf"]["algorithm"].native != "sha1":
            warnings.append("이 호환 프로필은 PRF 필드와 무관하게 HMAC-SHA1을 사용합니다.")
        if kdf["key_length"].native not in (None, 16):
            warnings.append("이 호환 프로필에서는 PBKDF2 keyLength 값을 따로 제한하지 않습니다.")
        iterations = kdf["iteration_count"].native
        if iterations < 1:
            raise UnsupportedProfile("반복 횟수 0 이하 PBKDF2의 네이티브 버퍼 동작은 미구현입니다.")
        material = hashlib.pbkdf2_hmac("sha1", password, kdf["salt"].native, iterations, 32)
        key = material[:16]
        raw_iv = params["cipher"]["parameters"]
        iv = core.OctetString.load(raw_iv.dump()).native if raw_iv.native is not None else b""
        iv = iv or material[16:32]  # Native derives IV only if the supplied IV is empty.
        cipher_oid = params["cipher"]["oid"].dotted
        if cipher_oid in (SEED_CBC, SEED_CBC + ".2"):
            cipher = SEED(key)
        elif cipher_oid == AES128_CBC:
            cipher = algorithms.AES(key)
        else:
            raise UnsupportedProfile("이 PBES2 암호 알고리즘은 아직 구현하지 않았습니다.")
    else:
        raise UnsupportedProfile("이 개인키 암호화 OID는 아직 구현하지 않았습니다.")
    decryptor = Cipher(cipher, modes.CBC(iv)).decryptor()
    plain = decryptor.update(info["encrypted"].native) + decryptor.finalize()
    if plain and plain[-1] == 0:
        warnings.append("패딩 길이 0입니다. 이 호환 프로필에서 허용하므로 계속 처리합니다.")
    plain = native_unpad(plain)
    try:
        parsed = keys.PrivateKeyInfo.load(plain)
        parsed["private_key_algorithm"].native
        parsed["private_key"].native
        der = parsed.dump()
    except (ValueError, TypeError, KeyError) as error:
        raise CertificateError("개인키 복호화 결과를 읽을 수 없습니다.") from error
    return der, warnings


def vid_random(private_der: bytes) -> bytes:
    result = b""
    info = keys.PrivateKeyInfo.load(private_der)
    # Native scans all attributes: the last matching value wins.
    for attr in info["attributes"]:
        if attr["type"].dotted == VID_RANDOM_OID:
            bit_string = core.OctetBitString.load(attr["values"][0].dump())
            result = bit_string.native
    if not result:
        raise CertificateError("개인키에 VID 난수가 없습니다.")
    return result


@dataclass
class SignedCertificate:
    signed_data: bytes
    random: bytes
    warnings: list[str]

    def callback(self) -> dict:
        return certificate_callback(base64.b64encode(self.signed_data).decode("ascii"),
                                    base64.b64encode(self.random).decode("ascii"))


def sign_empty(certificate_der: bytes, private_der: bytes,
               signing_time: datetime | None = None) -> bytes:
    certificate = x509.Certificate.load(certificate_der)
    cert = crypto_x509.load_der_x509_certificate(certificate_der)
    try:
        key_usage = cert.extensions.get_extension_for_class(crypto_x509.KeyUsage).value
        if not key_usage.digital_signature:
            raise CertificateError("digitalSignature가 없는 키는 서명에 사용할 수 없습니다.")
    except crypto_x509.ExtensionNotFound:
        pass  # Original explicitly accepts a missing keyUsage extension.
    private = serialization.load_der_private_key(private_der, password=None)
    if not isinstance(private, rsa.RSAPrivateKey) or certificate.public_key.algorithm != "rsa":
        raise UnsupportedProfile("현재 독립 서명 구현은 RSA 인증서만 지원합니다.")
    now = (signing_time or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    attrs = cms.CMSAttributes([
        {"type": "content_type", "values": ["data"]},
        {"type": "signing_time", "values": [cms.Time({"utc_time": core.UTCTime(now)})]},
        {"type": "message_digest", "values": [hashlib.sha256(b"").digest()]},
    ])
    tbs = attrs.dump()
    signature = private.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
    try:
        # Original g.b verifies its own CMS and the recovered empty message.
        cert.public_key().verify(signature, tbs, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as error:
        raise CertificateError("인증서 공개키로 서명을 검증할 수 없습니다.") from error
    digest = algos.DigestAlgorithm({"algorithm": "sha256", "parameters": None})
    signer = cms.SignerInfo({
        "version": "v1", "sid": {"issuer_and_serial_number": {
            "issuer": certificate.issuer, "serial_number": certificate.serial_number}},
        "digest_algorithm": digest, "signed_attrs": attrs,
        "signature_algorithm": {"algorithm": "sha256_rsa", "parameters": core.Null()},
        "signature": signature,
    })
    # Option 0 returns bare SignedData, with an explicit empty eContent.
    return cms.SignedData({
        "version": "v1", "digest_algorithms": [digest],
        "encap_content_info": {"content_type": "data", "content": b""},
        "certificates": [certificate], "signer_infos": [signer],
    }).dump()


def prepare_certificate(certificate_der: bytes, encrypted_key: bytes,
                        password: bytes, signing_time: datetime | None = None) -> SignedCertificate:
    private, warnings = decrypt_key(encrypted_key, password)
    signed = sign_empty(certificate_der, private, signing_time)
    random = vid_random(private)
    return SignedCertificate(signed, random, warnings)
