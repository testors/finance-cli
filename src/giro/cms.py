"""Offline RSA-recipient CMS envelope for the query-string protocol.

GeneralSyntax=TRUE, GenerationIV=FALSE. Encoding stage ONLY, not the complete
putRecipientCert initialization. RecipientContext validates certificate
purpose, chain and CRL BEFORE this stage. This encoder cannot substitute for
that mandatory validation in a live client.
Does not implement signed-data envelopes / payment signatures.
"""
from dataclasses import dataclass, field
import secrets

from .crypto import API_IV, _cbc
from .errors import GiroError

SEED_CBC_OID = '1.2.410.200004.1.4'


def _tlv(tag, value):
    size = len(value)
    if size < 128:
        length = bytes([size])
    else:
        encoded = size.to_bytes((size.bit_length() + 7) // 8, 'big')
        length = bytes([128 | len(encoded)]) + encoded
    return bytes([tag]) + length + value


@dataclass(frozen=True)
class Envelope:
    data: bytes = field(repr=False)
    session_key: bytes = field(repr=False)


def envelop_query(plaintext, certificate_der):
    """Generate a fresh 16-byte SEED key and DER ContentInfo; memory only.

    Caller supplies query bytes, not arbitrary CMS SignedData. This low-level
    encoder assumes certificate validation has already happened upstream.
    Offline synthetic tests exercise encoding, NOT certificate acceptance.
    """
    if not isinstance(plaintext, bytes):
        raise GiroError('전자봉투 평문은 bytes여야 합니다.')
    try:
        from asn1crypto import x509 as asn1_x509, core
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
    except ImportError:
        raise GiroError('전자봉투에는 cryptography와 asn1crypto가 필요합니다.') from None
    try:
        cert = asn1_x509.Certificate.load(certificate_der)
        tbs = cert['tbs_certificate']
        public = x509.load_der_x509_certificate(certificate_der).public_key()
        algorithm = tbs['subject_public_key_info']['algorithm']
        if not isinstance(public, rsa.RSAPublicKey) or algorithm['algorithm'].dotted != '1.2.840.113549.1.1.1':
            raise GiroError('이 오프라인 구현은 RSA rsaEncryption 수신자 인증서 경로만 복원했습니다.')
        key = secrets.token_bytes(16)
        padded = plaintext + bytes([16 - len(plaintext) % 16]) * (16 - len(plaintext) % 16)
        encrypted_content = _cbc(key, API_IV, padded)
        encrypted_key = public.encrypt(key, padding.PKCS1v15())
        issuer_serial = _tlv(0x30, tbs['issuer'].dump() + tbs['serial_number'].dump())
        recipient = _tlv(0x30, b'\x02\x01\x00' + issuer_serial + algorithm.dump()
                         + _tlv(0x04, encrypted_key))
        content_algorithm = _tlv(0x30, core.ObjectIdentifier(SEED_CBC_OID).dump() + b'\x05\x00')
        content_info = _tlv(0x30, core.ObjectIdentifier('1.2.840.113549.1.7.1').dump()
                           + content_algorithm + _tlv(0x80, encrypted_content))
        enveloped_data = _tlv(0x30, b'\x02\x01\x00' + _tlv(0x31, recipient) + content_info)
        encoded = _tlv(0x30, core.ObjectIdentifier('1.2.840.113549.1.7.3').dump()
                      + _tlv(0xa0, enveloped_data))
        return Envelope(encoded, key)
    except GiroError:
        raise
    except (ValueError, TypeError, KeyError):
        raise GiroError('수신자 인증서 해석 또는 전자봉투 생성 실패') from None
