"""PIN derivation and RSA signed-attribute containers for Shinhan certificates."""
from datetime import datetime, timezone
import hashlib

from asn1crypto import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from finance_cli.credentials.joint.cms import der, seq, oid_der, algorithm

SHA256 = '2.16.840.1.101.3.4.2.1'
DATA = '1.2.840.113549.1.7.1'


def unique_value(pin, salt):
    if not isinstance(pin, bytes) or len(salt) != 32:
        raise ValueError('invalid_pin_material')
    return hashlib.pbkdf2_hmac('sha512', pin, salt, 2048, 64).hex().upper()


def attributes(date, digest, nonce):
    def attribute(name, encoded):
        return seq(oid_der(name), der(0x31, encoded))
    values = [attribute('1.2.840.113549.1.9.3', oid_der(DATA)),
              attribute('1.2.840.113549.1.9.5', der(0x17, date)),
              attribute('1.2.840.113549.1.9.4', der(4, digest))]
    if nonce is not None:
        values.append(attribute('1.2.840.113549.1.9.25.3', der(4, nonce)))
    # Attribute order is significant here; do not use a sorting SET encoder.
    return der(0xa0, b''.join(values))


def pkcs7(certificate, signature, message, attrs, *, oid_mode=0):
    cert = x509.Certificate.load(certificate, strict=True)
    issuer, serial = cert.issuer.dump(), cert.serial_number
    digest_algorithm = algorithm(SHA256)
    signature_algorithm = algorithm('1.2.840.113549.1.1.1' if oid_mode == 1 else '1.2.840.113549.1.1.11')
    signer = seq(1, seq(issuer, serial), digest_algorithm, *([attrs] if attrs else []),
                 signature_algorithm, der(4, signature))
    content = seq(oid_der(DATA), *([der(0xa0, der(4, message))] if message else []))
    signed = seq(1, der(0x31, digest_algorithm), content, der(0xa0, certificate), der(0x31, signer))
    return seq(oid_der('1.2.840.113549.1.7.2'), der(0xa0, signed))


def sign(certificate, private_key, plaintext, nonce, *, moment=None, now=None, oid_mode=0):
    if not plaintext or len(plaintext) > 30720 or not nonce:
        raise ValueError('signing_input_unavailable')
    current = now or datetime.now(timezone.utc)
    cert = x509.Certificate.load(certificate, strict=True)
    validity = cert['tbs_certificate']['validity']
    if not validity['not_before'].native <= current <= validity['not_after'].native:
        raise ValueError('certificate_outside_validity')
    # The caller samples local time separately from the login plaintext clock.
    time_text = (moment or datetime.now()).strftime('%y%m%d%H%M%S')+'Z'
    attrs = attributes(time_text.encode('ascii'), hashlib.sha256(plaintext).digest(), nonce)
    key = serialization.load_der_private_key(private_key, password=None)
    signature = key.sign(b'\x31'+attrs[1:], padding.PKCS1v15(), hashes.SHA256())
    return pkcs7(certificate, signature, plaintext, attrs, oid_mode=oid_mode)
