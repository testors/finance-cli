"""CMS/VID primitives extracted from Hana; no institution login or file I/O."""
from datetime import datetime, timezone
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.asn1 import DerObjectId, DerOctetString, DerSequence, DerSetOf

RSA_OID = '1.2.840.113549.1.1.1'
SHA256_RSA = '1.2.840.113549.1.1.11'
SHA256_OID = '2.16.840.1.101.3.4.2.1'
DATA_OID = '1.2.840.113549.1.7.1'

def der(tag, content):
    n = len(content)
    length = bytes([n]) if n < 128 else bytes([128 + (n.bit_length()+7)//8]) + n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([tag]) + length + content


def sequence(data):
    return DerSequence().decode(data, strict=True)


def oid(data):
    return DerObjectId().decode(data, strict=True).value


def oid_der(value):
    return DerObjectId(value).encode()


def octets(data):
    return DerOctetString().decode(data, strict=True).payload


def seq(*values):
    return DerSequence(values).encode()


def algorithm(value):
    return seq(oid_der(value), b'\x05\x00')


def certificate_parts(cert_der):
    cert = sequence(cert_der)
    if len(cert) != 3 or oid(sequence(cert[1])[0]) != SHA256_RSA:
        raise ValueError('Only SHA256withRSA certificates are supported')
    tbs = sequence(cert[0])
    offset = 1 if isinstance(tbs[0], bytes) and tbs[0][0] == 0xa0 else 0
    serial, issuer = tbs[offset], tbs[offset + 2]
    public = RSA.import_key(cert_der)
    if public.size_in_bits() != 2048:
        raise ValueError('Only the selected RSA 2048 profile is supported')
    return serial, issuer, public


def require_matching_key(cert_der, key):
    _, _, public = certificate_parts(cert_der)
    if (public.n, public.e) != (key.n, key.e):
        raise ValueError('Certificate and private key do not match')


def sign_cms(cert_der, key, message, signing_time=None):
    """Offline CMS primitive. The command-line interface remains login-only."""
    if not isinstance(message, bytes):
        raise TypeError('CMS content must be explicit bytes')
    require_matching_key(cert_der, key)
    serial, issuer, public = certificate_parts(cert_der)
    moment = signing_time or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValueError('signing_time must include a timezone')
    moment = moment.astimezone(timezone.utc)
    time_der = (der(0x17, moment.strftime('%y%m%d%H%M%SZ').encode())
                if 1950 <= moment.year < 2050 else
                der(0x18, moment.strftime('%Y%m%d%H%M%SZ').encode()))
    digest_alg, signature_alg = algorithm(SHA256_OID), algorithm(RSA_OID)

    def attribute(name, value):
        return seq(oid_der(name), DerSetOf([value]).encode())

    attrs = DerSetOf([
        attribute('1.2.840.113549.1.9.3', oid_der(DATA_OID)),
        attribute('1.2.840.113549.1.9.5', time_der),
        attribute('1.2.840.113549.1.9.4', DerOctetString(SHA256.new(message).digest()).encode()),
        attribute('1.2.840.113549.1.9.52', seq(digest_alg, b'\xa1' + signature_alg[1:])),
    ]).encode()
    signature = pkcs1_15.new(key).sign(SHA256.new(attrs))
    pkcs1_15.new(public).verify(SHA256.new(attrs), signature)
    signer_info = seq(1, seq(issuer, serial), digest_alg, b'\xa0' + attrs[1:],
                      signature_alg, DerOctetString(signature).encode())
    signed_data = seq(1, DerSetOf([digest_alg]).encode(),
                      seq(oid_der(DATA_OID), der(0xa0, DerOctetString(message).encode())),
                      der(0xa0, cert_der), DerSetOf([signer_info]).encode())
    return seq(oid_der('1.2.840.113549.1.7.2'), der(0xa0, signed_data))


def extract_vid_random(private_key_info_der):
    """Match SDK NPKIPrivateKeyInfo.c on decoded PKCS#8; no file/key-password I/O.

    This is the certificate VID random attribute, not a generated identity proof.
    Return None when no single-valued matching attribute exists. As in the SDK,
    the first qualifying attribute wins and unused BIT STRING bits are masked.
    """
    info = sequence(private_key_info_der)
    if len(info) not in (3, 4) or info[0] != 0 or oid(sequence(info[1])[0]) != RSA_OID:
        raise ValueError('Expected RSA PKCS#8 private key')
    if len(info) == 3:
        return None
    attributes = info[3]
    if not isinstance(attributes, bytes) or attributes[0] != 0xa0:
        raise ValueError('Expected PKCS#8 attributes')
    for encoded in DerSetOf().decode(b'\x31' + attributes[1:], strict=True):
        attr = sequence(encoded)
        if len(attr) != 2:
            raise ValueError('Invalid PKCS#8 attribute')
        if oid(attr[0]) != '1.2.410.200004.10.1.1.3':
            continue
        values = DerSetOf().decode(attr[1], strict=True)
        if len(values) != 1:
            continue
        # Decode the payload directly to preserve SDK getBytes() pad-bit rules.
        from Crypto.Util.asn1 import DerObject
        value = values[0]
        if not isinstance(value, bytes) or value[0] != 3:
            raise ValueError('VID random must be a BIT STRING')
        payload = DerObject().decode(value, strict=True).payload
        if not payload or payload[0] > 7 or (len(payload) == 1 and payload[0]):
            raise ValueError('Invalid VID BIT STRING')
        data = bytearray(payload[1:])
        if payload[0]:
            data[-1] &= (255 << payload[0]) & 255
        return bytes(data)
    return None


def vid_summary(private_key_info_der):
    """Report only presence/length, never the VID bytes or their fingerprint."""
    vid = extract_vid_random(private_key_info_der)
    return {'vid_attribute_present': vid is not None,
            'vid_byte_count': len(vid) if vid is not None else None,
            'vid_nonempty': bool(vid), 'vid_value_saved': False,
            'vid_identity_verified_by_bank': False}
