"""Certificate issuance messages, protected responses, VID and proof of possession."""
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac

from asn1crypto import x509
from Crypto.Util.asn1 import DerObject
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from finance_cli.credentials.joint.cms import der, seq, sequence, oid, oid_der, algorithm, octets

PBM = '1.2.840.113533.7.66.13'
SHA256 = '2.16.840.1.101.3.4.2.1'
HMAC256 = '1.2.840.113549.2.9'
RSA = '1.2.840.113549.1.1.1'
RSA_SHA256 = '1.2.840.113549.1.1.11'
OAEP = '1.2.840.113549.1.1.7'
KEY_TYPES = '1.3.6.1.5.5.7.4.2'
CA_CERT = '1.3.6.1.5.5.7.4.1'
CIPHER = '1.3.6.1.5.5.7.4.4'
VID = '1.2.410.200004.10.1.1.2'
REQUEST_ID = 0x6174


class ProtocolError(ValueError):
    def __init__(self, code, *, issuance='unknown'):
        self.code, self.issuance = code, issuance
        super().__init__(code)


def content(value, tag):
    if not isinstance(value, bytes) or not value or value[0] != tag:
        raise ProtocolError('cmp_unexpected_tag')
    return DerObject().decode(value, strict=True).payload


def bits(value):
    return der(3, b'\0'+value)


def bit_value(value):
    raw = content(value, 3)
    if not raw or raw[0] > 7 or (len(raw) == 1 and raw[0]):
        raise ProtocolError('cmp_invalid_bit_string')
    data = bytearray(raw[1:])
    if raw[0]:
        data[-1] &= (255 << raw[0]) & 255
    return bytes(data)


def optional(tag, value):
    return der(tag, der(4, value)) if value else b''


def pbm_algorithm(salt=bytes(20), iterations=1024):
    return seq(oid_der(PBM), seq(der(4, salt), algorithm(SHA256), iterations, algorithm(HMAC256)))


def mac(password, salt, iterations, message):
    # This protocol iterates a hash; it does not use PBKDF2 here.
    if iterations < 0:
        raise ProtocolError('cmp_invalid_iterations')
    if not iterations or not message:
        return bytes(32)
    initial = password+salt
    key = hashlib.sha256(initial).digest() if initial else bytes(32)
    for _ in range(iterations-1):
        key = hashlib.sha256(key).digest()
    return hmac.new(key, message, hashlib.sha256).digest()


def protect(header, body, password, *, salt=bytes(20), iterations=1024):
    protected = seq(header, body)
    return seq(header, body, der(0xa0, bits(mac(password, salt, iterations, protected))))


def wire(message):
    return base64.b64encode(message.hex().upper().encode('ascii'))


def unwire(value):
    return bytes.fromhex(base64.b64decode(value).decode('utf-8'))


def vid_plaintext(customer, random):
    digest = hashlib.sha256(hashlib.sha256(seq(der(0x13, customer), bits(random))).digest()).digest()
    return seq(seq(algorithm(SHA256), der(0xa0, der(4, digest))), bits(random))


def vid_info(certificate, ciphertext, *, oaep=True):
    cert = x509.Certificate.load(certificate, strict=True)
    encrypted = seq(der(0xa0, b'\x02\x01\x00'), der(0xa2, algorithm(OAEP if oaep else RSA)),
                    der(0xa3, seq(cert.issuer.dump(), cert.serial_number)), der(0xa4, der(4, ciphertext)))
    return seq(oid_der(VID), encrypted)


def pop_input(sender, spki):
    return seq(der(0xa0, sender), spki)


def ir_body(sender, spki, signature, reg_info):
    pop = der(0xa1, der(0xa0, content(pop_input(sender, spki), 0x30))+
              algorithm(RSA_SHA256)+bits(signature))
    request = seq(REQUEST_ID, seq(der(0xa6, content(spki, 0x30))))
    return der(0xa0, seq(seq(request, pop, seq(reg_info))))


@dataclass(repr=False)
class Context:
    reference: bytes
    password: bytes
    sender: bytes = field(default_factory=lambda: der(0x81, b''))
    recipient: bytes = field(default_factory=lambda: der(0x81, b''))
    sender_kid: bytes = b''
    recipient_kid: bytes = b''
    recipient_nonce: bytes = b''
    transaction_id: bytes = b''
    ca_certificate: bytes = b''
    key_types: list = field(default_factory=lambda: [2048, 3072, 4096])
    certificate: bytes = b''
    protection_verified: bool | None = None

    def genm(self):
        header = seq(2, der(0x81, b' '), der(0x81, b'Aton-CA'), der(0xa1, pbm_algorithm()),
                     optional(0xa2, self.reference), der(0xa5, der(4, bytes(20))))
        body = der(0xb5, seq(*(algorithm(name) for name in (KEY_TYPES, CA_CERT, CIPHER))))
        return protect(header, body, self.password)

    def header(self, now=None):
        moment = now or datetime.now(timezone.utc)
        date = moment.astimezone(timezone.utc).strftime('%Y%m%d%H%M%SZ').encode('ascii')
        return seq(2, self.sender, self.recipient, der(0xa0, der(0x18, date)),
                   der(0xa1, pbm_algorithm()), optional(0xa2, self.sender_kid),
                   optional(0xa3, self.recipient_kid), der(0xa5, der(4, bytes(20))),
                   optional(0xa6, self.recipient_nonce))

    def receive(self, encoded, expected_tag):
        self.protection_verified = None
        message = sequence(encoded)
        header, body = message[:2]
        content(body, expected_tag)
        values = sequence(header)
        tags = {v[0]: v for v in values[3:] if isinstance(v, bytes)}
        protection = next((v for v in message[2:] if v[0] == 0xa0), None)
        if 0xa1 in tags:
            alg = sequence(content(tags[0xa1], 0xa1))
            name = oid(alg[0])
            signature = bit_value(content(protection, 0xa0)) if protection else b''
            protected = seq(header, body)
            if name == PBM:
                params = sequence(alg[1])
                if oid(sequence(params[1])[0]) != SHA256 or oid(sequence(params[3])[0]) != HMAC256:
                    raise ProtocolError('cmp_unsupported_mac')
                expected = mac(self.password, octets(params[0]), params[2], protected)
                if not hmac.compare_digest(signature, expected):
                    raise ProtocolError('cmp_protection_rejected')
            else:
                if name != RSA_SHA256:
                    raise ProtocolError('cmp_unsupported_signature')
                extra = next((v for v in message[2:] if v[0] == 0xa1), None)
                certificates = sequence(content(extra, 0xa1)) if extra else []
                if not certificates:
                    raise ProtocolError('cmp_signer_missing')
                cert = x509.Certificate.load(certificates[0], strict=True)
                public = serialization.load_der_public_key(cert.public_key.dump())
                try:
                    public.verify(signature, protected, padding.PKCS1v15(), hashes.SHA256())
                except Exception:
                    raise ProtocolError('cmp_protection_rejected') from None
            self.protection_verified = True
        # Body consumption can fail after these header fields have changed.
        self.sender, self.recipient = values[2], values[1]
        def value(tag):
            return octets(content(tags[tag], tag)) if tag in tags else b''
        self.sender_kid, self.recipient_kid = value(0xa3), value(0xa2)
        self.recipient_nonce, self.transaction_id = value(0xa6), value(0xa4)
        return content(body, expected_tag)

    def genp(self, encoded):
        entries = sequence(self.receive(encoded, 0xb6))
        info = {}
        for entry in entries:
            values = sequence(entry)
            info[oid(values[0])] = values[1]
        self.ca_certificate = info.get(CA_CERT, b'')
        x509.Certificate.load(self.ca_certificate, strict=True).native
        candidates = []
        for value in sequence(info.get(KEY_TYPES, seq())):
            alg = sequence(value)
            if oid(alg[0]) == RSA and alg[1] in self.key_types:
                candidates.append(alg[1])
        if not candidates:
            raise ProtocolError('cmp_no_supported_key_type')
        self.key_types = candidates

    def ir(self, private_key, random, customer, *, now=None, oaep=True):
        key = serialization.load_der_private_key(private_key, password=None)
        spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cert = x509.Certificate.load(self.ca_certificate, strict=True)
        public = serialization.load_der_public_key(cert.public_key.dump())
        scheme = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None) if oaep else padding.PKCS1v15()
        ciphertext = public.encrypt(vid_plaintext(customer, random), scheme)
        reg = vid_info(self.ca_certificate, ciphertext, oaep=oaep)
        signature = key.sign(pop_input(self.sender, spki), padding.PKCS1v15(), hashes.SHA256())
        return protect(self.header(now), ir_body(self.sender, spki, signature, reg), self.password)

    def ip(self, encoded):
        values = sequence(self.receive(encoded, 0xa1))
        responses = sequence(values[-1])
        for response in responses:
            fields = sequence(response)
            if fields[0] != REQUEST_ID:
                continue
            status = sequence(fields[1])[0]
            if status != 0:
                raise ProtocolError('cmp_certificate_rejected', issuance='failure')
            if len(fields) < 3:
                raise ProtocolError('cmp_certificate_missing')
            pair = sequence(fields[2])
            if pair[0][0] == 0xa1:
                raise ProtocolError('cmp_encrypted_certificate_unresolved')
            certificate = content(pair[0], 0xa0)
            cert = x509.Certificate.load(certificate, strict=True)
            alias = str(cert.serial_number).zfill(12)
            self.certificate = certificate
            return certificate, alias
        raise ProtocolError('cmp_request_id_missing')

    def confirm(self, now=None):
        return protect(self.header(now), der(0xb3, b'\x05\0'), self.password)
