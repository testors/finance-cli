"""Pure PINsign V30 CMP/CRMF issuance codec. No HTTP or certificate mutation.

Profile recovered from the original CmpClient.issueCert. Fresh key generation,
durable attempts, and identity prerequisites belong to the workflow caller.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import secrets

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Util.asn1 import DerSequence, DerOctetString, DerObjectId

from .nfilter_format import der, read_der
from .onesign_crypto import ProtocolError, certificate_parts, oid, seq, require

PBM = '1.2.840.113533.7.66.13'
SHA256_OID = '2.16.840.1.101.3.4.2.1'
HMAC256 = '1.2.840.113549.2.9'
ECDSA256 = '1.2.840.10045.4.3.2'


def sequence(value):
    return DerSequence().decode(value, strict=True)


def payload(value, tag):
    actual, raw, end = read_der(value)
    require(actual == tag and end == len(value), 'cmp_der_tag')
    return raw


def octets(value):
    return payload(value, 4)


def algorithm(name):
    return seq(oid(name), b'\x05\x00')


def subject(certificate):
    # CA may use an RSA key; only the *new* customer key is constrained to P256.
    tbs = sequence(sequence(certificate)[0])
    offset = int(isinstance(tbs[0], bytes) and tbs[0][0] == 0xa0)
    return tbs[offset + 4]


def pbm_parameters(salt, iterations=10240):
    return seq(DerOctetString(salt).encode(), algorithm(SHA256_OID), iterations, algorithm(HMAC256))


def pbm_mac(password, params, content):
    salt, owf, count, mac = sequence(params)
    require(sequence(owf)[0] == oid(SHA256_OID) and sequence(mac)[0] == oid(HMAC256), 'cmp_pbm_algorithm_unsupported')
    # Original PKMACBuilder accepts the response's PBM parameters. Do not require
    # response salt/count to equal the values of our request.
    require(type(count) is int and count >= 1, 'cmp_pbm_iteration_invalid')
    base = password.encode('utf-8') + octets(salt)
    for _ in range(count):
        base = hashlib.sha256(base).digest()
    return hmac.digest(base, content, 'sha256')


def protect(header, body, password, params):
    # protection [0] EXPLICIT BIT STRING.
    return seq(header, body, der(0xa0, der(3, b'\0' + pbm_mac(password, params, seq(header, body)))))


@dataclass(frozen=True)
class Request:
    encoded: bytes = field(repr=False)
    transaction: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    public_key: bytes = field(repr=False)


def issue_request(key, ca_certificate, reference, password, *, moment=None, transaction=None, nonce=None, salt=None, signer=None):
    require(key.has_private() and key.curve == 'NIST P-256', 'cmp_p256_private_key_required')
    moment = moment or datetime.now(timezone.utc)
    transaction = secrets.token_bytes(20) if transaction is None else transaction
    nonce = secrets.token_bytes(20) if nonce is None else nonce
    salt = secrets.token_bytes(64) if salt is None else salt
    require(len(transaction) == len(nonce) == 20 and len(salt) == 64, 'cmp_random_length')
    spki = key.public_key().export_key(format='DER')
    # publicKey [6] IMPLICIT SubjectPublicKeyInfo; CertRequest id0, no controls.
    cert_request = seq(0, seq(der(0xa6, payload(spki, 0x30))))
    signature = signer(cert_request) if signer else DSS.new(key, 'fips-186-3', encoding='der').sign(SHA256.new(cert_request))
    # POPOSigningKey [1] IMPLICIT; no poposkInput when signing CertRequest.
    pop = der(0xa1, seq(oid(ECDSA256)) + der(3, b'\0' + signature))
    body = der(0xa0, seq(seq(cert_request, pop)))
    params = pbm_parameters(salt)
    header = seq(2, der(0xa4, seq()), der(0xa4, subject(ca_certificate)),
                 der(0xa0, der(0x18, moment.astimezone(timezone.utc).strftime('%Y%m%d%H%M%SZ').encode())),
                 der(0xa1, seq(oid(PBM), params)),
                 der(0xa2, DerOctetString(reference.encode()).encode()),
                 der(0xa4, DerOctetString(transaction).encode()),
                 der(0xa5, DerOctetString(nonce).encode()))
    return Request(protect(header, body, password, params), transaction, nonce, spki)


def header_fields(header):
    values = sequence(header)
    require(len(values) >= 3 and values[0] == 2, 'cmp_header_invalid')
    result = {}
    for value in values[3:]:
        tag, content, end = read_der(value)
        require(end == len(value) and 0xa0 <= tag <= 0xa8 and tag not in result, 'cmp_header_invalid')
        result[tag] = content
    return result


def verify_protection(encoded, password):
    values = sequence(encoded)
    require(len(values) >= 3, 'cmp_missing_protection')
    fields = header_fields(values[0])
    protection_alg = sequence(fields.get(0xa1, b''))
    require(protection_alg[0] == oid(PBM), 'cmp_not_password_protected')
    actual = payload(payload(values[2], 0xa0), 3)
    require(actual[:1] == b'\0', 'cmp_protection_bit_string')
    expected = pbm_mac(password, protection_alg[1], seq(values[0], values[1]))
    require(hmac.compare_digest(actual[1:], expected), 'cmp_protection_mismatch')
    return values, fields


def issue_response(encoded, request, password, *, observed=None):
    """Original response checks followed by binding the cert to our new key."""
    try:
        values = sequence(encoded)
        require(len(values) >= 2, 'cmp_response_missing_body')
        require(values[1][0] != 0xb7, 'cmp_ca_error')
        fields = header_fields(values[0])
        require(octets(fields.get(0xa4, b'')) == request.transaction, 'cmp_transaction_mismatch')
        require(octets(fields.get(0xa6, b'')) == request.nonce, 'cmp_nonce_mismatch')
        verify_protection(encoded, password)
        reply = sequence(payload(values[1], 0xa1))
        # optional caPubs [1] precedes mandatory sequence of CertResponse.
        responses = sequence(reply[-1])
        require(len(responses) == 1, 'cmp_certificate_response_count')
        response = sequence(responses[0])
        require(response[0] == 0 and sequence(response[1])[0] in (0, 1), 'cmp_certificate_status_or_id')
        pair = sequence(response[2])
        certificate = payload(pair[0], 0xa0)  # CertOrEncCert.certificate
        if observed is not None:
            observed(certificate)  # Verified CA success precedes local key usability checks.
        public = certificate_parts(certificate)[3]
        require(public.export_key(format='DER') == request.public_key, 'cmp_certificate_key_mismatch')
        return certificate
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError('cmp_malformed_response') from None


def inspect_request(encoded, password):
    """Offline structural comparison, validates the original SDK's POP and PBM."""
    values, fields = verify_protection(encoded, password)
    messages = sequence(payload(values[1], 0xa0))
    require(len(messages) == 1, 'cmp_request_count')
    message = sequence(messages[0])
    cert_request = sequence(message[0])
    require(cert_request[0] == 0 and len(cert_request) == 2, 'cmp_request_id_or_controls')
    template = sequence(cert_request[1])
    require(len(template) == 1, 'cmp_request_template')
    spki = der(0x30, payload(template[0], 0xa6))
    pop = sequence(der(0x30, payload(message[1], 0xa1)))
    require(pop[0] == seq(oid(ECDSA256)), 'cmp_pop_algorithm')
    signature = payload(pop[1], 3)[1:]
    DSS.new(ECC.import_key(spki), 'fips-186-3', encoding='der').verify(SHA256.new(message[0]), signature)
    params = sequence(sequence(fields[0xa1])[1])
    return {'transaction': octets(fields[0xa4]), 'nonce': octets(fields[0xa5]),
            'reference': octets(fields[0xa2]), 'salt': octets(params[0]), 'iterations': params[2],
            'moment': datetime.strptime(payload(fields[0xa0], 0x18).decode(), '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc),
            'signature': signature, 'public_key': spki}
