"""Offline SDK-compatible RSA signature subchecks; NOT a trust validator.

Implements the provider's observed RSA/PKCS1/DigestInfo acceptance, rather than
silently substituting a different verifier. No private keys or native SDK used.
Other algorithms/backend decoding boundaries are analysis limits, not success.
"""
import hashlib
import hmac

from .cert_factory import _node, SEQUENCE, OID, CertificateBackendLimit
from .cert_rules import CertificateRuleError
from .cms import _tlv

# Provider OID registrations, not a generic modern algorithm allow-list.
_ALGORITHMS = {
    '1.2.840.113549.1.1.4': ('md5','1.2.840.113549.2.5'),
    '1.2.840.113549.1.1.5': ('sha1','1.3.14.3.2.26'),
    '1.2.840.113549.1.1.11': ('sha256','2.16.840.1.101.3.4.2.1'),
    '1.2.840.113549.1.1.13': ('sha512','2.16.840.1.101.3.4.2.3'),
}


def _require_stable_der(node):
    # SDK getTBSCertificate/getTBSCertList re-encodes ASN.1. Do not verify raw
    # BER as if that were necessarily the same signed byte sequence.
    cls, method, tag = node.kind
    if tag >= 31 or node.encoded != _tlv((cls << 6) | (method << 5) | tag, node.contents):
        raise CertificateBackendLimit('SDK ASN.1 re-encoding boundary unresolved')
    if method:
        for child in node.children():
            _require_stable_der(child)
    elif cls == 0:
        raw = node.contents
        if ((tag == 1 and len(raw) != 1) or (tag == 5 and raw) or
                (tag == 30 and len(raw) % 2)):
            # DERBoolean keeps byte 0; DERNull discards its input; BMPString
            # consumes floor(length/2) chars. Their re-encoding is not raw BER.
            raise CertificateBackendLimit('SDK primitive re-encoding boundary unresolved')
        if tag == 20:
            try:
                raw.decode('utf-8')  # DERT61String uses default UTF-8 String/bytes
            except UnicodeError:
                raise CertificateBackendLimit('SDK T61 replacement/re-encoding boundary') from None
        if tag == 6:
            from asn1crypto.core import ObjectIdentifier
            try:
                canonical = ObjectIdentifier(ObjectIdentifier.load(node.encoded).dotted).dump()
            except ValueError:
                raise CertificateBackendLimit('SDK OID decoding boundary') from None
            if canonical != node.encoded:
                raise CertificateBackendLimit('SDK OID re-encoding boundary')


def algorithm_identifier(data):
    from asn1crypto.core import ObjectIdentifier
    node = _node(data)
    _require_stable_der(node)
    fields = node.children()
    if node.kind != SEQUENCE or not fields or fields[0].kind != OID:
        raise CertificateBackendLimit('AlgorithmIdentifier parsing boundary')
    # Exactly two members sets parameters; >2 also produces Java null params.
    return (ObjectIdentifier.load(fields[0].encoded).dotted,
            fields[1].encoded if len(fields) == 2 else None)


def rsa_recover_digest_info(signature, modulus, exponent):
    """RSAEngine(false) + PKCS1Encoding(false), observable byte behavior."""
    if modulus <= 0 or exponent <= 0:
        raise CertificateBackendLimit('RSA public key parameter boundary')
    size = (modulus.bit_length()+7)//8
    if len(signature) > size+1 or (len(signature) == size+1 and signature[0] & 128):
        raise CertificateRuleError('rsa_signature_input_too_large')
    # Original uses positive BigInteger.modPow, without an extra input<n test.
    value = pow(int.from_bytes(signature, 'big'), exponent, modulus)
    raw = value.to_bytes((value.bit_length()+7)//8, 'big')
    if len(raw) < size-11:
        raise CertificateRuleError('rsa_signature_block_truncated')
    if not raw or raw[0] not in (1,2):
        raise CertificateRuleError('rsa_signature_block_type')
    zero = raw.find(b'\0',1)
    start = zero+1 if zero >= 0 else len(raw)+1
    if start >= len(raw) or start < 10:
        raise CertificateRuleError('rsa_signature_padding_boundary')
    return raw[start:]


def verify_rsa(signature, signed_bytes, *, modulus, exponent, signature_oid):
    if signature_oid not in _ALGORITHMS:
        raise CertificateBackendLimit('SDK signature algorithm not yet implemented')
    name, digest_oid = _ALGORITHMS[signature_oid]
    recovered = _node(rsa_recover_digest_info(signature,modulus,exponent))
    fields = recovered.children()
    if recovered.kind != SEQUENCE or len(fields) < 2 or fields[1].kind != (0,0,4):
        raise CertificateBackendLimit('SDK DigestInfo parser boundary unresolved')
    if algorithm_identifier(fields[0].encoded) != (digest_oid, b'\x05\0'):
        raise CertificateRuleError('signature_digest_algorithm_mismatch')
    if not hmac.compare_digest(fields[1].contents, hashlib.new(name,signed_bytes).digest()):
        raise CertificateRuleError('signature_digest_mismatch')


def verify_signed_material(data, public_key, *, kind, provider_explicit):
    """X509CertificateObject.verify overloads or X509CRLObject.verify.

    kind is 'certificate' or 'crl'. In explicit-provider certificate validation,
    SDK selects TBS's OID without comparing the outer AlgorithmIdentifier.
    Trust-anchor verification's no-provider overload DOES compare the two.
    CRL verification compares both in either overload. Does not check trust,
    time, policy, name constraints or revocation.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    if kind not in ('certificate','crl'):
        raise ValueError('kind must be certificate or crl')
    outer = _node(data)
    _require_stable_der(outer)
    fields = outer.children()
    if outer.kind != SEQUENCE or len(fields) != 3 or fields[2].kind != (0,0,3):
        raise CertificateBackendLimit('signed material outer ASN.1 boundary')
    tbs = fields[0].children()
    if kind == 'certificate':
        inner_index = 2 if tbs and tbs[0].kind[0] == 2 else 1
    else:
        inner_index = 1 if tbs and tbs[0].kind == (0,0,2) else 0
    if len(tbs) <= inner_index:
        raise CertificateBackendLimit('signed material TBS index boundary')
    inner = algorithm_identifier(tbs[inner_index].encoded)
    outer_alg = algorithm_identifier(fields[1].encoded)
    if (kind == 'crl' or not provider_explicit) and inner != outer_alg:
        raise CertificateRuleError('outer_tbs_signature_algorithm_mismatch')
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CertificateBackendLimit('non-RSA signature path unimplemented')
    bits = fields[2].contents
    if not bits or bits[0] != 0:
        raise CertificateBackendLimit('SDK nonzero signature unused-bits boundary')
    numbers = public_key.public_numbers()
    verify_rsa(bits[1:], fields[0].encoded, modulus=numbers.n, exponent=numbers.e,
               signature_oid=inner[0])
