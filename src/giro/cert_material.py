"""Bounded offline DER material adapter for observed yessign subchecks.

Not a certificate factory, trust source, Android selector or path validator.
Unmodeled representations raise BackendLimit, not an invented SDK rejection.
Objects and errors never render certificate identities, keys or serials.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .cert_factory import _node, SEQUENCE, INTEGER, OID, CertificateBackendLimit
from .cert_names import SDKName
from .cert_rules import CertificateRuleError, java_int
from .cert_signatures import _require_stable_der, algorithm_identifier


def _kind(node, expected):
    if node.kind != expected:
        raise CertificateBackendLimit('SDK material field decoding boundary')
    return node


def _members(node, minimum=0):
    values = _kind(node, SEQUENCE).children()
    if len(values) < minimum:
        raise CertificateBackendLimit('SDK material sequence index boundary')
    return values


def _integer(node, *, positive=False):
    raw = _kind(node, INTEGER).contents
    if not raw:
        raise CertificateBackendLimit('SDK empty integer boundary')
    return int.from_bytes(raw, 'big', signed=not positive)


def _explicit(node):
    values = node.children()
    if node.kind[:2] != (2,1) or len(values) != 1:
        raise CertificateBackendLimit('SDK explicit tagging boundary')
    return values[0]


def _boolean(node):
    raw = _kind(node, (0,0,1)).contents
    if not raw:
        raise CertificateBackendLimit('SDK empty boolean boundary')
    return raw[0] != 0


def _date(node):
    # Canonical UTC/GeneralizedTime only. Java SimpleDateFormat accepts other
    # forms (and lenient calendar values); do not turn those into app failures.
    if node is None:
        return None
    raw = node.contents
    tag = node.kind
    if tag == (0,0,23) and len(raw) == 13 and raw[-1:] == b'Z' and raw[:-1].isdigit():
        year = int(raw[:2])
        text = str(1900+year if year >= 50 else 2000+year).encode()+raw[2:]
    elif tag == (0,0,24) and len(raw) == 15 and raw[-1:] == b'Z' and raw[:-1].isdigit():
        text = raw
    else:
        raise CertificateBackendLimit('SDK time representation not modeled')
    try:
        return datetime.strptime(text.decode('ascii'), '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise CertificateBackendLimit('SDK lenient time parsing not modeled') from None


@dataclass(frozen=True, repr=False)
class Extensions:
    values: dict = field(repr=False)

    @classmethod
    def parse(cls, node):
        from asn1crypto.core import ObjectIdentifier
        values = {}
        if node is not None:
            for item in _members(node):
                fields = _members(item,2)
                oid = ObjectIdentifier.load(_kind(fields[0],OID).encoded).dotted
                if len(fields) == 3:
                    critical, value = _boolean(fields[1]), fields[2]
                else:
                    critical, value = False, fields[1]
                # SDK Hashtable.put: repeated OIDs keep the last value.
                values[oid] = (critical, _kind(value,(0,0,4)).contents)
        return cls(values)

    def get(self, oid):
        entry = self.values.get(oid)
        if entry is None:
            return None
        node = _node(entry[1])  # first ASN.1 object; not a strict EOF check
        _require_stable_der(node)
        return node

    def key_usage(self, *, boolean_array=False):
        node = self.get('2.5.29.15')
        if node is None:
            return None
        raw = _kind(node,(0,0,3)).contents
        if not raw or raw[0] > 7:
            raise CertificateBackendLimit('SDK key usage bit-string boundary')
        if boolean_array:
            # X509CertificateObject.getKeyUsage visits only dataBits-padBits.
            length = (len(raw)-1)*8-raw[0]
            if length < 0:
                raise CertificateBackendLimit('SDK negative key usage length boundary')
            return sum(1 << (i//8*8+7-i%8) for i in range(length)
                       if raw[1+i//8] & (128 >> (i%8)))
        # DERBitString.longValue is little-endian; do not mask unused bits.
        return int.from_bytes(raw[1:9], 'little')

    def basic_constraints(self):
        node = self.get('2.5.29.19')
        if node is None:
            return None, None
        fields = _members(node)
        return ((_boolean(fields[0]) if fields else False),
                _integer(fields[1]) if len(fields) > 1 else None)


def _outer(data):
    outer = _node(data)
    _require_stable_der(outer)
    fields = _members(outer,3)
    if len(fields) != 3 or fields[2].kind != (0,0,3):
        raise CertificateBackendLimit('SDK signed material outer boundary')
    return outer, _members(fields[0])


@dataclass(frozen=True, repr=False)
class CertificateMaterial:
    data: bytes
    serial: int
    issuer_der: bytes
    subject_der: bytes
    validity: tuple
    spki: bytes
    extensions: Extensions
    version: int

    @classmethod
    def from_der(cls, data):
        outer, fields = _outer(data)
        version, offset = 1, 0
        if fields and fields[0].kind[0] == 2:
            version, offset = java_int(_integer(_explicit(fields[0]))+1), 1
        if len(fields) < offset+6:
            raise CertificateBackendLimit('SDK TBS certificate index boundary')
        serial = _integer(fields[offset])
        validity = _members(fields[offset+3],2)
        ext = None
        # Original scans trailing tagged fields backwards: earliest [3] wins.
        for item in reversed(fields[offset+6:]):
            if item.kind[0] != 2:
                raise CertificateBackendLimit('SDK TBS certificate trailing cast boundary')
            if item.kind[2] == 3:
                ext = _explicit(item)
        return cls(outer.encoded, serial, fields[offset+2].encoded,
                   fields[offset+4].encoded, tuple(validity[:2]),
                   fields[offset+5].encoded, Extensions.parse(ext), version)

    @property
    def issuer(self):
        return SDKName.from_der(self.issuer_der)

    @property
    def subject(self):
        return SDKName.from_der(self.subject_der)

    def check_validity(self, at):
        if at < _date(self.validity[0]):
            raise CertificateRuleError('certificate_not_yet_valid')
        if at > _date(self.validity[1]):
            raise CertificateRuleError('certificate_expired')

    def public_key(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        fields = _members(_node(self.spki),2)
        oid, _ = algorithm_identifier(fields[0].encoded)
        if oid not in ('1.2.840.113549.1.1.1', '2.5.8.1.1'):
            raise CertificateBackendLimit('non-RSA SDK public key not implemented')
        raw = _kind(fields[1],(0,0,3)).contents
        if not raw or raw[0] != 0:
            raise CertificateBackendLimit('SDK public key unused-bits boundary')
        numbers = _members(_node(raw[1:]),2)
        # RSAPublicKeyStructure gets positive n/e, unlike serial getValue().
        try:
            return rsa.RSAPublicNumbers(_integer(numbers[1],positive=True),
                                        _integer(numbers[0],positive=True)).public_key()
        except ValueError:
            raise CertificateBackendLimit('local RSA key construction boundary') from None


@dataclass(frozen=True, repr=False)
class CRLMaterial:
    data: bytes
    issuer_der: bytes
    updates: tuple
    entries: tuple
    extensions: Extensions

    @classmethod
    def from_der(cls, data):
        outer, fields = _outer(data)
        start = 1 if fields and fields[0].kind == INTEGER else 0
        if len(fields) < start+3:
            raise CertificateBackendLimit('SDK TBS CRL index boundary')
        current, next_update, offset = fields[start+2], None, start+3
        if offset < len(fields) and fields[offset].kind in ((0,0,23),(0,0,24)):
            next_update, offset = fields[offset], offset+1
        entries = []
        if offset < len(fields) and fields[offset].kind[0] != 2:
            for entry in _members(fields[offset]):
                parts = _members(entry,2)
                entries.append((_integer(parts[0]),parts[1]))
                if len(parts) == 3:
                    Extensions.parse(parts[2])  # constructor also visits entry extensions
            offset += 1
        ext = _explicit(fields[offset]) if offset < len(fields) and fields[offset].kind[0] == 2 else None
        return cls(outer.encoded, fields[start+1].encoded, (current,next_update),
                   tuple(entries), Extensions.parse(ext))

    @property
    def issuer(self):
        return SDKName.from_der(self.issuer_der)

    def update_dates(self):
        return tuple(_date(node) for node in self.updates)

    def revocation_date(self, serial):
        for candidate, date in self.entries:
            if candidate == serial:  # getRevokedCertificate returns FIRST match
                return _date(date)
        return None
