"""Known certificate-entry bytes and normal fingerprint value operations.

Definite-length X.509/SignedData inputs use wire-order certificates. This
backend does not observe installed files, select a live security provider,
verify certificate/CMS signatures, or emulate Java stream/VM failures.
"""
from dataclasses import dataclass, field
import hashlib

from asn1crypto import parser

from .codeguard_certificate_values import single_der_certificate
from .codeguard_rule import AnalysisLimit
from .codeguard_string_values import UNRESOLVED


def _take(data, expected):
    try:
        cls, method, tag, header, contents, trailer = parser.parse(data)
    except (ValueError, TypeError):
        raise AnalysisLimit('certificate input framing outside value scope') from None
    if (cls, method, tag) != expected or header[1] == 0x80 or trailer:
        raise AnalysisLimit('certificate input requires supported definite-length framing')
    size = len(header) + len(contents)
    return contents, data[size:], data[:size]


@dataclass(frozen=True, repr=False)
class CertificateInputValue:
    der: bytes | None
    consumed: int
    certificate_count: int
    container: str


def read_certificate_value(data):
    """Parse one known normal object; leave bytes after that object untouched.

    SignedData version/digest-set/content precede optional certificates. Every
    certificate is parsed in input order before choosing the first. Following
    CRL/signer fields are not interpreted or used for trust validation.
    Unsupported framing/parsing is a backend boundary, not a Java rejection.
    """
    if type(data) is not bytes:
        raise AnalysisLimit('known certificate input bytes required')
    content, _, encoded = _take(data, (0, 1, 16))
    if content[:1] == b'\x30':
        der = single_der_certificate(encoded)
        return CertificateInputValue(der, len(encoded), 1, 'x509')
    oid, rest, _ = _take(content, (0, 0, 6))
    if oid != b'\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02':
        raise AnalysisLimit('certificate container outside SignedData value scope')
    wrapped, _, _ = _take(rest, (2, 1, 0))
    signed, _, _ = _take(wrapped, (0, 1, 16))
    version, rest, _ = _take(signed, (0, 0, 2))
    if (not version or version[0] & 128 or len(version) > 9
            or not 1 <= int.from_bytes(version, 'big') < 2**64
            or (len(version) > 1 and version[0] == 0 and not version[1] & 128)):
        raise AnalysisLimit('SignedData version outside value scope')
    _, rest, _ = _take(rest, (0, 1, 17))
    _, rest, _ = _take(rest, (0, 1, 16))
    certificates = b''
    if rest[:1] == b'\xa0':
        certificates, _, _ = _take(rest, (2, 1, 0))
    parsed = []
    while certificates:
        _, certificates, certificate = _take(certificates, (0, 1, 16))
        parsed.append(single_der_certificate(certificate))
    return CertificateInputValue(parsed[0] if parsed else None, len(encoded), len(parsed), 'signed_data')


@dataclass(repr=False, eq=False)
class KnownCertificateStream:
    """Python-owned, explicitly supplied complete entry bytes; no host IO."""
    data: bytes
    position: int = field(default=0, init=False)

    def __post_init__(self):
        if type(self.data) is not bytes:
            raise AnalysisLimit('known certificate stream bytes required')


@dataclass(frozen=True, repr=False, eq=False)
class _Certificate:
    der: bytes


@dataclass(repr=False, eq=False)
class _Digest:
    value: object = field(default_factory=hashlib.sha256)


class _Factory:
    pass


class FingerprintValues:
    """Value backend for the package fingerprint's certificate/digest calls."""
    def resolve(self, effect):
        if effect.kind != 'package_java':
            return UNRESOLVED
        name, *args = effect.args
        if name == 'certificateFactory.getInstance' and args == ['X.509']:
            return _Factory()
        if name == 'certificateFactory.generateCertificate' and isinstance(args[0], _Factory):
            stream = args[1]
            if isinstance(stream, KnownCertificateStream):
                parsed = read_certificate_value(stream.data[stream.position:])
                stream.position += parsed.consumed
                return _Certificate(parsed.der) if parsed.der is not None else None
        if name == 'cast.X509Certificate' and (args[0] is None or isinstance(args[0], _Certificate)):
            return args[0]
        if name == 'certificate.getEncoded' and isinstance(args[0], _Certificate):
            return args[0].der
        if name == 'messageDigest.getInstance' and args == ['SHA256']:
            return _Digest()
        if name == 'messageDigest.update' and isinstance(args[0], _Digest) and type(args[1]) is bytes:
            args[0].value.update(args[1])
            return None
        if name == 'messageDigest.digest' and isinstance(args[0], _Digest):
            result = args[0].value.digest()
            args[0].value = hashlib.sha256()
            return result
        return UNRESOLVED


def project_fingerprint_values_steps(generator):
    """Resolve known entry values, forwarding actual IO, null and VM faults."""
    values = FingerprintValues()
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            value = values.resolve(effect)
            if value is UNRESOLVED:
                value = yield effect
        except Exception as fault:
            pending = fault
