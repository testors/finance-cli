"""Offline certificate selection and sub-rule inspection; NEVER a trust gate.

Implements the factory's first-object/first-certificate choice, not every ASN.1
constructor in the SDK. Backend gaps are analysis limits, not server failures.
No signatures, CMS signerInfos, path, policy chain or revocation are validated.
"""
from dataclasses import dataclass, field

from .cert_input import certificate_payload, CertificateInputError
from .errors import GiroError


class CertificateBackendLimit(GiroError):
    """The local ASN.1/X.509 backend cannot establish app-equivalent parsing."""


@dataclass(frozen=True)
class _Node:
    kind: tuple
    encoded: bytes = field(repr=False)
    contents: bytes = field(repr=False)

    def children(self):
        items, rest = [], self.contents
        while rest:
            node = _node(rest)
            items.append(node)
            rest = rest[len(node.encoded):]
        return items


def _node(data):
    try:
        from asn1crypto import parser
        cls, method, tag, header, contents, trailer = parser.parse(data)
    except ImportError:
        raise CertificateBackendLimit('certificate selection requires asn1crypto') from None
    except (ValueError, TypeError, RecursionError):
        # Do not equate this backend's malformed-BER policy to the SDK's parser.
        raise CertificateBackendLimit('ASN.1 backend parsing boundary unresolved') from None
    return _Node((cls, method, tag), header+contents+trailer, contents)


def _require(condition, rule):
    if not condition:
        raise CertificateInputError(rule)


SEQUENCE = (0, 1, 16)
SET = (0, 1, 17)
INTEGER = (0, 0, 2)
OID = (0, 0, 6)
BIT_STRING = (0, 0, 3)


@dataclass(frozen=True)
class SelectedCertificate:
    data: bytes = field(repr=False)
    container: str
    trailing_bytes: int
    certificate_validation_performed: bool = field(default=False, init=False)


def select_certificate(data: bytes):
    """First ASN.1 object, then SignedData.certificates[0] if applicable.

    Does not choose a newer/non-CA certificate, sort the set, require a CMS
    signature or reject trailing data. Full TBSCertificate/provider parsing is
    outside this selector. Exact raw selected bytes remain private in repr.
    """
    payload = certificate_payload(data)
    outer = _node(payload)
    _require(outer.kind == SEQUENCE, 'certificate_factory_requires_sequence')
    members = outer.children()
    signed = False
    if members and members[0].kind == OID:
        try:
            from asn1crypto.core import ObjectIdentifier
            signed = ObjectIdentifier.load(members[0].encoded).dotted == '1.2.840.113549.1.7.2'
        except (ValueError, TypeError):
            raise CertificateBackendLimit('ASN.1 OID decoding boundary unresolved') from None
    # Direct 30 80 input has a DIFFERENT entrypoint from PEM b(InputStream).
    if data[:2] == b'\x30\x80':
        _require(signed, 'direct_indefinite_input_requires_signed_data')
    selected = outer
    if signed and len(members) > 1:
        tagged = members[1]
        _require(tagged.kind[:2] == (2, 1), 'signed_data_content_must_be_tagged')
        wrapped = tagged.children()
        _require(len(wrapped) == 1 and wrapped[0].kind == SEQUENCE, 'signed_data_requires_explicit_sequence')
        fields = wrapped[0].children()
        _require(len(fields) >= 3 and tuple(f.kind for f in fields[:3]) ==
                 (INTEGER, SET, SEQUENCE), 'signed_data_header_types')
        certificates = None
        for item in fields[3:]:
            if item.kind[0] == 2:
                if item.kind[2] == 0:
                    _require(item.kind[1] == 1, 'signed_data_certificates_must_be_constructed')
                    certificates = item.children()  # later [0] replaces earlier [0]
                elif item.kind[2] != 1:
                    raise CertificateInputError('signed_data_unknown_tag')
            else:
                _require(item.kind == SET, 'signed_data_signer_infos_type')
        _require(bool(certificates), 'signed_data_certificates_missing_or_empty')
        selected = certificates[0]
    _require(selected.kind == SEQUENCE, 'selected_certificate_requires_sequence')
    fields = selected.children()
    _require(len(fields) == 3 and tuple(f.kind for f in fields) ==
             (SEQUENCE, SEQUENCE, BIT_STRING), 'x509_certificate_outer_structure')
    return SelectedCertificate(selected.encoded, 'signed_data' if signed else 'certificate',
                               len(payload)-len(outer.encoded))


def inspect_recipient(data: bytes):
    """Report independent local KU/EKU observations, NOT validation success.

    These subchecks occur later in the original full path. Reporting them here
    neither predicts the first app error nor bypasses prior chain/CRL gates.
    No certificate identity, serial, subject, keys or full bytes are printed.
    """
    from .cert_rules import check_extended_key_usage, check_recipient_key_usage, CertificateRuleError
    selection = select_certificate(data)
    try:
        from cryptography import x509
        from cryptography.exceptions import UnsupportedAlgorithm
    except ImportError:
        raise CertificateBackendLimit('certificate inspection requires cryptography') from None
    try:
        cert = x509.load_der_x509_certificate(selection.data)
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            mask = sum(weight for name, weight in (
                ('digital_signature', 128), ('content_commitment', 64), ('key_encipherment', 32),
                ('data_encipherment', 16), ('key_agreement', 8), ('key_cert_sign', 4), ('crl_sign', 2))
                if getattr(ku, name))
        except x509.ExtensionNotFound:
            mask = None
        try:
            eku = [oid.dotted_string for oid in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
        except x509.ExtensionNotFound:
            eku = None
    except (ValueError, TypeError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType, UnsupportedAlgorithm):
        raise CertificateBackendLimit('X.509 backend parsing boundary unresolved') from None
    checks = {}
    for name, fn, args in (('recipient_key_usage', check_recipient_key_usage, (mask,)),
                            ('extended_key_usage', check_extended_key_usage, (mask, eku))):
        try:
            fn(*args)
            checks[name] = {'rule_completed': True, 'rule_error': None}
        except CertificateRuleError as exc:
            checks[name] = {'rule_completed': False, 'rule_error': exc.rule}
    return {'offline': True, 'selection': selection.container,
            'trailing_bytes_ignored': selection.trailing_bytes, 'subchecks': checks,
            'certificate_validation_performed': False, 'live_login_ready': False,
            'remaining': ['trust_path_and_signatures', 'chain_policy_and_name_constraints',
                          'crl_idp_delta_and_ctl', 'android_provider_boundary_comparison']}
