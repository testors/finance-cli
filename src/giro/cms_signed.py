"""Bounded, offline yessign CMS SignedData parsing and RSA verification.

Not a generic CMS validator or trust source. Canonical DER is modeled; BER,
Android selector/HashMap order and unknown providers are explicit boundaries.
No keys, identities, signed bytes or signature values are rendered in repr.
"""
from dataclasses import dataclass
import hashlib
import hmac

from .cert_factory import _node, SEQUENCE, SET, INTEGER, OID, CertificateBackendLimit
from .cert_material import _members, _kind, _integer, _explicit, _date, CertificateMaterial, CRLMaterial
from .cert_rules import CertificateRuleError
from .cert_signatures import _require_stable_der, algorithm_identifier, verify_rsa, _ALGORITHMS
from .cms import _tlv

SIGNED_DATA = '1.2.840.113549.1.7.2'
CONTENT_TYPE = '1.2.840.113549.1.9.3'
MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
SIGNING_TIME = '1.2.840.113549.1.9.5'
RSA = '1.2.840.113549.1.1.1'
DIGESTS = {'1.2.840.113549.2.5':'md5', '1.3.14.3.2.26':'sha1',
           '2.16.840.1.101.3.4.2.1':'sha256', '2.16.840.1.101.3.4.2.2':'sha384',
           '2.16.840.1.101.3.4.2.3':'sha512'}
_RSA_BY_DIGEST = {digest:oid for oid,(_,digest) in _ALGORITHMS.items()}


def oid(node):
    from asn1crypto.core import ObjectIdentifier
    return ObjectIdentifier.load(_kind(node,OID).encoded).dotted


def digest_bytes(algorithm, data):
    if algorithm not in DIGESTS:
        raise CertificateBackendLimit('yessign digest provider mapping unresolved')
    return hashlib.new(DIGESTS[algorithm],data).digest()


def content_info(node):
    fields = _members(node,1)
    return oid(fields[0]), _explicit(fields[1]) if len(fields)>1 else None


@dataclass(frozen=True, repr=False)
class Signer:
    version: int
    sid: object
    digest_algorithm: str
    encryption_algorithm: str
    attributes: tuple | None
    signature: bytes

    @classmethod
    def parse(cls,node):
        fields = _members(node,5)
        version = _integer(fields[0])
        sid = fields[1]  # selectors are modeled separately; not guessed here
        if sid.kind == SEQUENCE:
            issuer_serial = _members(sid,2)
            _kind(issuer_serial[0],SEQUENCE)
            _integer(issuer_serial[1])
        elif sid.kind[:2] != (2,0):
            raise CertificateBackendLimit('CMS tagged SignerIdentifier decoding boundary')
        digest = algorithm_identifier(fields[2].encoded)[0]
        index, attrs = 3,None
        if fields[index].kind[0] == 2:
            if fields[index].kind[1] != 1:
                raise CertificateBackendLimit('CMS signed attributes tagging boundary')
            attrs = tuple(fields[index].children())
            index += 1
        if len(fields) <= index+1:
            raise CertificateBackendLimit('CMS SignerInfo field index boundary')
        encryption = algorithm_identifier(fields[index].encoded)[0]
        signature = _kind(fields[index+1],(0,0,4)).contents
        if len(fields)>index+2:
            trailing = fields[index+2]
            if trailing.kind[:2] != (2,1):
                raise CertificateBackendLimit('CMS unsigned attributes tagging boundary')
            trailing.children()  # ASN1Set constructor, no AttributeTable yet
        return cls(version,sid,digest,encryption,attrs,signature)


@dataclass(frozen=True, repr=False)
class SignedData:
    outer_type: str
    version: int
    content_type: str
    content: bytes | None
    certificates: tuple
    crls: tuple
    signer_nodes: tuple | None

    @classmethod
    def parse(cls,data):
        node = _node(data)  # original reads first object; no added EOF test
        _require_stable_der(node)
        outer_type, body = content_info(node)
        if body is None:
            raise CertificateBackendLimit('CMS missing SignedData constructor boundary')
        fields = _members(body,3)
        version = _integer(fields[0])
        _kind(fields[1],SET)  # no added algorithm-set membership gate
        content_type, content = content_info(fields[2])
        if content is not None:
            if content.kind in ((0,0,4),SEQUENCE,SET):
                # DERSequence/DERSet.getObjectBytes omits its outer TLV.
                content = content.contents
            else:
                raise CertificateBackendLimit('CMS getObjectBytes representation boundary')
        certs,crls,signers = (),(),None
        for item in fields[3:]:
            if item.kind[0] == 2:
                if item.kind[1] != 1 or item.kind[2] not in (0,1):
                    raise CertificateBackendLimit('CMS SignedData tagged field boundary')
                if item.kind[2] == 0: certs = tuple(item.children())
                else: crls = tuple(item.children())
            else:
                signers = tuple(_kind(item,SET).children())
        return cls(outer_type,version,content_type,content,certs,crls,signers)

    def store_material(self):
        # Original decodes ALL certs then ALL CRLs, even if only one signer is
        # later used. Do not skip a bad unused certificate/CRL to find a match.
        certs = tuple(CertificateMaterial.from_der(n.encoded) for n in self.certificates)
        crls = tuple(CRLMaterial.from_der(n.encoded) for n in self.crls)
        return certs,crls

    def signers(self):
        if self.signer_nodes is None:
            raise CertificateBackendLimit('CMS null signerInfos runtime boundary')
        # Store HashMap order/dedup is NOT ASN.1 SET order when there are several.
        return tuple(Signer.parse(n) for n in self.signer_nodes)


def attribute_table(attributes):
    if attributes is None: return None
    table = {}
    for node in attributes:
        fields = _members(node,2)
        table[oid(fields[0])] = tuple(_kind(fields[1],SET).children())
    return table  # duplicate OIDs overwrite, no uniqueness rule in original


def single_signer_certificate(signer, certificates):
    """Bounded X509CertSelector + Collection HashSet adapter.

    Only zero/one DISTINCT matching certificate is resolved, so unknown HashSet
    iteration order is never guessed. Different issuer encodings stay unknown
    (not automatically false). Other selector criteria are unset in SignerId.
    """
    from .cert_path import exact_principal_match
    matches = {}
    if signer.sid.kind == SEQUENCE:
        fields = _members(signer.sid,2)
        issuer,serial = fields[0].encoded,_integer(fields[1])
        for certificate in certificates:
            if certificate.serial != serial: continue  # before issuer comparison
            exact_principal_match(issuer,certificate.issuer_der)
            matches.setdefault(certificate.data,certificate)
    elif signer.sid.kind[:2] == (2,0):
        # Android compares setSubjectKeyIdentifier's bytes to the extension's
        # INNER DER bytes, not automatically to its unwrapped SKI payload.
        for certificate in certificates:
            value = certificate.extensions.values.get('2.5.29.14')
            if value is not None and value[1] == signer.sid.contents:
                matches.setdefault(certificate.data,certificate)
    else:
        raise CertificateBackendLimit('CMS SignerId selector representation boundary')
    if len(matches)>1:
        raise CertificateBackendLimit('multiple matching certificates require Android HashSet order')
    return tuple(matches.values())


def _first(values):
    if not values:
        raise CertificateRuleError('cms_attribute_empty_value_set')
    return values[0]  # extra values aren't a new rejection condition


def verify_signer(signed, signer, certificate):
    """SignerInformation.verify(cert, provider), no detached digest argument.

    A CTL caller must FIRST establish certificate equality with an existing
    trust anchor. This subcheck alone does not establish trust or freshness.
    Certificate validity is checked at signingTime ONLY when present, matching
    this method, not at an invented local current time.
    """
    signature_oid = (_RSA_BY_DIGEST.get(signer.digest_algorithm)
                     if signer.encryption_algorithm == RSA else signer.encryption_algorithm)
    if signature_oid not in _ALGORITHMS:
        raise CertificateBackendLimit('CMS signature provider mapping unresolved')
    if signer.digest_algorithm not in DIGESTS:
        raise CertificateBackendLimit('CMS message digest provider mapping unresolved')
    table = attribute_table(signer.attributes)
    if table is not None and SIGNING_TIME in table:
        certificate.check_validity(_date(_first(table[SIGNING_TIME])))
    key = certificate.public_key().public_numbers()
    if table is None:
        if signed.content is None:
            raise CertificateRuleError('cms_null_content_dereference')
        signed_bytes = signed.content
    else:
        if signed.content is None:
            raise CertificateRuleError('cms_content_hash_missing')
        calculated = digest_bytes(signer.digest_algorithm,signed.content)
        if MESSAGE_DIGEST not in table:
            raise CertificateRuleError('cms_content_hash_missing')
        if CONTENT_TYPE not in table:
            raise CertificateRuleError('cms_content_type_missing')
        expected = _kind(_first(table[MESSAGE_DIGEST]),(0,0,4)).contents
        if not hmac.compare_digest(calculated,expected):
            raise CertificateRuleError('cms_content_hash_mismatch')
        if oid(_first(table[CONTENT_TYPE])) != signed.content_type:
            raise CertificateRuleError('cms_content_type_mismatch')
        # This SDK's DERSet preserves insertion order: do NOT canonical-sort.
        signed_bytes = _tlv(0x31,b''.join(n.encoded for n in signer.attributes))
    try:
        verify_rsa(signer.signature,signed_bytes,modulus=key.n,exponent=key.e,signature_oid=signature_oid)
    except CertificateRuleError as error:
        if error.rule == 'signature_digest_mismatch':
            return False
        raise  # malformed RSA/DigestInfo was a SignatureException, not false
    return True
