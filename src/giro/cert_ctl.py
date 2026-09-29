"""Offline CTL membership/signature rules and original LDAP candidate loop.

No network, SDK, trust installation, private cache access or implicit clock.
Original filesystem effects are DESCRIBED only; no executor is provided.
"""
from dataclasses import dataclass, field
import hmac

from .cert_factory import _node, SEQUENCE, INTEGER, CertificateBackendLimit
from .cert_material import _members, _integer, _kind, _explicit, _date, Extensions
from .cert_rules import CertificateRuleError, java_int
from .cert_signatures import _require_stable_der, algorithm_identifier
from .cert_names import sdk_lower
from .cert_acquisition import AcquisitionEffect, LDAPValues, anchor_steps
from .cms import _tlv
from .cms_signed import SignedData, SIGNED_DATA, oid, digest_bytes, verify_signer
from .ldap_codec import parse_uri

CTL = '1.3.6.1.4.1.311.10.1'
CIVIL_USAGE = '1.2.410.200004.8.1.1.1'
# yessignGEnv default; using this value does not initiate a connection.
DEFAULT_CTL_DISTRIBUTION_POINT = 'ldap://ds.yessign.or.kr:389/cn=KISA-CTL,ou=ROOTCA,o=KISA,c=KR?certificateTrustList'


class ObservedCTLException(Exception):
    """Observed Java Exception, never a Python/backend failure substitute."""
    def __init__(self): super().__init__('observed_ctl_java_exception')


class ObservedCTLIOException(ObservedCTLException):
    pass


class ObservedCTLStoreException(ObservedCTLException):
    pass


@dataclass(frozen=True, repr=False)
class TrustList:
    version: int
    usage: tuple
    sequence_number: int
    this_update: object
    next_update: object
    digest_algorithm: str
    entries: tuple

    @classmethod
    def from_content(cls,content):
        # CertificateTrustList.getInstance wraps SEQUENCE around content bytes;
        # a caller supplying an already wrapped SEQUENCE is NOT auto-corrected.
        node = _node(_tlv(48,content))
        _require_stable_der(node)
        parts = _members(node)
        index,version = 0,0
        if parts and parts[0].kind == INTEGER:
            version,index = _integer(parts[0]),1
        if len(parts)<=index:
            raise CertificateBackendLimit('CTL subjectUsage index boundary')
        usage = tuple(_kind(parts[index],SEQUENCE).children())
        index += 1
        if len(parts)>index and parts[index].kind == (0,0,4): index += 1
        if len(parts)<index+5:
            raise CertificateBackendLimit('CTL mandatory fields index boundary')
        number = _integer(parts[index])
        # Time.getInstance chooses type here; actual date parsing is deferred.
        for date in parts[index+1:index+3]:
            if date.kind not in ((0,0,23),(0,0,24)):
                raise CertificateBackendLimit('CTL Time type boundary')
        algorithm = algorithm_identifier(parts[index+3].encoded)[0]
        entries = tuple(_kind(parts[index+4],SEQUENCE).children())
        for extension in parts[index+5:]:
            Extensions.parse(_explicit(extension))  # all decoded, last stored
        return cls(java_int(java_int(version)+1),usage,number,parts[index+1],
                   parts[index+2],algorithm,entries)

    def contains(self, certificate):
        calculated = digest_bytes(self.digest_algorithm,certificate.data)
        for entry in self.entries:
            fields = _members(entry,1)
            expected = _kind(fields[0],(0,0,4)).contents
            if len(fields)>1: _kind(fields[1],SEQUENCE)
            if hmac.compare_digest(calculated,expected): return True
        return False

    def check(self, certificate, *, signer_version, at):
        if java_int(signer_version) != 1: raise CertificateRuleError('ctl_signer_version')
        if self.version != 1: raise CertificateRuleError('ctl_version')
        if at < _date(self.this_update): raise CertificateRuleError('ctl_not_yet_valid')
        if at > _date(self.next_update): raise CertificateRuleError('ctl_expired')
        if not any(oid(item)==CIVIL_USAGE for item in self.usage):
            raise CertificateRuleError('ctl_civil_usage_missing')
        if not self.contains(certificate): raise CertificateRuleError('ctl_certificate_not_listed')


@dataclass(frozen=True, repr=False)
class CTLTrust:
    certificate: object
    candidate_index: int
    certificate_validation_performed: bool = field(default=False,init=False)


def _save_kisa_steps(target, *, locale_language, certificate_extension):
    if 'o=kisa' not in sdk_lower(target.subject.render(locale_language=locale_language),locale_language):
        return
    ski = target.extensions.get('2.5.29.14')
    if ski is None: raise CertificateRuleError('ctl_trust_cache_ski_missing')
    key = _kind(ski,(0,0,4)).contents.hex()+'_'+str(target.serial)+'.'+certificate_extension
    try:
        yield AcquisitionEffect('ctl_create_trust_directory')
    except ObservedCTLException:
        pass  # original ignores createDir result and Exception, not write errors
    stream = None
    try:
        stream = yield AcquisitionEffect('ctl_open_trust_cache',cache_key=key)
        yield AcquisitionEffect('ctl_write_trust_cache',target=stream,data=target.data)
    except ObservedCTLException:
        raise CertificateRuleError('ctl_trust_cache_write_failed') from None
    finally:
        if stream is not None:
            try:
                yield AcquisitionEffect('ctl_close_trust_cache',target=stream)
            except ObservedCTLIOException:
                pass  # only IOException from close is swallowed


def ctl_trust_steps(target, anchors, *, distribution_point, at, locale_language,
                    certificate_extension='der', parse=SignedData.parse):
    """findCTLTrustAnchor, from explicit LDAP/selector/order observations.

    A successful return is the CTL branch only, NOT full recipient validation.
    Existing anchors are supplied explicitly; a self-signature adds no trust.
    """
    if at.tzinfo is None: raise ValueError('explicit timezone required')
    location = parse_uri(distribution_point)
    if location is None: raise CertificateRuleError('ctl_distribution_point_invalid')
    reply = yield AcquisitionEffect('ldap_ctl',location=location)
    if not isinstance(reply,LDAPValues) or type(reply.code) is not int or not -2**31<=reply.code<2**31:
        raise CertificateBackendLimit('explicit CTL LDAP wrapper observation required')
    if reply.code == 0: raise CertificateRuleError('ctl_ldap_failed')
    if type(reply.vector_error) is not bool:
        raise CertificateBackendLimit('explicit CTL Vector decoding observation required')
    if reply.vector_error: raise CertificateRuleError('ctl_vector_failed')
    if reply.values is not None and not isinstance(reply.values,(list,tuple)):
        raise CertificateBackendLimit('CTL LDAP Vector shape unresolved')
    if not reply.values: raise CertificateRuleError('ctl_ldap_empty')
    last_error = None
    for index,data in enumerate(reply.values):
        if not isinstance(data,bytes):
            # Unlike issuer acquisition, only IOException is caught here.
            raise CertificateRuleError('ctl_ldap_value_cast_or_null')
        try: signed = parse(data)
        except ObservedCTLIOException:
            last_error = 'ctl_signed_data_parse_failed'
            continue
        if signed.outer_type != SIGNED_DATA:
            last_error = 'ctl_signed_data_type'
            continue
        if java_int(signed.version) != 1:
            last_error = 'ctl_signed_data_version'
            continue
        if signed.content_type != CTL:
            last_error = 'ctl_content_type'
            continue
        try: certs,crls = signed.store_material()
        except ObservedCTLException:
            last_error = 'ctl_store_material_failed'
            continue
        signers = signed.signers()
        if not signers: continue  # retains the preceding candidate's last error
        if len(signers)==1:
            signer = signers[0]
        else:
            # First HashMap.values iterator member AFTER SID dedup, not SET[0].
            selected = yield AcquisitionEffect('ctl_first_signer_index',target=signers,index=index)
            if type(selected) is not int or not 0<=selected<len(signers):
                raise CertificateBackendLimit('actual SignerInformationStore first member required')
            signer = signers[selected]
        try:
            matches = yield AcquisitionEffect('ctl_signer_certificates',target=signer,candidate=(certs,crls),index=index)
        except ObservedCTLStoreException:
            last_error = 'ctl_signer_store_failed'
            continue
        if not isinstance(matches,(tuple,list)):
            raise CertificateBackendLimit('ordered Android CTL signer selector result required')
        if not matches: raise CertificateRuleError('ctl_signer_iterator_empty')
        cert = matches[0]  # no fallback to another matching certificate
        for anchor_index,anchor in enumerate(anchors):
            if anchor is None: raise CertificateRuleError('ctl_anchor_null_trusted_cert')
            if anchor.data != cert.data:
                if anchor_index == len(anchors)-1: last_error = 'ctl_no_trusted_signer'
                continue
            try:
                if not verify_signer(signed,signer,cert):
                    raise CertificateRuleError('ctl_signature_invalid')
            except (CertificateRuleError,ObservedCTLException) as error:
                detail = error.rule if isinstance(error,CertificateRuleError) else 'observed_exception'
                raise CertificateRuleError('ctl_signature_error:'+detail) from None
            if signed.content is None:
                raise CertificateRuleError('ctl_null_content_dereference')
            trust_list = TrustList.from_content(signed.content)
            trust_list.check(target,signer_version=signer.version,at=at)
            yield from _save_kisa_steps(target,locale_language=locale_language,
                                       certificate_extension=certificate_extension)
            return CTLTrust(target,index)
    raise CertificateRuleError(last_error or 'ctl_no_valid_list')


@dataclass(frozen=True, repr=False)
class AnchorSelection:
    path: tuple
    anchor: object
    via_ctl: bool
    certificate_validation_performed: bool = field(default=False,init=False)


def select_path_anchor_steps(path, anchors, *, at, locale_language, distribution_point):
    """PKIX entry anchor/CTL selection only; no trust store installation.

    After CTL success original removes the old top from the path. A matching
    anchor's validity/signature exception must NOT be converted to CTL fallback.
    Remaining path checks/CRLs and recipient installation are still mandatory.
    """
    if not path: raise CertificateRuleError('certificate_path_empty')
    anchor = yield from anchor_steps(path[-1],anchors,at=at)
    if anchor is not None: return AnchorSelection(tuple(path),anchor,False)
    verified = yield from ctl_trust_steps(path[-1],anchors,at=at,locale_language=locale_language,
                                         distribution_point=distribution_point)
    present = yield AcquisitionEffect('ctl_global_trust_contains',target=verified.certificate)
    if type(present) is not bool:
        raise CertificateBackendLimit('actual global TrustAnchor set observation required')
    if not present:
        yield AcquisitionEffect('ctl_global_trust_add',target=verified.certificate)
    # Only DESCRIBES the global set write. No real trust store is changed.
    return AnchorSelection(tuple(path[:-1]),verified.certificate,True)


def inspect_ctl_candidate(data, target_data, anchor_data, *, at, locale_language):
    """Single PUBLIC local CTL candidate, with no LDAP or trust-write simulation.

    Diagnostic subchecks only. Even success cannot install an anchor or waive
    CRLs/path validation. Multiple signers/cert matches are not auto-selected.
    """
    from .cert_factory import select_certificate
    from .cert_material import CertificateMaterial
    from .cert_input import CertificateInputError
    from .cms_signed import single_signer_certificate
    if at.tzinfo is None: raise ValueError('explicit timezone required')
    result = dict(offline=True,network_attempted=False,ctl_rules_completed=False,
        certificate_validation_performed=False,trust_installed=False,live_login_ready=False)
    try:
        target = CertificateMaterial.from_der(select_certificate(target_data).data)
        anchors = tuple(CertificateMaterial.from_der(select_certificate(raw).data) for raw in anchor_data)
        signed = SignedData.parse(data)
        if signed.outer_type != SIGNED_DATA: raise CertificateRuleError('ctl_signed_data_type')
        if java_int(signed.version) != 1: raise CertificateRuleError('ctl_signed_data_version')
        if signed.content_type != CTL: raise CertificateRuleError('ctl_content_type')
        certs,_ = signed.store_material()
        signers = signed.signers()
        if not signers: raise CertificateRuleError('ctl_no_valid_list')
        if len(signers)!=1:
            raise CertificateBackendLimit('multiple signers require Android SID HashMap order/dedup')
        signer = signers[0]
        matches = single_signer_certificate(signer,certs)
        if not matches: raise CertificateRuleError('ctl_signer_iterator_empty')
        cert = matches[0]
        if not any(anchor.data==cert.data for anchor in anchors):
            raise CertificateRuleError('ctl_no_trusted_signer')
        try:
            if not verify_signer(signed,signer,cert): raise CertificateRuleError('ctl_signature_invalid')
        except CertificateRuleError as error:
            raise CertificateRuleError('ctl_signature_error:'+error.rule) from None
        if signed.content is None: raise CertificateRuleError('ctl_null_content_dereference')
        TrustList.from_content(signed.content).check(target,signer_version=signer.version,at=at)
        needs_write = 'o=kisa' in sdk_lower(target.subject.render(locale_language=locale_language),locale_language)
        return {**result,'ctl_rules_completed':True,'analysis_status':'single_ctl_rules_completed',
            'trust_cache_write_required':needs_write,
            'remaining':['actual_ldap_and_trust_state','remaining_path_and_crls','recipient_installation']}
    except CertificateRuleError as error:
        return {**result,'analysis_status':'ctl_rule_failed','rule_error':error.rule}
    except CertificateInputError:
        return {**result,'analysis_status':'certificate_input_failed'}
    except (CertificateBackendLimit,ImportError) as error:
        return {**result,'analysis_status':'unmodeled',
            'message':str(error) if isinstance(error,CertificateBackendLimit) else 'optional certificate backend unavailable'}
