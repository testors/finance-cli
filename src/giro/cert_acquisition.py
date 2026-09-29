"""Static issuer/CRL acquisition and builder control flow as pure generators.

Each external operation is an explicit Effect. This module never executes IO,
reads app cache, writes trust, substitutes empty data for missing observations,
or interprets acquisition alone as recipient validation. Store replies must
already have Android selector/HashSet ordering; raw LDAP replies use ldap_codec.
"""
from dataclasses import dataclass, replace, field

from .cert_factory import CertificateBackendLimit, select_certificate, OID
from .cert_input import CertificateInputError
from .cert_material import CertificateMaterial, CRLMaterial, _members, _kind, _explicit
from .cert_constraints import general_name
from .cert_crl import (AuthorityKeyIdentifier, check_issuer_candidate,
                       check_crl_candidate, select_crl_from_candidates)
from .cert_rules import CertificateRuleError
from .cert_signatures import verify_signed_material
from .ldap_codec import parse_uri


@dataclass(frozen=True, repr=False)
class AcquisitionEffect:
    kind: str
    target: object = None
    candidate: object = None
    index: int | None = None
    cache_key: str | None = None
    location: object = None
    data: bytes | None = None


@dataclass(frozen=True)
class ObservedReadFailure:
    """Actual original cache read/parse Exception, not an assumed cache miss."""


@dataclass(frozen=True)
class ObservedStoreFailure:
    """Actual CertStoreException; the issuer loop continues to the next store."""


class ObservedMaterialParseFailure(ValueError):
    """Adapter established the original material parser's exception."""


@dataclass(frozen=True, repr=False)
class LDAPValues:
    code: int
    values: tuple | None
    vector_error: bool = False


@dataclass(frozen=True, repr=False)
class AcquiredMaterial:
    material: object
    source: str
    cache_io_warning: bool = False


@dataclass(frozen=True, repr=False)
class BuiltPath:
    path: tuple
    anchor: object
    certificate_validation_performed: bool = field(default=False,init=False)


def _ca_key(target):
    aki = AuthorityKeyIdentifier.from_extensions(target.extensions)
    if aki is None:
        raise CertificateRuleError('issuer_acquisition_aki_missing')
    key = 'null' if aki.key_id is None else aki.key_id.hex()
    if aki.serial is not None: key += '_'+str(aki.serial)
    return key+'.der'


def _oid(node):
    from asn1crypto.core import ObjectIdentifier
    return ObjectIdentifier.load(_kind(node,OID).encoded).dotted


def crl_location(target):
    """First URI of first usable fullName; never search past a bad first URI."""
    extension = target.extensions.get('2.5.29.31')
    if extension is None: return None
    for point in _members(extension):
        distribution = None
        for field in _members(point):
            if field.kind[0] != 2:
                raise CertificateBackendLimit('DistributionPoint tagged field boundary')
            if field.kind[2] == 0:
                distribution = _explicit(field)
                if distribution.kind[:2] != (2,1):
                    raise CertificateBackendLimit('DistributionPointName representation boundary')
                if distribution.kind[2] == 0:
                    # GeneralNames constructor parses every name before getNames.
                    names = tuple(general_name(n) for n in distribution.children())
            elif field.kind[2] == 1:
                if field.kind[1] or not field.contents:
                    raise CertificateBackendLimit('DistributionPoint reasons boundary')
            elif field.kind[2] == 2:
                if not field.kind[1]:
                    raise CertificateBackendLimit('DistributionPoint CRL issuer boundary')
                tuple(general_name(n) for n in field.children())
        if distribution is None:
            raise CertificateRuleError('distribution_point_null_dereference')
        if distribution.kind[2] == 0:
            for tag,value in names:
                if tag == 6:
                    return parse_uri(value)
    return None


def issuer_location(target, *, locale_language):
    extension = target.extensions.get('1.3.6.1.5.5.7.1.1')
    selected = None
    if extension is not None:
        descriptions = _members(extension)
        # isAccess reads OIDs only; getAccess then visits GeneralNames too.
        found = any(_oid(_members(item,1)[0]) == '1.3.6.1.5.5.7.48.2' for item in descriptions)
        if found:
            for item in descriptions:
                parts = _members(item,2)
                oid = _oid(parts[0])
                tag,value = general_name(parts[1])
                if oid == '1.3.6.1.5.5.7.48.2':
                    # Source casts DERString; it doesn't insist on URI tag 6.
                    if tag not in (1,2,6):
                        raise CertificateRuleError('aia_location_string_cast')
                    selected = parse_uri(value)
                    if selected is None:
                        raise CertificateRuleError('aia_ca_issuers_parse_failed')
                    break
    if selected is None:
        selected = crl_location(target)
        if selected is None:
            raise CertificateRuleError('crl_distribution_point_parse_failed')
    return replace(selected,dn=target.issuer.render(locale_language=locale_language),attribute='cacertificate')


def parse_certificate(data):
    try:
        return CertificateMaterial.from_der(select_certificate(data).data)
    except CertificateInputError:
        raise ObservedMaterialParseFailure() from None


def parse_crl(data):
    # yessignX509CRLObject has a separate streaming/PEM parser. Only canonical
    # DER currently shares this adapter; unsupported input is NOT a bad CRL.
    if not data or data[:1] != b'\x30':
        raise CertificateBackendLimit('streaming CRL input/PEM boundary')
    return CRLMaterial.from_der(data)


def _cache_candidate(observation, parse):
    if isinstance(observation,ObservedReadFailure): return None
    if not isinstance(observation,bytes):
        raise CertificateBackendLimit('explicit cache read observation required')
    try: return parse(observation)
    except ObservedMaterialParseFailure: return None


def _ldap_candidate(reply, parse, kind):
    if not isinstance(reply,LDAPValues):
        raise CertificateBackendLimit('explicit LDAP wrapper/vector observation required')
    if type(reply.code) is not int or not -2147483648 <= reply.code <= 2147483647:
        raise CertificateBackendLimit('observed Java LDAP wrapper code required')
    if reply.code == 0:
        raise CertificateRuleError(kind+'_ldap_failed')
    if type(reply.vector_error) is not bool:
        raise CertificateBackendLimit('explicit LDAP vector decode outcome required')
    if reply.vector_error:
        raise CertificateRuleError(kind+'_ldap_vector_failed')
    if reply.values is not None and not isinstance(reply.values,(tuple,list)):
        raise CertificateBackendLimit('decoded LDAP Vector observation required')
    if not reply.values:
        raise CertificateRuleError(kind+'_ldap_empty')
    for data in reply.values:
        if not isinstance(data,bytes):
            # Original byte[] cast/null stream construction fails in this loop.
            continue
        try: candidate = parse(data)
        except ObservedMaterialParseFailure: continue
        if candidate is None:
            raise CertificateRuleError(kind+'_ldap_null_material')
        return candidate  # FIRST parsed value, even if later validation fails
    raise CertificateRuleError(kind+'_ldap_no_parsable_material')


def _save_effect(kind, key, material):
    # Includes createDir/open/encode/write/close, represented by observed final
    # outcome. No path is interpreted or written here. Encoding failure is
    # distinct from IOException, which the original ignores.
    outcome = yield AcquisitionEffect('write_'+kind+'_cache',cache_key=key,data=material.data)
    if outcome == 'encoding_error':
        raise CertificateRuleError(kind+'_cache_encoding_failed')
    if outcome not in ('written','io_error'):
        raise CertificateBackendLimit('explicit cache write outcome required')
    return outcome == 'io_error'


def issuer_steps(target, *, store_count, at, locale_language, parse=parse_certificate):
    """Original issuer search, assuming provider available; no generic PKIX."""
    if type(store_count) is not int or store_count < 0:
        raise CertificateBackendLimit('actual store count required')
    for index in range(store_count):
        candidates = yield AcquisitionEffect('issuer_store',target=target,index=index)
        if isinstance(candidates,ObservedStoreFailure): continue
        if not isinstance(candidates,(tuple,list)):
            raise CertificateBackendLimit('ordered Android issuer-store selection required')
        for candidate in candidates:
            if candidate is None: continue
            try: check_issuer_candidate(target,candidate,at=at,locale_language=locale_language)
            except CertificateRuleError: continue
            return AcquiredMaterial(candidate,'store')
    key = _ca_key(target)
    observation = yield AcquisitionEffect('read_certificate_cache',cache_key=key)
    candidate = _cache_candidate(observation,parse)
    if candidate is not None:
        try: check_issuer_candidate(target,candidate,at=at,locale_language=locale_language)
        except CertificateRuleError: pass
        else: return AcquiredMaterial(candidate,'cache')
    location = issuer_location(target,locale_language=locale_language)
    reply = yield AcquisitionEffect('ldap_certificate',location=location)
    candidate = _ldap_candidate(reply,parse,'issuer')
    check_issuer_candidate(target,candidate,at=at,locale_language=locale_language)
    warning = yield from _save_effect('certificate',key,candidate)
    return AcquiredMaterial(candidate,'ldap',warning)


def crl_steps(target, issuer, *, candidates, at, locale_language, attribute,
              save_crl, parse=parse_crl):
    """Store presence gate → CRLDP → cache → LDAP; candidate checks only."""
    candidate = select_crl_from_candidates(target,issuer,candidates,at=at,locale_language=locale_language)
    if candidate is not None: return AcquiredMaterial(candidate,'store')
    location = crl_location(target)
    if location is None: raise CertificateRuleError('crl_distribution_point_parse_failed')
    if location.attribute is None: location = replace(location,attribute=attribute)
    key = ('null' if location.dn is None else location.dn)+'.crl'
    observation = yield AcquisitionEffect('read_crl_cache',cache_key=key)
    candidate = _cache_candidate(observation,parse)
    if candidate is not None:
        try: check_crl_candidate(target,issuer,candidate,at=at,locale_language=locale_language)
        except CertificateRuleError: pass
        else: return AcquiredMaterial(candidate,'cache')
    reply = yield AcquisitionEffect('ldap_crl',location=location)
    candidate = _ldap_candidate(reply,parse,'crl')
    check_crl_candidate(target,issuer,candidate,at=at,locale_language=locale_language)
    if type(save_crl) is not bool:
        raise CertificateBackendLimit('actual SaveCRL setting required')
    warning = (yield from _save_effect('crl',key,candidate)) if save_crl else False
    return AcquiredMaterial(candidate,'ldap',warning)


def anchor_steps(target, anchors, *, at):
    """Ordered TrustAnchor loop. None represents an anchor without trustedCert."""
    last_error = None
    for index,anchor in enumerate(anchors):
        if anchor is None: continue
        matches = yield AcquisitionEffect('anchor_match',target=target,candidate=anchor,index=index)
        if type(matches) is not bool:
            raise CertificateBackendLimit('actual Android anchor selector result required')
        if not matches: continue
        try: anchor.check_validity(at)
        except CertificateRuleError as exc:
            last_error = exc.rule
            continue
        key = anchor.public_key()  # original getPublicKey is outside catch
        try: verify_signed_material(target.data,key,kind='certificate',provider_explicit=False)
        except CertificateRuleError as exc:
            last_error = exc.rule
            continue
        return anchor
    if last_error is not None:
        raise CertificateRuleError('matching_anchor_failed:'+last_error)
    return None


def build_path_steps(target, *, anchors, store_count, at, locale_language,
                     parse=parse_certificate, step_budget=64):
    """Original builder walk up to PKIX entry, without trust promotion.

    The local step budget stops diagnostic resource use, not an app rejection.
    No cycle rejection, shortest-path search or alternate-chain backtracking
    is invented. A self-issued top still needs anchor/CTL in engineValidate.
    """
    built = yield from walk_path_steps(target,anchors=anchors,store_count=store_count,at=at,
        locale_language=locale_language,parse=parse,step_budget=step_budget)
    if built.anchor is not None: return built
    anchor = yield from anchor_steps(built.path[-1],anchors,at=at)
    if anchor is None:
        raise CertificateBackendLimit('self-issued path top requires original CTL validation')
    return BuiltPath(built.path,anchor)


def walk_path_steps(target, *, anchors, store_count, at, locale_language,
                    parse=parse_certificate, step_budget=64):
    """Builder's pre-validator walk. A self-issued stop confers NO trust.

    Callers must still perform the validator's separate anchor/CTL lookup and
    mandatory path/CRL checks. Used by the connected recipient pipeline.
    """
    if at.tzinfo is None: raise ValueError('explicit timezone required')
    target.check_validity(at)
    path, current, steps = [target], target, 0
    while not current.issuer.equals(current.subject,locale_language=locale_language):
        anchor = yield from anchor_steps(current,anchors,at=at)
        if anchor is not None: return BuiltPath(tuple(path),anchor)
        if steps >= step_budget:
            raise CertificateBackendLimit('local builder step budget reached; not an SDK rejection')
        acquired = yield from issuer_steps(current,store_count=store_count,at=at,
                                          locale_language=locale_language,parse=parse)
        current = acquired.material
        path.append(current)
        steps += 1
    return BuiltPath(tuple(path),None)
