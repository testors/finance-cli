"""Offline issuer/CRL subpipeline using parsed DER and independent RSA.

No trust discovery, network/cache access, CTL validation or full PKIX result.
Input candidate order must come from the original selector/iterator; Android
X500Principal equivalence and HashSet iteration are not replaced by SDKName.
"""
from dataclasses import dataclass

from .cert_factory import CertificateBackendLimit
from .cert_material import _kind, _members, _integer, _explicit
from .cert_names import SDKName, sdk_lower
from .cert_rules import (CertificateRuleError, check_crl_window,
                         check_crl_signer_usage, check_revocation_entry,
                         check_missing_idp, crl_source_action)
from .cert_signatures import verify_signed_material


def _general_names(tagged):
    if tagged.kind[:2] != (2,1):
        raise CertificateBackendLimit('SDK GeneralNames tagging boundary')
    values = tagged.children()
    for value in values:
        cls, method, tag = value.kind
        if cls != 2 or tag > 8 or tag == 3:
            raise CertificateRuleError('general_name_unknown_tag')
        if tag in (0,5):
            raise CertificateBackendLimit('SDK complex GeneralName encoding not modeled')
        if tag == 4:
            _kind(_explicit(value),(0,1,16))
        elif method:
            raise CertificateBackendLimit('SDK primitive GeneralName representation boundary')
        yield value


@dataclass(frozen=True, repr=False)
class AuthorityKeyIdentifier:
    key_id: bytes | None
    issuer_names: object
    serial: int | None

    @classmethod
    def from_extensions(cls, extensions):
        node = extensions.get('2.5.29.35')
        if node is None:
            return None
        key, names, serial = None, None, None
        for part in _members(node):
            if part.kind[0] != 2:
                raise CertificateBackendLimit('SDK AKI tagged field boundary')
            if part.kind == (2,0,0):
                key = part.contents
            elif part.kind == (2,1,1):
                names = part
            elif part.kind == (2,0,2):
                if not part.contents:
                    raise CertificateBackendLimit('SDK empty AKI serial boundary')
                serial = int.from_bytes(part.contents,'big',signed=True)
            elif part.kind[2] in (0,1,2):
                raise CertificateBackendLimit('SDK AKI implicit/explicit boundary')
            else:
                raise CertificateRuleError('aki_unknown_tag')
        return cls(key,names,serial)

    def cert_issuer(self):
        if self.issuer_names is None:
            return None
        for name in _general_names(self.issuer_names):
            if name.kind[2] == 4:
                return SDKName.from_der(_explicit(name).encoded)
        # Original dereferences null when GeneralNames has no directoryName.
        raise CertificateRuleError('aki_directory_name_missing')

    def equals(self, other, *, locale_language):
        if other is None or self.key_id != other.key_id:
            return False
        left, right = self.cert_issuer(), other.cert_issuer()
        if (left is None) != (right is None):
            return False
        if left is not None:
            if not left.equals(right,locale_language=locale_language):
                return False
            if self.serial is None:
                raise CertificateRuleError('aki_serial_null_dereference')
            return self.serial == other.serial
        # Even identical non-null serials fail if BOTH certIssuer are absent.
        return self.serial is None and other.serial is None


def check_issuer_candidate(target, issuer, *, at, locale_language):
    """findIssuerCert candidate rule, not signature or CA/path validation."""
    issuer.check_validity(at)
    check_issuer_link(target,issuer,locale_language=locale_language)


def check_issuer_link(target, issuer, *, locale_language):
    """Name/AKI/SKI only; loop validity/signature stages occur separately."""
    if not target.issuer.equals(issuer.subject,locale_language=locale_language):
        raise CertificateRuleError('issuer_name_mismatch')
    aki = AuthorityKeyIdentifier.from_extensions(target.extensions)
    ski = issuer.extensions.get('2.5.29.14')
    if aki is None or aki.key_id is None or ski is None:
        raise CertificateRuleError('issuer_key_identifier_missing')
    if aki.key_id != _kind(ski,(0,0,4)).contents:
        raise CertificateRuleError('issuer_key_identifier_mismatch')
    cert_issuer = aki.cert_issuer()
    if cert_issuer is not None:
        if aki.serial is None:
            raise CertificateRuleError('issuer_aki_serial_missing')
        # Optional certIssuer names the issuer certificate's ISSUER, not subject.
        if not cert_issuer.equals(issuer.issuer,locale_language=locale_language):
            raise CertificateRuleError('issuer_aki_cert_issuer_mismatch')
        if aki.serial != issuer.serial:
            raise CertificateRuleError('issuer_aki_serial_mismatch')


def check_crl_candidate(target, issuer, crl, *, at, locale_language):
    check_crl_window(*crl.update_dates(),at)
    verify_signed_material(crl.data,issuer.public_key(),kind='crl',provider_explicit=True)
    if not crl.issuer.equals(issuer.subject,locale_language=locale_language):
        raise CertificateRuleError('crl_issuer_name_mismatch')
    crl_aki = AuthorityKeyIdentifier.from_extensions(crl.extensions)
    target_aki = AuthorityKeyIdentifier.from_extensions(target.extensions)
    if crl_aki is None or target_aki is None or crl_aki.key_id is None or target_aki.key_id is None:
        raise CertificateRuleError('crl_or_target_aki_missing')
    if not target_aki.equals(crl_aki,locale_language=locale_language):
        raise CertificateRuleError('crl_target_aki_mismatch')


def select_crl_from_candidates(target, issuer, candidates, *, at, locale_language):
    """Candidates already selected/ordered by Android X509CRLSelector+Set.

    Returns None only for an empty candidate set (caller needs cache/LDAP).
    Does not swallow local analysis limits and pretend the app rejected a CRL.
    """
    had_candidates = False
    for crl in candidates:
        had_candidates = True
        try:
            check_crl_candidate(target,issuer,crl,at=at,locale_language=locale_language)
        except CertificateRuleError:
            continue
        return crl
    crl_source_action(store_had_candidates=had_candidates,valid_store_candidate=False)
    return None


def delta_bounds(crl):
    node = crl.extensions.get('2.5.29.27')
    if node is None:
        return None
    number = crl.extensions.get('2.5.29.20')
    if number is None:
        raise CertificateRuleError('delta_crl_number_missing')
    return _integer(node,positive=True), _integer(number,positive=True)-1


def _dp_name(tagged):
    name = _explicit(tagged)
    if name.kind[:2] != (2,1):
        raise CertificateBackendLimit('SDK DistributionPointName tagging boundary')
    # Relative-name branch constructs an ASN1Set but yields no comparison names.
    return tuple(_general_names(name)) if name.kind[2] == 0 else ()


def _check_idp(target, idp):
    points = target.extensions.get('2.5.29.31')
    if points is None or not _members(points):
        raise CertificateRuleError('target_crl_distribution_point_missing')
    first = _members(points)[0]  # not a search over every certificate CRLDP
    target_names, crl_issuers = None, None
    for part in _members(first):
        if part.kind[0] != 2:
            raise CertificateBackendLimit('SDK CRLDP tagged field boundary')
        if part.kind[2] == 0:
            target_names = _dp_name(part)
        elif part.kind[2] == 2:
            crl_issuers = tuple(_general_names(part))
        elif part.kind[2] == 1 and part.kind != (2,0,1):
            raise CertificateBackendLimit('SDK CRLDP reason flags boundary')
    idp_names = None
    flags = {1:False, 2:False, 4:False, 5:False}
    for part in _members(idp):
        if part.kind[0] != 2:
            raise CertificateBackendLimit('SDK IDP tagged field boundary')
        tag = part.kind[2]
        if tag == 0:
            idp_names = _dp_name(part)
        elif tag in flags:
            if part.kind[1] or not part.contents:
                raise CertificateBackendLimit('SDK IDP boolean boundary')
            flags[tag] = part.contents[0] != 0
        elif tag == 3:
            if part.kind[1] or not part.contents:
                raise CertificateBackendLimit('SDK IDP reason flags boundary')
        else:
            raise CertificateRuleError('idp_unknown_tag')
    if idp_names is None:
        raise CertificateRuleError('idp_distribution_point_missing')
    choices = target_names if target_names is not None else crl_issuers
    if choices is None:
        raise CertificateRuleError('target_dp_and_crl_issuer_missing')
    # GeneralName.equals: tag and ASN.1 value equality, NOT SDK X509Name.equals.
    if not any(a.encoded == b.encoded for a in choices for b in idp_names):
        raise CertificateRuleError('idp_distribution_point_mismatch')
    is_ca, _ = target.extensions.basic_constraints()
    if flags[1] and is_ca:
        raise CertificateRuleError('idp_user_only_but_target_ca')
    if flags[2] and not is_ca:
        raise CertificateRuleError('idp_ca_only_but_target_not_ca')
    if flags[5]:
        raise CertificateRuleError('idp_attribute_certificates_only')
    # Parsed onlySomeReasons/indirectCRL do not add a gate in this SDK method.


def check_selected_crl(target, issuer, crl, *, at, locale_language,
                       trust_anchor, licensed_ca, base_candidates=()):
    """Candidate signature/window/AKI checks + postselection revocation/IDP.

    base_candidates MUST already match Android selector's issuer and the
    delta_bounds interval. This function intentionally does not certify that
    prerequisite, perform LDAP/cache lookups or announce full PKIX success.
    """
    generator = selected_crl_steps(target,issuer,crl,at=at,locale_language=locale_language,
                                    trust_anchor=trust_anchor,licensed_ca=licensed_ca)
    try: next(generator)
    except StopIteration: return
    try: generator.send(base_candidates)
    except StopIteration: return
    raise CertificateBackendLimit('unexpected second delta base selection')


def selected_crl_steps(target, issuer, crl, *, at, locale_language, trust_anchor, licensed_ca):
    """Same mandatory checks, yielding delta bounds ONLY at original lookup.

    Returned candidates must be the real selector/HashSet result. The effect
    does not let a caller replace revocation/IDP validation with a boolean.
    """
    check_crl_candidate(target,issuer,crl,at=at,locale_language=locale_language)
    # Equality is encoded CERTIFICATE equality, not matching root/issuer names.
    is_anchor = issuer.data == trust_anchor.data
    check_crl_signer_usage(None if is_anchor else issuer.extensions.key_usage(boolean_array=True),
                           is_trust_anchor=is_anchor)
    check_revocation_entry(crl.revocation_date(target.serial),at)
    idp = crl.extensions.get('2.5.29.28')
    bounds = delta_bounds(crl)
    if bounds is not None:
        base_candidates = yield bounds
        for base in base_candidates:
            base_idp = base.extensions.get('2.5.29.28')
            if ((idp is None and base_idp is None) or
                    (idp is not None and base_idp is not None and idp.encoded == base_idp.encoded)):
                break
        else:
            raise CertificateRuleError('delta_base_crl_not_found')
        # Bytecode does not verify/merge base entries in this loop. Do not add
        # a new app rejection here; full trust/selector validation remains due.
    if idp is None:
        # Java short-circuit: LicensedCA does not evaluate issuer lowercase.
        lower = '' if licensed_ca else sdk_lower(crl.issuer.render(locale_language=locale_language),locale_language)
        check_missing_idp(licensed_ca=licensed_ca,issuer_name_lower=lower)
    else:
        _check_idp(target,idp)


def inspect_crl_candidate(target_bytes, issuer_bytes, crl_der, *, at, locale_language):
    """Private-value-free CLI report of three INDEPENDENT subchecks.

    Input certificates are selected using the SDK factory framing rules; CRL
    input is DER. No inferred anchor, LicensedCA mode, delta base or trust path.
    Failure here does not invent a Giro response code or predict first PKIX
    error ordering. Missing local backend support remains an analysis warning.
    """
    from .cert_factory import select_certificate
    from .cert_material import CertificateMaterial, CRLMaterial
    result = {'offline': True, 'network_attempted': False, 'live_login_ready': False,
              'certificate_validation_performed': False, 'subchecks': {},
              'remaining': ['trusted_path_and_name_constraints', 'android_store_selectors',
                            'postselection_crl_scope_and_delta_context', 'ctl_cache_ldap']}
    if at.tzinfo is None:
        raise ValueError('inspection time requires an explicit timezone')
    try:
        target = CertificateMaterial.from_der(select_certificate(target_bytes).data)
        issuer = CertificateMaterial.from_der(select_certificate(issuer_bytes).data)
        crl = CRLMaterial.from_der(crl_der)
    except (CertificateBackendLimit, ImportError):
        return {**result, 'analysis_status': 'unmodeled_material'}
    checks = (
        ('issuer_candidate', lambda: check_issuer_candidate(target,issuer,at=at,locale_language=locale_language)),
        ('target_signature', lambda: verify_signed_material(target.data,issuer.public_key(),kind='certificate',provider_explicit=True)),
        ('crl_candidate', lambda: check_crl_candidate(target,issuer,crl,at=at,locale_language=locale_language)),
    )
    for name, check in checks:
        try:
            check()
            detail = {'rule_completed': True, 'rule_error': None}
        except CertificateRuleError as exc:
            detail = {'rule_completed': False, 'rule_error': exc.rule}
        except (CertificateBackendLimit, ImportError):
            detail = {'rule_completed': None, 'analysis_status': 'unmodeled'}
        result['subchecks'][name] = detail
    return {**result, 'analysis_status': 'candidate_subchecks_only'}
