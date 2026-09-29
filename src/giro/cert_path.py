"""Offline supplied-path replay of CertVerifier's CRL recipient configuration.

No automatic trust, path discovery, cache, LDAP, clock or sockets.
Input is an explicit leaf-first path, a caller-designated anchor and ordered
CRL store candidates. Completion is relative to those inputs, NOT recipient
installation or live readiness. Android store ordering/selector boundaries
remain visible instead of silently substituting a generic PKIX validator.
The separate anchor-selection generator composes offline CMS/CTL checks before
the same mandatory path rules; its IO effects do not execute themselves.
"""
from dataclasses import dataclass, field

from .cert_factory import CertificateBackendLimit, OID, SEQUENCE, _node
from .cert_material import _members, _kind, _integer
from .cert_constraints import NameConstraints, dn_value, general_name
from .cert_crl import (check_issuer_link, select_crl_from_candidates,
                      check_selected_crl, delta_bounds)
from .cert_names import sdk_lower
from .cert_rules import (CertificateRuleError, PolicyState, DEFAULT_POLICIES,
    check_ca_structure, check_extended_key_usage, check_recipient_key_usage,
    unhandled_critical, crl_attribute)
from .cert_signatures import verify_signed_material


@dataclass(frozen=True, repr=False)
class PolicySequence:
    nodes: tuple

    def __len__(self):
        return len(self.nodes)

    def __iter__(self):
        from asn1crypto.core import ObjectIdentifier
        for node in self.nodes:
            fields = _members(node,1)
            if len(fields) > 1:
                _kind(fields[1],SEQUENCE)
            yield ObjectIdentifier.load(_kind(fields[0],OID).encoded).dotted


def _policies(extensions):
    node = extensions.get('2.5.29.32')
    return None if node is None else PolicySequence(tuple(_members(node)))


def _explicit_policy(extensions):
    node = extensions.get('2.5.29.36')
    result = None
    if node is not None:
        for part in _members(node):
            if part.kind[0] != 2:
                raise CertificateBackendLimit('PolicyConstraints tagged field boundary')
            if part.kind[2] in (0,1):
                if part.kind[1] or not part.contents:
                    raise CertificateBackendLimit('PolicyConstraints integer boundary')
                value = int.from_bytes(part.contents,'big',signed=True)
                if part.kind[2] == 0:
                    result = value
    return result


def _inhibit_any(extensions):
    node = extensions.get('2.5.29.54')
    return None if node is None else _integer(node)


def _ski(cert):
    node = cert.extensions.get('2.5.29.14')
    if node is not None:
        _kind(node,(0,0,4))
    return node


def _eku(cert):
    from asn1crypto.core import ObjectIdentifier
    # Both extension objects are fetched before the original null test.
    ku, eku = cert.extensions.get('2.5.29.15'), cert.extensions.get('2.5.29.37')
    if ku is None or eku is None:
        return
    values = (ObjectIdentifier.load(_kind(n,OID).encoded).dotted for n in _members(eku))
    check_extended_key_usage(cert.extensions.key_usage(),values)


def _critical(cert):
    critical = [oid for oid,(flag,_) in cert.extensions.values.items() if flag]
    if unhandled_critical(critical,version=cert.version):
        raise CertificateRuleError('unhandled_critical_extension')


def exact_principal_match(a, b):
    """Only the byte-identical X500Principal selector case is established.

    Different encodings may still be equal in Android. Neither a false match
    nor a new certificate rejection is invented for that unresolved boundary.
    """
    if a != b:
        raise CertificateBackendLimit('Android X500Principal nonidentical selector boundary')
    dn_value(a)  # DER shape/re-encoding boundary, not SDKName unordered equality
    return True


def _subject_principal(cert):
    # For canonical single-AVA RDNs, DER input is already the X500Principal
    # representation. Multi-AVA sorting and noncanonical provider input remain
    # unresolved; do not replace it by X509Name's first-AVA projection.
    values = dn_value(cert.subject_der)
    if any(len(_node(rdn).children()) != 1 for rdn in values):
        raise CertificateBackendLimit('Android subject multi-AVA encoding boundary')
    return values


@dataclass(frozen=True, repr=False)
class CRLContext:
    candidates: tuple = field(default_factory=tuple)
    base_candidates: tuple = field(default_factory=tuple)


def _verify_revocation(cert, issuer, anchor, context, *, at, locale_language, licensed_ca):
    # The supplied sequence is already the original store/HashSet order.
    for candidate in context.candidates:
        exact_principal_match(candidate.issuer_der,issuer.subject_der)
    chosen = select_crl_from_candidates(cert,issuer,context.candidates,at=at,locale_language=locale_language)
    if chosen is None:
        raise CertificateBackendLimit('CRL candidates absent: original cache/LDAP stage required')
    def selected_bases():
        # Lazy: selection must not precede KU/revocation-entry/IDP decoding.
        bounds = delta_bounds(chosen)
        for candidate in context.base_candidates:
            exact_principal_match(candidate.issuer_der,chosen.issuer_der)
            number = candidate.extensions.get('2.5.29.20')
            if number is None:
                continue
            value = _integer(number)
            if value < 0:
                raise CertificateBackendLimit('Android negative CRL-number selector boundary')
            if bounds[0] <= value <= bounds[1]:
                yield candidate
    check_selected_crl(cert,issuer,chosen,at=at,locale_language=locale_language,
                       trust_anchor=anchor,licensed_ca=licensed_ca,base_candidates=selected_bases())


class PathRuleError(CertificateRuleError):
    def __init__(self, rule, stage, index):
        self.stage, self.certificate_index = stage,index
        super().__init__(rule)


def validate_supplied_path(path, *, trust_anchor, crls, at, locale_language,
                          initial_policies=DEFAULT_POLICIES):
    """Replay default CRL/keyEncipherment recipient path, without discovery.

    path excludes the anchor and is leaf-first. crls has one CRLContext per
    path certificate in the same order. All signatures/time/CRL/name/policy/
    CA/critical/EKU/recipient-KU gates in this configuration are mandatory.
    There is no disable-revocation or clean-environment fallback switch.
    """
    return _validate_path_rules(path,trust_anchor=trust_anchor,crls=crls,at=at,
        locale_language=locale_language,initial_policies=initial_policies,entry_checked=False)


def validate_path_with_anchor_steps(path, anchors, *, crls, at, locale_language,
                                    distribution_point, initial_policies=DEFAULT_POLICIES):
    """Offline anchor/CTL selection → mandatory existing path/CRL rules.

    Input is the builder's leaf-first path BEFORE a possible CTL top removal.
    This composes real CMS/CTL subchecks, never accepts a 'CTL passed' boolean.
    All IO/selection observations stay explicit; no trust is installed.
    """
    from .cert_ctl import select_path_anchor_steps
    if not path: raise CertificateRuleError('certificate_path_empty')
    if at.tzinfo is None: raise ValueError('explicit timezone required')
    path[0].check_validity(at)  # builder's first check, before anchor acquisition
    selection = yield from select_path_anchor_steps(path,anchors,at=at,
        locale_language=locale_language,distribution_point=distribution_point)
    if not selection.path:
        # Original subsequently indexes List[-1] for the policy mode.
        raise CertificateRuleError('ctl_path_empty_after_top_removal')
    contexts = crls[:-1] if selection.via_ctl else crls
    result = _validate_path_rules(selection.path,trust_anchor=selection.anchor,crls=contexts,at=at,
        locale_language=locale_language,initial_policies=initial_policies,entry_checked=True)
    result.update(anchor_selection_completed=True,anchor_via_ctl=selection.via_ctl)
    return result


def _validate_path_rules(path, *, trust_anchor, crls, at, locale_language,
                         initial_policies, entry_checked):
    """Internal shared body; entry_checked is NOT an exposed validation switch."""
    if not path:
        raise CertificateRuleError('certificate_path_empty')
    if at.tzinfo is None:
        raise ValueError('explicit timezone required for offline path replay')
    if len(crls) != len(path):
        raise CertificateBackendLimit('one CRL context per supplied path certificate required')
    def revocation(cert,issuer,anchor,index,licensed):
        _verify_revocation(cert,issuer,anchor,crls[index],at=at,
                           locale_language=locale_language,licensed_ca=licensed)
        yield from ()
    generator = _path_rule_steps(path,trust_anchor=trust_anchor,at=at,locale_language=locale_language,
        initial_policies=initial_policies,entry_checked=entry_checked,revocation=revocation)
    try: next(generator)
    except StopIteration as done: return done.value
    raise CertificateBackendLimit('unexpected IO in supplied path replay')


def _path_rule_steps(path, *, trust_anchor, at, locale_language, initial_policies,
                     entry_checked, revocation):
    """Internal ordered body shared by supplied and acquired CRL validation.

    revocation is an INTERNAL mandatory-check implementation, not a public
    caller-selectable validator or a skip-revocation switch.
    """
    if not path:
        raise CertificateRuleError('certificate_path_empty')
    if at.tzinfo is None:
        raise ValueError('explicit timezone required for offline path replay')
    index, stage = 0, 'builder_target_validity'
    try:
        # buildAndValidate performs this before acquiring issuers/anchor.
        if not entry_checked:
            path[0].check_validity(at)
        index, stage = len(path)-1, 'supplied_anchor'
        if not entry_checked:
            exact_principal_match(path[-1].issuer_der,trust_anchor.subject_der)
            trust_anchor.check_validity(at)
        issuer_key = trust_anchor.public_key()
        if not entry_checked:
            verify_signed_material(path[-1].data,issuer_key,kind='certificate',provider_explicit=False)
        _ski(trust_anchor)
        stage = 'policy_mode'
        licensed = 'ou=licensedca' in sdk_lower(path[-1].subject.render(locale_language=locale_language),locale_language)
        state = PolicyState.initial(len(path),licensed_ca=licensed,initial_policies=initial_policies)
        constraints = NameConstraints()
        remaining = len(path)
        issuer = trust_anchor
        completed = []
        for index in range(len(path)-1,-1,-1):
            cert = path[index]
            stage = 'signature'
            verify_signed_material(cert.data,issuer_key,kind='certificate',provider_explicit=True)
            stage = 'validity'
            cert.check_validity(at)
            stage = 'revocation'
            yield from revocation(cert,issuer,trust_anchor,index,licensed)
            stage = 'issuer_link'
            check_issuer_link(cert,issuer,locale_language=locale_language)
            self_issued = cert.subject.equals(cert.issuer,locale_language=locale_language)
            stage = 'name_constraints'
            if index == 0 or not self_issued:
                constraints.check(4,_subject_principal(cert))
                san = cert.extensions.get('2.5.29.17')
                if san is not None:
                    for node in _members(san):
                        constraints.check(*general_name(node))
            stage = 'certificate_policies'
            state = state.select(_policies(cert.extensions))
            if index:
                stage = 'ca_version'
                if cert.version == 1:
                    raise CertificateRuleError('v1_cannot_be_ca')
                stage = 'name_constraints_update'
                constraints.add_extension(cert.extensions.get('2.5.29.30'))
                stage = 'policy_counters'
                state = state.advance(self_issued=self_issued,
                    require_explicit=None if self_issued else _explicit_policy(cert.extensions),
                    inhibit_any=None if self_issued else _inhibit_any(cert.extensions))
                stage = 'ca_constraints'
                is_ca,path_length = cert.extensions.basic_constraints()
                remaining = check_ca_structure(version=cert.version,is_ca=is_ca,
                    path_length=path_length,self_issued=self_issued,remaining_path=remaining)
                stage = 'ca_key_usage'
                usage = cert.extensions.key_usage(boolean_array=True)
                if usage is None or not usage & 4:
                    raise CertificateRuleError('ca_key_cert_sign_required')
                stage = 'extended_key_usage'
                _eku(cert)
                stage = 'critical_extensions'
                _critical(cert)
            stage = 'next_issuer_state'
            issuer_key = cert.public_key()
            _ski(cert)  # performed even for the last/target certificate
            issuer = cert
            completed.append({'certificate_index':index,
                'revocation_attribute':crl_attribute(target=index==0,
                    issuer_name_equals_root_name=cert.issuer.render(locale_language=locale_language)==trust_anchor.subject.render(locale_language=locale_language))})
        index, stage = 0, 'target_policy_counter'
        state = state.advance(target=True,self_issued=self_issued,require_explicit=_explicit_policy(path[0].extensions))
        stage = 'target_extended_key_usage'
        _eku(path[0])
        stage = 'target_critical_extensions'
        _critical(path[0])
        stage = 'recipient_key_usage'
        check_recipient_key_usage(path[0].extensions.key_usage(boolean_array=True))
        return {'offline':True,'path_rules_completed':True,'supplied_path_length':len(path),
                'completed':completed,'licensed_ca':licensed,'revocation_checked':True,
                'trust_discovery_performed':False,'certificate_validation_performed':False,
                'live_login_ready':False,
                'remaining':['issuer_and_ctl_discovery','android_selector_and_store_order',
                             'cache_ldap_and_recipient_installation']}
    except CertificateRuleError as exc:
        raise PathRuleError(exc.rule,stage,index) from None


def inspect_path_manifest(document):
    """Public local material only. Paths resolved as supplied, no network/cache.

    The manifest describes a hypothetical/observed path context, not permission
    to trust its anchor globally. Output contains no paths or identities.
    """
    from datetime import datetime
    from pathlib import Path
    from .cert_factory import select_certificate
    from .cert_material import CertificateMaterial, CRLMaterial
    from .errors import GiroError
    result = {'offline':True,'network_attempted':False,'path_rules_completed':False,
              'certificate_validation_performed':False,'trust_discovery_performed':False,
              'live_login_ready':False}
    try:
        if not isinstance(document,dict): raise ValueError()
        paths = document['path']
        contexts = document['crls']
        if not isinstance(paths,list) or not paths or any(not isinstance(p,str) for p in paths): raise ValueError()
        if not isinstance(document['trust_anchor'],str) or not isinstance(document['locale'],str): raise ValueError()
        if not isinstance(contexts,list) or len(contexts) != len(paths): raise ValueError()
        for context in contexts:
            if not isinstance(context,dict): raise ValueError()
            for key in ('candidates','base_candidates'):
                value = context.get(key,[])
                if not isinstance(value,list) or any(not isinstance(p,str) for p in value): raise ValueError()
        at = datetime.fromisoformat(document['at'])
        if at.tzinfo is None: raise ValueError()
    except (KeyError,ValueError,TypeError):
        raise GiroError('경로 manifest에는 path, trust_anchor, crls, 시간대가 있는 at, locale가 필요합니다.') from None
    try:
        def certificate(path):
            return CertificateMaterial.from_der(select_certificate(Path(path).read_bytes()).data)
        def crl(path):
            return CRLMaterial.from_der(Path(path).read_bytes())
        certs = tuple(certificate(path) for path in paths)
        anchor = certificate(document['trust_anchor'])
        contexts = tuple(CRLContext(tuple(crl(p) for p in context.get('candidates',[])),
                                    tuple(crl(p) for p in context.get('base_candidates',[]))) for context in contexts)
        return {**result,**validate_supplied_path(certs,trust_anchor=anchor,crls=contexts,
                         at=at,locale_language=document['locale']), 'analysis_status':'supplied_path_rules_completed'}
    except PathRuleError as exc:
        return {**result,'analysis_status':'path_rule_failed','rule_error':exc.rule,
                'stage':exc.stage,'certificate_index':exc.certificate_index}
    except (CertificateBackendLimit,ImportError) as exc:
        return {**result,'analysis_status':'unmodeled_or_material_needed',
                'message':str(exc) if isinstance(exc,CertificateBackendLimit) else 'optional certificate backend unavailable'}
    except OSError:
        raise GiroError('경로 manifest의 공개 인증서/CRL 파일을 읽을 수 없습니다.') from None
