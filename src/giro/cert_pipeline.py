"""Connected issuer discovery → anchor/CTL → ordered path/CRL validation.

Public material only. No implicit IO, trust anchors or clock. Actual IO may be
provided by an explicit executor; unsupported selectors/providers never become
empty stores, clean revocation results or successful recipient installation.
"""
from .cert_acquisition import (AcquisitionEffect, ObservedStoreFailure, walk_path_steps, crl_steps)
from .cert_ctl import select_path_anchor_steps
from .cert_crl import selected_crl_steps
from .cert_factory import CertificateBackendLimit
from .cert_path import _path_rule_steps
from .cert_rules import DEFAULT_POLICIES, CertificateRuleError, crl_attribute
from .cert_selectors import select_material_effect, unique_selection


def _crl_candidates_steps(target, issuer, store_count, *, chosen=None, bounds=None):
    candidates=[]
    for index in range(store_count):
        effect = (AcquisitionEffect('crl_store',target=target,candidate=issuer,index=index)
                  if chosen is None else AcquisitionEffect('delta_crl_store',target=target,
                      candidate=(chosen,bounds),index=index))
        reply = yield effect
        if isinstance(reply,ObservedStoreFailure): continue
        if not isinstance(reply,(tuple,list)):
            raise CertificateBackendLimit('explicit selected CRL store candidates required')
        candidates.extend(reply)
    # Original aggregate is also a HashSet. Distinct multiple results remain
    # unresolved even when EACH store returned one item.
    return unique_selection(candidates)


def build_and_validate_steps(target, *, anchors, store_count, at, locale_language,
                             ctl_distribution_point, save_crl, initial_policies=DEFAULT_POLICIES,
                             step_budget=64):
    built = yield from walk_path_steps(target,anchors=anchors,store_count=store_count,at=at,
        locale_language=locale_language,step_budget=step_budget)
    # buildAndValidate adds a Collection store of the path CERTIFICATES here.
    # It cannot contribute CRLs; no fabricated observation/empty original
    # store is used to model that known, locally constructed extra collection.
    selection = yield from select_path_anchor_steps(built.path,anchors,at=at,
        locale_language=locale_language,distribution_point=ctl_distribution_point)
    if not selection.path: raise CertificateRuleError('ctl_path_empty_after_top_removal')
    def revocation(cert,issuer,anchor,index,licensed):
        candidates = yield from _crl_candidates_steps(cert,issuer,store_count)
        attribute = crl_attribute(target=index==0,issuer_name_equals_root_name=
            cert.issuer.render(locale_language=locale_language)==anchor.subject.render(locale_language=locale_language))
        acquired = yield from crl_steps(cert,issuer,candidates=candidates,at=at,
            locale_language=locale_language,attribute=attribute,save_crl=save_crl)
        checker = selected_crl_steps(cert,issuer,acquired.material,at=at,
            locale_language=locale_language,trust_anchor=anchor,licensed_ca=licensed)
        try: bounds=next(checker)
        except StopIteration: return
        bases = yield from _crl_candidates_steps(cert,issuer,store_count,chosen=acquired.material,bounds=bounds)
        try: checker.send(bases)
        except StopIteration: return
        raise CertificateBackendLimit('unexpected repeated delta lookup')
    result = yield from _path_rule_steps(selection.path,trust_anchor=selection.anchor,at=at,
        locale_language=locale_language,initial_policies=initial_policies,entry_checked=True,revocation=revocation)
    result.update(path_acquisition_completed=True,anchor_selection_completed=True,
                  anchor_via_ctl=selection.via_ctl,
                  anchor_order_provenance='explicit_input_not_android_hashset',
                  remaining=['general_selector_provider_boundaries','actual_io_provenance',
                             'ctl_global_trust_and_cache_state','recipient_installation'])
    return result


def public_store_steps(generator, stores):
    """Compute bounded selectors from actual supplied material; delegate IO."""
    value,error=None,None
    while True:
        try: effect=generator.throw(error) if error is not None else generator.send(value)
        except StopIteration as done: return done.value
        error=None
        try:
            if effect.kind in ('anchor_match','issuer_store','crl_store','delta_crl_store'):
                value=select_material_effect(effect,stores)
            elif effect.kind=='ctl_signer_certificates':
                from .cms_signed import single_signer_certificate
                value=single_signer_certificate(effect.target,effect.candidate[0])
            else: value=yield effect
        except Exception as exc: error=exc


def inspect_recipient_material(target_data, anchor_data, issuer_data, crl_data, *, at, locale_language):
    """Build from explicitly supplied public stores; no network, cache or writes.

    Like other inspectors, completion is a sub-pipeline diagnostic, not a
    globally trusted recipient, authentication result or permission to install.
    Missing material is never assumed to be an empty ORIGINAL app store.
    """
    from .cert_acquisition import parse_certificate, parse_crl, ObservedMaterialParseFailure
    from .cert_ctl import DEFAULT_CTL_DISTRIBUTION_POINT
    from .cert_input import CertificateInputError
    from .cert_selectors import MaterialStore
    from .cert_path import PathRuleError
    if at.tzinfo is None: raise ValueError('explicit timezone required')
    result=dict(offline=True,network_attempted=False,path_rules_completed=False,
        certificate_validation_performed=False,trust_discovery_performed=False,live_login_ready=False,
        anchor_order_provenance='explicit_input_not_android_hashset')
    try:
        target=parse_certificate(target_data)
        anchors=tuple(parse_certificate(data) for data in anchor_data)
        store=MaterialStore(tuple(parse_certificate(data) for data in issuer_data),
                            tuple(parse_crl(data) for data in crl_data))
        generator=public_store_steps(build_and_validate_steps(target,anchors=anchors,store_count=1,
            at=at,locale_language=locale_language,
            ctl_distribution_point=DEFAULT_CTL_DISTRIBUTION_POINT,save_crl=True),(store,))
        try: effect=next(generator)
        except StopIteration as done:
            return {**result,**done.value,'analysis_status':'acquired_path_rules_completed'}
        # Intentionally no IO executor in this CLI. Record only effect kind,
        # never a URI/cache path/certificate identity or fabricated IO outcome.
        generator.close()
        return {**result,'analysis_status':'material_or_io_needed','pending_effect':effect.kind}
    except PathRuleError as exc:
        return {**result,'analysis_status':'path_rule_failed','rule_error':exc.rule,
                'stage':exc.stage,'certificate_index':exc.certificate_index}
    except CertificateRuleError as exc:
        return {**result,'analysis_status':'acquisition_rule_failed','rule_error':exc.rule}
    except (CertificateInputError,ObservedMaterialParseFailure):
        return {**result,'analysis_status':'certificate_input_failed'}
    except (CertificateBackendLimit,ImportError) as exc:
        return {**result,'analysis_status':'unmodeled',
            'message':str(exc) if isinstance(exc,CertificateBackendLimit) else 'optional certificate backend unavailable'}
