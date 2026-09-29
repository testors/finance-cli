"""Private in-memory initial-material diagnostics; no IO or response issuance.

Local cert parsing/rule-plan decoding is NOT Android provider/native-check
execution. Never return cookies, challenge, rule, RCL, key or raw exceptions.
"""
from email.message import Message

from .android_headers import HeaderFields
from .codeguard_codec import derive_rule_plan,CodeGuardCodecError
from .codeguard_effects import JavaFault
from .codeguard_device import inspect_rcl_requirements
from .codeguard_exchange import UpdaterState,challenge_parts,rcl_after_challenge
from .codeguard_flow import challenge_should_continue
from .codeguard_http_values import decode_values_steps
from .codeguard_probe import _certificate_metadata
from .codeguard_rule import AnalysisLimit,NativeRuleError
from .codeguard_updater import consume_cookie_headers_steps
from .errors import GiroError

_TRIM=''.join(map(chr,range(33)))


def projected_response_headers(message):
    """Prove a bounded projection from Python's header representation.

    HTTP/1 ASCII, unfolded, defect-free headers only. Don't claim recovered
    Android wire lines for Python's discarded/folded/non-ASCII cases. Python
    latin-1 vs Okio UTF-8 is irrelevant ONLY inside the ASCII subset.
    """
    if not isinstance(message,Message):
        raise AnalysisLimit('explicit HTTP header Message required')
    if message.defects or message.get_unixfrom() is not None or message.get_payload()!='':
        raise AnalysisLimit('Python header parser information-loss boundary')
    pairs=[]
    for name,value in message.raw_items():
        if (type(name) is not str or not name or not name.isascii()
                or any(ord(c)<=32 or ord(c)>=127 or c==':' for c in name)
                or type(value) is not str or not value.isascii() or '\r' in value or '\n' in value):
            raise AnalysisLimit('ASCII unfolded header projection boundary')
        pairs.append((name,value.strip(_TRIM)))
    return HeaderFields(tuple(pairs))


def inspect_cookie_material(message, *, locale_language):
    report=dict(analysis_status='header_projection_boundary',cookie_values_processed=False,
                cookie_forwarded=False,cookie_persisted=False,
                header_projection_scope='ascii_unfolded_python_header_subset',
                locale_source='explicit_cli_argument')
    try:
        fields=projected_response_headers(message)
        headers=fields.get('Set-Cookie')
    except AnalysisLimit:
        return report
    report['set_cookie_header_count']=0 if headers is None else len(headers)
    state=UpdaterState()
    generator=decode_values_steps(consume_cookie_headers_steps(state,headers),locale_language=locale_language)
    try:
        try: next(generator)
        except StopIteration:
            report.update(analysis_status='cookie_values_processed',cookie_values_processed=True)
        else:
            report['analysis_status']='cookie_unresolved_effect'
    except AnalysisLimit:
        report['analysis_status']='cookie_value_adapter_boundary'
    except JavaFault:
        report['analysis_status']='cookie_original_exception'
    except Exception:
        report['analysis_status']='local_cookie_inspection_boundary'
    finally:
        generator.close()
    report['cookie_string_present']=bool(state.cookie)
    return report


def inspect_challenge_material(challenge, state, *, app_info,version):
    """Analyze available initial values without fabricating environment inputs.

    Diagnostics don't change the already-decoded CMD200 body result. No A/B
    native inputs, first response, nonce, check outcome or token is produced.
    """
    report=dict(analysis_status='not_inspected',native_checks_performed=False,
                native_response_generated=False,server_token_generated=False,
                android_certificate_equivalence_verified=False,
                nonce_key_source='server_HASH_KEY' if state.hash_key else 'challenge_sha256_fallback')
    if not challenge_should_continue(challenge):
        return {**report,'analysis_status':'mainservice_prefix_stop'}
    parts=challenge_parts(challenge)
    if len(parts)<2:
        return {**report,'analysis_status':'no_assigned_challenge_rule'}
    if len(parts)>=3:
        report['challenge_certificate']=_certificate_metadata(parts[2])
    if state.rcl:
        try:
            suffix=rcl_after_challenge(state.rcl,parts[0])
        except CodeGuardCodecError:
            return {**report,'analysis_status':'rcl_substring_original_exception'}
        report['rcl_suffix_present']=bool(suffix)
        if suffix:
            # Inventory only. Never consume platform effects or commands here.
            report['rcl_requirements']=inspect_rcl_requirements(suffix)
    else:
        report['rcl_suffix_present']=False
    try:
        rule=derive_rule_plan(parts[1],parts[0],app_info,version)
    except NativeRuleError as fault:
        report.update(analysis_status='rule_codec_native_error',native_code=fault.native_code)
    except AnalysisLimit:
        report['analysis_status']='rule_codec_analysis_boundary'
    except GiroError:
        report['analysis_status']='local_crypto_adapter_boundary'
    else:
        # Counts only: even selected offsets/opcodes or decoded rule stay out.
        report.update(analysis_status='rule_plan_decoded',operation_count=len(rule.operation_ids))
    return report
