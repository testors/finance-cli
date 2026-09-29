"""Explicit CMD101→200 diagnostic, NEVER CMD300, login or attestation.

Default CLI is a plan. The separately approved live path fetches a public
certificate and requests one challenge with a newly generated client key.
No original SDK/JNI, environment checks, identity collection or disk state.
Raw bodies, cookies, key/seed and challenge stay out of reports and logs.
"""
from datetime import datetime, timezone
import time

from .android_json import parse_object, string_field
from .codeguard_codec import java_base64_decode
from .codeguard_effects import JavaFault
from .codeguard_exchange import (UpdaterState, ExchangeStageError, read_line_join,
                                 rsa_wrap_key, challenge_parts)
from .codeguard_flow import challenge_should_continue
from .codeguard_http_values import decode_default_utf8
from .codeguard_platform import key_bytes_from_seed
from .codeguard_probe import (APP_BASE, APP_INFO, VERSION, _request, _fetch_request,
                              inspect_body, plan as bootstrap_plan)
from .codeguard_rule import AnalysisLimit
from .errors import GiroError

USER_AGENT='GiroCLI-CodeGuard-challenge/0.1 (CMD101-200-only-probe)'


def plan(abi, *, inspect_material=False,locale_language=None):
    initial=bootstrap_plan(abi)  # Validate the selected ABI before any IO
    if inspect_material and (type(locale_language) is not str or not locale_language):
        raise GiroError('material 검사에는 명시적 --locale 언어가 필요합니다.')
    differences=list(initial['differences_from_app'])
    differences.extend(['local_x509_rsa_backend_not_android',
        'stop_before_cmd200_if_certificate_or_rsa_adapter_unavailable',
        'cookies_counted_not_parsed_or_forwarded','stop_before_native_and_CMD300'])
    if inspect_material:
        differences.remove('cookies_counted_not_parsed_or_forwarded')
        differences.append('bounded_cookie_value_projection_not_full_urlconnection')
    return dict(offline=True,network_attempted=False,analysis_status='plan_only',
        commands=[101,200],method='GET',endpoint=APP_BASE+'CodeGuard/check.jsp',
        maximum_requests=2,requests_attempted=0,abi=abi,
        application_identity_source='service_configuration',
        tls_verification_required=True,redirects=False,retries=0,
        pin_used=False,device_id_used=False,phone_number_used=False,
        environment_response_submitted=False,token_request_submitted=False,
        raw_response_persisted=False,cookies_persisted=False,secrets_persisted=False,
        key_source='own_currentTimeMillis_Java_Random_setSeed_nextBytes_16',
        rsa_padding='PKCS1_v1_5',mix_setting=False,
        sdk_initialization_verified=False,certificate_validation_performed=False,
        live_login_ready=False,server_token_generated=False,inspect_material=inspect_material,
        material_diagnostics=(['cookie_values','challenge_certificate','rule_plan','rcl_policy_inventory']
                              if inspect_material else []),
        differences_from_app=differences)


class _StringFields:
    """Lazy access keeps Updater's field-conversion/partial-write ordering.

    Eager conversion of HASH_KEY would incorrectly occur before RCL decoding
    and mix/split assignment. None here preserves isNull → per-field defaults.
    """
    def __init__(self, document): self.document=document
    def get(self, key): return string_field(self.document,key,None)
    def __repr__(self): return '<CodeGuard JSONObject fields (private)>'


def inspect_challenge_body(data, state, *, inspect_material=False):
    """Body stage only; not full Updater success or cookie/HTTP equivalence.

    HASH_KEY helper failures may return empty while challenge succeeds; do not
    impose nonempty values, `000`, strict Base64/PKCS#7 or schema validation.
    """
    report=dict(cmd200_body_processed=False,live_login_ready=False,
                server_token_generated=False)
    try:
        document=parse_object(read_line_join(decode_default_utf8(data)))
        challenge=state.consume_cmd200_fields(_StringFields(document))
        report.update(analysis_status='cmd200_body_processed',cmd200_body_processed=True,
            challenge_present=bool(challenge),challenge_part_count=len(challenge_parts(challenge)),
            mainservice_prefix_guard_continues=challenge_should_continue(challenge))
    except JavaFault:
        report['analysis_status']='cmd200_json_exception'
    except ExchangeStageError as fault:
        report.update(analysis_status='cmd200_original_field_exception',field_stage=fault.stage)
    except AnalysisLimit:
        report['analysis_status']='cmd200_value_adapter_boundary'
    except GiroError:
        report['analysis_status']='cmd200_local_crypto_adapter_boundary'
    report.update(rcl_present=bool(state.rcl),hash_key_present=bool(state.hash_key),
                  is_mix=state.is_mix,is_split=state.is_split)
    if inspect_material and report['cmd200_body_processed']:
        from .codeguard_material import inspect_challenge_material
        try:
            report['initial_material']=inspect_challenge_material(challenge,state,app_info=APP_INFO,version=VERSION)
        except Exception:
            # Optional local diagnostics must not change the original body
            # outcome or leak provider error/input text in a traceback.
            report['initial_material']={'analysis_status':'local_material_inspection_boundary'}
    # Don't return original challenge/error string, RCL, hash/key or parser text.
    return report


def _wrap_new_key(certificate_text, state):
    """Own fresh exchange, never predict/search another client's seed or key.

    Android's key is assigned before cert parsing, preserved here. The local
    backend may differ; on adapter failure the PROBE stops (no empty KEY
    request), explicitly without asserting the original app would stop.
    """
    state.key=key_bytes_from_seed(time.time_ns()//1_000_000)
    from cryptography import x509
    raw=java_base64_decode(certificate_text)
    if raw is None: return None
    certificate=x509.load_der_x509_certificate(raw)
    return rsa_wrap_key(certificate.public_key(),state.key)


def probe_challenge(abi, *, inspect_material=False,locale_language=None):
    """At most one 101 and one 200. Requires its OWN user-approved test scope.

    Both TLS connections are verified. Never retry to refresh a failed
    exchange, use cached app prefs, follow an endpoint embedded in a response,
    submit environment data or obtain/use any token. No raw result escapes.
    """
    result=plan(abi,inspect_material=inspect_material,locale_language=locale_language)
    result.update(offline=False,analysis_status='incomplete',observed_at_utc=
                  datetime.now(timezone.utc).isoformat(),requests=[])
    try:
        first={'command':101}
        result['requests'].append(first)
        body=_fetch_request(_request(abi,user_agent=USER_AGENT),first)
        if body is None:
            result['analysis_status']='cmd101_transport_incomplete'
            return result
        first.update(inspect_body(body))
        if not first['cmd101_fields_decoded']:
            result['analysis_status']='cmd101_fields_unavailable'
            return result
        # Parse again inside the memory-only scope, never cache/log the body.
        document=parse_object(read_line_join(decode_default_utf8(body)))
        certificate=string_field(document,'CERT','')
        state=UpdaterState()
        try:
            wrapped=_wrap_new_key(certificate,state)
        except Exception:
            # Backend errors are not Android exceptions or success; do not
            # disclose ASN.1 input/provider messages. KeyboardInterrupt still
            # propagates. An empty KEY request is outside this probe's scope.
            result['analysis_status']='local_key_wrap_adapter_boundary'
            return result
        if wrapped is None:
            result['analysis_status']='certificate_unavailable_for_probe'
            return result
        request=state.cmd200_request(APP_BASE,app_info=APP_INFO+VERSION+'1',
            abi=abi,wrapped_key=wrapped,mix_setting=False,user_agent=USER_AGENT)
        second={'command':200}
        result['requests'].append(second)
        inspect_headers=None
        if inspect_material:
            from .codeguard_material import inspect_cookie_material
            inspect_headers=lambda message:inspect_cookie_material(message,locale_language=locale_language)
        body=_fetch_request(request,second,count_cookie_headers=True,inspect_headers=inspect_headers)
        if body is None:
            result['analysis_status']='cmd200_transport_incomplete'
            return result
        second.update(inspect_challenge_body(body,state,inspect_material=inspect_material))
        result['analysis_status']=second['analysis_status']
        return result
    finally:
        # Metadata only; Python immutable strings/bytes aren't guaranteed
        # securely zeroized. No persistence is promised, not memory erasure.
        result['network_attempted']=any(r.get('network_attempted',False) for r in result['requests'])
        result['requests_attempted']=sum(r.get('request_attempted',False) for r in result['requests'])
