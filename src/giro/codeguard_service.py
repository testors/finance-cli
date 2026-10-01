"""Offline MainService.generateToken: compose response + Updater stages.

No IO executor, SDK, fake clean observations or socket is provided. This
connects the full normal call sequence for initialized MainService/Updater
state, not native check implementation or proof of real server compatibility.
"""
from .codeguard_effects import Effect, JavaFault, LinkFault, observed_bool
from .codeguard_flow import (challenge_should_continue, java_text, JavaStageError,
                            decode_returned_token, ReturnedTokenDecodeError)
from .codeguard_inputs import fallback_nonce_key
from .codeguard_response import encrypted_response_steps, _error
from .codeguard_rule import AnalysisLimit
from .codeguard_updater import (agent_certificate_steps, check_update_steps,
                               challenge_steps, token_steps, preference, runtime_fault)


def generate_token_http_values_steps(main, runtime, agent, *, locale_language,
                                     project_headers=False, **options):
    """Compose raw Android JSON/cookie conversions with the existing sequence.

    This is still an offline generator. HTTP streams, TLS, native/environment,
    initialization and other platform operations remain explicit effects.
    """
    from .codeguard_http_values import decode_values_steps
    generator=generate_token_steps(main,runtime,agent,**options)
    if project_headers:
        from .android_headers import project_header_values_steps
        generator=project_header_values_steps(generator)
    return (yield from decode_values_steps(generator,locale_language=locale_language))


def _response_route(main, runtime, agent, generator):
    """Route nested response refreshes into the SAME Updater/key/cookie state.

    Forward adapter faults into the original generator's try scope. Avoid
    catching an adapter's own StopIteration as generator completion.
    """
    try:
        effect = next(generator)
    except StopIteration as done:
        return done.value
    while True:
        error = None
        try:
            if effect.kind == 'request_challenge':
                value = yield from challenge_steps(runtime,agent,main,effect.args[0])
            elif effect.kind == 'read_rcl':
                value = runtime.data.rcl
            elif effect.kind == 'engine_version':
                value = agent.engine_version
            elif effect.kind == 'read_engine_version_preference':
                value = yield from preference(runtime,'ENGINE_VERSION',effect.args[0])
            elif effect.kind == 'write_engine_version_preference':
                value = yield Effect('preference_write',(runtime.context,'ENGINE_VERSION',effect.args[0],'commit'))
            else:
                value = yield effect
        except Exception as fault:
            error = fault
        try:
            effect = generator.throw(error) if error is not None else generator.send(value)
        except StopIteration as done:
            return done.value


def generate_token_steps(main, runtime, agent, *, server_url, timeout,
                         root_check, rooting_info, encrypted_token, decode_certificate=None):
    """Explicitly prepared MainService and retained Updater state.

    MainService's later static context may differ from Updater's context.
    Construction/load observations can be composed by codeguard_main; this
    function itself does not create them or assume successful library loads.
    getNonce effect must include its actual checks, not arithmetic alone.
    """
    runtime.url, runtime.timeout = server_url, timeout
    runtime.app_info, runtime.version = main.app_info, main.version
    cert = yield from agent_certificate_steps(runtime,agent)
    if not cert:
        yield from check_update_steps(runtime,agent,main)  # bool return ignored by original
    text = yield from challenge_steps(runtime,agent,main,java_text(main.app_info)+java_text(main.version)+'1')
    if not challenge_should_continue(text):
        return text
    yield from main.challenge.consume_steps(text,decode_certificate=decode_certificate)
    main.challenge.apply_rcl(runtime.data.rcl)
    first = yield from _response_route(main,runtime,agent,encrypted_response_steps(
        main,root_check=root_check,rooting_info=rooting_info,encrypted_token=encrypted_token,
        decode_certificate=decode_certificate))
    zip_result = observed_bool((yield Effect('check_zip_os14')))
    hash_key = runtime.data.hash_key or ''  # capture AFTER ZIP check and BEFORE local formatter
    if not zip_result:
        detail = yield Effect('zip_error_message')
        first = yield Effect('format_local_error',('CG_CONN_ENGINE01','unZip error : '+java_text(detail),'CG_CONN_ENGINE'))
    is_mix = observed_bool(runtime.data.is_mix)  # captured before metadata read
    try:
        metadata = yield Effect('split_metadata_boolean')  # None means observed absent bundle
        split = False if metadata is None else observed_bool(metadata)
    except JavaFault:
        split = False
    if not split:
        split = observed_bool(runtime.data.is_split)
    try:
        if not hash_key:
            if main.challenge.challenge is None:
                yield from runtime_fault('NullPointerException','getNonce.challenge.getBytes')
            hash_key = fallback_nonce_key(main.challenge.challenge).decode('ascii')
        second = yield Effect('native_get_nonce',(hash_key,main.challenge.challenge,is_mix,split))
    except (JavaFault,LinkFault) as fault:
        second = yield from _error(main,'3',fault.message)
    try:
        fingerprint = observed_bool((yield Effect('check_fingerprint')))
        if not fingerprint:
            detail = yield Effect('fingerprint_error_message')
            first = yield Effect('format_local_error',('CG_CONN_ENGINE01','FingerPrint error('+java_text(detail)+')','CG_CONN_ENGINE'))
    except JavaFault:
        pass  # includes formatter; keep previous first response
    if first is None:
        raise JavaStageError('null_response_before_guard')
    # Original engine-error indexOf values do not prevent CMD300 submission.
    result = yield from token_steps(runtime,agent,main,first,second)
    try:
        return decode_returned_token(result,challenge=main.challenge.challenge,
                                     encrypted_token=observed_bool(encrypted_token))
    except ReturnedTokenDecodeError:
        # Original b(String,String) includes the Java exception message in its
        # CG_RETRY signature; do not substitute a Python decrypt error string.
        try:
            fault = yield Effect('returned_token_decode_fault')
        except JavaFault as observed:
            fault = observed
        if not isinstance(fault,JavaFault):
            raise AnalysisLimit('original returned-token decrypt exception required')
        return (yield Effect('format_local_error',('CG_RETRY01','token decryption fail',
                                                  'CG_RETRY('+java_text(fault.message)+')')))
