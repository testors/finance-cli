"""First-response arithmetic and framing, NOT MainService.start execution.

Only bytes and strings explicitly supplied by the caller are used. The native
process/reflection/file checks and Java OSCheck are NOT represented by a
default clean result here. This module neither issues nor submits a token.
"""
import base64

from .codeguard_codec import (decode_rule, evaluate_rule, java_utf8,
                              jni_modified_utf8, native_base64_decode,
                              NativeBase64Error)
from .codeguard_inputs import package_digest
from .codeguard_native_io import package_digest_read_steps
from .codeguard_rule import AnalysisLimit, NativeRuleError, parse_rule, parsing_positions


def first_response_arithmetic(package_bytes, encoded_challenge, encoded_rule, app_info, version):
    """Reconstruct the byte payload reached AFTER the original JNI checks.

    MainService.start at 0xa02c/0xa03c passes NULL for both the auxiliary-file
    input and the rule's optional extra operand. Its fifth Java String (PID)
    is NOT that operand. Return bytes before JNI NewStringUTF, not a statement
    that JNI/OS checks passed. The original encoded challenge is preserved.
    """
    return _first_response(package_digest(package_bytes), encoded_challenge,
                           encoded_rule, app_info, version)


def first_response_read_steps(file_size, encoded_challenge, encoded_rule, app_info, version):
    """The same arithmetic from observed native fread calls, including short reads.

    Entry requires completed JNI/process/path resolution and file positioning.
    Only the digest/arithmetic stage is expanded; this is NOT native_start.
    """
    digest = yield from package_digest_read_steps(file_size)
    return _first_response(digest, encoded_challenge, encoded_rule, app_info, version)


def _first_response(digest, encoded_challenge, encoded_rule, app_info, version):
    if encoded_challenge is None:
        raise NativeRuleError(20)
    challenge_text = jni_modified_utf8(encoded_challenge)
    try:
        challenge = native_base64_decode(challenge_text)
    except NativeBase64Error:
        raise NativeRuleError(21) from None
    # The caller decodes the same rule twice. On deterministic byte inputs the
    # outputs coincide; allocation failure/partial native memory is unmodeled.
    rule = decode_rule(jni_modified_utf8(encoded_rule))
    plan = parse_rule(rule, parsing_positions(challenge, jni_modified_utf8(app_info),
                                              jni_modified_utf8(version)))
    response = evaluate_rule(plan, digest, challenge, extra=None)
    return b'::'.join((base64.b64encode(response), base64.b64encode(digest),
                       challenge_text.split(b'\0', 1)[0]))


def java_response_frame(*, app_info, version, engine_version, cached_engine_version,
                        build_string, elapsed_ms, etc_data, detail_enabled, rcl,
                        device_detail, device_detail_ex, os_status, native_return,
                        location_text):
    """MainService's string append stage with explicit already-resolved inputs.

    OS/device data, elapsed time and cached engine version must come from the
    corresponding stage; none are synthesized. location_text is the original
    Java-rendered coordinate string (or its original empty result). Null/native
    error-120 side effects and UnsatisfiedLinkError preference writes remain
    outside this pure serializer, as do the preceding OSCheck and callbacks.
    """
    if native_return is None or 'E101_ENGINE_LOAD_ERROR0_120' in native_return:
        raise AnalysisLimit('native result requires unresolved Java error callback/annotation')
    if type(detail_enabled) is not bool or type(elapsed_ms) is not int:
        raise TypeError('explicit boolean and measured integer duration required')
    if 'UnsatisfiedLinkError' in native_return:
        raise AnalysisLimit('Java engine preference side effect is not modeled')
    def append(value):
        # StringBuffer.append(String) uses literal "null", not an empty string.
        return 'null' if value is None else value
    selected_engine = cached_engine_version if not engine_version else engine_version
    details = ''
    if etc_data is not None:
        details = '!' + etc_data  # empty-but-nonnull still writes '!'
    elif detail_enabled:
        detail = device_detail_ex if rcl else device_detail
        details = '!' + base64.b64encode(java_utf8(detail)).decode('ascii')
    prefix = append(app_info) + '::' + append(version)
    return (prefix + '##' + append(selected_engine) + '/' + append(build_string)
            + '@' + str(elapsed_ms) + details + '*' + append(os_status)
            + '##' + native_return + '##' + append(location_text))
