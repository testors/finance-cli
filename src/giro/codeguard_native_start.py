"""Bounded MainService.start composition, driven by explicit observations.

Expands process checks, both path lookups, file IO, arithmetic and JNI release/
return order. It supplies no Android context, identity, files or clean values.
Unsafe early branches and native allocation/stack corruption remain analysis
boundaries; this is not a live protection provider or server acceptance proof.
"""
from .codeguard_first import first_response_native_bytes
from .codeguard_native_io import (native_process_check_steps, native_pid_bytes_stat_steps,
                                  package_digest_file_steps)
from .codeguard_native_jni import (_jni, package_path_lookup_steps,
                                   delete_path_references_steps, utf_chars_bytes, native_return_text)
from .codeguard_rule import AnalysisLimit, NativeRuleError


class NativeStartBoundary(AnalysisLimit):
    """A known code assignment with unresolved complete native return."""
    def __init__(self, code):
        self.native_code = code
        super().__init__('native start branch needs unresolved runtime semantics')


def _error_bytes(code, process_name, pid_bytes):
    suffix = pid_bytes if 121 <= code <= 128 else process_name
    if type(suffix) is not bytes:
        raise NativeStartBoundary(code)  # sprintf %s with a null pointer
    value = b'E101_ENGINE_LOAD_ERROR0_' + str(code).encode('ascii') + b'_' + suffix.split(b'\0', 1)[0]
    # Only the 64-byte initialized error region is within this bounded model.
    # A longer sprintf is not newly classified as an original rejection.
    if len(value) >= 64:
        raise AnalysisLimit('native error formatting exceeds bounded stack region')
    return value


def native_start_steps(service, challenge, rule, app_info, version, pid):
    """Return resolved Java String/None from the final string operation.

    JNI effects use opaque environment references or explicit owned string
    values. The final returned value is plain text; owned string conversion
    does not supply missing context, package, process or file observations.
    Unknown native/JNI state must raise AnalysisLimit; it must not be supplied
    as a clean value or translated to JavaFault. Python owns arithmetic buffers;
    native malloc failure, memory corruption and stack-canary failure are not
    reconstructed as successful normal allocation paths or fabricated errors.
    """
    code = yield from native_process_check_steps()
    if code:
        raise NativeStartBoundary(code)
    if any(value is None for value in (challenge, rule, app_info, version)):
        raise NativeStartBoundary(100)
    if service is None:
        raise NativeStartBoundary(110)
    outer = yield from package_path_lookup_steps(service, phase='start')
    utf_chars_bytes(outer.source_utf, require_handle=True)
    utf_chars_bytes(outer.data_utf, require_handle=True)
    if len(outer.data_bytes.split(b'\0', 1)[0]) >= 256:
        raise AnalysisLimit('native dataDir strcpy exceeds buffer')
    refs = (challenge, rule, app_info, version, pid)
    acquisitions = []
    for ref in refs:
        acquisitions.append((yield _jni('GetStringUTFChars', ref)))
    utf = [utf_chars_bytes(value, require_handle=True) for value in acquisitions]
    # The Java-null PID test follows GetStringUTFChars, before strcmp.
    code = 123 if pid is None else (yield from native_pid_bytes_stat_steps(utf[4]))
    result = None
    if code == 0:
        yield from delete_path_references_steps(outer, phase='start')
        inner = yield from package_path_lookup_steps(service, phase='digest')
        utf_chars_bytes(inner.source_utf, require_handle=True)
        yield from delete_path_references_steps(inner, phase='digest')
        digest = yield from package_digest_file_steps(inner.source_bytes, inner.process_name)
        try:
            result = first_response_native_bytes(digest, *utf[:4])
        except NativeRuleError as error:
            code = error.native_code
        # No finally: unresolved memory/adapter failures are not a known native
        # rule return, and do not authorize invented later cleanup observations.
        yield _jni('ReleaseStringUTFChars', inner.source_ref, inner.source_utf.handle)
    yield _jni('ReleaseStringUTFChars', outer.source_ref, outer.source_utf.handle)
    if outer.data_bytes is not None:
        yield _jni('ReleaseStringUTFChars', outer.data_ref, outer.data_utf.handle)
    for ref, value in zip(refs[:4], acquisitions[:4]):
        if value is not None:
            yield _jni('ReleaseStringUTFChars', ref, value.handle)
    # Error sprintf precedes PID release. Normal response also releases PID
    # before NewStringUTF. PID never enters the rule's optional extra operand.
    if code:
        result = _error_bytes(code, outer.process_name, utf[4])
    if utf[4] is not None:
        yield _jni('ReleaseStringUTFChars', pid, acquisitions[4].handle)
    returned = yield _jni('NewStringUTF', result)
    return native_return_text(returned)


def project_native_start_steps(generator, *, service):
    """Expand native_start within response/token generation, without an executor.

    The caller supplies the real service context and resolves every remaining
    effect. Faults keep the original generator's catch scope; no retry is added.
    """
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as finished:
            return finished.value
        pending = None
        try:
            if effect.kind == 'native_start':
                value = yield from native_start_steps(service, *effect.args)
            else:
                value = yield effect
        except Exception as fault:
            pending = fault
