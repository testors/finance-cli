"""Offline MainService.generateResponse/OSCheck control flow.

Generators describe Android/native/future/preference effects; no effect runner
is installed. Inputs must be genuine observations (or labeled synthetic tests).
In particular a timeout is not manufactured to replace an environment check.
Future.get does not cancel the worker: shared detail fields are read explicitly
at framing time, even after an observed timeout. No clean OS value is assumed.
"""
import base64
from dataclasses import dataclass
import hashlib

from .codeguard_codec import RULE_KEY, RULE_IV, CodeGuardCodecError, java_seed_encrypt, java_utf8, wrap_response
from .codeguard_effects import Effect, JavaFault, LinkFault, observed_bool, shortened_log, signed_long
from .codeguard_flow import ChallengeState, JavaStageError, java_text
from .codeguard_rule import AnalysisLimit


@dataclass(repr=False)
class ResponseState:
    challenge: ChallengeState
    app_info: str | None
    version: str | None
    pid: str | None
    build_string: str | None
    etc_data: str | None
    status_log: str | None
    updater_engine_version: str | None
    native_error_detail: str | None
    os_status: str | None = None
    detail_enabled: bool = False

    @property
    def app_identity(self):
        return java_text(self.app_info) + '::' + java_text(self.version)

    def append_log(self, suffix):
        self.status_log = java_text(self.status_log) + suffix

    def set_app_info(self, pid, app_info, version):
        self.append_log(',E30')
        self.pid, self.app_info, self.version = str(pid), app_info, version
        # Existing CodeGuardChallenge g/h/i/j/e/cert/location remain unchanged.

    def set_etc_data(self, value):
        if value is None:
            raise AnalysisLimit('null etc-data needs original exception-text adapter')
        self.etc_data = base64.b64encode(java_utf8(value)).decode('ascii')


def os_status_digest(source):
    """Only SHA1/SEED/Base64 arithmetic for an already selected OSCheck source."""
    if source is None:
        raise AnalysisLimit('null OS source needs original exception-text adapter')
    digest = hashlib.sha1(java_utf8(source)).digest()
    return base64.b64encode(java_seed_encrypt(digest, RULE_KEY, RULE_IV)).decode('ascii')


def oscheck_steps(state, *, challenge, root_check, rooting_info, fourth, rcl):
    """MainService.a(String,ZZ,String,String); not a real OS-check adapter."""
    root_check, rooting_info = observed_bool(root_check), observed_bool(rooting_info)
    source = challenge
    try:
        if rooting_info:
            source = 'OS_modification_by_rooting_info'
        elif root_check:
            manager = 'extended' if rcl else 'standard'
            result = yield Effect('device_check', (manager, rcl if rcl else fourth))
            state.detail_enabled = observed_bool(result)
            if state.detail_enabled:
                source = yield Effect('device_detail', (manager,))
    except JavaFault:
        state.append_log(',E32.4')
    return os_status_digest(source)


def _refresh(state, decode_certificate):
    value = yield Effect('request_challenge', (java_text(state.app_info)+java_text(state.version)+'1',))
    # Unlike generateToken's initial log, this branch DOES null-check first.
    if value is not None and not value.startswith('E101_NET_ERROR'):
        yield from state.challenge.consume_steps(value, decode_certificate=decode_certificate)
        rcl = yield Effect('read_rcl')
        try:
            state.challenge.apply_rcl(rcl)
        except (JavaStageError, CodeGuardCodecError):
            # Catch scope is known, but Android's exact exception.getMessage()
            # enters the wire string. Do not manufacture that runtime text.
            raise AnalysisLimit('RCL runtime failure needs original exception-text adapter') from None


def _error(state, suffix, message):
    state.status_log = shortened_log(state.status_log, 1000) + '(' + java_text(message) + ')'
    location = yield Effect('location_text')
    return (state.app_identity + '##' + java_text(state.updater_engine_version) + '/' +
            java_text(state.build_string) + '##E101_ENGINE_LOAD_ERROR' + suffix + '(' +
            state.status_log + ')##' + java_text(location))


def response_steps(state, *, root_check, rooting_info, decode_certificate=None):
    """Generate the first plaintext response with exact refresh/catch ordering.

    native_start returns the complete observed/reimplemented JNI result, NOT
    just first_response_arithmetic with its still-unimplemented checks omitted.
    Effect failures are thrown as JavaFault/LinkFault by an observation adapter.
    Python bugs, AnalysisLimit and unknown environment data are never caught as
    original Java failures or converted to successful-looking responses.
    """
    root_check, rooting_info = observed_bool(root_check), observed_bool(rooting_info)
    state.append_log(',E32')
    state.detail_enabled = False  # original write before submitting OSCheck
    if not state.challenge.challenge:
        state.append_log(',E32.5.2')
        yield from _refresh(state, decode_certificate)  # outside both catches

    try:
        effective_rooting = rooting_info if state.etc_data else False
        try:
            state.os_status = yield Effect('oscheck_future', (
                state.challenge.challenge, root_check, effective_rooting,
                state.challenge.fourth, state.challenge.rcl_suffix, 5000))
        except JavaFault as fault:
            if fault.kind not in ('InterruptedException', 'ExecutionException', 'TimeoutException'):
                raise
            # Actual observed Future failure only; no cancellation or shutdown here.
            state.os_status = os_status_digest(state.challenge.challenge)
    except JavaFault as fault:
        state.append_log(',E32.5(' + java_text(fault.message) + ')')
        state.os_status = 'OS_CHECK_ERR001(' + java_text(fault.java_string) + ')'

    try:
        if not state.challenge.challenge or not state.challenge.rule:
            state.append_log(',E32.5.1')
            yield from _refresh(state, decode_certificate)
        before = yield Effect('clock_ms')
        native_return = yield Effect('native_start', (state.challenge.challenge, state.challenge.rule,
                                                     state.app_info, state.version, state.pid))
        after = yield Effect('clock_ms')
        elapsed = signed_long(signed_long(after) - signed_long(before))
        engine = yield Effect('engine_version')
        if not engine:
            engine = yield Effect('read_engine_version_preference', ('0.0',))
        prefix = state.app_identity + '##' + java_text(engine) + '/' + java_text(state.build_string) + '@' + str(elapsed)
        if state.etc_data is not None:
            prefix += '!' + state.etc_data  # empty is not null
        else:
            # Explicit shared-field observation handles the still-running OSCheck.
            state.detail_enabled = observed_bool((yield Effect('read_detail_enabled')))
            if state.detail_enabled:
                manager = 'extended' if state.challenge.rcl_suffix else 'standard'
                detail = yield Effect('device_detail', (manager,))
                if detail is None:
                    raise AnalysisLimit('null device detail needs original exception-text adapter')
                prefix += '!' + base64.b64encode(java_utf8(detail)).decode('ascii')
        prefix += '*' + java_text(state.os_status) + '##'
        # Original constructs prefix (including metadata reads) BEFORE null test.
        if native_return is None:
            return (yield from _error(state, '4', state.native_error_detail))
        if 'E101_ENGINE_LOAD_ERROR0_120' in native_return:
            try:
                processes = yield Effect('running_app_processes')
                if processes is None:
                    raise AnalysisLimit('null process list needs original exception-text adapter')
                for pid, name in processes:
                    if str(pid) == state.pid:
                        native_return += '_' + java_text(name)
                        break
            except JavaFault as fault:
                if fault.kind != 'SecurityException':
                    raise
        location = yield Effect('location_text')
        result = prefix + native_return + '##' + java_text(location)
        if 'UnsatisfiedLinkError' in result:  # entire frame, not only native_return
            state.append_log(',E32.6')
            try:
                yield Effect('write_engine_version_preference', ('0.0',))
            except JavaFault:
                pass  # commit false also ignored; no actual write by this model
        return result
    except LinkFault:
        return (yield from _error(state, '3', ''))
    except JavaFault as fault:
        return (yield from _error(state, '2', fault.message))


def encrypted_response_steps(state, *, encrypted_token, **kwargs):
    """The outer generateEncResponse has no added catch/rejection policy."""
    result = yield from response_steps(state, **kwargs)
    return wrap_response(result, encrypted_token=observed_bool(encrypted_token))
