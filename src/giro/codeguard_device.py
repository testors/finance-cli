"""Offline DeviceManagerEx RCL parser and control flow.

No OS/package/file/process executor. Especially, policy 11 falls through to
Runtime.exec(String) when package lookup is absent/empty; it is NOT safe to run
unreviewed RCL descriptions. Missing observations never become clean results.
Java runtime faults are explicit; Python bugs/AnalysisLimit/LinkFault propagate.
"""
from dataclasses import dataclass

from .android_json import parse_array, parse_object, array_string_at, string_field, int_field, boolean_field
from .codeguard_effects import Effect, JavaFault, observed_bool
from .codeguard_flow import java_text
from .codeguard_rule import AnalysisLimit


@dataclass(repr=False)
class RclEntry:
    description: str = ''
    policy: int = 0
    enabled: bool = False
    os_type: int = 0

    @classmethod
    def parse(cls, text):
        entry = cls()
        try:
            obj = parse_object(text)
            entry.description = string_field(obj, 'description', '')
            entry.policy = int_field(obj, 'policy')
            entry.os_type = int_field(obj, 'osType')
            entry.enabled = boolean_field(obj, 'enabled')  # assigned LAST
        except JavaFault:
            pass  # catch(Exception); earlier assignments remain, not rollback
        return entry


def rcl_entries(text):
    """All enabled entries, or original outer JSONException (before any check).

    JSONArray.getString is outside the entry constructor's catch. A late failure
    here discards the earlier usable list in the caller. Unknown policies and
    empty descriptions remain; osType filtering belongs to the evaluation loop.
    """
    array = parse_array(text)
    entries = []
    for index in range(len(array.values)):
        entry = RclEntry.parse(array_string_at(array, index))
        if entry.enabled: entries.append(entry)
    return entries


def inspect_rcl_requirements(text):
    """Count potential platform requirements without evaluating any rule.

    No descriptions, paths, package names or commands leave this report. Counts
    cover enabled entries, not actual executed checks (the loop short-circuits).
    Original malformed-array false and unknown analysis are distinct; neither
    is reported as proof of a clean device. Local faults remain diagnostics.
    """
    report = dict(analysis_status='not_inspected', environment_checks_performed=False,
                  process_execution_performed=False, native_response_generated=False)
    try:
        entries = rcl_entries(text)
    except JavaFault as fault:
        report['analysis_status'] = ('rcl_original_json_exception' if fault.is_instance('JSONException')
                                     else 'rcl_original_exception')
        return report
    except AnalysisLimit:
        return {**report, 'analysis_status':'rcl_value_adapter_boundary'}
    except Exception:
        return {**report, 'analysis_status':'local_rcl_inspection_boundary'}
    counts = dict(install_app=0, filename=0, build_tags=0, runtime_exec=0, unknown=0)
    names = {11:'install_app', 12:'filename', 13:'build_tags', 14:'runtime_exec'}
    android = [entry for entry in entries if entry.os_type == 1]
    for entry in android:
        counts[names.get(entry.policy, 'unknown')] += 1
    report.update(analysis_status='rcl_requirements_decoded', enabled_entry_count=len(entries),
                  android_entry_count=len(android), non_android_entry_count=len(entries)-len(android),
                  android_policy_counts=counts,
                  possible_process_execution=bool(counts['install_app'] or counts['runtime_exec']))
    return report


@dataclass(repr=False)
class ExtendedDeviceState:
    # Original static field is shared and is NOT reset on each check.
    detail: str = ''


def _string_or_null(value):
    if value is not None and type(value) is not str:
        raise AnalysisLimit('observed Java String or null required')
    return value


BUILD_FIELDS = ('TAGS', 'PRODUCT', 'MANUFACTURER', 'BRAND', 'DEVICE', 'MODEL', 'HARDWARE', 'FINGERPRINT')


def _contains(text, part):
    haystack = text.encode('utf-16-le', 'surrogatepass')
    needle = part.encode('utf-16-le', 'surrogatepass')
    return any(haystack[i:i+len(needle)] == needle for i in range(0, len(haystack)+1, 2))


def extended_device_steps(state, text):
    """DeviceManagerEx.a(Context,String); context is supplied by the observer.

    Every IO/logging call is an effect; this generator never executes commands.
    Handles/processes are opaque. A runtime adapter must throw original Java
    faults, not return guessed values on denied/unavailable observations.
    """
    try:
        entries = rcl_entries(text)
        yield Effect('device_log', ('isRooted rcl',))
    except JavaFault as fault:
        if not fault.is_instance('JSONException'): raise
        return False

    for entry in entries:
        if entry.os_type != 1: continue
        description, policy = entry.description, entry.policy
        if policy == 11:
            manager = yield Effect('device_package_manager')  # outside catch
            try:
                info = yield Effect('device_application_info', (manager, description, 1))
            except JavaFault as fault:
                if not fault.is_instance('NameNotFoundException'): raise
                info = None
            yield Effect('device_log', ('isRooted POLICY_AND_INSTALLAPP',))
            if info is not None:
                name = _string_or_null((yield Effect('device_application_package_name', (info,))))
                if name:
                    state.detail = description
                    return True
            # Policy 11 continues into policy 14.

        if policy in (11, 14):
            runtime = yield Effect('device_runtime')  # outside catch
            try:
                process = yield Effect('device_runtime_exec', (runtime, description))
                state.detail = description  # BEFORE destroy/log, also on later failure
                yield Effect('device_process_destroy', (process,))
                yield Effect('device_log', ('isRooted POLICY_AND_SHALLCMD',))
                return True
            except JavaFault:
                continue

        if policy == 12:
            try:
                file = yield Effect('device_file', (description,))
                yield Effect('device_log', ('isRooted POLICY_AND_FILENAME',))
                exists = observed_bool((yield Effect('device_file_exists', (file,))))
                if exists:
                    state.detail = description
                    return True
            except JavaFault:
                continue

        if policy == 13:
            values = []
            for field in BUILD_FIELDS:
                values.append(_string_or_null((yield Effect('device_build_field', (field,)))))
            tags, product, manufacturer, brand, device, model, hardware, fingerprint = map(java_text, values)
            message = ('isRooted POLICY_AND_BUILDKEY : '+tags+' , '+product+manufacturer+
                       ' , '+brand+' , '+device+' , '+model+', '+hardware+' , '+fingerprint)
            yield Effect('device_log', (message,))
            # Only TAGS participates in the predicate; Java contains is UTF-16.
            if values[0] is not None and _contains(values[0], description):
                state.detail = description
                return True
    return False


def project_device_steps(generator, *, extended_state, standard_state=None):
    """Expand modeled checks/detail reads; preserve futures and opaque effects.

    The caller owns shared state and thread scheduling. This does NOT resolve
    oscheck_future synchronously or synthesize a native/environment result.
    """
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as finished:
            return finished.value
        pending = None
        try:
            if effect.kind == 'device_check' and effect.args[0] == 'extended':
                value = yield from extended_device_steps(extended_state, effect.args[1])
            elif effect.kind == 'device_detail' and effect.args == ('extended',):
                value = extended_state.detail
            elif standard_state is not None and effect.kind == 'device_check' and effect.args[0] == 'standard':
                from .codeguard_standard_device import standard_device_steps
                value = yield from standard_device_steps(standard_state, effect.args[1])
            elif standard_state is not None and effect.kind == 'device_detail' and effect.args == ('standard',):
                value = standard_state.detail
            else:
                value = yield effect
        except Exception as fault:
            pending = fault  # same object; original generator decides catch scope


def project_extended_device_steps(generator, *, state):
    """Only Ex expansion; standard remains an explicit observation as before."""
    return project_device_steps(generator, extended_state=state)
