"""Offline DeviceManager.b(Context,String) and ExecShell model.

Do not execute these effects automatically: the original attempts Runtime.exec
even with an empty option list. No subprocess, package manager or filesystem IO
is implemented here; missing/denied observations are not clean check results.
"""
from dataclasses import dataclass

from .codeguard_device import _string_or_null, _contains
from .codeguard_effects import Effect, JavaFault, LinkFault, observed_bool
from .codeguard_flow import java_text


@dataclass(repr=False)
class StandardDeviceState:
    detail: str = ''


PACKAGES = ('s.spapafree.freebank', 'eu.chainfire.supersu', 'com.stump',
            'com.geohot.towelroot', 'spapa.spapasu.freesu')


def _debug_log(message):
    if observed_bool((yield Effect('device_log_debug_enabled'))):
        yield Effect('device_log', (message,))


def _close_streams(reader, writer):
    try:
        yield Effect('device_reader_close', (reader,))
        yield Effect('device_writer_close', (writer,))
    except JavaFault as fault:
        if not fault.is_instance('IOException'): raise
        # Reader failure skips writer; not two independent finally blocks.


def which_su_steps():
    """ExecShell result is None only for the initial Runtime/exec Exception.

    Empty list counts as a nonnull success in caller b(). Constructor, destroy,
    log and non-IO close faults propagate. Read faults retain partial lines.
    Original printStackTrace is an effect, never written to Python stderr.
    """
    lines = []
    try:
        runtime = yield Effect('device_runtime')
        process = yield Effect('device_runtime_exec_array', (runtime, ('/system/xbin/which', 'su')))
    except JavaFault:
        return None
    output = yield Effect('device_process_output_stream', (process,))
    writer = yield Effect('device_buffered_default_writer', (output,))
    input_stream = yield Effect('device_process_input_stream', (process,))
    reader = yield Effect('device_buffered_default_reader', (input_stream,))
    try:
        while True:
            line = _string_or_null((yield Effect('device_reader_line', (reader,))))
            if line is None: break
            yield from _debug_log('--> Line received: '+line)
            lines.append(line)
    except JavaFault as fault:
        try:
            yield Effect('device_print_stack_trace', (fault,))
        except (JavaFault, LinkFault):
            yield from _close_streams(reader, writer)
            raise
    except LinkFault:
        yield from _close_streams(reader, writer)
        raise
    yield from _close_streams(reader, writer)
    yield Effect('device_process_destroy', (process,))
    yield Effect('device_log', ('--> Full response was: ['+', '.join(lines)+']',))
    return lines


def _su_or_packages(state):
    runtime = yield Effect('device_runtime')  # outside catch, unlike ExecShell
    try:
        process = yield Effect('device_runtime_exec', (runtime, 'su'))
        yield Effect('device_process_destroy', (process,))
        state.detail = 'run su'  # AFTER destroy, unlike DeviceManagerEx
        return True
    except JavaFault:
        pass
    for name in PACKAGES:
        manager = yield Effect('device_package_manager')  # also outside catch
        try:
            yield Effect('device_application_info', (manager, name, 1))
        except JavaFault:
            continue
        state.detail = name  # result isn't inspected, even if null
        return True
    return False


def _file_check(state, path):
    try:
        file = yield Effect('device_file', (path,))
        if observed_bool((yield Effect('device_file_exists', (file,)))):
            state.detail = path
            return True
    except JavaFault:
        pass
    return False


def _lagfix_check(state):
    if observed_bool((yield Effect('device_context_present'))):
        try:
            manager = yield Effect('device_package_manager')
            yield Effect('device_package_info', (manager, 'com.tegrak.lagfix', 1))
            state.detail = 'com.tegrak.lagfix'
            return True
        except JavaFault:
            pass
    return False


def standard_device_steps(state, options):
    """Always su/packages first; options select 0..4 in fixed order, not input order.

    None selects all five, '' selects none after the mandatory prefix. The
    a(Context) convenience overload supplies '0234'; b(Context,String) does NOT
    default an empty/null argument to that string.
    """
    options = _string_or_null(options)
    yield from _debug_log('osCheckList: '+java_text(options))
    if (yield from _su_or_packages(state)): return True
    for option in '01234':
        if options is not None and option not in options: continue
        if option == '0':
            result = yield from _file_check(state, '/system/app/Superuser.apk')
        elif option == '1':
            result = (yield from which_su_steps()) is not None
            if result: state.detail = '/system/xbin/which su'
        elif option == '2':
            tags = _string_or_null((yield Effect('device_build_field', ('TAGS',))))
            result = tags is not None and _contains(tags, 'test-keys')
            if result: state.detail = 'test-keys'
        elif option == '3':
            result = yield from _lagfix_check(state)
        else:
            result = yield from _file_check(state, '/system/app/userSU.apk')
        if result: return True
        if options is not None:
            yield from _debug_log('osCheck '+option+' ok')
    return False
