"""Giro task configuration and explicit phone/build input transformations.

These are application settings, not successful environment observations. No
phone, host identifier, clock, preference, socket or security check is read.
Creating a task does not reset the longer-lived Agent/MainService state.
"""
from .codeguard_effects import Effect, JavaFault
from .codeguard_flow import java_text
from .codeguard_rule import AnalysisLimit
from .codeguard_worker import WorkerSettings
from .protocol import APP_VERSION


def _string(value):
    if value is not None and type(value) is not str:
        raise AnalysisLimit('explicit Java String or null observation required')
    return value


def giro_task_settings(*, etc_data):
    """Settings after the normal manager configures a NEW task for version 209.

    etc_data is the actual phone helper result; there is deliberately no
    default. The flags describe this task's configured calls, not a clean
    device. Agent root_check and native checks remain separate and enabled.
    """
    return WorkerSettings(etc_data=_string(etc_data), rooting_info=None,
                          task_info=None, encrypted_token=False, short_error=False,
                          server_url_to_ip=False, max_timeout=10000 * 10,
                          so_list=None, app_info='IGIROMOBILE', version=APP_VERSION + '_209')


def giro_task_checks():
    """Fresh task render flags. Does not change native or OSCheck conditions."""
    return dict(debugging=False, emulator=False, odex=False)


def phone_number_steps(context):
    """Phone helper; service acquisition includes the TelephonyManager cast.

    A null service is still passed to the method-call effect: its exception
    must not be mistaken for a null phone number or a SecurityException.
    """
    try:
        manager = yield Effect('telephony_service', (context, 'phone'))
        value = _string((yield Effect('telephony_line1_number', (manager,))))
        return value.replace('+82', '0') if value is not None else None
    except JavaFault as fault:
        if not fault.is_instance('SecurityException'):
            raise
        # The logger is inside the catch, not inside another catch. A logger
        # failure propagates. No actual message is printed by this generator.
        yield Effect('phone_security_log', (fault,))
        return ''


def build_string_steps():
    """The three Build strings read once at MainService construction.

    The attempted '#' replacement discards its returned String. Preserve '#'
    and null append semantics. Callers retain the result with that instance;
    reusing MainService does not re-read these values on every token request.
    """
    try:
        model = _string((yield Effect('build_string_field', ('MODEL',))))
        build_id = _string((yield Effect('build_string_field', ('ID',))))
        release = _string((yield Effect('build_string_field', ('RELEASE',))))
        return '/'.join(java_text(value) for value in (model, build_id, release))
    except JavaFault as fault:
        yield Effect('build_exception_log', (fault,))
        return ''  # assignment happens only after all three appends
