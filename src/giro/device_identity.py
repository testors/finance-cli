"""Device identity selection from explicit application observations.

No host ID, random ID, preference access, phone API or network is provided.
This models selection and persistence ordering; it does not prove that an
identity belongs to a registered device. Effects never expose values in repr.
"""
from dataclasses import dataclass

from .codeguard_effects import Effect, JavaFault
from .codeguard_rule import AnalysisLimit


@dataclass(repr=False)
class DeviceIdentityState:
    preferences: object = None


def _string(value):
    if value is not None and type(value) is not str:
        raise AnalysisLimit('explicit application String or null observation required')
    return value


def _store(state, value):
    # Adapter includes SharedPreferencesUtil.store. Its commit result is
    # ignored. A null value makes no put/remove call, but still commits.
    yield Effect('device_preference_store', (state.preferences, 'deviceId', value))
    return value


def _secure_id(state, context):
    resolver = yield Effect('device_content_resolver', (context,))
    value = _string((yield Effect('device_secure_string', (resolver, 'android_id'))))
    return (yield from _store(state, value))


def device_id_steps(state, context):
    """Common identity helper, including the exact SecurityException scope.

    The preference-read adapter includes getValue and the String cast; actual
    ClassCastException is supplied as JavaFault. Unknown inputs remain unknown.
    A cached nonempty value avoids phone access; whitespace is not trimmed.
    Empty phone IDs are returned unchanged. Null and observed SecurityException
    select Settings.Secure, but missing platform support is not such an event.
    """
    if state.preferences is None:
        preferences = yield Effect('device_preferences', (context, 'pref'))
        if preferences is None:
            raise AnalysisLimit('actual application preference object required')
        state.preferences = preferences
    cached = _string((yield Effect('device_preference_string', (state.preferences, 'deviceId'))))
    if cached is not None and cached != '':
        return cached
    # Service lookup/cast is outside the SecurityException catch.
    manager = yield Effect('device_telephony_service', (context, 'phone'))
    if manager is None:
        return (yield from _secure_id(state, context))
    try:
        value = _string((yield Effect('device_telephony_id', (manager,))))
        if value is None:
            return (yield from _secure_id(state, context))
        return (yield from _store(state, value))
    except JavaFault as fault:
        if not fault.is_instance('SecurityException'):
            raise
    return (yield from _secure_id(state, context))
