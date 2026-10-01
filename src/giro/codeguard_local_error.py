"""Known local error values, never a server-issued authentication token.

Clock and map profile are explicit inputs. These conversions neither perform
security checks nor establish token issuance. No host clock or runtime is read.
The selected map profile describes value ordering only, not a device identity.
"""
from .android_json import JSONObject, java_text
from .codeguard_effects import Effect, java_length, signed_long
from .codeguard_flow import java_substring
from .codeguard_rule import AnalysisLimit
from .codeguard_updater import runtime_fault


# Iteration order of a fresh default HashMap with these five fixed String
# keys inserted in the application order. This is not a general HashMap.
_KEY_ORDERS = {
    'aosp-6-7': ('CODE_RESPONSE', 'CODE_GUARD_OS_RESULT', 'CODE_APP_INFO',
                 'CG_SIGNATURE', 'CG_VALIDTO'),
    'aosp-8': ('CODE_APP_INFO', 'CODE_GUARD_OS_RESULT', 'CODE_RESPONSE',
               'CG_VALIDTO', 'CG_SIGNATURE'),
}


def local_error_fields(code, message, detail, *, now_ms):
    """Return five values; CG_VALIDTO is an error timestamp, not server TTL.

    Map insertion of null code/message retains JSON null through wrap().
    Null detail needs the explicit runtime failure path in local_error_steps.
    Truncation counts UTF-16 units and preserves any split surrogate halves.
    """
    if any(value is not None and type(value) is not str for value in (code, message, detail)):
        raise AnalysisLimit('local error requires known String or null values')
    if detail is None:
        raise AnalysisLimit('null local error detail needs runtime fault observation')
    if type(now_ms) is not int or not -2**63 <= now_ms < 2**63:
        raise AnalysisLimit('explicit Java epoch millisecond long required')
    valid_to = str(signed_long(now_ms + 1800000))
    for _ in range(2):
        size = java_length(detail)
        if size > 200:
            detail = java_substring(detail, 0, 100) + '--' + java_substring(detail, size-100)
    return {'CODE_APP_INFO': code, 'CODE_GUARD_OS_RESULT': 'UNKNOWN',
            'CODE_RESPONSE': message, 'CG_VALIDTO': valid_to, 'CG_SIGNATURE': detail}


def format_local_error(code, message, detail, *, now_ms, map_profile):
    """Serialize the known String/null subset using an explicit map profile."""
    if type(map_profile) is not str or map_profile not in _KEY_ORDERS:
        raise AnalysisLimit('local error map ordering profile is unresolved')
    values = local_error_fields(code, message, detail, now_ms=now_ms)
    return java_text(JSONObject({key: values[key] for key in _KEY_ORDERS[map_profile]}))


def local_error_steps(code, message, detail, *, map_profile):
    now = yield Effect('clock_ms')  # Date().getTime precedes detail.length()
    if detail is None:
        yield from runtime_fault('NullPointerException', 'formatToken.detail.length')
    return format_local_error(code, message, detail, now_ms=now, map_profile=map_profile)


def project_local_error_steps(generator, *, map_profile):
    """Compose only local formatting; all clock, IO and check effects remain."""
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            if effect.kind == 'format_local_error':
                value = yield from local_error_steps(*effect.args, map_profile=map_profile)
            else:
                value = yield effect
        except Exception as fault:
            pending = fault
