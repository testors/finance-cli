"""Bounded ApplicationPackageManager getApplicationInfo client flow, offline.

Binder/cache policy, PackageManager acquisition, ABI adjustment and StrictMode
actions remain explicit effects. No package visibility/UID or clean state is
invented. A shell lookup is NOT an ApplicationPackageManager observation.
"""
from dataclasses import dataclass

from .codeguard_effects import Effect, JavaFault, observed_bool
from .codeguard_rule import AnalysisLimit


@dataclass(repr=False)
class ApplicationManagerState:
    context: object
    # Original mUserUnlocked cache, owned per ApplicationPackageManager instance.
    user_unlocked: bool = False


def _int32(value):
    if type(value) is not int or not -2**31 <= value < 2**31:
        raise AnalysisLimit('observed Java int required')
    return value


def implicit_direct_boot_steps(manager, user_id):
    if observed_bool((yield Effect('pm_strictmode_implicit_direct_boot_enabled'))):
        own_user = _int32((yield Effect('pm_process_user_id')))
        is_own = user_id == own_user
        if is_own and observed_bool(manager.user_unlocked): return
        unlocked = observed_bool((yield Effect('pm_is_user_unlocking_or_unlocked', (manager.context, user_id))))
        if unlocked:
            if is_own: manager.user_unlocked = True
        else:
            yield Effect('pm_on_implicit_direct_boot')


def application_info_steps(manager, name, flags):
    """ApplicationPackageManager.getApplicationInfo(String,int).

    Applies only to an explicitly identified framework manager, not every custom
    PackageManager implementation. Cache effect includes framework RemoteException
    translation. A genuinely observed null cache result becomes NameNotFound;
    unknown/permission/transport failures must be thrown, NEVER supplied as null.
    """
    if not isinstance(manager, ApplicationManagerState) or type(name) is not str:
        raise AnalysisLimit('explicit ApplicationPackageManager/String observation required')
    flags = _int32(flags)  # int->long SIGN extension, not unsigned conversion
    user_id = _int32((yield Effect('pm_context_user_id', (manager.context,))))
    # updateFlagsForApplication -> updateFlagsForPackage: returns flags unchanged.
    if flags & 15 and not flags & 269221888:
        yield from implicit_direct_boot_steps(manager, user_id)
    info = yield Effect('pm_application_info_cached', (name, flags, user_id))
    if info is None:
        raise JavaFault('NameNotFoundException', message=name,
                        java_string='android.content.pm.PackageManager$NameNotFoundException: '+name)
    # Do not skip ABI/VM/property/copy operations merely because caller only
    # needs packageName. Their faults occur before getApplicationInfo returns.
    return (yield Effect('pm_maybe_adjust_application_info', (info,)))


def project_application_info_steps(generator):
    """Expand device_application_info only for explicit framework manager state.

    Context acquisition and real cache/Binder observations remain unresolved;
    this adapter does not create an Android context or adopt another app's UID.
    """
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as finished:
            return finished.value
        pending = None
        try:
            if effect.kind == 'device_application_info' and isinstance(effect.args[0], ApplicationManagerState):
                value = yield from application_info_steps(*effect.args)
            else:
                value = yield effect
        except Exception as fault:
            pending = fault
