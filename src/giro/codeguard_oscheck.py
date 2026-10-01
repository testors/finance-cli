"""OSCheck callable/Future composition over explicit scheduling observations.

No thread, clock, command or environment executor is installed. A caller may
advance each work generator only at its observed scheduling points. Timeout
does not complete, cancel or replace that work. Crypto uses the existing pure
normal-path arithmetic; Java crypto-provider/allocation failures are not
inferred from Python failures and remain outside this bounded composition.
"""
from dataclasses import dataclass, field

from .codeguard_device import extended_device_steps, _string_or_null
from .codeguard_effects import Effect, JavaFault, LinkFault, observed_bool
from .codeguard_response import oscheck_steps
from .codeguard_rule import AnalysisLimit
from .codeguard_standard_device import standard_device_steps


def _java(name, *args):
    return Effect('oscheck_java', (name, *args))


def _scope_device(generator, work, context):
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            # Context and work identity travel with each IO effect. Two workers
            # may be suspended simultaneously; there is no global current job.
            value = yield Effect('oscheck_device', (work, context, effect))
        except Exception as fault:
            pending = fault


@dataclass(repr=False, eq=False)
class OSCheckWork:
    owner: object
    challenge: str | None
    root_check: bool
    rooting_info: bool
    fourth: str | None
    rcl: str | None
    extended_state: object
    standard_state: object
    phase: str = field(default='created', init=False)
    value: str | None = field(default=None, init=False)
    failure: object = field(default=None, init=False)

    def _body(self):
        generator = oscheck_steps(self.owner, challenge=self.challenge,
            root_check=self.root_check, rooting_info=self.rooting_info,
            fourth=self.fourth, rcl=self.rcl, shared_reads=True)
        value, pending = None, None
        while True:
            try:
                effect = generator.throw(pending) if pending is not None else generator.send(value)
            except StopIteration as done:
                return done.value
            pending = None
            try:
                if effect.kind == 'device_check':
                    manager, options = effect.args
                    # Static context is read by the running callable, not by
                    # its constructor or the response thread at submission.
                    context = yield _java('main.staticContext', self)
                    checker = (extended_device_steps(self.extended_state, options)
                               if manager == 'extended' else
                               standard_device_steps(self.standard_state, options))
                    value = yield from _scope_device(checker, self, context)
                elif effect.kind == 'device_detail':
                    manager = effect.args[0]
                    shared = self.extended_state if manager == 'extended' else self.standard_state
                    value = _string_or_null((yield _java('device.detail', manager, shared)))
                elif effect.kind == 'oscheck_detail_enabled':
                    value = yield _java('main.detailEnabled', self.owner)
                else:
                    value = yield effect
            except Exception as fault:
                pending = fault

    def steps(self):
        """Start ONCE, then retain/resume this same generator after suspension.

        Java/Link faults belong to the worker. Future.get wrapping is a separate
        observation; a Python/analysis failure must never become ExecutionException.
        """
        if self.phase != 'created':
            raise AnalysisLimit('OSCheck callable already started; resume its generator')
        self.phase = 'running'
        try:
            value = yield from self._body()
        except (JavaFault, LinkFault) as fault:
            self.phase, self.failure = 'threw', fault
            raise
        except Exception:
            self.phase = 'unresolved'
            raise
        self.value, self.phase = _string_or_null(value), 'returned'
        return self.value


@dataclass(frozen=True, repr=False)
class CompletedOSCheck:
    """An observed successful get of THIS computed callable's result."""
    work: OSCheckWork


def oscheck_future_steps(owner, *, root_check, rooting_info, timeout,
                         extended_state, standard_state):
    """Executor creation, constructor capture, submit and timed get in order.

    Constructor field observations happen after executor creation. The work
    retains those inputs even if the owner's challenge fields change later.
    No thread starts simply by constructing the generator/work description.
    """
    root_check, rooting_info = observed_bool(root_check), observed_bool(rooting_info)
    if type(timeout) is not int or not -2**63 <= timeout < 2**63:
        raise AnalysisLimit('observed Future timeout long required')
    executor = yield _java('executors.newSingleThreadExecutor')
    captured = []
    for field_name in ('challenge', 'fourth', 'rcl_suffix'):
        captured.append(_string_or_null((yield _java('challenge.field', owner, field_name))))
    work = OSCheckWork(owner, captured[0], root_check, rooting_info, captured[1], captured[2],
                       extended_state, standard_state)
    callable_ref = yield _java('callable.new', work)
    future = yield _java('executor.submit', executor, callable_ref, work)
    result = yield _java('future.get', future, timeout, 'MILLISECONDS', work)
    if not isinstance(result, CompletedOSCheck) or result.work is not work or work.phase != 'returned':
        raise AnalysisLimit('successful Future.get requires this completed OSCheck work')
    return work.value


def project_oscheck_steps(generator, *, owner, extended_state, standard_state):
    """Expand the coarse OSCheck effect for the SAME MainService owner.

    Early string snapshots in that coarse effect are replaced by explicit
    constructor field reads at their actual positions. Flags were evaluated
    before executor creation and remain captured. Scheduling and later shared
    field visibility remain explicit, including after a timed-out get.
    """
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            if effect.kind == 'oscheck_future':
                _, root_check, rooting_info, _, _, timeout = effect.args
                value = yield from oscheck_future_steps(owner,root_check=root_check,
                    rooting_info=rooting_info,timeout=timeout,
                    extended_state=extended_state,standard_state=standard_state)
            elif effect.kind == 'read_detail_enabled':
                value = yield _java('main.detailEnabled', owner)
            elif effect.kind == 'device_detail':
                manager = effect.args[0]
                if manager not in ('extended','standard'):
                    raise AnalysisLimit('unrecognized device manager')
                shared = extended_state if manager == 'extended' else standard_state
                value = _string_or_null((yield _java('device.detail', manager, shared)))
            else:
                value = yield effect
        except Exception as fault:
            pending = fault
