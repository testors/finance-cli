"""Agent initialization jobs and worker routing with explicit scheduling/IO.

No thread, network or environment executor is installed. One runtime models
one Agent/class lifetime. Initial-update and MainService Updaters are separate;
certificate/key material and MainService's static status log are shared.
"""
from dataclasses import dataclass, field

from .codeguard_effects import Effect, JavaFault, LinkFault, observed_bool
from .codeguard_flow import java_text
from .codeguard_main import MainServiceProcess, new_updater, project_main_service_steps
from .codeguard_package import check_zip_steps
from .codeguard_rule import AnalysisLimit
from .codeguard_updater import AgentMaterial, check_update_steps, runtime_fault
from .codeguard_worker import AgentCallState, agent_call_steps, agent_update_steps


@dataclass(repr=False)
class AgentRuntime:
    call: AgentCallState = field(default_factory=lambda: AgentCallState(
        None, None, None, None, None, True, False, False, False, '0', None))
    material: AgentMaterial = field(default_factory=lambda: AgentMaterial(None, None, '', False, ''))
    main: MainServiceProcess = field(default_factory=MainServiceProcess)
    context: object = None
    updater: object = None
    update_url: str | None = None
    handler: object = None
    message_what: int = 0
    listener: object = None
    update_status: bool = False
    max_timeout: int = 10000

    def set_max_timeout(self, value):
        if type(value) is not int or not -2**31 <= value < 2**31:
            raise AnalysisLimit('observed Java timeout int required')
        self.max_timeout = (value * 10 + 2**31) % 2**32 - 2**31


@dataclass(repr=False, eq=False)
class AgentInitWork:
    """Retain and resume the SAME steps generator after a scheduling pause.

    Only timeout/resolve_ip are captured by the update job. Other properties
    refer to the shared Agent, including callbacks and the current Updater.
    Mutations between yielded effects describe explicit schedules, not a
    claim about visibility of unsynchronized fields on a particular runtime.
    """
    runtime: AgentRuntime
    kind: str
    timeout: int
    resolve_ip: bool = False
    phase: str = field(default='created', init=False)

    @property
    def context(self): return self.runtime.context
    @property
    def app_info(self): return self.runtime.call.app_info
    @property
    def version(self): return self.runtime.call.version
    @property
    def server_url(self): return self.runtime.update_url
    @server_url.setter
    def server_url(self, value): self.runtime.update_url = value
    @property
    def handler(self): return self.runtime.handler
    @handler.setter
    def handler(self, value): self.runtime.handler = value
    @property
    def message_what(self): return self.runtime.message_what
    @property
    def listener(self): return self.runtime.listener
    @property
    def updater_present(self): return self.runtime.updater is not None
    @updater_present.setter
    def updater_present(self, value):
        if value is not True or self.runtime.updater is None:
            raise AnalysisLimit('Updater creation did not establish the shared reference')

    def steps(self):
        if self.phase != 'created':
            raise AnalysisLimit('initialization job already started; resume its generator')
        self.phase = 'running'
        try:
            if self.kind == 'update':
                result = yield from project_agent_update_steps(agent_update_steps(self), runtime=self.runtime)
            elif self.kind == 'zip':
                try:
                    ready = yield from check_zip_steps(self.runtime, os14=False)
                    if not observed_bool(ready):
                        yield Effect('invalidate_engine_artifacts', (self.runtime.context,))
                except JavaFault:
                    yield Effect('invalidate_engine_artifacts', (self.runtime.context,))
                result = None
            else:
                raise AnalysisLimit('unknown initialization job')
        except (JavaFault, LinkFault):
            self.phase = 'threw'
            raise
        except Exception:
            self.phase = 'unresolved'
            raise
        self.phase = 'returned'
        return result


def agent_init_steps(runtime, *, context, app_info, version, update_url,
                     handler, message_what, timeout):
    """The handler overload used by the application, with IP resolution false.

    Starts ZIP then update jobs without joining either. Returning does not
    prove either job ran, nor that certificate/engine initialization succeeded.
    Allocation and unrepresented logging/Error failures are outside this model.
    """
    runtime.call.set_app_info(app_info, version)
    yield Effect('agent_app_info_log', (app_info, version))
    runtime.handler, runtime.message_what = handler, message_what
    if context is None:
        yield from runtime_fault('NullPointerException', 'Agent.init.context.toString')
    yield Effect('agent_init_context_log', (context,))
    runtime.context, runtime.update_url = context, update_url
    runtime.updater = new_updater(context)
    runtime.call.status_log = java_text(runtime.call.status_log) + ',1'
    runtime.update_status = False
    for kind in ('zip', 'update'):
        work = AgentInitWork(runtime, kind, timeout)
        thread = yield Effect('agent_thread_new', (work,))
        yield Effect('agent_thread_start', (thread, work))


def project_agent_update_steps(generator, *, runtime):
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            kind, args = effect.kind, effect.args
            value = None
            if kind == 'create_updater':
                runtime.updater = new_updater(args[0])
            elif kind == 'update_set_app_info':
                runtime.updater.app_info, runtime.updater.version = args
            elif kind == 'update_set_timeout':
                runtime.updater.timeout = args[0]
            elif kind == 'update_set_context':
                runtime.updater.context = args[0]
            elif kind == 'update_set_url':
                runtime.updater.url = args[0]
            elif kind == 'check_update':
                # This particular invocation retains its receiver across IO,
                # even if another init replaces runtime.updater meanwhile.
                value = yield from check_update_steps(runtime.updater, runtime.material, runtime.main)
            elif kind == 'read_update_status':
                value = runtime.updater.status  # read current shared receiver again
            else:
                value = yield effect
        except Exception as fault:
            pending = fault


def project_agent_worker_steps(generator, *, runtime):
    """Connect worker setters and generateToken to retained Agent/Main state.

    Task construction/configuration, queue callbacks and platform/provider
    effects remain separate. This does not infer a successful token from the
    worker's boolean return or from an initial-update completion notification.
    """
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            kind, args = effect.kind, effect.args
            value = None
            if kind == 'set_agent_context':
                runtime.context = args[0]
            elif kind == 'set_agent_short_error':
                runtime.call.short_error = observed_bool(args[0])
            elif kind == 'set_agent_encrypted_token':
                runtime.call.encrypted_token = observed_bool(args[0])
            elif kind == 'set_agent_field':
                name, data = args
                if name == 'rooting_info':
                    runtime.call.set_rooting_info(data)
                elif name in ('etc_data', 'task_info'):
                    setattr(runtime.call, name, data)
                else:
                    raise AnalysisLimit('unknown Agent setter')
            elif kind == 'task_max_timeout':
                value = runtime.max_timeout
            elif kind == 'agent_context':
                value = runtime.context
            elif kind == 'agent_generate_token':
                call = agent_call_steps(runtime.call, context=args[0], server_url=args[1],
                                        timeout=None, shared_reads=True)
                call = project_main_service_steps(call, process=runtime.main, agent=runtime.material)
                value = yield from project_agent_worker_steps(call, runtime=runtime)
            else:
                value = yield effect
        except Exception as fault:
            pending = fault
