"""Application task lifetimes with explicitly dispatched work and messages.

No executor, Android runtime, environment provider or network is installed.
Effects are scheduling/IO boundaries; dispatch order must be supplied. Python
bindings represent callback routing, not platform Handler/Looper observations.
Allocation, monitor scheduling and unrepresented logging failures are outside
this model, as are framework Future cancellation and thread interruption.
"""
from dataclasses import dataclass, field

from .codeguard_agent import AgentRuntime, agent_init_steps, project_agent_worker_steps
from .codeguard_app import giro_task_checks, phone_number_steps
from .codeguard_effects import Effect, JavaFault, LinkFault, observed_bool, signed_long
from .codeguard_flow import java_text
from .codeguard_rule import AnalysisLimit
from .codeguard_task import TaskTokenState
from .codeguard_updater import runtime_fault
from .codeguard_worker import WorkerSettings, worker_steps


@dataclass(repr=False)
class ManagerConfig:
    context: object = None
    app_info: str | None = None
    version: str | None = None
    token_url: str | None = None
    update_url: str | None = None


@dataclass(repr=False)
class GuardProcess:
    agent: AgentRuntime = field(default_factory=AgentRuntime)
    manager: object = None
    task: object = None
    is_init: bool = False
    log_debug: bool = False

    def manager_instance(self, config=None):
        if self.manager is None:
            self.is_init = False
            # Copy Builder fields; later Builder changes are not manager changes.
            config = ManagerConfig() if config is None else ManagerConfig(**vars(config))
            self.manager = ManagerLifecycle(self, config)
        return self.manager

    def task_instance_steps(self):
        yield Effect('task_monitor_enter', (self,))
        try:
            if self.task is None:
                task = TaskLifecycle(self)
                yield Effect('task_constructor', (task,))
                self.task = task  # only after construction returns
            value = self.task
        except (JavaFault, LinkFault):
            yield Effect('task_monitor_exit', (self,))
            raise
        # Missing observations do not establish a Java failure/monitor cleanup.
        yield Effect('task_monitor_exit', (self,))
        return value


@dataclass(repr=False, eq=False)
class ManagerHandler:
    manager: object
    kind: str
    listener: object = None

    def message_steps(self, what=None, payload=None):
        """Delivery ignores both fields, including messages from an older task."""
        manager = self.manager
        if self.kind == 'update':
            if manager.update_listener is not None:
                yield Effect('manager_update_listener', (manager.update_listener,))
        elif self.kind == 'token':
            manager.token = ''
            if manager.task is not None:
                manager.token = yield from manager.task.get_token_steps()
            if self.listener is not None:
                yield Effect('manager_token_listener', (self.listener, manager.token))
        else:
            raise AnalysisLimit('unknown manager message binding')


@dataclass(repr=False, eq=False)
class ManagerLifecycle:
    process: GuardProcess
    config: ManagerConfig
    task: object = None
    token: str | None = ''
    update_listener: object = None
    task_listener: object = None  # setter field; getToken captures its argument instead
    update_what: int = 100
    task_what: int = 200

    def init_steps(self):
        self.process.log_debug = False  # application logging setting only
        config = self.config
        if config.context is None:
            yield from runtime_fault('Exception', 'CgManager.init.context')
        context, app, version, url = config.context, config.app_info, config.version, config.update_url
        handler = ManagerHandler(self, 'update')
        yield Effect('manager_handler_new', (handler,))
        yield from agent_init_steps(self.process.agent, context=context, app_info=app,
            version=version, update_url=url, handler=handler, message_what=self.update_what, timeout=5000)
        self.process.is_init = True  # says nothing about either initialization job

    def close_steps(self):
        if self.task is not None:
            yield from self.task.close_steps()  # keep self.task; do not cancel work

    def get_token_steps(self, *, context, listener):
        yield from self.close_steps()  # deliberately outside catch(Exception)
        try:
            self.task = yield from self.process.task_instance_steps()
            task = self.task
            app, version = self.config.app_info, self.config.version
            yield Effect('task_log', ('set_app_info',))
            agent = self.process.agent
            agent.call.set_app_info(app, version)
            yield Effect('agent_app_info_log', (app, version))
            agent.context = context
            task.settings.app_info, task.settings.version = app, version
            task.state.context = context
            yield Effect('task_log', ('set_app_info_thread',))
            self.task.state.server_url = self.config.token_url
            self.task.settings.server_url_to_ip = False
            self.process.agent.set_max_timeout(10000)
            task = self.task  # setEtcData receiver is captured BEFORE the phone call
            task.settings.etc_data = yield from phone_number_steps(context)
            task = self.task  # setHandler receiver is captured before allocation
            handler = ManagerHandler(self, 'token', listener)
            yield Effect('manager_handler_new', (handler,))
            task.handler, task.message_what = handler, self.task_what
            yield from self.task.execute_steps(context)
        except JavaFault as fault:
            yield Effect('manager_exception_trace', (fault,))
            yield Effect('manager_exception_log', (fault,))
            if listener is not None:
                yield Effect('manager_token_listener', (listener, ''))


@dataclass(repr=False, eq=False)
class TaskLifecycle:
    process: GuardProcess
    state: TaskTokenState = field(default_factory=lambda: TaskTokenState(
        None, -1, '', None, '', None, None, '', started_ms=0))
    settings: WorkerSettings = field(default_factory=lambda: WorkerSettings(
        None, None, None, False, False, False, 10000, None, None, None))
    checks: dict = field(default_factory=giro_task_checks)
    handler: object = None
    message_what: int = 0
    listener: object = None
    status: str = 'PENDING'

    def clear_steps(self):
        yield Effect('task_log', ('clear',))
        self.state.clear()
        self.process.task = None  # unconditional, even when it points at another task

    def close_steps(self):
        yield Effect('task_log', ('close',))
        yield from self.clear_steps()

    def execute_steps(self, context):
        if self.status != 'PENDING':
            yield from runtime_fault('IllegalStateException', 'Task.execute.status')
        self.status = 'RUNNING'
        yield Effect('task_log', ('pre_execute',))
        self.state.token = None
        work = TaskWork(self, context)
        yield Effect('task_executor_execute', (work,))
        return self

    def render_steps(self):
        state = self.state
        value = state.token
        if value is None or value == '':
            agent_log, task_log = self.process.agent.call.status_log, state.task_log
            if state.status_code in (101, 102):
                kind, label = ('REFUSED', 'Refused') if state.status_code == 101 else ('TIMEOUT', 'Timeout')
                model = yield Effect('build_string_field', ('MODEL',))
                release = yield Effect('build_string_field', ('RELEASE',))
                detail = ('CG_CONN_' + kind + '(agent:' + java_text(agent_log) + '&&' + java_text(task_log) +
                          ')' + java_text(model) + '(' + java_text(release) + ')url:' + java_text(state.server_url))
                args = ('CG_CONN_' + kind + '01', 'Connection ' + label, detail)
            else:
                if state.status_message is None:
                    state.status_message = 'Connection Engine Error'
                args = ('CG_CONN_ENGINE01', state.status_message, 'CG_CONN_ENGINE')
            value = yield Effect('format_local_error', args)
        for name, message, bad_when in (('debugging', 'isDebuggging', True),
                                       ('emulator', 'isEmulator', True), ('odex', 'isOdexModify', False)):
            if observed_bool(self.checks[name]):
                args = (name, state.context) if name == 'odex' else (name,)
                if observed_bool((yield Effect('task_environment_check', args))) is bad_when:
                    value = yield Effect('format_local_error', ('CG_CONN_ENGINE01', message, 'CG_CONN_ENGINE'))
        return value

    def get_token_steps(self):
        yield Effect('task_log', ('get_token',))
        value = yield from self.render_steps()
        yield from self.clear_steps()  # not finally; formatting/check failure keeps token
        return value

    def finish_steps(self, result, *, cancelled):
        """Explicit framework finish dispatch, not a cancel/Future implementation.

        Callback failure leaves status RUNNING. False/null result still sends
        the same callback signal. There is no invented worker-to-UI schedule.
        """
        if observed_bool(cancelled):
            yield Effect('task_log', ('cancelled',))
            self.process.task = None
            self.state.token = None
        else:
            if result is None:
                yield Effect('task_log', ('post_null_result',))
            now = yield Effect('clock_ms')
            self.state.started_ms = signed_long(now - self.state.started_ms)
            yield Effect('task_log', ('post_execute',))
            if self.handler is not None:
                what = self.message_what
                value = yield from self.render_steps()
                yield Effect('task_send_message', (self.handler, what, value))  # boolean ignored
            if self.listener is not None:
                yield Effect('task_listener', (self.listener, 1))
        self.status = 'FINISHED'


@dataclass(repr=False, eq=False)
class TaskWork:
    task: TaskLifecycle
    context: object
    phase: str = field(default='created', init=False)

    def steps(self):
        if self.phase != 'created':
            raise AnalysisLimit('task work already started; resume its generator')
        self.phase = 'running'
        try:
            self.task.settings.max_timeout = self.task.process.agent.max_timeout
            result = yield from project_agent_worker_steps(worker_steps(
                self.task.state, self.task.settings, context=self.context), runtime=self.task.process.agent)
        except (JavaFault, LinkFault):
            self.phase = 'threw'
            raise
        except Exception:
            self.phase = 'unresolved'
            raise
        self.phase = 'returned'
        return result  # separate from framework result posting and finish dispatch
