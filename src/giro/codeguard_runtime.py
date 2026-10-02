"""Python protection execution over an explicitly supplied platform.

Owns scheduling, callbacks and process state; does not discover a device or
enable CLI login. The memory platform is a declared simulation. Python native
bindings execute the independent calculations, not an Android library loader.
Unknown provider failures propagate as processing errors, never SDK tokens.
"""
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError, wait
from dataclasses import dataclass
from threading import Lock, RLock, Thread, local
from time import monotonic

from .android_headers import project_header_values_steps
from .codeguard_crypto import project_crypto_steps
from .codeguard_device import ExtendedDeviceState
from .codeguard_effects import JavaFault, LinkFault
from .codeguard_http import project_http_steps
from .codeguard_http_values import decode_values_steps
from .codeguard_lifecycle import GuardProcess
from .codeguard_local_error import project_local_error_steps
from .codeguard_oscheck import CompletedOSCheck, oscheck_future_steps
from .codeguard_package import project_package_steps
from .codeguard_rule import AnalysisLimit
from .codeguard_simulation import run_simulation_steps
from .codeguard_standard_device import StandardDeviceState
from .codeguard_string_values import project_native_value_steps
from .login import ProtectionRuntime


@dataclass(repr=False)
class RuntimeJob:
    kind: str
    work: object
    future: Future
    thread: Thread


_LOGS = frozenset(('task_log', 'agent_app_info_log', 'agent_init_context_log',
    'main_app_info_log', 'main_load_log', 'manager_exception_trace',
    'manager_exception_log', 'build_exception_log', 'phone_security_log'))


class PythonProtectionRuntime(ProtectionRuntime):
    """One process lifetime and serial public calls, with asynchronous workers.

    initialize() returns after starting two jobs, without joining them. token()
    waits for the manager callback, including local error/empty forms. Work and
    OSCheck errors are not translated into successful callback values. The
    supplied HTTP transport/crypto/platform retain their own explicit policies.
    Caller owns the transport and must close this runtime before closing it.
    """
    def __init__(self, *, config, platform, transport, crypto, locale_language, map_profile):
        self.process = GuardProcess()
        self.manager = self.process.manager_instance(config)
        self.platform, self.transport, self.crypto = platform, transport, crypto
        self.locale_language, self.map_profile = locale_language, map_profile
        self.extended, self.standard = ExtendedDeviceState(), StandardDeviceState()
        self.jobs, self.events = [], []  # no effect arguments or secret values
        self._jobs_lock, self._calls = Lock(), Lock()
        self._monitors = {name: RLock() for name in ('task', 'main', 'package')}
        self._held = local()
        self._ui = ThreadPoolExecutor(max_workers=1, thread_name_prefix='cg-callback')
        self._closed, self._pending = False, None
        platform.bind(self.process)

    def run(self, steps):
        steps = project_native_value_steps(steps, service=self.platform.service, certificate_values=True)
        steps = project_package_steps(steps, certificate_values=True)
        steps = project_local_error_steps(steps, map_profile=self.map_profile)
        steps = project_crypto_steps(steps, crypto=self.crypto)
        steps = decode_values_steps(project_header_values_steps(steps), locale_language=self.locale_language)
        held = getattr(self._held, 'locks', None)
        if held is None:
            held = self._held.locks = []
        depth = len(held)
        try:
            return run_simulation_steps(project_http_steps(steps, transport=self.transport),
                                        self.resolve, max_effects=None)
        finally:
            # Python resource cleanup only; do not invent a modeled monitor-exit
            # observation after an unresolved provider failure.
            while len(held) > depth:
                held.pop().release()
                self.events.append('processing_monitor_cleanup')

    def _monitor(self, name, enter):
        lock = self._monitors[name]
        if enter:
            lock.acquire()
            self._held.locks.append(lock)
        else:
            self._held.locks.remove(lock)
            lock.release()

    def _start(self, kind, work, operation):
        future = Future()
        def execute():
            try:
                future.set_result(operation())
            except BaseException as error:
                future.set_exception(error)
        thread = Thread(target=execute, name='cg-' + kind, daemon=True)
        job = RuntimeJob(kind, work, future, thread)
        with self._jobs_lock:
            self.jobs.append(job)
        thread.start()
        return future

    def _ensure_open(self):
        if self._closed:
            raise RuntimeError('protection runtime is closed')

    def initialize(self):
        with self._calls:
            self._ensure_open()
            return self._ui.submit(self.run, self.manager.init_steps()).result()

    def wait_for_initialization(self, timeout=None):
        """Optional caller synchronization; never invoked by initialize/token."""
        deadline = None if timeout is None else monotonic() + timeout
        with self._jobs_lock:
            jobs = [job for job in self.jobs if job.kind in ('zip', 'update')]
        for job in jobs:
            job.future.result(None if deadline is None else max(0, deadline - monotonic()))

    def token(self, *, timeout=None):
        with self._calls:
            self._ensure_open()
            if self._pending is not None and not self._pending.done():
                raise RuntimeError('previous protection callback is still pending')
            callback = self._pending = Future()
            self._ui.submit(self.run, self.manager.get_token_steps(
                context=self.manager.config.context, listener=callback)).result()
            # A caller timeout does not cancel, clear, retry or create a token.
            return callback.result(timeout)

    def _deliver(self, callback, operation):
        try:
            return operation()
        except BaseException as error:
            if callback is not None and not callback.done():
                callback.set_exception(error)
            raise

    def resolve(self, effect):
        kind, args = effect.kind, effect.args
        self.events.append(kind)
        if kind in _LOGS or kind in ('manager_handler_new', 'task_constructor'):
            return None
        if kind in ('task_monitor_enter', 'task_monitor_exit', 'main_monitor_enter', 'main_monitor_exit'):
            return self._monitor(kind.split('_')[0], kind.endswith('enter'))
        if kind == 'package_java' and args[0] in ('monitor.enter', 'monitor.exit'):
            return self._monitor('package', args[0].endswith('enter'))
        if kind == 'main_load_library' and args[0] in ('CodeGuard', 'ImageDecoder'):
            return None  # bound to project_native_value_steps, never a no-op native check
        if kind == 'agent_thread_new':
            return args[0]
        if kind == 'agent_thread_start':
            work = args[1]
            self._start(work.kind, work, lambda: self.run(work.steps()))
            return None
        if kind == 'task_executor_execute':
            work, = args
            callback = work.task.handler.listener
            def execute():
                result = self._deliver(callback, lambda: self.run(work.steps()))
                return self._ui.submit(self._deliver, callback,
                    lambda: self.run(work.task.finish_steps(result, cancelled=False))).result()
            self._start('task', work, execute)
            return None
        if kind in ('task_send_message', 'update_send_empty_message'):
            handler = args[0]
            self._ui.submit(self._deliver, handler.listener,
                            lambda: self.run(handler.message_steps(*args[1:])))
            return True
        if kind == 'manager_token_listener':
            args[0].set_result(args[1])
            return None
        if kind in ('manager_update_listener', 'update_listener', 'task_listener'):
            return args[0](*args[1:])
        if kind == 'oscheck_future':
            _, root, rooting, _, _, timeout = args
            return self.run(oscheck_future_steps(self.process.agent.main.instance.response,
                root_check=root, rooting_info=rooting, timeout=timeout,
                extended_state=self.extended, standard_state=self.standard))
        if kind == 'oscheck_java':
            return self._oscheck(*args)
        if kind == 'oscheck_device':
            return self.platform.resolve(args[2])
        if kind == 'read_detail_enabled':
            return self.process.agent.main.instance.response.detail_enabled
        if kind == 'device_detail':
            if args[0] not in ('extended', 'standard'):
                raise AnalysisLimit('unknown device manager')
            return (self.extended if args[0] == 'extended' else self.standard).detail
        return self.platform.resolve(effect)

    def _oscheck(self, name, *args):
        if name == 'executors.newSingleThreadExecutor':
            return object()
        if name == 'challenge.field':
            return getattr(args[0].challenge, args[1])
        if name == 'callable.new':
            return args[0]
        if name == 'executor.submit':
            work = args[2]
            return self._start('oscheck', work, lambda: self.run(work.steps()))
        if name == 'future.get':
            future, timeout, unit, work = args
            done, _ = wait((future,), timeout=max(0, timeout) / 1000)
            if not done:
                raise JavaFault('TimeoutException', message=None,
                                java_string='java.util.concurrent.TimeoutException')
            try:
                future.result()
            except (JavaFault, LinkFault):
                raise JavaFault('ExecutionException', message=None,
                                java_string='java.util.concurrent.ExecutionException') from None
            return CompletedOSCheck(work)
        if name == 'main.staticContext':
            return self.process.agent.main.context
        if name == 'main.detailEnabled':
            return args[0].detail_enabled
        if name == 'device.detail':
            return args[1].detail
        raise AnalysisLimit('unknown OSCheck scheduling effect')

    def close(self, timeout=10):
        """Drain owned work without cancelling late checks or closing transport."""
        with self._calls:
            self._closed = True
            deadline = monotonic() + timeout
            # Running task workers may create OSCheck workers before returning.
            while True:
                with self._jobs_lock:
                    jobs = list(self.jobs)
                for job in jobs:
                    job.thread.join(max(0, deadline - monotonic()))
                    if job.thread.is_alive():
                        raise TimeoutError('protection work remains active')
                with self._jobs_lock:
                    if len(jobs) == len(self.jobs):
                        break
            self._ui.shutdown(wait=True)
