"""MainService construction and Agent call routing over explicit observations.

This module does not load libraries, acquire monitors or collect host values.
The process object represents one class-loader lifetime. Only a completed
constructor publishes its instance; failed attempts retain the static log.
"""
from dataclasses import dataclass

from .codeguard_app import build_string_steps
from .codeguard_effects import Effect, JavaFault, LinkFault, observed_bool
from .codeguard_exchange import UpdaterState
from .codeguard_flow import ChallengeState, java_text
from .codeguard_response import ResponseState
from .codeguard_rule import AnalysisLimit
from .codeguard_service import generate_token_steps
from .codeguard_updater import UpdaterRuntime


def new_updater(context):
    return UpdaterRuntime(UpdaterState(), context, None, 10000, None, None)


@dataclass(repr=False)
class MainInstance:
    response: ResponseState
    updater: UpdaterRuntime | None
    encrypted_token: bool = False


class MainServiceProcess:
    def __init__(self):
        self.instance = None
        self.context = None
        self._initial_log = 'E0'

    @property
    def status_log(self):
        return self._initial_log if self.instance is None else self.instance.response.status_log

    def append_log(self, suffix):
        value = java_text(self.status_log) + suffix
        if self.instance is None:
            self._initial_log = value
        else:
            self.instance.response.status_log = value


def load_engine_steps(process):
    # The first success message is only a logger call, not a third library.
    stages = ((None, ',E19.101', '', ',E19.103', ',E19.102:'),
              ('CodeGuard', ',E19.10', ',E20.20', ',E21.11', ',E21:'),
              ('ImageDecoder', ',E19.11.1', ',E20.21', ',E21.11', ',E21:'))
    for name, before, after, java_suffix, link_suffix in stages:
        try:
            process.append_log(before)
            if name is not None:
                yield Effect('main_load_library', (name,))
                process.append_log(after)
            yield Effect('main_load_log', ('success', name))
        except JavaFault as fault:
            process.append_log(java_suffix)
            yield Effect('main_load_log', ('failure', name, fault))
        except LinkFault as fault:
            text = yield Effect('main_link_to_string', (fault,))
            if type(text) is not str:
                raise AnalysisLimit('observed UnsatisfiedLinkError.toString required')
            process.append_log(link_suffix + text)
            yield Effect('main_load_log', ('failure', name, fault))


def main_instance_steps(process, context):
    yield Effect('main_monitor_enter', (process,))
    try:
        if process.instance is None:
            build = yield from build_string_steps()
            updater = new_updater(context)
            yield from load_engine_steps(process)
            response = ResponseState(None, None, None, None, build, None,
                                     process.status_log, None, None)
            process.instance = MainInstance(response, updater)
        # The Updater retains its constructor context. This static field is
        # assigned on EVERY getInstance call, only after construction returns.
        process.context = context
    except (JavaFault, LinkFault):
        yield Effect('main_monitor_exit', (process,))
        raise
    # An analysis/Python failure is unresolved execution, not a Java Throwable
    # observation from which monitor cleanup or later calls may be inferred.
    yield Effect('main_monitor_exit', (process,))
    return process.instance


def project_main_service_steps(generator, *, process, agent, decode_certificate=None):
    """Route Agent's MainService calls into one retained instance and Updater.

    Agent context, PID, loader/monitor results and remaining token effects are
    still explicit. No host PID/context or successful library load is inferred.
    This does not initialize AgentManager's separate update-thread Updater.
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
            if kind == 'main_service_instance':
                value = yield from main_instance_steps(process, args[0])
            elif kind in ('main_set_updater', 'main_set_server', 'main_set_app_info',
                          'main_set_encrypted_token', 'main_set_etc_data', 'main_generate_token'):
                instance = process.instance
                if instance is None:
                    raise AnalysisLimit('MainService call before observed construction')
                main = instance.response
                value = None
                if kind == 'main_set_updater':
                    if instance.updater is None:
                        instance.updater = new_updater(args[0])
                elif kind == 'main_set_server':
                    instance.updater.url = args[0]
                elif kind == 'main_set_app_info':
                    main.append_log(',E30')
                    yield Effect('main_app_info_log', args[1:])
                    main.pid, main.app_info, main.version = str(args[0]), args[1], args[2]
                    if main.challenge is None:
                        main.challenge = ChallengeState()
                elif kind == 'main_set_encrypted_token':
                    instance.encrypted_token = observed_bool(args[0])
                elif kind == 'main_set_etc_data':
                    main.set_etc_data(args[0])
                else:
                    url, timeout, root_check, rooting_info = args
                    value = yield from generate_token_steps(main, instance.updater, agent,
                        server_url=url, timeout=timeout, root_check=root_check,
                        rooting_info=rooting_info, encrypted_token=instance.encrypted_token,
                        decode_certificate=decode_certificate)
            else:
                value = yield effect
        except Exception as fault:
            pending = fault
