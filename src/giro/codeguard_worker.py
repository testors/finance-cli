"""Offline CodeGuardTask.doInBackground and AgentManager pre/post-call state.

Effects are descriptions only. There is no SDK runner, network, cache deletion,
normal-token substitute or environment-detection bypass in this module.
"""
import base64
from dataclasses import dataclass

from .codeguard_codec import java_utf8
from .codeguard_effects import Effect, JavaFault, observed_bool, shortened_log
from .codeguard_flow import java_text


def java_split_literal(value, delimiter):
    if value == '':
        return ['']
    parts = value.split(delimiter)
    while parts and parts[-1] == '':
        parts.pop()
    return parts


@dataclass(repr=False)
class WorkerSettings:
    etc_data: str | None
    rooting_info: str | None
    task_info: str | None
    encrypted_token: bool
    short_error: bool
    server_url_to_ip: bool
    max_timeout: int
    so_list: tuple | None
    app_info: str | None
    version: str | None


def classify_return(state, value):
    """Task classification is substring/list-order, not prefix or token parse."""
    state.token = value
    if value is None:
        state.status_message = 'TOKEN NOT GENERATE'
        return  # status_code retains the pre-generate value -1
    errors = tuple('E101_NET_ERROR_%03d' % n for n in range(8)) + ('E101_ENGINE_LOAD_ERROR',)
    for error in errors:
        if error in value:
            if error == 'E101_ENGINE_LOAD_ERROR':
                state.status_code, state.status_message = 121, value
            elif error == 'E101_NET_ERROR_000':
                state.status_code, state.status_message = 101, 'CONNECTION REFUSED'
            else:
                state.status_code, state.status_message = 102, 'CONNECTION TIMEOUT'
            parts = java_split_literal(value, '&&')
            if len(parts) > 1:
                state.task_log = parts[1]  # failed extraction keeps previous log
            state.token = None
            return
    state.status_code = 0  # includes empty, unknown error codes, TOKEN_FAIL


def worker_steps(state, settings, *, context):
    """Sequential worker effects; caller supplies params[0], not an SDK context.

    Context is opaque. Async scheduling, absent/invalid params arrays and
    concurrent mutation are not inferred. Return True is NOT login success.
    """
    if context is not None:
        state.context = context
    state.started_ms = yield Effect('clock_ms')
    yield Effect('set_agent_context', (context,))
    state.status_message, state.status_code = 'ENGINE IS NOT CONNECTED', 121
    if observed_bool(settings.short_error):
        yield Effect('set_agent_short_error', (True,))  # false never resets static d
    state.status_message, state.status_code = 'ENGINE IS CONNECTED', -1
    for name, value in (('etc_data', settings.etc_data), ('rooting_info', settings.rooting_info),
                        ('task_info', settings.task_info)):
        if value:
            yield Effect('set_agent_field', (name, value))
    yield Effect('set_agent_encrypted_token', (observed_bool(settings.encrypted_token),))
    if observed_bool(settings.server_url_to_ip):
        address = yield Effect('read_ip_preference', (context, ''))
        if address:
            state.server_url = address
        else:
            try:
                state.server_url = yield Effect('arrange_url_with_ip', (context, state.server_url, settings.max_timeout))
            except JavaFault:
                pass
    value = yield Effect('agent_generate_token', (context, state.server_url))
    classify_return(state, value)
    try:
        if state.token is not None and 'TOKEN_FAIL' not in state.token and settings.so_list:
            result = yield Effect('check_so', (state.context, settings.so_list))
            if result:
                message = 'isSOModify:' + base64.b64encode(java_utf8(result)).decode('ascii')
                app = java_text(settings.app_info) + java_text(settings.version) + '1'
                state.token = yield Effect('format_local_error', (app, message, 'CODEGUARD_VERIFICATION_TOKEN_FAIL'))
        if state.token is not None and 'CODEGUARD_VERIFICATION_TOKEN_FAIL' in state.token:
            yield Effect('invalidate_engine_artifacts', (state.context,))
    except JavaFault:
        pass  # only this final SO/invalidation region is caught
    return True


@dataclass(repr=False)
class AgentCallState:
    app_info: str | None
    version: str | None
    etc_data: str | None
    rooting_info: str | None
    task_info: str | None
    root_check: bool
    rooting_flag: bool
    encrypted_token: bool
    short_error: bool
    status_log: str | None
    pending_value: str | None

    def set_app_info(self, app_info, version):
        self.app_info, self.version = app_info, version
        self.rooting_flag, self.rooting_info = False, None
        # etc/task/root_check/enc/short-error fields are NOT cleared.

    def set_rooting_info(self, value):
        if value:
            self.rooting_flag, self.rooting_info = True, value

    def additional_data(self):
        value = self.etc_data
        if self.rooting_info is not None:
            value = self.rooting_info if value is None else value + '/' + self.rooting_info
        if self.task_info is not None:
            value = self.task_info if value is None else value + '^' + self.task_info
        return value

    def annotate_error(self, value):
        if value is not None and ('E101_ENGINE_LOAD_ERROR' in value or 'E101_NET_ERROR' in value):
            parts = java_split_literal(value, '##')
            if len(parts) > 2:
                limit = 200 if observed_bool(self.short_error) else 1000
                self.status_log = shortened_log(self.status_log, limit)
                parts[2] += '(' + self.status_log + ')'
                value = ''.join(part + '##' for part in parts)
        return value


def agent_call_steps(state, *, context, server_url, timeout, shared_reads=False):
    yield Effect('set_agent_context', (context,))
    state.status_log = java_text(state.status_log) + ',60'
    additional = state.additional_data()
    current = (yield Effect('agent_context')) if shared_reads else context
    yield Effect('main_service_instance', (current,))
    current = (yield Effect('agent_context')) if shared_reads else context
    yield Effect('main_set_updater', (current,))
    yield Effect('main_set_server', (server_url,))
    pid = yield Effect('process_pid')
    yield Effect('main_set_app_info', (pid, state.app_info, state.version))
    yield Effect('main_set_encrypted_token', (observed_bool(state.encrypted_token),))
    if additional:
        yield Effect('main_set_etc_data', (additional,))  # otherwise old MainService p persists
    if shared_reads:
        timeout = yield Effect('task_max_timeout')  # static read immediately before generateToken
    value = yield Effect('main_generate_token', (server_url, timeout, observed_bool(state.root_check),
                                                observed_bool(state.rooting_flag)))
    value = state.annotate_error(value)
    state.pending_value = None  # only after generateToken AND annotation return
    return value


@dataclass(repr=False)
class AgentUpdateState:
    context: object
    app_info: str | None
    version: str | None
    server_url: str | None
    timeout: int
    resolve_ip: bool
    updater_present: bool
    handler: object
    message_what: int
    listener: object


def _update_complete(state):
    if state.handler is not None:
        yield Effect('update_send_empty_message', (state.handler, state.message_what))
        state.handler = None  # after send returns, even if it returned false
    if state.listener is not None:
        yield Effect('update_listener', (state.listener, 0))


def agent_update_steps(state):
    """agent.c.run ordering only, NOT Updater.b internals or init threads.

    False update return/Java Exception still reaches the same callback. That
    callback never proves a cert/key/engine was installed. Callback exceptions
    in the first try may cause a second notification in the catch block.
    """
    try:
        if observed_bool(state.resolve_ip):
            try:
                state.server_url = yield Effect('arrange_url_with_ip', (state.context, state.server_url, state.timeout))
            except JavaFault:
                pass
        if not observed_bool(state.updater_present):
            yield Effect('create_updater', (state.context,))
            state.updater_present = True
        yield Effect('update_set_app_info', (state.app_info, state.version))
        timeout = (state.timeout * 10 + 2**31) % 2**32 - 2**31
        yield Effect('update_set_timeout', (timeout,))
        yield Effect('update_set_context', (state.context,))
        yield Effect('update_set_url', (state.server_url,))
        yield Effect('check_update')  # returned boolean used only in original log
        yield from _update_complete(state)
        yield Effect('read_update_status')  # after callbacks; not a success gate
    except JavaFault:
        yield from _update_complete(state)
