"""Offline CodeGuardTask token consumption and CgManager callback semantics.

No OS checks, SDK task scheduling, flag changes, token issuance or network.
Flags/observations are explicit caller inputs; callbacks are model adapters.
Only this layer's observed ordering is modeled, not Android thread races.
"""
from dataclasses import dataclass

from .codeguard_rule import AnalysisLimit
from .codeguard_flow import java_text


@dataclass(repr=False)
class TaskTokenState:
    token: str | None
    status_code: int
    status_message: str | None
    agent_log: str | None
    task_log: str | None
    model: str | None
    release: str | None
    server_url: str | None
    clear_called: bool = False
    context: object = None
    started_ms: int | None = None

    def render(self, *, check_flags, observed_check, format_error):
        """private a(): render without consuming token or changing check flags.

        check_flags are the actual task u/t/v fields, not CLI bypass switches.
        observed_check is invoked only where the original invokes its check.
        Exception/unknown observations are never defaulted to a clean result.
        """
        value = self.token
        if value is None or value == '':
            if self.status_code in (101,102):
                kind,label = ('REFUSED','Refused') if self.status_code == 101 else ('TIMEOUT','Timeout')
                detail = ('CG_CONN_'+kind+'(agent:'+java_text(self.agent_log)+'&&'+java_text(self.task_log)+')'+
                          java_text(self.model)+'('+java_text(self.release)+')url:'+java_text(self.server_url))
                value = format_error('CG_CONN_'+kind+'01','Connection '+label,detail)
            else:
                if self.status_message is None:
                    self.status_message = 'Connection Engine Error'
                value = format_error('CG_CONN_ENGINE01',self.status_message,'CG_CONN_ENGINE')
        for name,message,bad_when in (('debugging','isDebuggging',True),
                                      ('emulator','isEmulator',True),('odex','isOdexModify',False)):
            flag = check_flags.get(name)
            if type(flag) is not bool:
                raise AnalysisLimit('actual CodeGuardTask check flag required')
            if flag:
                observation = observed_check(name)
                if type(observation) is not bool:
                    raise AnalysisLimit('actual CodeGuardTask environment observation required')
                if observation is bad_when:
                    value = format_error('CG_CONN_ENGINE01',message,'CG_CONN_ENGINE')
        return value

    def get_token(self, **adapters):
        value = self.render(**adapters)
        # Not finally: original exceptions leave the raw token uncleared.
        self.clear()
        return value

    def clear(self):
        self.token = None
        self.clear_called = True  # original also sets global singleton A=null


def post_execute(state, result, *, send_message, callback_listener, **adapters):
    """onPostExecute; result false/null doesn't change the callback signal 1.

    send_message, when present, takes the message.obj string. No queue/thread
    or original SDK callback is run. Its boolean return isn't a success gate.
    """
    if send_message is not None:
        send_message(state.render(**adapters))
    if callback_listener is not None:
        callback_listener(1)


def manager_message(current_task, message_object, **adapters):
    """CgManager.2 ignores message.obj and reads the CURRENT task again.

    A caller must supply the task reference observed at this callback. This
    does not assume Android queue ordering or equate the signal to auth success.
    """
    return '' if current_task is None else current_task.get_token(**adapters)
