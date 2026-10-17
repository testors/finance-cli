"""Queue admission callbacks for startup and selected program navigation."""
import copy
import json
import queue
import threading
import time

from finance_cli.core import storage
from . import netfunnel_app, netfunnel_http, netfunnel_protocol as protocol, netfunnel_state
from .enrollment import Pending


class Gate:
    def __init__(self, report, run, *, progress=None):
        self.report, self.run, self.progress = report, run, progress
        self.client = protocol.Client(protocol.Property('', ''), self.send)
        self.workers = []
        self.lock = threading.RLock()
        self.stop = None
        self.trace = None
        self.context = threading.local()
        self.engine = netfunnel_state.Engine(self.client, sleep=self.sleep)

    def sleep(self, seconds):
        stop = self.context.stop
        if stop.wait(seconds):
            stop.clear()
            raise InterruptedError('queue_wait_interrupted')

    def record(self, **values):
        # Own redacted journal, including completions after business has resumed.
        with self.lock:
            trace = getattr(self.context, 'trace', self.trace)
            if trace is None: return
            try:
                with trace.open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(values, ensure_ascii=False)+'\n')
            except Exception:
                self.local_error = True

    def send(self, url, params, timeout):
        opcode = next(value for name, value in params if name == 'opcode')
        self.record(kind='command', opcode=opcode)
        try:
            return netfunnel_http.get(url, params, timeout, observe=lambda value: self.record(opcode=opcode, **value))
        except Exception:
            self.record(kind='command_exception', opcode=opcode)
            raise

    def spawn(self, work, *, completion=False):
        messages, trace, stop = self.messages, self.trace, self.stop
        def perform():
            self.context.trace, self.context.stop = trace, stop
            try:
                work()
            except protocol.LocalError:
                self.record(kind='local_error', completion=completion)
                if not completion: messages.put(('flow', ('UNVERIFIED', {})))
            except Exception:
                self.record(kind='worker_error', completion=completion)
                if not completion: messages.put(('flow', ('UNVERIFIED', {})))
            finally:
                self.record(kind='worker_finished', completion=completion)
        # Completion may finish while banking continues. A CLI process waits
        # for this worker before normal exit, without changing the bank result.
        worker = threading.Thread(target=perform, daemon=not completion)
        self.workers.append(worker)
        worker.start()

    def complete(self):
        if not self.client.properties.bypass and self.client.response.key:
            self.record(kind='completion_scheduled')
            self.spawn(self.engine.end, completion=True)

    def check(self, service, action):
        if self.stop is not None: self.stop.set()
        self.stop = threading.Event()
        self.messages = queue.Queue()
        messages = self.messages
        self.local_error = False
        number = len(self.report.setdefault('netfunnel', []))+1
        summary = {'service': service, 'action': action, 'state': 'waiting',
                   'sdk_retry_limit': 2, 'http_retry_limit': 3}
        self.report['netfunnel'].append(summary)
        self.report['network_used'] = True
        # Reserve once before starting this queue sequence. Subsequent journal
        # failures never change its retries, callbacks or bank result.
        storage.atomic_json(self.run/'report.json', self.report)
        self.trace = self.run/f'netfunnel-{number}.jsonl'
        try:
            storage.write_new(self.trace, b'')
        except Exception:
            self.local_error = True
            self.trace = None
        summary['journal'] = str(self.trace) if self.trace else None
        self.client.properties.service, self.client.properties.action = service, action
        def notice():
            self.record(kind='block_notice_request')
            return netfunnel_http.get('https://app-notice.shinhan.com/nss_noti.json?v='+str(int(time.time()*1000)),
                                      observe=lambda value: self.record(notice=True, **value))
        callbacks = netfunnel_app.Callbacks(lambda callback: messages.put(('handler', callback)),
            self.complete, notice, lambda kind, value: messages.put(('flow', (kind, value))), self.record)
        def observed(engine, event):
            self.record(kind='sdk_event', code=event.code, underlying_code=event.error)
        self.engine.listeners = [observed, callbacks.first, callbacks.second]
        self.spawn(self.engine.begin)
        try:
            while True:
                kind, value = self.messages.get()
                if kind == 'handler':
                    value()
                    continue
                kind, value = value
                summary['state'] = kind
                if kind == 'PROGRESS' and self.progress:
                    try: self.progress(value['remaining'], value['count'])
                    except Exception: self.local_error = True
                if kind in ('END', 'BLOCK', 'UNVERIFIED'):
                    if kind == 'BLOCK':
                        path = self.run/f'netfunnel-{number}-notice.json'
                        try:
                            storage.write_new(path, json.dumps(value['notice'], ensure_ascii=False).encode())
                            summary['notice_file'] = str(path)
                        except Exception:
                            self.local_error = True
                    return kind, value.get('notice'), summary.get('notice_file')
        except (KeyboardInterrupt, EOFError):
            summary['state'] = 'interrupted'
            self.complete()
            raise
        finally:
            callbacks.cleanup()
            with self.lock:
                summary['background_pending'] = any(worker.is_alive() for worker in self.workers)
                if self.local_error:
                    self.report.setdefault('warnings', []).append('netfunnel_diagnostic_error')
                    self.report['local_status'] = 'incomplete'


def start(report, run, state, *, choose=None, progress=None):
    gate = Gate(report, run, progress=progress)
    for service, action in [('service_4', 'sol_login_1'), ('service_1', 'nsol_start')]:
        kind, notice, path = gate.check(service, action)
        if kind == 'END':
            state['invest_only_user'] = False
            return
        if kind == 'UNVERIFIED':
            raise Pending('startup_netfunnel_unverified')
        selection = choose(copy.deepcopy(notice), path) if choose else None
        if selection is None:
            raise Pending('startup_netfunnel_notice_choice_required')
        if selection != notice['button']['type']:
            raise Pending('startup_netfunnel_notice_choice_unverified')
        report['netfunnel'][-1]['choice'] = selection if selection in ('exit', 'continue') else 'other'
        if selection == 'exit':
            raise Pending('startup_netfunnel_user_exit')
        if selection != 'continue':
            raise Pending('startup_netfunnel_notice_action_required')
        # The first Continue action requests exactly one second service check.


def program(exchange, action, *, progress=None):
    kind, notice, path = Gate(exchange.report, exchange.run, progress=progress).check('service_1', action)
    if kind != 'END':
        raise Pending('loan_netfunnel_blocked' if kind == 'BLOCK' else 'loan_netfunnel_unverified')
    exchange.report['notice_navigation'] = 'allowed'
