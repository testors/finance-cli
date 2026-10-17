"""Queue callbacks and CLI navigation with memory transport and controlled workers."""
import json
from pathlib import Path
import threading
from unittest.mock import Mock, patch

from finance_cli.core import storage
from finance_cli.services.shinhan import netfunnel, netfunnel_app as app, netfunnel_http as http
from finance_cli.services.shinhan import netfunnel_notice as notice, netfunnel_protocol as protocol, netfunnel_state as state
from finance_cli.services.shinhan import cli, session, setup, transport
from test_shinhan import PrivateHome, response


def block(button='exit'):
    return {'errAction': 'SYN', 'errActionType': {'SYN': {'message': 'SYN-PRIVATE-NOTICE',
        'blockTypes': [], 'button': {'title': 'SYN-TITLE', 'type': button}}}, 'blocks': {}}


class CallbackTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.pending, self.delivered, self.scheduled = [], [], []
        self.client = protocol.Client(protocol.Property('service_1', 'SYN'), Mock())
        self.engine = state.Engine(self.client)
        self.client.response = protocol.Response(code=201, key='SYN', tps=3, nwait=10)
        self.engine.progress.update(self.client.response)
        self.engine.progress.notices = 1
        self.fetch = Mock(return_value=json.dumps(block()))
        self.callbacks = app.Callbacks(self.pending.append, lambda: self.scheduled.append('END'), self.fetch,
                                       lambda kind, value: self.delivered.append((kind, value)))

    def dispatch(self, code):
        event = state.Event(code, code)
        self.callbacks.first(self.engine, event)
        self.callbacks.second(self.engine, event)
        while self.pending: self.pending.pop(0)()

    def test_201_progress_and_211_completion_are_different(self):
        self.dispatch(201)
        self.assertEqual(self.delivered, [('START', {}), ('PROGRESS', {'remaining': 4, 'count': 10})])
        self.assertEqual(self.scheduled, [])
        self.delivered.clear(); self.dispatch(211)
        self.assertEqual(self.delivered, [('START', {}), ('END', {})])
        self.assertEqual(self.scheduled, ['END'])

    def test_handler_reads_current_progress_and_native_count_limit_field(self):
        event = state.Event(201, 201)
        self.callbacks.first(self.engine, event)
        self.client.response.nwait = 3
        self.engine.progress.update(self.client.response); self.engine.progress.notices = 2
        self.pending.pop()()
        self.assertEqual(self.delivered, [('PROGRESS', {'remaining': 1, 'count': 3})])
        self.delivered.clear()
        self.client.properties.ui_count_limit = 1
        self.client.properties.ui_time_limit = 2
        self.dispatch(201)
        self.assertEqual(self.delivered, [('PROGRESS', {'remaining': 1, 'count': 2})])

    def test_block_closes_flow_and_later_complete_is_not_delivered(self):
        self.dispatch(301)
        self.assertEqual([kind for kind, value in self.delivered], ['BLOCK'])
        self.assertEqual(self.scheduled, ['END'])
        self.assertTrue(self.callbacks.closed)
        self.assertEqual(self.delivered[0][1]['notice']['button']['type'], 'exit')

    def test_notice_io_error_delivers_end_without_completion_request(self):
        self.fetch.side_effect = OSError('synthetic')
        self.dispatch(301)
        self.assertEqual(self.delivered, [('END', {})])
        self.assertEqual(self.scheduled, [])

    def test_local_limit_is_unverified_instead_of_notice_io_end(self):
        self.fetch.side_effect = protocol.LocalError('local limit')
        self.dispatch(302)
        self.assertEqual(self.delivered, [('UNVERIFIED', {})])
        self.assertEqual(self.scheduled, [])

    def test_cleanup_does_not_send_complete_and_terminal_sdk_errors_still_end(self):
        self.dispatch(999)
        self.assertEqual(self.delivered, [('END', {})])
        self.callbacks.cleanup()
        self.assertEqual(self.scheduled, ['END'])


class NoticeTests(PrivateHome):
    def test_typed_map_order_missing_blocks_and_default_fields(self):
        value = block('continue')
        value['errActionType']['SYN']['blockTypes'] = ['b', 'missing', 'a', 'b']
        value['blocks'] = {'a': {}, 'b': {'title': 12, 'webURL': None}}
        decoded = notice.parse(json.dumps(value))
        self.assertEqual([row['type'] for row in decoded['blocks']], ['b', 'a', 'b'])
        self.assertEqual(decoded['blocks'][0]['title'], '12')
        self.assertEqual(decoded['blocks'][0]['webURL'], '')
        self.assertEqual(decoded['button']['type'], 'continue')

    def test_missing_null_wrong_required_fields_fall_back_to_exit_not_end(self):
        for value in ['null', '{}', '[]', '{errAction:x,errActionType:{},blocks:{}}',
                      json.dumps(block() | {'errAction': None}),
                      json.dumps(block() | {'errActionType': {'SYN': {'message': 'x'}}}),
                      json.dumps(block() | {'blocks': {'SYN': None}})]:
            self.assertEqual(notice.parse(value), notice.DEFAULT)


class GateTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.install()
        self.run = storage.directory(setup.root()/'queue-fixture')
        self.report = {'bank_result': 'unknown'}

    def test_complete_runs_concurrently_and_failure_preserves_business_success(self):
        entered, release = threading.Event(), threading.Event()
        def get(url, params=(), *args, **kwargs):
            if params[0] == ('opcode', '5101'): return '200:key=SYN-PRIVATE-KEY'
            entered.set()
            if not release.wait(5): raise AssertionError('completion release missing')
            raise OSError('synthetic')
        gate = netfunnel.Gate(self.report, self.run)
        try:
            with patch.object(http, 'get', side_effect=get):
                self.assertEqual(gate.check('service_4', 'sol_login_1')[0], 'END')
                self.assertTrue(entered.wait(1))
                self.assertTrue(self.report['netfunnel'][0]['background_pending'])
                self.report['bank_result'] = 'success'
                release.set()
                for worker in gate.workers: worker.join(2)
        finally:
            release.set()
        self.assertEqual(self.report['bank_result'], 'success')
        self.assertEqual(gate.client.response.key, 'SYN-PRIVATE-KEY')
        self.assertNotIn('SYN-PRIVATE', ''.join(path.read_text() for path in self.run.iterdir()))

    def test_block_pending_stops_startup_before_bank_request(self):
        with patch.object(http, 'get', side_effect=['301:', json.dumps(block())]), \
             patch.object(transport, 'post', side_effect=AssertionError('Bank request after block')):
            result = session.execute('start')
        self.assertEqual(result['required_action'], 'startup_netfunnel_notice_choice_required')
        self.assertEqual(result['bank_result'], 'unknown')
        self.assertEqual(result['netfunnel'][0]['state'], 'BLOCK')
        self.assertNotIn('SYN-PRIVATE', json.dumps(result))
        self.assertEqual(Path(result['netfunnel'][0]['notice_file']).stat().st_mode & 0o777, 0o600)

    def test_startup_continue_uses_second_service_then_bank(self):
        calls = []
        def get(url, params=(), *args, **kwargs):
            calls.append(params)
            if not params: return json.dumps(block('continue'))
            return '301:' if len(calls) == 1 else '200:'
        with patch.object(http, 'get', side_effect=get), \
             patch.object(transport, 'post', return_value=transport.Reply(200, [], response('SUCCESS', {}))) as bank:
            result = session.execute('start', queue_input=lambda value, path: 'continue')
        self.assertEqual(result['bank_result'], 'success')
        bank.assert_called_once()
        self.assertEqual(calls[0][1:], [('sid', 'service_4'), ('aid', 'sol_login_1')])
        self.assertEqual(calls[2][1:], [('sid', 'service_1'), ('aid', 'nsol_start')])
        self.assertFalse(storage.read_json(setup.root()/'session.json')['invest_only_user'])

    def test_no_choice_is_automatically_selected_and_exit_never_calls_bank(self):
        for selected in ('exit', 'continue'):
            with patch.object(http, 'get', side_effect=['302:', json.dumps(block())]), \
                 patch.object(transport, 'post', side_effect=AssertionError('Unexpected bank request')):
                result = session.execute('start', queue_input=lambda *args: selected)
            self.assertEqual(result['required_action'], 'startup_netfunnel_user_exit' if selected == 'exit' else 'startup_netfunnel_notice_choice_unverified')
            self.assertEqual(result['bank_result'], 'unknown')

    def test_local_limit_never_creates_native_end_or_bank_failure(self):
        with patch.object(http, 'get', side_effect=protocol.LocalError('local limit')), \
             patch.object(transport, 'post', side_effect=AssertionError('Unexpected bank request')):
            result = session.execute('start')
        self.assertEqual(result['required_action'], 'startup_netfunnel_unverified')
        self.assertEqual(result['bank_result'], 'unknown')

    def test_extension_does_not_add_startup_queue(self):
        storage.atomic_json(setup.root()/'session.json', {'cookie': 'SYN'})
        with patch.object(http, 'get', side_effect=AssertionError('Unexpected queue request')), \
             patch.object(transport, 'post', return_value=transport.Reply(200, [], response('SUCCESS', {}))):
            self.assertEqual(session.execute('extend')['bank_result'], 'success')

    def test_journal_write_failure_does_not_change_queue_or_bank_outcome(self):
        original = storage.write_new
        def write(path, data):
            if path.suffix == '.jsonl': raise OSError('synthetic disk error')
            return original(path, data)
        with patch.object(storage, 'write_new', side_effect=write), \
             patch.object(transport, 'post', return_value=transport.Reply(200, [], response('SUCCESS', {}))) as bank:
            result = session.execute('start')
        bank.assert_called_once()
        self.assertEqual(result['bank_result'], 'success')
        self.assertEqual(result['netfunnel'][0]['state'], 'END')
        self.assertIn('netfunnel_diagnostic_error', result['warnings'])

    def test_cli_choice_only_uses_presented_button_and_progress_goes_to_stderr(self):
        value = notice.parse(json.dumps(block('continue')))
        with patch('sys.stdin.isatty', return_value=False), patch('getpass.getpass') as prompt:
            self.assertEqual(cli.queue_choice(value, None), 'continue'); prompt.assert_not_called()
        with patch('sys.stdin.isatty', return_value=True), patch('getpass.getpass', return_value='1'), patch('sys.stderr'):
            self.assertEqual(cli.queue_choice(value, None), 'continue')
