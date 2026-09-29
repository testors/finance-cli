from pathlib import Path
import unittest
from giro.codeguard_task import TaskTokenState, post_execute, manager_message
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_flow import ObservedJavaException

class TaskTests(unittest.TestCase):

    def state(self, token='synthetic return', code=-1, message=''):
        return TaskTokenState(token, code, message, 'agent', 'task', 'model', 'release', 'synthetic.invalid')

    def adapters(self, *, flags=None, observations=None, formatter=None):
        self.calls = []

        def format_error(*args):
            self.calls.append(args)
            return 'local error ' + str(len(self.calls))

        def observed_check(name):
            if observations is None:
                self.fail('no environment observation expected')
            return observations[name]
        return {'check_flags': flags or dict.fromkeys(('debugging', 'emulator', 'odex'), False), 'observed_check': observed_check, 'format_error': formatter or format_error}

    def test_private_render_retains_raw_token_public_get_consumes(self):
        state = self.state()
        adapters = self.adapters()
        self.assertEqual(state.render(**adapters), 'synthetic return')
        self.assertFalse(state.clear_called)
        self.assertEqual(state.get_token(**adapters), 'synthetic return')
        self.assertIsNone(state.token)
        self.assertTrue(state.clear_called)

    def test_nonempty_error_string_not_parsed_or_reclassified(self):
        state = self.state('E101_NET_ERROR_006')
        self.assertEqual(state.get_token(**self.adapters()), 'E101_NET_ERROR_006')
        self.assertEqual(self.calls, [])

    def test_null_and_empty_token_both_format_but_empty_message_preserved(self):
        for token in (None, ''):
            state = self.state(token, message='')
            state.render(**self.adapters())
            self.assertEqual(self.calls, [('CG_CONN_ENGINE01', '', 'CG_CONN_ENGINE')])

    def test_only_null_engine_message_is_mutated_to_default(self):
        state = self.state(None, message=None)
        state.render(**self.adapters())
        self.assertEqual(state.status_message, 'Connection Engine Error')
        self.assertEqual(len(self.calls), 1)

    def test_refused_and_timeout_preserve_different_codes_and_java_null(self):
        for (code, label) in ((101, 'REFUSED'), (102, 'TIMEOUT')):
            state = self.state(None, code=code, message=None)
            state.agent_log = None
            state.render(**self.adapters())
            self.assertEqual(self.calls[0][0], 'CG_CONN_' + label + '01')
            self.assertEqual(self.calls[0][2], 'CG_CONN_' + label + '(agent:null&&task)model(release)url:synthetic.invalid')
            self.assertIsNone(state.status_message)

    def test_checks_override_in_debug_emulator_odex_order(self):
        flags = dict.fromkeys(('debugging', 'emulator', 'odex'), True)
        observations = {'debugging': True, 'emulator': True, 'odex': False}
        output = self.state().get_token(**self.adapters(flags=flags, observations=observations))
        self.assertEqual([call[1] for call in self.calls], ['isDebuggging', 'isEmulator', 'isOdexModify'])
        self.assertEqual(output, 'local error 3')

    def test_unknown_flag_or_result_not_assumed_clean(self):
        with self.assertRaises(AnalysisLimit):
            self.state().render(**self.adapters(flags={'debugging': None}))
        with self.assertRaises(AnalysisLimit):
            self.state().render(**self.adapters(flags={'debugging': True}, observations={'debugging': None}))

    def test_formatter_exception_does_not_clear_or_become_success(self):
        state = self.state(None)

        def failed(*_):
            raise ObservedJavaException()
        with self.assertRaises(ObservedJavaException):
            state.get_token(**self.adapters(formatter=failed))
        self.assertFalse(state.clear_called)

    def test_check_exception_preserves_raw_token(self):
        state = self.state()
        adapters = self.adapters(flags={'debugging': True})

        def failed(_):
            raise ObservedJavaException()
        adapters['observed_check'] = failed
        with self.assertRaises(ObservedJavaException):
            state.get_token(**adapters)
        self.assertEqual(state.token, 'synthetic return')
        self.assertFalse(state.clear_called)

    def test_post_execute_false_null_still_signals_one_not_auth_success(self):
        for result in (None, False, True):
            (state, signals, messages) = (self.state(), [], [])
            post_execute(state, result, send_message=messages.append, callback_listener=signals.append, **self.adapters())
            self.assertEqual(signals, [1])
            self.assertEqual(messages, ['synthetic return'])
            self.assertFalse(state.clear_called)

    def test_no_handler_does_not_format_or_evaluate_flags(self):
        signals = []
        post_execute(self.state(None), False, send_message=None, callback_listener=signals.append)
        self.assertEqual(signals, [1])

    def test_send_false_ignored_but_exception_prevents_listener(self):
        signals = []
        post_execute(self.state(), True, send_message=lambda _: False, callback_listener=signals.append, **self.adapters())
        self.assertEqual(signals, [1])

        def failed(_):
            raise ObservedJavaException()
        with self.assertRaises(ObservedJavaException):
            post_execute(self.state(), True, send_message=failed, callback_listener=signals.append, **self.adapters())
        self.assertEqual(signals, [1])

    def test_manager_ignores_message_object_and_uses_current_task(self):
        (old, new) = (self.state('old task'), self.state('new task'))
        adapters = self.adapters()
        posted = []
        post_execute(old, True, send_message=posted.append, callback_listener=None, **adapters)
        self.assertEqual(manager_message(new, posted[0], **adapters), 'new task')
        self.assertFalse(old.clear_called)
        self.assertTrue(new.clear_called)
        self.assertEqual(manager_message(None, 'must not be used'), '')

    def test_error_formats_twice_across_post_and_manager_not_reused_message(self):
        state = self.state(None)
        (adapters, messages) = (self.adapters(), [])
        post_execute(state, False, send_message=messages.append, callback_listener=None, **adapters)
        output = manager_message(state, messages[0], **adapters)
        self.assertEqual((messages[0], output), ('local error 1', 'local error 2'))
        self.assertTrue(state.clear_called)

    def test_raw_state_hidden(self):
        self.assertNotIn('PRIVATE', repr(self.state('PRIVATE')))
