from pathlib import Path
import unittest
from unittest.mock import patch
from giro.codeguard_effects import LinkFault, java_length
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_task import TaskTokenState, manager_message, post_execute
from giro.codeguard_worker import AgentCallState, AgentUpdateState, WorkerSettings, agent_call_steps, agent_update_steps, java_split_literal, worker_steps
import test_codeguard_response as support

def task_state():
    return TaskTokenState('prior', -1, 'prior message', 'agent', 'prior log', 'model', 'release', 'https://synthetic.invalid/')

def worker_settings(**changes):
    values = dict(etc_data=None, rooting_info=None, task_info=None, encrypted_token=False, short_error=False, server_url_to_ip=False, max_timeout=5000, so_list=None, app_info='APP', version='1')
    values.update(changes)
    return WorkerSettings(**values)

def agent_state(**changes):
    values = dict(app_info='APP', version='1', etc_data=None, rooting_info=None, task_info=None, root_check=True, rooting_flag=False, encrypted_token=False, short_error=False, status_log='0', pending_value='pending')
    values.update(changes)
    return AgentCallState(**values)

class WorkerTests(unittest.TestCase):

    def run_worker(self, *, state=None, settings=None, context='context', overrides=None):
        self.effects = []
        self.state = state or task_state()
        replies = dict(clock_ms=100, set_agent_context=None, set_agent_encrypted_token=None, agent_generate_token='synthetic token')
        replies.update(overrides or {})

        def reply(effect):
            self.effects.append(effect)
            value = replies[effect.kind]
            return value(effect) if callable(value) else value
        return support.drive(worker_steps(self.state, settings or worker_settings(), context=context), reply)

    def kinds(self):
        return [e.kind for e in self.effects]

    def test_basic_order_and_true_is_not_success_classification(self):
        self.assertIs(self.run_worker(overrides={'agent_generate_token': 'TOKEN_FAIL'}), True)
        self.assertEqual(self.kinds(), ['clock_ms', 'set_agent_context', 'set_agent_encrypted_token', 'agent_generate_token'])
        self.assertEqual((self.state.started_ms, self.state.status_code, self.state.token), (100, 0, 'TOKEN_FAIL'))

    def test_setters_skip_empty_but_enc_is_always_written(self):
        self.run_worker(settings=worker_settings(etc_data='', rooting_info='root', task_info='task', short_error=True), overrides={'set_agent_field': None, 'set_agent_short_error': None})
        fields = [e.args for e in self.effects if e.kind == 'set_agent_field']
        self.assertEqual(fields, [('rooting_info', 'root'), ('task_info', 'task')])
        self.assertEqual(self.kinds()[2], 'set_agent_short_error')
        self.assertLess(self.kinds().index('set_agent_short_error'), self.kinds().index('set_agent_field'))

    def test_false_short_error_never_resets_sticky_static_flag(self):
        self.run_worker()
        self.assertNotIn('set_agent_short_error', self.kinds())

    def test_null_context_retains_task_context_but_is_passed_to_agent(self):
        state = task_state()
        state.context = 'older context'
        self.run_worker(state=state, context=None)
        self.assertEqual(state.context, 'older context')
        self.assertEqual(self.effects[1].args, (None,))
        self.assertIsNone(self.effects[-1].args[0])

    def test_cached_ip_precedes_dns_and_keeps_string_verbatim(self):
        self.run_worker(settings=worker_settings(server_url_to_ip=True), overrides={'read_ip_preference': 'saved value'})
        self.assertEqual(self.state.server_url, 'saved value')
        self.assertNotIn('arrange_url_with_ip', self.kinds())

    def test_arrange_exception_keeps_url_but_null_return_overwrites(self):
        for (result, expected) in ((support.fault(), 'https://synthetic.invalid/'), (None, None), ('resolved', 'resolved')):
            self.run_worker(settings=worker_settings(server_url_to_ip=True), overrides={'read_ip_preference': '', 'arrange_url_with_ip': result})
            self.assertEqual(self.state.server_url, expected)

    def test_preference_and_generate_exceptions_not_swallowed(self):
        with self.assertRaises(type(support.fault())):
            self.run_worker(settings=worker_settings(server_url_to_ip=True), overrides={'read_ip_preference': support.fault()})
        state = task_state()
        with self.assertRaises(type(support.fault())):
            self.run_worker(state=state, overrides={'agent_generate_token': support.fault()})
        self.assertEqual(state.token, 'prior')
        self.assertEqual(state.status_code, -1)

    def test_null_return_keeps_minus_one_and_sets_message(self):
        self.run_worker(overrides={'agent_generate_token': None})
        self.assertEqual((self.state.status_code, self.state.status_message, self.state.token), (-1, 'TOKEN NOT GENERATE', None))

    def test_known_errors_match_substrings_in_list_order_not_position(self):
        self.run_worker(overrides={'agent_generate_token': 'E101_ENGINE_LOAD_ERROR then E101_NET_ERROR_007 then E101_NET_ERROR_000&&log'})
        self.assertEqual((self.state.status_code, self.state.status_message, self.state.task_log), (101, 'CONNECTION REFUSED', 'log'))
        self.assertIsNone(self.state.token)

    def test_all_known_timeouts_and_engine_load_status(self):
        for code in range(1, 8):
            self.run_worker(overrides={'agent_generate_token': 'prefixE101_NET_ERROR_%03d&&tail' % code})
            self.assertEqual((self.state.status_code, self.state.status_message), (102, 'CONNECTION TIMEOUT'))
        self.run_worker(overrides={'agent_generate_token': 'prefixE101_ENGINE_LOAD_ERROR2'})
        self.assertEqual((self.state.status_code, self.state.status_message), (121, 'prefixE101_ENGINE_LOAD_ERROR2'))

    def test_unknown_error_empty_and_whitespace_keep_app_classification(self):
        for value in ('', ' ', 'E101_NET_ERROR_008', 'TOKEN_FAIL'):
            self.run_worker(overrides={'agent_generate_token': value})
            self.assertEqual((self.state.status_code, self.state.token), (0, value))
            self.assertEqual(self.state.status_message, 'ENGINE IS CONNECTED')

    def test_split_drops_trailing_empty_but_middle_empty_overwrites_log(self):
        for (text, expected) in (('E101_NET_ERROR_000&&', 'prior log'), ('E101_NET_ERROR_000&&&&x', ''), ('E101_NET_ERROR_000&&a&&b', 'a')):
            self.run_worker(overrides={'agent_generate_token': text})
            self.assertEqual(self.state.task_log, expected)
        self.assertEqual(java_split_literal('', '&&'), [''])
        self.assertEqual(java_split_literal('&&', '&&'), [])

    def test_so_check_skips_null_or_token_fail_but_not_empty(self):
        for value in (None, 'TOKEN_FAIL', 'CODEGUARD_VERIFICATION_TOKEN_FAIL'):
            self.run_worker(settings=worker_settings(so_list=('lib.so',)), overrides={'agent_generate_token': value, 'invalidate_engine_artifacts': None})
            self.assertNotIn('check_so', self.kinds())
        self.run_worker(settings=worker_settings(so_list=('lib.so',)), overrides={'agent_generate_token': '', 'check_so': ''})
        self.assertIn('check_so', self.kinds())

    def test_so_local_formatter_arguments_and_invalidation_effect(self):
        self.run_worker(settings=worker_settings(so_list=('lib.so',)), overrides={'check_so': '한글', 'format_local_error': 'local CODEGUARD_VERIFICATION_TOKEN_FAIL', 'invalidate_engine_artifacts': False})
        effect = next((e for e in self.effects if e.kind == 'format_local_error'))
        self.assertEqual(effect.args, ('APP11', 'isSOModify:7ZWc6riA', 'CODEGUARD_VERIFICATION_TOKEN_FAIL'))
        self.assertEqual(self.kinds()[-1], 'invalidate_engine_artifacts')
        self.assertEqual(self.state.status_code, 0)

    def test_so_exception_keeps_previous_token_no_invalidation(self):
        self.run_worker(settings=worker_settings(so_list=('lib.so',)), overrides={'check_so': 'changed', 'format_local_error': support.fault()})
        self.assertEqual(self.state.token, 'synthetic token')
        self.assertNotIn('invalidate_engine_artifacts', self.kinds())

    def test_so_link_and_analysis_limit_not_swallowed(self):
        for error in (LinkFault(), AnalysisLimit('unknown')):
            with self.assertRaises(type(error)):
                self.run_worker(settings=worker_settings(so_list=('lib.so',)), overrides={'check_so': error})

    def test_worker_to_double_render_and_current_manager_consumption(self):
        self.run_worker(overrides={'agent_generate_token': 'aE101_NET_ERROR_000&&observed log'})
        (messages, calls) = ([], [])

        def formatter(*args):
            calls.append(args)
            return 'synthetic error ' + str(len(calls))
        adapters = dict(check_flags=dict.fromkeys(('debugging', 'emulator', 'odex'), False), observed_check=lambda _: self.fail('unexpected check'), format_error=formatter)
        post_execute(self.state, True, send_message=messages.append, callback_listener=None, **adapters)
        result = manager_message(self.state, messages[0], **adapters)
        self.assertEqual((messages, result), (['synthetic error 1'], 'synthetic error 2'))
        self.assertIn('&&observed log)', calls[0][2])
        self.assertTrue(self.state.clear_called)

    def test_effect_and_settings_hide_values_and_do_not_execute_io(self):
        settings = worker_settings(etc_data='PRIVATE')
        with patch('socket.socket', side_effect=AssertionError('no network')), patch('ctypes.CDLL', side_effect=AssertionError('no SDK')), patch('builtins.open', side_effect=AssertionError('no file reads')):
            self.run_worker(settings=settings, overrides={'set_agent_field': None})
        self.assertNotIn('PRIVATE', repr(settings) + repr(self.effects) + repr(self.state))

class AgentTests(unittest.TestCase):

    def run_agent(self, state, *, result='synthetic token'):
        self.effects = []

        def reply(e):
            self.effects.append(e)
            if e.kind == 'process_pid':
                return 42
            if e.kind == 'main_generate_token':
                return result
            return None
        return support.drive(agent_call_steps(state, context='context', server_url='url', timeout=50), reply)

    def test_additional_data_null_empty_separator_matrix(self):
        cases = ((None, None, None, None), ('', None, None, ''), (None, 'root', None, 'root'), ('', 'root', None, '/root'), (None, None, 'task', 'task'), ('', None, 'task', '^task'), ('etc', 'root', 'task', 'etc/root^task'), ('', '', '', '/^'))
        for (etc, root, task, expected) in cases:
            self.assertEqual(agent_state(etc_data=etc, rooting_info=root, task_info=task).additional_data(), expected)

    def test_app_info_resets_only_rooting_info_and_flag(self):
        state = agent_state(etc_data='etc', rooting_info='root', rooting_flag=True, task_info='task')
        state.set_app_info('new', '2')
        self.assertEqual((state.rooting_flag, state.rooting_info, state.etc_data, state.task_info), (False, None, 'etc', 'task'))
        state.set_rooting_info('root2')
        state.set_rooting_info('')
        self.assertEqual((state.rooting_flag, state.rooting_info), (True, 'root2'))

    def test_agent_main_call_order_and_empty_data_does_not_clear_main(self):
        state = agent_state(etc_data='')
        self.run_agent(state)
        self.assertEqual([e.kind for e in self.effects], ['set_agent_context', 'main_service_instance', 'main_set_updater', 'main_set_server', 'process_pid', 'main_set_app_info', 'main_set_encrypted_token', 'main_generate_token'])
        self.assertEqual(self.effects[5].args, (42, 'APP', '1'))
        self.assertEqual(self.effects[-1].args, ('url', 50, True, False))
        self.assertEqual(state.status_log, '0,60')
        self.assertIsNone(state.pending_value)

    def test_nonempty_data_is_raw_at_main_setter_not_double_encoded(self):
        self.run_agent(agent_state(etc_data='etc', rooting_info='root', task_info='task'))
        self.assertEqual(next((e for e in self.effects if e.kind == 'main_set_etc_data')).args, ('etc/root^task',))

    def test_annotation_adds_log_to_third_field_and_one_trailing_separator(self):
        state = agent_state(status_log='a#b')
        self.assertEqual(state.annotate_error('APP##ver##E101_NET_ERROR_000&&log####'), 'APP##ver##E101_NET_ERROR_000&&log(a_b)##')
        self.assertEqual(state.status_log, 'a_b')

    def test_annotation_is_anywhere_match_not_third_field_validation(self):
        state = agent_state()
        self.assertEqual(state.annotate_error('E101_NET_ERROR_008##v##payload'), 'E101_NET_ERROR_008##v##payload(0)##')

    def test_annotation_short_error_uses_utf16_and_retains_202_units(self):
        state = agent_state(short_error=True, status_log='😀' * 150)
        state.annotate_error('a##b##E101_ENGINE_LOAD_ERROR2')
        self.assertEqual(java_length(state.status_log), 202)
        self.assertIn('--', state.status_log)

    def test_no_annotation_with_too_few_nontrailing_fields(self):
        state = agent_state(status_log='#log')
        for value in (None, '', 'normal', 'E101_NET_ERROR_000##v####'):
            self.assertEqual(state.annotate_error(value), value)
        self.assertEqual(state.status_log, '#log')

    def test_generate_failure_does_not_clear_pending_value(self):
        state = agent_state()
        with self.assertRaises(type(support.fault())):
            self.run_agent(state, result=support.fault())
        self.assertEqual(state.pending_value, 'pending')

    def test_nested_agent_response_worker_callback_synthetic_not_server_success(self):
        (state, agent, main) = (task_state(), agent_state(), support.sample_state())
        seen = []
        ticks = iter((1, 10, 13))

        def reply(e):
            seen.append(e.kind)
            if e.kind == 'clock_ms':
                return next(ticks)
            if e.kind == 'agent_generate_token':
                return support.drive(agent_call_steps(agent, context=e.args[0], server_url=e.args[1], timeout=50), reply)
            if e.kind == 'process_pid':
                return 42
            if e.kind == 'main_set_app_info':
                main.set_app_info(*e.args)
            elif e.kind == 'main_set_etc_data':
                main.set_etc_data(e.args[0])
            elif e.kind == 'main_generate_token':
                return support.drive(support.response_steps(main, root_check=e.args[2], rooting_info=e.args[3]), reply)
            elif e.kind == 'oscheck_future':
                return 'synthetic OS result'
            elif e.kind == 'native_start':
                return None
            elif e.kind == 'engine_version':
                return 'v'
            elif e.kind == 'read_detail_enabled':
                return False
            elif e.kind == 'location_text':
                return ''
            elif e.kind not in ('set_agent_context', 'set_agent_encrypted_token', 'main_service_instance', 'main_set_updater', 'main_set_server', 'main_set_encrypted_token'):
                self.fail('unexpected effect ' + e.kind)
            return None
        self.assertTrue(support.drive(worker_steps(state, worker_settings(), context='context'), reply))
        self.assertEqual(state.status_code, 121)
        self.assertIsNone(state.token)
        self.assertIn('E101_ENGINE_LOAD_ERROR4', state.status_message)
        self.assertIn('(0,60)', state.status_message)
        self.assertLess(seen.index('main_set_app_info'), seen.index('native_start'))

class UpdateTests(unittest.TestCase):

    def run_update(self, *, overrides=None, **changes):
        values = dict(context='ctx', app_info='APP', version='1', server_url='url', timeout=5000, resolve_ip=False, updater_present=True, handler='handler', message_what=100, listener='listener')
        values.update(changes)
        (self.state, self.effects) = (AgentUpdateState(**values), [])

        def reply(e):
            self.effects.append(e)
            result = (overrides or {}).get(e.kind)
            return result(e) if callable(result) else result
        return support.drive(agent_update_steps(self.state), reply)

    def test_false_update_and_exception_have_same_completion(self):
        for result in (True, False, support.fault()):
            self.run_update(overrides={'check_update': result})
            sends = [e.args for e in self.effects if e.kind == 'update_send_empty_message']
            calls = [e.args for e in self.effects if e.kind == 'update_listener']
            self.assertEqual(sends, [('handler', 100)])
            self.assertEqual(calls, [('listener', 0)])
            self.assertIsNone(self.state.handler)

    def test_update_initialization_order_and_timeout_int_overflow(self):
        self.run_update(updater_present=False, timeout=2 ** 30)
        self.assertEqual([e.kind for e in self.effects[:6]], ['create_updater', 'update_set_app_info', 'update_set_timeout', 'update_set_context', 'update_set_url', 'check_update'])
        self.assertEqual(self.effects[2].args, (-2 ** 31,))
        self.assertTrue(self.state.updater_present)

    def test_ip_exception_uses_original_url_and_update_continues(self):
        self.run_update(resolve_ip=True, overrides={'arrange_url_with_ip': support.fault()})
        self.assertEqual(self.state.server_url, 'url')
        self.assertIn('check_update', [e.kind for e in self.effects])

    def test_false_send_still_clears_handler_and_calls_listener(self):
        self.run_update(overrides={'update_send_empty_message': False})
        self.assertIsNone(self.state.handler)
        self.assertIn('update_listener', [e.kind for e in self.effects])

    def test_send_exception_retries_before_clear_then_listener(self):
        answers = iter((support.fault(), False))
        self.run_update(overrides={'update_send_empty_message': lambda _: next(answers)})
        kinds = [e.kind for e in self.effects]
        self.assertEqual(kinds[-3:], ['update_send_empty_message', 'update_send_empty_message', 'update_listener'])
        self.assertIsNone(self.state.handler)

    def test_listener_exception_can_notify_twice_but_second_exception_escapes(self):
        answers = iter((support.fault(), None))
        self.run_update(overrides={'update_listener': lambda _: next(answers)})
        kinds = [e.kind for e in self.effects]
        self.assertEqual(kinds.count('update_listener'), 2)
        self.assertEqual(kinds.count('update_send_empty_message'), 1)
        with self.assertRaises(type(support.fault())):
            self.run_update(overrides={'update_listener': support.fault()})

    def test_status_read_after_callback_can_repeat_listener(self):
        self.run_update(overrides={'read_update_status': support.fault()})
        self.assertEqual([e.kind for e in self.effects][-3:], ['update_listener', 'read_update_status', 'update_listener'])

    def test_no_listener_handler_does_not_invent_callback_and_link_error_escapes(self):
        self.run_update(handler=None, listener=None, overrides={'check_update': False})
        self.assertNotIn('update_listener', [e.kind for e in self.effects])
        with self.assertRaises(LinkFault):
            self.run_update(overrides={'check_update': LinkFault()})
        self.assertNotIn('update_listener', [e.kind for e in self.effects])
