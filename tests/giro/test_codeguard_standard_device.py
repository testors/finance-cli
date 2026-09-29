"""Synthetic platform observations; never runs su, which, or package queries."""
import unittest
from giro.codeguard_standard_device import StandardDeviceState, standard_device_steps, which_su_steps, PACKAGES
from giro.codeguard_device import ExtendedDeviceState, project_device_steps
from giro.codeguard_response import oscheck_steps, os_status_digest
from giro.codeguard_effects import JavaFault, LinkFault
from giro.codeguard_rule import AnalysisLimit
from test_codeguard_response import drive, fault, sample_state

class DeviceFixture:

    def setUp(self):
        self.state = StandardDeviceState('old')
        self.effects = []

    def run_check(self, options='', overrides=None, generator=None):
        replies = dict(device_log_debug_enabled=False, device_log=None, device_runtime=object(), device_runtime_exec=fault('IOException'), device_runtime_exec_array=object(), device_process_destroy=None, device_package_manager=object(), device_application_info=fault('NameNotFoundException'), device_application_package_name=None, device_file=object(), device_file_exists=False, device_context_present=True, device_package_info=fault(), device_build_field='release-keys', device_process_output_stream=object(), device_process_input_stream=object(), device_buffered_default_writer=object(), device_buffered_default_reader=object(), device_reader_line=None, device_reader_close=None, device_writer_close=None, device_print_stack_trace=None)
        replies.update(overrides or {})

        def reply(effect):
            self.effects.append(effect)
            result = replies[effect.kind]
            return result(effect) if callable(result) else result
        return drive(generator if generator is not None else standard_device_steps(self.state, options), reply)

    def kinds(self):
        return [e.kind for e in self.effects]

class StandardDeviceTests(DeviceFixture, unittest.TestCase):

    def test_empty_options_still_attempt_su_then_all_five_packages(self):
        self.assertFalse(self.run_check())
        calls = [e for e in self.effects if e.kind == 'device_runtime_exec']
        self.assertEqual(calls[0].args[1], 'su')
        self.assertEqual([e.args[1] for e in self.effects if e.kind == 'device_application_info'], list(PACKAGES))
        self.assertNotIn('device_file', self.kinds())
        self.assertEqual(self.state.detail, 'old')

    def test_su_updates_detail_after_destroy(self):

        def destroy(_):
            self.assertEqual(self.state.detail, 'old')
        self.assertTrue(self.run_check(overrides={'device_runtime_exec': object(), 'device_process_destroy': destroy}))
        self.assertEqual(self.state.detail, 'run su')
        self.assertNotIn('device_package_manager', self.kinds())

    def test_su_destroy_error_does_not_leave_run_su_detail(self):
        self.assertFalse(self.run_check(overrides={'device_runtime_exec': object(), 'device_process_destroy': fault()}))
        self.assertEqual(self.state.detail, 'old')

    def test_su_getruntime_is_outside_catch(self):
        with self.assertRaises(JavaFault):
            self.run_check(overrides={'device_runtime': fault()})
        self.assertNotIn('device_package_manager', self.kinds())

    def test_package_null_return_still_counts_and_shortcircuits(self):
        self.assertTrue(self.run_check(overrides={'device_application_info': None}))
        self.assertEqual(self.state.detail, PACKAGES[0])
        self.assertEqual(self.kinds().count('device_application_info'), 1)
        self.assertNotIn('device_application_package_name', self.kinds())

    def test_package_any_java_exception_continues_but_manager_fault_propagates(self):
        self.assertFalse(self.run_check(overrides={'device_application_info': fault('SecurityException')}))
        with self.assertRaises(JavaFault):
            self.run_check(overrides={'device_package_manager': fault()})

    def test_options_are_membership_fixed_order_not_input_sequence(self):
        self.assertFalse(self.run_check('443200', {'device_runtime_exec_array': fault()}))
        self.assertEqual([e.args[0] for e in self.effects if e.kind == 'device_file'], ['/system/app/Superuser.apk', '/system/app/userSU.apk'])
        self.assertLess(self.kinds().index('device_file'), self.kinds().index('device_build_field'))
        self.assertNotIn('device_runtime_exec_array', self.kinds())

    def test_null_options_select_all_and_empty_which_result_counts(self):
        self.assertTrue(self.run_check(None))
        self.assertEqual(self.state.detail, '/system/xbin/which su')
        self.assertNotIn('device_build_field', self.kinds())

    def test_default_convenience_options_exclude_which(self):
        self.assertFalse(self.run_check('0234'))
        self.assertNotIn('device_runtime_exec_array', self.kinds())
        self.assertIn('device_build_field', self.kinds())

    def test_positive_file_sets_detail_and_shortcircuits(self):
        self.assertTrue(self.run_check('04', {'device_file_exists': True}))
        self.assertEqual(self.state.detail, '/system/app/Superuser.apk')
        self.assertEqual(self.kinds().count('device_file'), 1)

    def test_file_java_failure_continues_unknown_boolean_does_not(self):
        self.assertFalse(self.run_check('0', {'device_file_exists': fault()}))
        with self.assertRaises(AnalysisLimit):
            self.run_check('0', {'device_file_exists': None})

    def test_tags_only_and_case_sensitive_null(self):
        self.assertTrue(self.run_check('2', {'device_build_field': 'some-test-keys-tag'}))
        self.assertEqual(self.state.detail, 'test-keys')
        for tags in (None, '', 'TEST-KEYS'):
            self.assertFalse(self.run_check('2', {'device_build_field': tags}))

    def test_lagfix_null_result_counts_as_success(self):
        self.assertTrue(self.run_check('3', {'device_package_info': None}))
        self.assertEqual(self.state.detail, 'com.tegrak.lagfix')

    def test_lagfix_null_context_skips_packageinfo(self):
        self.assertFalse(self.run_check('3', {'device_context_present': False}))
        self.assertNotIn('device_package_info', self.kinds())

    def test_lagfix_package_manager_fault_is_locally_caught(self):
        calls = 0

        def manager(_):
            nonlocal calls
            calls += 1
            return fault() if calls > 5 else object()
        self.assertFalse(self.run_check('3', {'device_package_manager': manager}))
        self.assertEqual(calls, 6)

    def test_selected_negative_debug_logs_not_emitted_for_null_options(self):
        overrides = {'device_log_debug_enabled': True, 'device_runtime_exec_array': fault()}
        self.assertFalse(self.run_check('0', overrides))
        self.assertEqual([e.args[0] for e in self.effects if e.kind == 'device_log'], ['osCheckList: 0', 'osCheck 0 ok'])
        self.effects.clear()
        self.assertFalse(self.run_check(None, overrides))
        self.assertEqual([e.args[0] for e in self.effects if e.kind == 'device_log'], ['osCheckList: null'])

    def test_real_faults_propagate_not_python_or_link_to_clean(self):
        for problem in (AnalysisLimit('unknown'), RuntimeError('synthetic'), LinkFault()):
            with self.subTest(problem=type(problem)), self.assertRaises(type(problem)):
                self.run_check(overrides={'device_runtime_exec': problem})

    def test_shared_detail_survives_false(self):
        self.assertTrue(self.run_check('4', {'device_file_exists': True}))
        self.assertFalse(self.run_check())
        self.assertEqual(self.state.detail, '/system/app/userSU.apk')

    def test_combined_projector_routes_standard_without_touching_ex_state(self):
        (service, extended) = (sample_state(), ExtendedDeviceState('EX-OLD'))
        gen = project_device_steps(oscheck_steps(service, challenge='c', root_check=True, rooting_info=False, fourth='2', rcl=''), extended_state=extended, standard_state=self.state)
        self.assertEqual(self.run_check(overrides={'device_build_field': 'test-keys'}, generator=gen), os_status_digest('test-keys'))
        self.assertEqual(extended.detail, 'EX-OLD')
        self.assertTrue(service.detail_enabled)

class ExecShellTests(DeviceFixture, unittest.TestCase):

    def shell(self, **overrides):
        return self.run_check(overrides=overrides, generator=which_su_steps())

    def test_which_initial_runtime_or_exec_fault_returns_null(self):
        for kind in ('device_runtime', 'device_runtime_exec_array'):
            self.effects.clear()
            self.assertIsNone(self.shell(**{kind: fault()}))
            self.assertNotIn('device_process_output_stream', self.kinds())

    def test_which_stream_construction_fault_is_not_caught(self):
        for kind in ('device_process_output_stream', 'device_buffered_default_writer', 'device_process_input_stream', 'device_buffered_default_reader'):
            self.effects.clear()
            with self.assertRaises(JavaFault):
                self.shell(**{kind: fault()})
            self.assertNotIn('device_process_destroy', self.kinds())

    def test_which_reads_all_lines_until_null(self):
        lines = iter(('one', 'two', '', None))
        self.assertEqual(self.shell(device_reader_line=lambda _: next(lines)), ['one', 'two', ''])
        self.assertEqual(self.kinds().count('device_reader_line'), 4)
        call = next((e for e in self.effects if e.kind == 'device_runtime_exec_array'))
        self.assertEqual(call.args[1], ('/system/xbin/which', 'su'))

    def test_which_read_exception_returns_partial_list_after_close_destroy(self):
        lines = iter(('one', fault('IOException')))
        self.assertEqual(self.shell(device_reader_line=lambda _: next(lines)), ['one'])
        self.assertLess(self.kinds().index('device_print_stack_trace'), self.kinds().index('device_reader_close'))
        self.assertIn('device_process_destroy', self.kinds())

    def test_which_empty_output_is_empty_list_not_null(self):
        self.assertEqual(self.shell(), [])

    def test_which_reader_close_ioexception_skips_writer_but_destroys(self):
        self.assertEqual(self.shell(device_reader_close=fault('IOException')), [])
        self.assertNotIn('device_writer_close', self.kinds())
        self.assertIn('device_process_destroy', self.kinds())

    def test_which_writer_close_ioexception_is_ignored(self):
        self.assertEqual(self.shell(device_writer_close=fault('IOException')), [])

    def test_which_close_nonio_fault_propagates_skips_destroy(self):
        with self.assertRaises(JavaFault):
            self.shell(device_reader_close=fault('SecurityException'))
        self.assertNotIn('device_process_destroy', self.kinds())

    def test_which_destroy_failure_propagates_not_null(self):
        with self.assertRaises(JavaFault):
            self.shell(device_process_destroy=fault())

    def test_which_read_linkerror_closes_then_rethrows_no_destroy(self):
        with self.assertRaises(LinkFault):
            self.shell(device_reader_line=LinkFault())
        self.assertIn('device_writer_close', self.kinds())
        self.assertNotIn('device_process_destroy', self.kinds())

    def test_which_stacktrace_fault_closes_and_rethrows(self):
        with self.assertRaises(JavaFault):
            self.shell(device_reader_line=fault(), device_print_stack_trace=fault('SecurityException'))
        self.assertIn('device_writer_close', self.kinds())
        self.assertNotIn('device_process_destroy', self.kinds())

    def test_which_debug_log_fault_does_not_append_current_line(self):
        lines = iter(('one', 'two', None))

        def log(effect):
            if effect.args[0] == '--> Line received: two':
                return fault()
        self.assertEqual(self.shell(device_reader_line=lambda _: next(lines), device_log_debug_enabled=True, device_log=log), ['one'])
if __name__ == '__main__':
    unittest.main()
