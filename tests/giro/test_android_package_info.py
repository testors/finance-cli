"""Synthetic framework observations only; no Binder/package queries."""
import unittest
from giro.android_package_info import ApplicationManagerState, application_info_steps, project_application_info_steps
from giro.codeguard_device import ExtendedDeviceState, extended_device_steps
from giro.codeguard_effects import Effect, JavaFault, LinkFault
from giro.codeguard_rule import AnalysisLimit
from test_codeguard_response import drive, fault
from test_codeguard_device import rcl

class PackageInfoTests(unittest.TestCase):

    def setUp(self):
        self.manager = ApplicationManagerState(object())
        self.info = object()
        self.effects = []

    def run_info(self, flags=1, overrides=None, generator=None):
        replies = dict(pm_context_user_id=10, pm_strictmode_implicit_direct_boot_enabled=False, pm_process_user_id=10, pm_is_user_unlocking_or_unlocked=True, pm_on_implicit_direct_boot=None, pm_application_info_cached=self.info, pm_maybe_adjust_application_info=self.info, device_log=None, device_package_manager=self.manager, device_application_package_name='synth.pkg', device_runtime=object(), device_runtime_exec=object(), device_process_destroy=None)
        replies.update(overrides or {})

        def reply(effect):
            self.effects.append(effect)
            result = replies[effect.kind]
            return result(effect) if callable(result) else result
        return drive(generator if generator is not None else application_info_steps(self.manager, 'SYNTH-PRIVATE', flags), reply)

    def kinds(self):
        return [e.kind for e in self.effects]

    def test_context_user_and_unchanged_flags_in_cache_key(self):
        self.assertIs(self.run_info(), self.info)
        call = next((e for e in self.effects if e.kind == 'pm_application_info_cached'))
        self.assertEqual(call.args, ('SYNTH-PRIVATE', 1, 10))
        self.assertNotIn('pm_process_user_id', self.kinds())

    def test_null_cache_result_throws_name_not_found_without_exposing_in_repr(self):
        with self.assertRaises(JavaFault) as caught:
            self.run_info(overrides={'pm_application_info_cached': None})
        self.assertEqual(caught.exception.kind, 'NameNotFoundException')
        self.assertEqual(caught.exception.message, 'SYNTH-PRIVATE')
        self.assertNotIn('SYNTH-PRIVATE', str(caught.exception) + repr(caught.exception))
        self.assertNotIn('pm_maybe_adjust_application_info', self.kinds())

    def test_cache_exception_not_changed_to_name_not_found(self):
        for kind in ('SecurityException', 'RuntimeException'):
            problem = fault(kind)
            with self.assertRaises(JavaFault) as caught:
                self.run_info(overrides={'pm_application_info_cached': problem})
            self.assertIs(caught.exception, problem)

    def test_unknown_cache_observation_not_changed_to_absence(self):
        for problem in (AnalysisLimit('no observation'), RuntimeError('synthetic'), LinkFault()):
            with self.subTest(problem=type(problem)), self.assertRaises(type(problem)):
                self.run_info(overrides={'pm_application_info_cached': problem})

    def test_adjustment_fault_propagates_even_though_name_is_all_caller_needs(self):
        with self.assertRaises(JavaFault):
            self.run_info(overrides={'pm_maybe_adjust_application_info': fault()})

    def test_flag_masks_skip_implicit_check(self):
        for flags in (0, 16, 1 | 269221888):
            self.effects.clear()
            self.run_info(flags)
            self.assertNotIn('pm_strictmode_implicit_direct_boot_enabled', self.kinds())

    def test_flags_int_to_long_is_sign_extension(self):
        self.run_info(-1)
        self.assertEqual(next((e for e in self.effects if e.kind == 'pm_application_info_cached')).args[1], -1)

    def test_strictmode_disabled_does_not_read_user_state(self):
        self.run_info()
        self.assertNotIn('pm_is_user_unlocking_or_unlocked', self.kinds())
        self.assertFalse(self.manager.user_unlocked)

    def test_own_user_unlock_sets_cache_and_later_skips_lookup(self):
        self.run_info(overrides={'pm_strictmode_implicit_direct_boot_enabled': True})
        self.assertTrue(self.manager.user_unlocked)
        self.effects.clear()
        self.run_info(overrides={'pm_strictmode_implicit_direct_boot_enabled': True})
        self.assertNotIn('pm_is_user_unlocking_or_unlocked', self.kinds())

    def test_other_user_does_not_set_or_consume_own_unlocked_cache(self):
        for prior in (False, True):
            self.manager.user_unlocked = prior
            self.effects.clear()
            self.run_info(overrides={'pm_strictmode_implicit_direct_boot_enabled': True, 'pm_process_user_id': 0})
            self.assertIn('pm_is_user_unlocking_or_unlocked', self.kinds())
            self.assertIs(self.manager.user_unlocked, prior)

    def test_locked_user_reports_strictmode_but_does_not_set_cache(self):
        self.run_info(overrides={'pm_strictmode_implicit_direct_boot_enabled': True, 'pm_is_user_unlocking_or_unlocked': False})
        self.assertIn('pm_on_implicit_direct_boot', self.kinds())
        self.assertFalse(self.manager.user_unlocked)

    def test_strictmode_fault_prevents_cache_request(self):
        with self.assertRaises(JavaFault):
            self.run_info(overrides={'pm_strictmode_implicit_direct_boot_enabled': True, 'pm_is_user_unlocking_or_unlocked': False, 'pm_on_implicit_direct_boot': fault()})
        self.assertNotIn('pm_application_info_cached', self.kinds())

    def test_no_invented_user_or_boolean(self):
        for kind in ('pm_context_user_id', 'pm_strictmode_implicit_direct_boot_enabled'):
            with self.subTest(kind=kind), self.assertRaises(AnalysisLimit):
                self.run_info(overrides={kind: None})

    def test_framework_projection_then_ex_package_success(self):
        state = ExtendedDeviceState()
        gen = project_application_info_steps(extended_device_steps(state, rcl((11, 'target'))))
        self.assertTrue(self.run_info(generator=gen))
        self.assertEqual(state.detail, 'target')
        self.assertNotIn('device_runtime_exec', self.kinds())

    def test_genuine_null_cache_result_reaches_ex_exec_fallthrough(self):
        state = ExtendedDeviceState()
        gen = project_application_info_steps(extended_device_steps(state, rcl((11, 'target'))))
        self.assertTrue(self.run_info(generator=gen, overrides={'pm_application_info_cached': None}))
        self.assertIn('device_runtime_exec', self.kinds())

    def test_security_failure_does_not_reach_ex_exec(self):
        state = ExtendedDeviceState()
        gen = project_application_info_steps(extended_device_steps(state, rcl((11, 'target'))))
        with self.assertRaises(JavaFault):
            self.run_info(generator=gen, overrides={'pm_application_info_cached': fault('SecurityException')})
        self.assertNotIn('device_runtime_exec', self.kinds())

    def test_custom_package_manager_stays_opaque(self):
        manager = object()

        def generator():
            return (yield Effect('device_application_info', (manager, 'target', 1)))
        projected = project_application_info_steps(generator())
        self.assertEqual(next(projected).kind, 'device_application_info')
        with self.assertRaises(StopIteration) as done:
            projected.send('observed custom result')
        self.assertEqual(done.exception.value, 'observed custom result')

    def test_manager_repr_does_not_print_context(self):
        self.assertNotIn('PRIVATE', repr(ApplicationManagerState('PRIVATE')))
if __name__ == '__main__':
    unittest.main()
