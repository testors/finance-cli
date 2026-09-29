"""Synthetic observations only; no device checks/commands or server requests."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch
from giro.android_json import parse_object, parse_array, array_string_at, int_field, boolean_field, JSONArray
from giro.codeguard_device import RclEntry, rcl_entries, inspect_rcl_requirements, ExtendedDeviceState, extended_device_steps, project_extended_device_steps, BUILD_FIELDS
from giro.codeguard_effects import Effect, JavaFault, LinkFault
from giro.codeguard_response import oscheck_steps, os_status_digest
from giro.codeguard_rule import AnalysisLimit
from test_codeguard_response import drive, fault, sample_state

def rcl(*entries):
    return json.dumps([dict(description=desc, policy=policy, osType=1, enabled=True) for (policy, desc) in entries])

class RclJsonTests(unittest.TestCase):

    def test_number_long_wraps_but_string_double_saturates(self):
        self.assertEqual(int_field(parse_object('{x:4294967307}'), 'x'), 11)
        self.assertEqual(int_field(parse_object('{x:"4294967307"}'), 'x'), 2147483647)
        self.assertEqual(int_field(parse_object('{x:9223372036854775807}'), 'x'), -1)

    def test_double_casts_truncate_saturate_and_nan_zero(self):
        for (raw, result) in (('11.75', 11), ('-11.75', -11), ('"NaN"', 0), ('"Infinity"', 2147483647), ('"-Infinity"', -2147483648), ('" 0x1.8p3f "', 12), ('"1e9999"', 2147483647)):
            with self.subTest(raw=raw):
                self.assertEqual(int_field(parse_object('{x:' + raw + '}'), 'x'), result)

    def test_number_octal_vs_string_decimal(self):
        self.assertEqual(int_field(parse_object('{x:013}'), 'x'), 11)
        self.assertEqual(int_field(parse_object('{x:"013"}'), 'x'), 13)

    def test_invalid_int_does_not_become_zero(self):
        for raw in ('true', 'false', '"11x"', '[]', '{}', '"0x10"'):
            with self.subTest(raw=raw), self.assertRaises(JavaFault) as caught:
                int_field(parse_object('{x:' + raw + '}'), 'x')
            self.assertEqual(caught.exception.kind, 'JSONException')

    def test_defaults_only_missing_null(self):
        for raw in ('{}', '{x:null}'):
            self.assertEqual(int_field(parse_object(raw), 'x', 99), 99)
            self.assertIs(boolean_field(parse_object(raw), 'x', True), True)
        self.assertIs(boolean_field(parse_object('{x:false}'), 'x', True), False)

    def test_boolean_case_without_trim_or_numeric_truth(self):
        for (raw, result) in (('true', True), ('"TrUe"', True), ('"falſe"', False)):
            self.assertIs(boolean_field(parse_object('{x:' + raw + '}'), 'x'), result)
        for raw in ('1', '0', '" true "', '[]'):
            with self.subTest(raw=raw), self.assertRaises(JavaFault):
                boolean_field(parse_object('{x:' + raw + '}'), 'x')

    def test_unknown_unicode_is_analysis_limit_not_json_failure(self):
        with self.assertRaises(AnalysisLimit):
            boolean_field(parse_object('{x:"未知"}'), 'x')

    def test_array_lenient_trailing_and_getstring_objects(self):
        array = parse_array('/*x*/[{a:1};true;null;] ignored')
        self.assertEqual([array_string_at(array, i) for i in range(4)], ['{"a":1}', 'true', 'null', 'null'])

    def test_array_wrong_root_or_index(self):
        for raw in ('{}', 'null', '"a"'):
            with self.subTest(raw=raw), self.assertRaises(JavaFault):
                parse_array(raw)
        for index in (-1, 1):
            with self.assertRaises(JavaFault) as caught:
                array_string_at(parse_array('[1]'), index)
            self.assertEqual(caught.exception.message, 'Index ' + str(index) + ' out of range [0..1)')

    def test_nonfinite_direct_array_value_vs_nested_render_failure(self):
        array = parse_array('[NaN,[NaN]]')
        self.assertEqual(array_string_at(array, 0), 'NaN')
        with self.assertRaises(JavaFault) as caught:
            array_string_at(array, 1)
        self.assertEqual(caught.exception.message, 'Value null at 1 of type org.json.JSONArray cannot be converted to String')

    def test_jdk_numeric_and_boolean_vectors(self):
        if not shutil.which('java'):
            self.skipTest('JDK unavailable for synthetic vector crosscheck')
        source = Path(__file__).parent / 'java' / 'RclVectors.java'
        output = subprocess.check_output(['java', str(source)], text=True)
        self.assertEqual(output.splitlines(), ['11', '2147483647', '-1', '11', '-11', '0', '2147483647', '-2147483648', '12', 'true', 'false', 'false'])

class RclEntryTests(unittest.TestCase):

    def test_defaults_and_disabled_entry_not_in_list(self):
        entry = RclEntry.parse('{}')
        self.assertEqual((entry.description, entry.policy, entry.os_type, entry.enabled), ('', 0, 0, False))
        self.assertEqual(rcl_entries('[{},null,3,true,"bad",NaN]'), [])

    def test_partial_assignment_before_policy_error(self):
        entry = RclEntry.parse('{description:123,policy:[],osType:1,enabled:true}')
        self.assertEqual((entry.description, entry.policy, entry.os_type, entry.enabled), ('123', 0, 0, False))

    def test_partial_assignment_before_os_type_and_enabled_error(self):
        entry = RclEntry.parse('{description:d,policy:12,osType:[],enabled:true}')
        self.assertEqual((entry.policy, entry.os_type, entry.enabled), (12, 0, False))
        entry = RclEntry.parse('{description:d,policy:12,osType:1,enabled:1}')
        self.assertEqual((entry.policy, entry.os_type, entry.enabled), (12, 1, False))

    def test_string_array_element_and_object_element_equivalent(self):
        obj = dict(description='synth-path', policy='12.75', osType='1', enabled='TRUE')
        entries = rcl_entries(json.dumps([obj, json.dumps(obj)]))
        self.assertEqual(len(entries), 2)
        self.assertEqual(vars(entries[0]), vars(entries[1]))
        self.assertEqual((entries[0].policy, entries[0].os_type), (12, 1))

    def test_unknown_policy_os_empty_description_preserved_during_parse(self):
        entries = rcl_entries('[{enabled:true},{policy:999,osType:2,description:"",enabled:true}]')
        self.assertEqual([(e.policy, e.os_type, e.description) for e in entries], [(0, 0, ''), (999, 2, '')])

    def test_late_outer_getstring_failure_is_not_inner_disabled_entry(self):
        with self.assertRaises(JavaFault):
            rcl_entries(rcl((12, 'first'))[:-1] + ',[NaN]]')

    def test_unknown_numeric_rendering_not_silently_disabled(self):
        with self.assertRaises(AnalysisLimit):
            rcl_entries('[{description:1.2345678901234567,enabled:true}]')

    def test_repr_never_includes_description_or_static_detail(self):
        secret = 'SYNTHETIC-SENSITIVE-DETAIL'
        self.assertNotIn(secret, repr(RclEntry(description=secret)))
        self.assertNotIn(secret, repr(ExtendedDeviceState(secret)))
        self.assertNotIn(secret, repr(Effect('device_runtime_exec', (object(), secret))))

class ExtendedDeviceTests(unittest.TestCase):

    def setUp(self):
        self.state = ExtendedDeviceState('old-detail')
        self.effects = []

    def run_check(self, text, overrides=None):
        replies = dict(device_log=None, device_package_manager=object(), device_application_info=None, device_application_package_name='', device_runtime=object(), device_runtime_exec=object(), device_process_destroy=None, device_file=object(), device_file_exists=False, device_build_field=lambda e: 'synth-' + e.args[0])
        replies.update(overrides or {})

        def reply(effect):
            self.effects.append(effect)
            result = replies[effect.kind]
            return result(effect) if callable(result) else result
        return drive(extended_device_steps(self.state, text), reply)

    def kinds(self):
        return [e.kind for e in self.effects]

    def test_invalid_rcl_returns_false_before_any_effect(self):
        self.assertFalse(self.run_check('not-an-array'))
        self.assertEqual(self.effects, [])
        self.assertEqual(self.state.detail, 'old-detail')

    def test_late_bad_array_string_prevents_earlier_check(self):
        self.assertFalse(self.run_check(rcl((12, 'first'))[:-1] + ',[NaN]]'))
        self.assertEqual(self.effects, [])

    def test_disabled_wrong_os_unknown_policy_do_not_run_checks(self):
        text = '[{enabled:false,osType:1,policy:14},{enabled:true,osType:2,policy:14},{enabled:true,osType:1,policy:999}]'
        self.assertFalse(self.run_check(text))
        self.assertEqual(self.kinds(), ['device_log'])

    def test_file_positive_stops_before_next_entry(self):
        self.assertTrue(self.run_check(rcl((12, 'first'), (14, 'second')), {'device_file_exists': True}))
        self.assertEqual(self.state.detail, 'first')
        self.assertNotIn('device_runtime_exec', self.kinds())

    def test_file_false_keeps_detail(self):
        self.assertFalse(self.run_check(rcl((12, 'path'))))
        self.assertEqual(self.state.detail, 'old-detail')

    def test_file_fault_is_caught_and_next_entry_runs(self):
        self.assertTrue(self.run_check(rcl((12, 'path'), (14, 'cmd')), {'device_file_exists': fault()}))
        self.assertEqual(self.state.detail, 'cmd')

    def test_file_unknown_boolean_or_python_failure_not_clean(self):
        for result in (None, 0, RuntimeError('synthetic'), AnalysisLimit('synthetic'), LinkFault()):
            with self.subTest(result=type(result)), self.assertRaises((AnalysisLimit, RuntimeError, LinkFault)):
                self.run_check(rcl((12, 'path')), {'device_file_exists': result})

    def test_package_nonempty_name_returns_true_without_exec_or_name_equality(self):
        self.assertTrue(self.run_check(rcl((11, 'requested')), {'device_application_info': object(), 'device_application_package_name': 'different-name'}))
        self.assertEqual(self.state.detail, 'requested')
        self.assertNotIn('device_runtime_exec', self.kinds())
        call = next((e for e in self.effects if e.kind == 'device_application_info'))
        self.assertEqual(call.args[1:], ('requested', 1))

    def test_package_null_info_falls_through_to_runtime_exec(self):
        self.assertTrue(self.run_check(rcl((11, 'package-as-command'))))
        call = next((e for e in self.effects if e.kind == 'device_runtime_exec'))
        self.assertEqual(call.args[1], 'package-as-command')

    def test_package_missing_exception_falls_through(self):
        self.assertTrue(self.run_check(rcl((11, 'pkg')), {'device_application_info': fault('NameNotFoundException')}))
        self.assertIn('device_runtime_exec', self.kinds())

    def test_package_empty_or_null_name_falls_through(self):
        for name in ('', None):
            self.effects.clear()
            self.assertTrue(self.run_check(rcl((11, 'pkg')), {'device_application_info': object(), 'device_application_package_name': name}))
            self.assertIn('device_runtime_exec', self.kinds())

    def test_package_other_fault_not_swallowed(self):
        for kind in ('device_application_info', 'device_package_manager', 'device_application_package_name'):
            with self.subTest(kind=kind), self.assertRaises(JavaFault) as caught:
                self.run_check(rcl((11, 'pkg')), {'device_application_info': object(), kind: fault('SecurityException')})
            self.assertEqual(caught.exception.kind, 'SecurityException')

    def test_runtime_get_is_outside_catch(self):
        with self.assertRaises(JavaFault):
            self.run_check(rcl((14, 'cmd')), {'device_runtime': fault()})

    def test_exec_failure_keeps_old_detail(self):
        self.assertFalse(self.run_check(rcl((14, 'cmd')), {'device_runtime_exec': fault('IOException')}))
        self.assertEqual(self.state.detail, 'old-detail')
        self.assertNotIn('device_process_destroy', self.kinds())

    def test_destroy_failure_retains_new_detail_but_returns_false(self):
        self.assertFalse(self.run_check(rcl((14, 'cmd')), {'device_process_destroy': fault()}))
        self.assertEqual(self.state.detail, 'cmd')

    def test_destroy_failure_continues_to_later_entry(self):
        self.assertTrue(self.run_check(rcl((14, 'cmd'), (12, 'file')), {'device_process_destroy': fault(), 'device_file_exists': True}))
        self.assertEqual(self.state.detail, 'file')

    def test_exec_does_not_observe_exit_status_or_wait(self):
        self.assertTrue(self.run_check(rcl((14, 'cmd --synthetic arg'))))
        self.assertEqual(self.kinds(), ['device_log', 'device_runtime', 'device_runtime_exec', 'device_process_destroy', 'device_log'])

    def test_command_log_failure_is_caught_after_detail_changed(self):

        def log(effect):
            return fault() if 'SHALLCMD' in effect.args[0] else None
        self.assertFalse(self.run_check(rcl((14, 'cmd')), {'device_log': log}))
        self.assertEqual(self.state.detail, 'cmd')

    def test_initial_log_only_catches_jsonexception(self):
        self.assertFalse(self.run_check('[]', {'device_log': fault('JSONException')}))
        with self.assertRaises(JavaFault):
            self.run_check('[]', {'device_log': fault()})

    def test_build_only_tags_matches_but_all_fields_are_read(self):
        self.assertTrue(self.run_check(rcl((13, 'TAGS'))))
        self.assertEqual([e.args[0] for e in self.effects if e.kind == 'device_build_field'], list(BUILD_FIELDS))
        self.assertEqual(self.state.detail, 'TAGS')
        self.assertFalse(self.run_check(rcl((13, 'PRODUCT'))))

    def test_build_empty_description_matches_nonnull_tags(self):
        self.assertTrue(self.run_check(rcl((13, ''))))
        self.assertEqual(self.state.detail, '')

    def test_build_null_tags_does_not_match_empty_description(self):
        self.assertFalse(self.run_check(rcl((13, '')), {'device_build_field': None}))

    def test_build_contains_is_case_sensitive_utf16(self):
        self.assertFalse(self.run_check(rcl((13, 'tags'))))
        self.assertTrue(self.run_check(rcl((13, '\ud83d')), {'device_build_field': '😀'}))
        self.assertFalse(self.run_check(rcl((13, 'Ȁ')), {'device_build_field': '\x01\x02'}))

    def test_build_reads_fault_propagates_before_predicate(self):

        def build(effect):
            return fault() if effect.args[0] == 'FINGERPRINT' else 'target'
        with self.assertRaises(JavaFault):
            self.run_check(rcl((13, 'target')), {'device_build_field': build})
        self.assertEqual(self.state.detail, 'old-detail')

    def test_analysis_limit_is_not_clean_result(self):
        with self.assertRaises(AnalysisLimit):
            self.run_check(None)

    def test_shared_detail_not_reset_by_later_false(self):
        self.assertTrue(self.run_check(rcl((14, 'first'))))
        self.assertFalse(self.run_check('[]'))
        self.assertEqual(self.state.detail, 'first')

class DeviceProjectionTests(unittest.TestCase):

    def test_oscheck_build_match_routes_detail_and_digest(self):
        (state, device) = (sample_state(), ExtendedDeviceState())
        gen = project_extended_device_steps(oscheck_steps(state, challenge='challenge', root_check=True, rooting_info=False, fourth=None, rcl=rcl((13, 'TAGS'))), state=device)

        def reply(effect):
            if effect.kind == 'device_log':
                return None
            if effect.kind == 'device_build_field':
                return 'synth-' + effect.args[0]
            self.fail('unexpected effect')
        self.assertEqual(drive(gen, reply), os_status_digest('TAGS'))
        self.assertTrue(state.detail_enabled)

    def test_observed_device_fault_reaches_original_oscheck_catch(self):
        (state, device) = (sample_state(), ExtendedDeviceState('old'))
        gen = project_extended_device_steps(oscheck_steps(state, challenge='challenge', root_check=True, rooting_info=False, fourth=None, rcl=rcl((11, 'pkg'))), state=device)
        self.assertEqual(drive(gen, lambda e: None if e.kind == 'device_log' else fault()), os_status_digest('challenge'))
        self.assertEqual(state.status_log, 'E0,E32.4')
        self.assertEqual(device.detail, 'old')

    def test_unavailable_platform_is_not_caught_as_java_failure(self):
        state = sample_state()
        gen = project_extended_device_steps(oscheck_steps(state, challenge='challenge', root_check=True, rooting_info=False, fourth=None, rcl=rcl((12, 'path'))), state=ExtendedDeviceState())
        with self.assertRaises(AnalysisLimit):
            drive(gen, lambda e: None if e.kind == 'device_log' else AnalysisLimit('no observer'))
        self.assertEqual(state.status_log, 'E0')

    def test_standard_and_future_pass_through_unmodified(self):
        seen = []

        def sequence():
            self.assertEqual((yield Effect('device_check', ('standard', '0234'))), 'observed-standard')
            return (yield Effect('oscheck_future', ('synthetic future',)))

        def reply(effect):
            seen.append(effect.kind)
            return 'observed-standard' if effect.kind == 'device_check' else 'observed-future'
        result = drive(project_extended_device_steps(sequence(), state=ExtendedDeviceState()), reply)
        self.assertEqual(result, 'observed-future')
        self.assertEqual(seen, ['device_check', 'oscheck_future'])

    def test_root_check_disabled_never_decodes_rcl(self):
        state = sample_state()
        gen = project_extended_device_steps(oscheck_steps(state, challenge='challenge', root_check=False, rooting_info=False, fourth=None, rcl='not parsed'), state=ExtendedDeviceState())
        self.assertEqual(drive(gen, lambda _: self.fail('unexpected effect')), os_status_digest('challenge'))

    def test_generator_has_no_process_executor(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no process execution')):
            generator = extended_device_steps(ExtendedDeviceState(), rcl((14, 'never execute')))
            self.assertEqual(next(generator).kind, 'device_log')
            self.assertEqual(generator.send(None).kind, 'device_runtime')
            self.assertEqual(generator.send(object()).kind, 'device_runtime_exec')
            generator.close()

class RclInventoryTests(unittest.TestCase):

    def test_counts_all_candidates_without_shortcircuit_or_evaluation(self):
        report = inspect_rcl_requirements(rcl((11, 'secret'), (12, 'path'), (13, 'tags'), (14, 'cmd'), (999, 'unknown')))
        self.assertEqual(report['android_policy_counts'], dict(install_app=1, filename=1, build_tags=1, runtime_exec=1, unknown=1))
        self.assertEqual(report['android_entry_count'], 5)
        self.assertTrue(report['possible_process_execution'])
        self.assertFalse(report['environment_checks_performed'])
        self.assertFalse(report['process_execution_performed'])

    def test_install_app_alone_has_possible_exec_due_to_fallthrough(self):
        self.assertTrue(inspect_rcl_requirements(rcl((11, 'secret')))['possible_process_execution'])
        self.assertFalse(inspect_rcl_requirements(rcl((12, 'secret')))['possible_process_execution'])

    def test_disabled_and_other_os_not_counted_as_android_work(self):
        report = inspect_rcl_requirements('[{enabled:false,osType:1,policy:14},{enabled:true,osType:2,policy:14}]')
        self.assertEqual(report['enabled_entry_count'], 1)
        self.assertEqual(report['non_android_entry_count'], 1)
        self.assertEqual(report['android_entry_count'], 0)
        self.assertFalse(report['possible_process_execution'])

    def test_json_failure_and_unmodeled_input_are_distinct_not_clean_results(self):
        self.assertEqual(inspect_rcl_requirements('broken')['analysis_status'], 'rcl_original_json_exception')
        report = inspect_rcl_requirements('[{description:1.2345678901234567,enabled:true}]')
        self.assertEqual(report['analysis_status'], 'rcl_value_adapter_boundary')
        self.assertNotIn('possible_process_execution', report)

    def test_empty_array_is_parsed_not_environment_success(self):
        report = inspect_rcl_requirements('[]')
        self.assertEqual(report['analysis_status'], 'rcl_requirements_decoded')
        self.assertEqual(report['android_entry_count'], 0)
        self.assertNotIn('device_clean', report)

    def test_no_secret_strings_even_on_fault(self):
        for text in (rcl((14, 'SYNTH-SECRET-COMMAND')), 'SYNTH-SECRET-MALFORMED'):
            report = inspect_rcl_requirements(text)
            self.assertNotIn('SYNTH-SECRET', json.dumps(report))

    def test_unexpected_local_fault_is_diagnostic_and_sanitized(self):
        with patch('giro.codeguard_device.rcl_entries', side_effect=RuntimeError('SYNTH-SECRET')):
            report = inspect_rcl_requirements('[]')
        self.assertEqual(report['analysis_status'], 'local_rcl_inspection_boundary')
        self.assertNotIn('SYNTH-SECRET', json.dumps(report))

    def test_does_not_evaluate_effect_generator(self):
        with patch('giro.codeguard_device.extended_device_steps', side_effect=AssertionError('never evaluate')):
            self.assertEqual(inspect_rcl_requirements(rcl((14, 'cmd')))['analysis_status'], 'rcl_requirements_decoded')
if __name__ == '__main__':
    unittest.main()
