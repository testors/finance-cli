import unittest
from unittest.mock import patch

from giro.codeguard_native_jni import (NativeLookupBoundary, PackageManagerLookup,
                                      package_manager_lookup_steps, package_path_lookup_steps)
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_native_io import FailedCmdlineRead


class NativeLookupTests(unittest.TestCase):
    def run_lookup(self, phase, *, sdk=34, matches=True, absent=(), observed=None):
        calls = []
        def drive():
            generator = package_manager_lookup_steps('service', phase=phase)
            value = None
            while True:
                try:
                    effect = generator.send(value)
                except StopIteration as done:
                    return done.value
                self.assertEqual(effect.kind, 'native_jni')
                calls.append(effect.args)
                name, *args = effect.args
                if observed is not None:
                    observed(effect)
                if name == 'GetStaticIntField': value = sdk
                elif name == 'CallBooleanMethod': value = matches
                elif name == 'FindClass': value = args[0]
                elif name == 'GetObjectClass': value = ('class', args[0])
                elif name in ('GetMethodID', 'GetStaticFieldID'): value = args[1]
                elif name == 'CallObjectMethod': value = 'manager'
                else: self.fail(name)
                if len(calls) in absent: value = None
        try:
            return drive(), calls
        except NativeLookupBoundary as branch:
            return branch, calls

    def test_all_three_lookups_are_separate_and_preserve_ignored_getpath_calls(self):
        all_calls = []
        for phase in ('start', 'getpath', 'digest'):
            result, calls = self.run_lookup(phase)
            all_calls += calls
            self.assertEqual(len(calls), 13)
            self.assertEqual(calls[10], ('GetMethodID', 'java/lang/Class', 'isInstance', '(Ljava/lang/Object;)Z'))
            self.assertEqual(calls[11], ('CallBooleanMethod', 'android/app/ApplicationPackageManager', 'isInstance', 'manager'))
            self.assertEqual(calls[-1], ('GetMethodID', ('class', 'manager'), 'getApplicationInfo',
                                       '(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;'))
            if phase == 'getpath': self.assertEqual(result, 0)
            else:
                self.assertIsInstance(result, PackageManagerLookup)
                self.assertEqual(result.manager, 'manager')
        self.assertEqual(all_calls.count(('CallObjectMethod', 'service', 'getPackageManager')), 3)

    def test_sdk_class_selection_keeps_legacy_boundaries(self):
        for sdk, expected in ((-1, 'ApplicationContext$ApplicationPackageManager'),
                              (6, 'ApplicationContext$ApplicationPackageManager'),
                              (7, 'ContextImpl$ApplicationPackageManager'),
                              (10, 'ContextImpl$ApplicationPackageManager'),
                              (11, 'ApplicationPackageManager')):
            for phase in ('start', 'getpath', 'digest'):
                _, calls = self.run_lookup(phase, sdk=sdk)
                self.assertEqual(calls[8], ('FindClass', 'android/app/' + expected))

    def test_false_isinstance_has_different_branch_codes_and_getpath_ignores_it(self):
        for phase, code in (('start', 131), ('digest', 14)):
            result, calls = self.run_lookup(phase, matches=False)
            self.assertIsInstance(result, AnalysisLimit)
            self.assertEqual((result.phase, result.native_code), (phase, code))
            self.assertEqual(calls[-1][0], 'CallBooleanMethod')
        result, calls = self.run_lookup('getpath', matches=False)
        self.assertEqual(result, 0)
        self.assertEqual(calls[-1][2], 'getApplicationInfo')

    def test_missing_expected_class_still_looks_up_class_and_application_method(self):
        for phase in ('start', 'getpath', 'digest'):
            result, calls = self.run_lookup(phase, absent=(9, 10))
            self.assertEqual(len(calls), 11)
            self.assertEqual(calls[9], ('FindClass', 'java/lang/Class'))
            self.assertFalse(any(c[0] == 'CallBooleanMethod' for c in calls))
            self.assertNotIsInstance(result, NativeLookupBoundary)

    def test_start_checks_service_class_before_application_class_lookup(self):
        result, calls = self.run_lookup('start', absent=(1,))
        self.assertEqual(result.native_code, 110)
        self.assertEqual(len(calls), 1)
        for phase in ('getpath', 'digest'):
            _, calls = self.run_lookup(phase, absent=(1,))
            self.assertEqual(calls[2][1], None)

    def test_application_class_and_method_null_branches_do_not_become_error_strings(self):
        for phase, code in (('start', 110), ('digest', 13)):
            for number in (2, 3, 10, 11, 13):
                result, calls = self.run_lookup(phase, absent=(number,))
                self.assertEqual(result.native_code, code)
                self.assertEqual(len(calls), number)
                self.assertNotIn('E101_', str(result))

    def test_manager_null_branch_exists_only_in_start(self):
        result, calls = self.run_lookup('start', absent=(4,))
        self.assertEqual(result.native_code, 110)
        self.assertEqual(len(calls), 4)
        for phase in ('getpath', 'digest'):
            _, calls = self.run_lookup(phase, absent=(4,))
            self.assertEqual(calls[4], ('GetObjectClass', None))
            self.assertEqual(calls[11][-1], None)

    def test_getpath_does_not_add_native_null_branches(self):
        result, calls = self.run_lookup('getpath', absent=(1, 2, 3, 4, 5, 6, 7, 10, 11, 13))
        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 13)
        self.assertEqual(calls[11][2], None)

    def test_no_implicit_exception_clear_or_retry(self):
        calls = []
        def unresolved(effect):
            calls.append(effect.args)
            if effect.args == ('FindClass', 'android/app/ApplicationPackageManager'):
                raise AnalysisLimit('unresolved pending JNI exception')
        with self.assertRaises(AnalysisLimit):
            self.run_lookup('digest', observed=unresolved)
        self.assertEqual(len(calls), 9)
        self.assertFalse(any(c[0] == 'ExceptionClear' for c in calls))

    def test_unknown_sdk_or_checked_boolean_is_not_a_clean_observation(self):
        for sdk in (None, True, '34', 2**31):
            with self.assertRaises(AnalysisLimit): self.run_lookup('start', sdk=sdk)
        with self.assertRaises(AnalysisLimit): self.run_lookup('digest', matches=None)
        with self.assertRaises(AnalysisLimit): next(package_manager_lookup_steps('s', phase='guess'))

    def test_no_sdk_or_host_io_and_no_reference_values_in_repr(self):
        with patch('builtins.open', side_effect=AssertionError('no files')), \
             patch('socket.socket', side_effect=AssertionError('no network')), \
             patch('ctypes.CDLL', side_effect=AssertionError('no SDK')):
            result, _ = self.run_lookup('start')
        self.assertNotIn('android/', repr(result))
        effect = next(package_manager_lookup_steps('private-context', phase='start'))
        self.assertNotIn('private-context', repr(effect))


class NativePathTests(unittest.TestCase):
    def run_paths(self, phase, **overrides):
        observations = dict(pid=123, process_class='android/os/Process', method='myPid',
                            stream='cmdline', line=b'pkg:engine', info='info',
                            source_ref='sourceDir', data_ref='dataDir',
                            source=b'/installed/pkg/base', data=b'/data/pkg')
        observations.update(overrides)
        generator = package_path_lookup_steps('service', phase=phase)
        value, calls = None, []
        while True:
            try:
                effect = generator.send(value)
            except StopIteration as done:
                return done.value, calls
            except NativeLookupBoundary as boundary:
                return boundary, calls
            if effect.kind != 'native_jni':
                calls.append((effect.kind, *effect.args))
                value = {'native_fopen': observations['stream'], 'native_fgets': observations['line'],
                         'native_fclose': 0}[effect.kind]
                continue
            calls.append(effect.args)
            name, *args = effect.args
            if name == 'FindClass':
                value = observations['process_class'] if args[0] == 'android/os/Process' else args[0]
            elif name == 'GetStaticIntField': value = 34
            elif name == 'GetObjectClass': value = ('class', args[0])
            elif name in ('GetMethodID', 'GetStaticFieldID', 'GetFieldID'): value = args[1]
            elif name == 'CallBooleanMethod': value = True
            elif name == 'GetStaticMethodID': value = observations['method']
            elif name == 'CallStaticIntMethod': value = observations['pid']
            elif name == 'NewStringUTF': value = 'process-name-ref'
            elif name == 'CallObjectMethod':
                value = 'manager' if args[1] == 'getPackageManager' else observations['info']
            elif name == 'GetObjectField':
                value = observations['source_ref' if args[1] == 'sourceDir' else 'data_ref']
            elif name == 'GetStringUTFChars': value = observations['source' if args[0] == 'sourceDir' else 'data']
            else: self.fail(name)

    def test_outer_resolves_two_fields_and_inner_repeats_getpath_then_one_field(self):
        outer, first = self.run_paths('start')
        inner, second = self.run_paths('digest')
        self.assertEqual((outer.process_name, inner.process_name), (b'pkg', b'pkg'))
        self.assertEqual(outer.data_bytes, b'/data/pkg')
        self.assertIsNone(inner.data_ref)
        self.assertEqual((len(first), len(second)), (27, 37))
        all_calls = first + second
        self.assertEqual(sum(c[0] == 'CallObjectMethod' and c[2] == 'getPackageManager' for c in all_calls), 3)
        applications = [c for c in all_calls if c[0] == 'CallObjectMethod' and c[2] == 'getApplicationInfo']
        self.assertEqual(applications, [('CallObjectMethod', 'manager', 'getApplicationInfo', 'process-name-ref', 0)]*2)
        self.assertEqual([c[0] for c in first[-6:]], ['GetFieldID', 'GetFieldID', 'GetObjectField',
                                                    'GetObjectField', 'GetStringUTFChars', 'GetStringUTFChars'])
        self.assertNotIn('DeleteLocalRef', [c[0] for c in all_calls])

    def test_outer_ignores_cmdline_helper_failure_but_inner_stops(self):
        for changes, inner_code in ((dict(stream=None), 15), (dict(line=FailedCmdlineRead(b'\0')), 16)):
            outer, calls = self.run_paths('start', **changes)
            self.assertEqual(outer.process_name, b'')
            self.assertIn(('NewStringUTF', b''), calls)
            inner, calls = self.run_paths('digest', **changes)
            self.assertEqual(inner.native_code, inner_code)
            self.assertNotIn('NewStringUTF', [c[0] for c in calls])

    def test_missing_process_jni_and_zero_pid_are_not_normal_inner_success(self):
        for changes in (dict(process_class=None), dict(method=None), dict(pid=0)):
            for phase, code in (('start', -1), ('digest', 0)):
                result, calls = self.run_paths(phase, **changes)
                self.assertIsInstance(result, AnalysisLimit)
                self.assertEqual(result.native_code, code)
                self.assertFalse(any(c[0] == 'native_fopen' for c in calls))

    def test_null_info_is_checked_after_field_ids_but_before_object_fields(self):
        for phase, count in (('start', 2), ('digest', 1)):
            result, calls = self.run_paths(phase, info=None)
            self.assertEqual(result.native_code, 110 if phase == 'start' else 13)
            self.assertEqual([c[0] for c in calls[-count:]], ['GetFieldID']*count)
            self.assertFalse(any(c[0] == 'GetObjectField' for c in calls))

    def test_null_field_values_stop_before_utf_acquisition(self):
        for changes in (dict(source_ref=None), dict(data_ref=None)):
            result, calls = self.run_paths('start', **changes)
            self.assertEqual(result.native_code, 110)
            self.assertEqual(calls[-1][0], 'GetObjectField')

    def test_source_mismatch_precedes_dereferencing_data_utf_pointer(self):
        result, calls = self.run_paths('start', source=b'/elsewhere', data=None)
        self.assertEqual(result.native_code, 110)
        self.assertEqual([c[0] for c in calls[-2:]], ['GetStringUTFChars']*2)
        with self.assertRaises(AnalysisLimit): self.run_paths('start', data=None)
        for phase in ('start', 'digest'):
            with self.assertRaises(AnalysisLimit): self.run_paths(phase, source=None)

    def test_inner_path_mismatch_and_outer_data_mismatch_have_distinct_codes(self):
        self.assertEqual(self.run_paths('digest', source=b'/elsewhere')[0].native_code, 13)
        self.assertEqual(self.run_paths('start', data=b'/elsewhere')[0].native_code, 110)
        self.assertEqual(self.run_paths('start', data=b'/data/pkg-other')[0].process_name, b'pkg')

    def test_nonzero_negative_pid_is_formatted_without_host_validation(self):
        result, calls = self.run_paths('start', pid=-2)
        self.assertEqual(result.process_name, b'pkg')
        self.assertIn(('native_fopen', b'/proc/-2/cmdline', b'r'), calls)
        for pid in (None, True, 2**31):
            with self.assertRaises(AnalysisLimit): self.run_paths('start', pid=pid)


if __name__ == '__main__':
    unittest.main()
