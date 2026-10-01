"""Synthetic JNI/process/file observations, never an environment provider."""
import base64
import hashlib
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from giro.codeguard_codec import RULE_IV, RULE_KEY, java_seed_encrypt, java_seed_decrypt, jni_modified_utf8
from giro.codeguard_effects import Effect
from giro.codeguard_first import first_response_arithmetic, first_response_native_bytes
from giro.codeguard_native_start import NativeStartBoundary, native_start_steps, project_native_start_steps
from giro.codeguard_native_jni import NativeUtfChars
from giro.codeguard_rule import AnalysisLimit, NativeRuleError
from giro.codeguard_service import generate_token_steps
from cg_exchange_fixture import Transcript, drive, fault


def rule():
    return base64.b64encode(java_seed_encrypt(b'HEADER00'+b'\x02'*40, RULE_KEY, RULE_IV)).decode()


class NativeObservations:
    def __init__(self, *, package=b'synthetic inner package', returned='decode', utf=None, override=None):
        self.package, self.returned, self.utf = package, returned, utf or {}
        self.override = override
        self.effects, self.manager_count, self.stream_count = [], 0, 0
        self.positions = {}
        self.acquisitions = []

    def reply(self, effect):
        self.effects.append(effect)
        if self.override is not None:
            chosen, value = self.override(effect)
            if chosen: return value
        kind, args = effect.kind, effect.args
        if kind == 'native_fopen':
            path, mode = args
            if path.endswith(b'/files/libCodeGuard.so'): return None
            self.stream_count += 1
            stream = (path, self.stream_count)
            self.positions[stream] = 0
            return stream
        if kind == 'native_fgets':
            return b'TracerPid:0\n' if args[0][0] == b'/proc/self/status' else b'pkg:engine\0'
        if kind in ('native_fclose', 'native_rewind', 'native_fseek'): return 0
        if kind == 'native_ftell': return len(self.package)
        if kind == 'native_fread':
            stream, size, count = args
            position = self.positions[stream]
            self.positions[stream] += count
            return self.package[position:position+count]
        if kind == 'native_stat': return -1  # explicit synthetic failure, ignored by source
        if kind != 'native_jni': raise AssertionError(kind)
        name, *args = args
        if name == 'GetObjectClass': return ('class', args[0])
        if name == 'FindClass': return args[0]
        if name in ('GetMethodID', 'GetStaticMethodID', 'GetStaticFieldID', 'GetFieldID'): return args[1]
        if name == 'GetStaticIntField': return 34
        if name == 'CallBooleanMethod': return True  # explicit test observation only
        if name == 'CallStaticIntMethod': return 123
        if name == 'CallObjectMethod':
            if args[1] == 'getPackageManager':
                self.manager_count += 1
                return ('manager', self.manager_count)
            return ('info', args[0][1])
        if name == 'GetObjectField': return (args[1], args[0][1])
        if name == 'GetStringUTFChars':
            ref = args[0]
            if ref in self.utf:
                data = self.utf[ref]
            elif isinstance(ref, tuple):
                field, number = ref
                data = b'/installed/pkg/base-' + str(number).encode() if field == 'sourceDir' else b'/data/pkg'
            else:
                data = jni_modified_utf8(ref)
            value = None if data is None else NativeUtfChars('utf-'+str(len(self.acquisitions)+1), data)
            self.acquisitions.append((ref, value))
            return value
        if name in ('DeleteLocalRef', 'ReleaseStringUTFChars'): return None
        if name == 'NewStringUTF':
            raw = args[0]
            if raw == b'pkg': return ('name', raw)
            return raw.decode('ascii') if self.returned == 'decode' else self.returned
        raise AssertionError(name)

    def calls(self, name):
        return [e.args[1:] for e in self.effects if e.kind == 'native_jni' and e.args[0] == name]

    def run(self, **options):
        values = dict(service='service', challenge='TQ==', rule=rule(), app_info='APP', version='1', pid='123')
        values.update(options)
        return drive(native_start_steps(**values), self.reply)


class NativeStartTests(unittest.TestCase):
    def test_normal_path_uses_inner_package_and_returns_after_releases(self):
        obs = NativeObservations()
        self.assertEqual(obs.run(), first_response_arithmetic(obs.package, 'TQ==', rule(), 'APP', '1').decode())
        self.assertEqual(obs.manager_count, 3)
        self.assertEqual(len(obs.effects), 110)
        self.assertEqual([e.args for e in obs.effects if e.kind == 'native_stat'], [(b'/proc/123/stat',)])
        opens = [e.args[0] for e in obs.effects if e.kind == 'native_fopen']
        self.assertIn(b'/installed/pkg/base-3', opens)
        self.assertNotIn(b'/installed/pkg/base-1', opens)
        self.assertEqual(obs.calls('ReleaseStringUTFChars'), [
            (('sourceDir', 3), 'utf-8'),
            (('sourceDir', 1), 'utf-1'), (('dataDir', 1), 'utf-2'),
            ('TQ==', 'utf-3'), (rule(), 'utf-4'), ('APP', 'utf-5'), ('1', 'utf-6'), ('123', 'utf-7')])
        self.assertEqual(obs.effects[-1].args[0], 'NewStringUTF')

    def test_reference_deletes_preserve_order_without_deleting_string_refs(self):
        obs = NativeObservations()
        obs.run()
        expected = lambda number: [
            ('android/app/ApplicationPackageManager',), ('android/os/Process',),
            (('class', 'service'),), ('android/content/pm/ApplicationInfo',),
            ('java/lang/Class',), ('android/os/Build$VERSION',),
            (('info', number),), (('manager', number),), (('class', ('manager', number)),)]
        self.assertEqual(obs.calls('DeleteLocalRef'), expected(1)+expected(3))
        pid_stat = next(i for i,e in enumerate(obs.effects) if e.kind == 'native_stat')
        first_delete = next(i for i,e in enumerate(obs.effects) if e.kind == 'native_jni' and e.args[0] == 'DeleteLocalRef')
        self.assertLess(pid_stat, first_delete)

    def test_actual_utf_bytes_are_used_without_encoding_opaque_refs_again(self):
        refs = [object() for _ in range(5)]
        values = [b'TQ==', rule().encode(), b'APP', b'1', b'123']
        obs = NativeObservations(utf=dict(zip(refs, values)))
        result = obs.run(challenge=refs[0], rule=refs[1], app_info=refs[2], version=refs[3], pid=refs[4])
        self.assertEqual(result, first_response_arithmetic(obs.package, 'TQ==', rule(), 'APP', '1').decode())

    def test_pid_never_enters_arithmetic_but_each_stat_and_release_is_kept(self):
        results = []
        for pid in ('123', 'other-pid'):
            obs = NativeObservations()
            results.append(obs.run(pid=pid))
            self.assertIn((pid, 'utf-7'), obs.calls('ReleaseStringUTFChars'))
        self.assertEqual(results[0], results[1])

    def test_short_pid_returns_123_after_utf_release_without_inner_lookup(self):
        for pid in ('', '0', 'x', 'null'):
            obs = NativeObservations()
            self.assertEqual(obs.run(pid=pid), 'E101_ENGINE_LOAD_ERROR0_123_' + pid)
            self.assertEqual(obs.manager_count, 1)
            self.assertEqual(obs.calls('DeleteLocalRef'), [])
            self.assertFalse(any(e.kind in ('native_stat', 'native_ftell') for e in obs.effects))
            self.assertEqual(len(obs.calls('GetStringUTFChars')), 7)
            self.assertEqual(obs.calls('ReleaseStringUTFChars')[-1], (pid, 'utf-7'))

    def test_rule_error_is_formatted_only_after_file_io_and_inner_utf_release(self):
        obs = NativeObservations()
        self.assertEqual(obs.run(challenge='bad'), 'E101_ENGINE_LOAD_ERROR0_21_pkg')
        self.assertTrue(any(e.kind == 'native_fread' for e in obs.effects))
        self.assertEqual(len(obs.calls('ReleaseStringUTFChars')), 8)

    def test_explicit_null_utf_uses_native_stage_codes_and_skips_null_release(self):
        for field, value, code in (('challenge', 'TQ==', 20), ('rule', rule(), 30),
                                   ('app_info', 'APP', 40), ('version', '1', 41)):
            obs = NativeObservations(utf={value: None})
            self.assertEqual(obs.run(), f'E101_ENGINE_LOAD_ERROR0_{code}_pkg')
            self.assertNotIn(value, [args[0] for args in obs.calls('ReleaseStringUTFChars')])
            self.assertEqual(len(obs.calls('ReleaseStringUTFChars')), 7)

    def test_early_argument_or_process_boundaries_never_manufacture_error_text(self):
        for name, code in (('challenge', 100), ('rule', 100), ('app_info', 100), ('version', 100), ('service', 110)):
            obs = NativeObservations()
            with self.assertRaises(NativeStartBoundary) as caught: obs.run(**{name: None})
            self.assertEqual(caught.exception.native_code, code)
            self.assertEqual(len(obs.effects), 6)  # two process passes precede argument checks
        obs = NativeObservations(override=lambda e: (e.kind == 'native_fopen', None))
        with self.assertRaises(NativeStartBoundary) as caught: obs.run()
        self.assertEqual(caught.exception.native_code, 127)
        self.assertEqual(len(obs.effects), 1)

    def test_java_null_pid_gets_utf_before_any_complete_error_return_is_known(self):
        obs = NativeObservations()
        with self.assertRaises(NativeStartBoundary) as caught: obs.run(pid=None)
        self.assertEqual(caught.exception.native_code, 123)
        self.assertIn((None,), obs.calls('GetStringUTFChars'))
        self.assertEqual(len(obs.calls('ReleaseStringUTFChars')), 6)

    def test_null_pid_utf_pointer_for_nonnull_java_pid_stops_before_strcmp(self):
        obs = NativeObservations(utf={'123': None})
        with self.assertRaises(AnalysisLimit): obs.run()
        self.assertEqual(obs.calls('ReleaseStringUTFChars'), [])

    def test_data_dir_overflow_stops_before_input_utf_calls(self):
        obs = NativeObservations(utf={('dataDir', 1): b'pkg'+b'x'*253})
        with self.assertRaises(AnalysisLimit): obs.run()
        self.assertEqual(obs.calls('GetStringUTFChars'), [(('sourceDir', 1),), (('dataDir', 1),)])

    def test_null_final_new_string_result_is_preserved(self):
        obs = NativeObservations(returned=None)
        self.assertIsNone(obs.run())
        self.assertEqual(len(obs.calls('ReleaseStringUTFChars')), 8)
        with self.assertRaises(AnalysisLimit): NativeObservations(returned=object()).run()

    def test_unknowns_do_not_trigger_invented_cleanup_or_retries(self):
        def missing(e):
            return (e.kind == 'native_fread', AnalysisLimit('missing read'))
        obs = NativeObservations(override=missing)
        with self.assertRaises(AnalysisLimit): obs.run()
        self.assertEqual(sum(e.kind == 'native_fread' for e in obs.effects), 1)
        self.assertEqual(obs.calls('ReleaseStringUTFChars'), [])

    def test_unbounded_error_formatting_is_not_fabricated_before_pid_release(self):
        name = b'p'*40
        def long_name(e):
            if e.kind == 'native_fgets' and e.args[0][0] != b'/proc/self/status':
                return True, name+b'\0'
            if e.kind == 'native_jni' and e.args[0] == 'GetStringUTFChars' and isinstance(e.args[1], tuple):
                return True, NativeUtfChars(object(), b'/data/'+name)
            return False, None
        obs = NativeObservations(override=long_name)
        with self.assertRaises(AnalysisLimit): obs.run(challenge='bad')
        self.assertEqual(len(obs.calls('ReleaseStringUTFChars')), 7)
        self.assertNotIn('123', [args[0] for args in obs.calls('ReleaseStringUTFChars')])

    def test_repeated_same_string_ref_keeps_distinct_acquisitions_and_inner_first_release(self):
        def shared_source(e):
            chosen = e.kind == 'native_jni' and e.args[0] == 'GetObjectField' and e.args[2] == 'sourceDir'
            return chosen, ('sourceDir', 'shared')
        obs = NativeObservations(override=shared_source)
        obs.run()
        releases = [args for args in obs.calls('ReleaseStringUTFChars') if args[0] == ('sourceDir', 'shared')]
        self.assertEqual(releases, [(('sourceDir', 'shared'), 'utf-8'), (('sourceDir', 'shared'), 'utf-1')])

    def test_missing_pointer_identity_does_not_become_bytes_as_a_release_handle(self):
        def bytes_only(e):
            chosen = e.kind == 'native_jni' and e.args[0] == 'GetStringUTFChars' and isinstance(e.args[1], tuple)
            return chosen, b'/data/pkg'
        obs = NativeObservations(override=bytes_only)
        with self.assertRaises(AnalysisLimit): obs.run()
        self.assertEqual(obs.calls('ReleaseStringUTFChars'), [])

    def test_no_host_files_sdk_or_network_used(self):
        with patch('builtins.open', side_effect=AssertionError('no files')), \
             patch('socket.socket', side_effect=AssertionError('no network')), \
             patch('os.getpid', side_effect=AssertionError('no host PID')):
            self.assertIsInstance(NativeObservations().run(), str)


class NativeStartProjectionTests(unittest.TestCase):
    def run_service(self, obs, *, challenge='TQ=='):
        t = Transcript([(200, {'CODE_CHALLENGE': challenge+'::'+rule()}),
                        (300, {'CODE_TOKEN': 'SYNTHETIC-TOKEN'})])
        t.main.pid = '123'
        for kind in ('native_jni', 'native_fopen', 'native_fgets', 'native_fclose', 'native_fseek',
                     'native_ftell', 'native_rewind', 'native_fread', 'native_stat'):
            t.overrides[kind] = obs.reply
        def unused(effect): raise AssertionError('opaque native_start must be expanded')
        t.overrides['native_start'] = unused
        generator = generate_token_steps(t.main, t.runtime, t.agent, server_url='https://synthetic.invalid/',
                                        timeout=500, root_check=True, rooting_info=False, encrypted_token=False)
        return t, project_native_start_steps(generator, service='service')

    def test_response_bytes_are_encrypted_and_submitted_in_same_exchange(self):
        obs = NativeObservations()
        t, generator = self.run_service(obs)
        self.assertEqual(t.run(generator), 'SYNTHETIC-TOKEN')
        self.assertEqual([x[0] for x in t.requests], [200, 300])
        form = parse_qs(t.writes[-1][1].decode())
        first = java_seed_decrypt(base64.b64decode(form['CODE_RESPONSE'][0]), RULE_KEY, RULE_IV).decode()
        expected = first_response_arithmetic(obs.package, 'TQ==', rule(), 'APP', '1').decode()
        self.assertIn('##'+expected+'##', first)
        self.assertNotIn('SYNTHETIC-NATIVE-OBSERVATION', first)
        self.assertEqual(form['CODE_RESPONSE2'], ['SYNTHETIC-NONCE-OBSERVATION'])

    def test_native_rule_error_still_reaches_300_as_original_plain_error(self):
        obs = NativeObservations()
        t, generator = self.run_service(obs, challenge='bad')
        self.assertEqual(t.run(generator), 'SYNTHETIC-TOKEN')
        form = parse_qs(t.writes[-1][1].decode())
        self.assertIn('E101_ENGINE_LOAD_ERROR0_21_pkg', form['CODE_RESPONSE'][0])

    def test_null_final_native_string_keeps_java_error4_path(self):
        t, generator = self.run_service(NativeObservations(returned=None))
        self.assertEqual(t.run(generator), 'SYNTHETIC-TOKEN')
        form = parse_qs(t.writes[-1][1].decode())
        self.assertIn('E101_ENGINE_LOAD_ERROR4', form['CODE_RESPONSE'][0])

    def test_repeated_token_generation_reuses_updater_but_repeats_native_observations(self):
        obs = NativeObservations()
        t, first = self.run_service(obs)
        t.documents = iter([(200, {'CODE_CHALLENGE': 'TQ==::'+rule()}), (300, {'CODE_TOKEN': 'FIRST'}),
                            (200, {'CODE_CHALLENGE': 'QQ==::'+rule()}), (300, {'CODE_TOKEN': 'SECOND'})])
        self.assertEqual(t.run(first), 'FIRST')
        obs.package = b'changed synthetic package'
        second = generate_token_steps(t.main, t.runtime, t.agent, server_url='https://synthetic.invalid/',
                                      timeout=500, root_check=True, rooting_info=False, encrypted_token=False)
        self.assertEqual(t.run(project_native_start_steps(second, service='service')), 'SECOND')
        self.assertEqual([x[0] for x in t.requests], [200, 300, 200, 300])
        self.assertEqual(obs.manager_count, 6)
        self.assertEqual(t.runtime.data.key, b'\x02'*16)
        form = parse_qs(t.writes[-1][1].decode())
        first = java_seed_decrypt(base64.b64decode(form['CODE_RESPONSE'][0]), RULE_KEY, RULE_IV).decode()
        expected = first_response_arithmetic(obs.package, 'QQ==', rule(), 'APP', '1').decode()
        self.assertIn('##'+expected+'##', first)

    def test_analysis_boundary_is_not_converted_to_java_error_or_sent(self):
        obs = NativeObservations(override=lambda e: (e.kind == 'native_fopen', AnalysisLimit('unobserved')))
        t, generator = self.run_service(obs)
        with self.assertRaises(AnalysisLimit): t.run(generator)
        self.assertEqual([x[0] for x in t.requests], [200])

    def test_final_jni_fault_keeps_enclosing_java_catch_scope(self):
        def final_fault(e):
            chosen = e.kind == 'native_jni' and e.args[0] == 'NewStringUTF' and b'::' in e.args[1]
            return chosen, fault(message='SYNTHETIC final JNI failure')
        t, generator = self.run_service(NativeObservations(override=final_fault))
        self.assertEqual(t.run(generator), 'SYNTHETIC-TOKEN')
        form = parse_qs(t.writes[-1][1].decode())
        self.assertIn('E101_ENGINE_LOAD_ERROR2', form['CODE_RESPONSE'][0])

    def test_non_native_effects_and_generator_return_are_preserved(self):
        def source():
            value = yield Effect('other', ('data',))
            return value
        generator = project_native_start_steps(source(), service='service')
        self.assertEqual(next(generator).args, ('data',))
        with self.assertRaises(StopIteration) as done: generator.send('returned')
        self.assertEqual(done.exception.value, 'returned')


class NativeBytesTests(unittest.TestCase):
    def test_c_string_terminators_are_not_part_of_the_arithmetic_or_output(self):
        digest = hashlib.sha256(b'package').digest()
        result = first_response_native_bytes(digest, b'TQ==\0unread', rule().encode()+b'\0unread',
                                             b'APP\0unread', b'1\0unread')
        self.assertEqual(result, first_response_arithmetic(b'package', 'TQ==', rule(), 'APP', '1'))

    def test_native_null_operands_remain_distinct_codes(self):
        values = [b'TQ==', rule().encode(), b'APP', b'1']
        for index, code in enumerate((20, 30, 40, 41)):
            args = list(values)
            args[index] = None
            with self.assertRaises(NativeRuleError) as caught:
                first_response_native_bytes(bytes(32), *args)
            self.assertEqual(caught.exception.native_code, code)

    def test_python_types_are_not_native_values_or_rejections(self):
        for digest in (None, bytes(31), bytes(33), bytearray(32)):
            with self.assertRaises(AnalysisLimit):
                first_response_native_bytes(digest, b'TQ==', rule().encode(), b'APP', b'1')
        with self.assertRaises(AnalysisLimit):
            first_response_native_bytes(bytes(32), 'TQ==', rule().encode(), b'APP', b'1')


if __name__ == '__main__':
    unittest.main()
