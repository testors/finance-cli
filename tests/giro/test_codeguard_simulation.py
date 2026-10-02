"""Declared synthetic environments; no Android observation or server request."""
import base64
from dataclasses import replace
import json
import unittest
from unittest.mock import patch

from giro.codeguard_app import build_string_steps
from giro.codeguard_device import ExtendedDeviceState, extended_device_steps, project_device_steps
from giro.codeguard_effects import Effect, JavaFault
from giro.codeguard_first import first_response_arithmetic
from giro.codeguard_flow import ChallengeState
from giro.codeguard_inputs import NonceArtifacts, nonce_artifact_codes, fallback_nonce_key
from giro.codeguard_native_jni import NativeLookupBoundary
from giro.codeguard_native_start import NativeStartBoundary
from giro.codeguard_nonce import cg_auth_code
from giro.codeguard_response import ResponseState, response_steps, oscheck_steps
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_simulation import (EnvironmentSimulation, PackageRecord,
                                       CommandOutcome, run_simulation_steps)
from giro.codeguard_string_values import project_native_value_steps
from test_codeguard_certificate_values import synthetic_certificates
from test_codeguard_native_start import rule


def fault(kind):
    return JavaFault(kind, message='synthetic', java_string='synthetic.' + kind)


def environment(der, *, pid=123, uid=10001, directory='one', suffix=':engine'):
    package = PackageRecord('sample.app', '/installed/sample.app/' + directory,
                            '/data/sample.app', '/lib/sample.app', (der,))
    files = {
        b'/proc/self/status': f'Name:sample\nTracerPid:0\nUid:{uid}\n'.encode(),
        f'/proc/{pid}/cmdline'.encode(): ('sample.app' + suffix + '\0').encode(),
        package.source_dir.encode(): b'synthetic whole package',
        b'/data/data/sample.app/files/libCodeGuard.so': None,
        b'/lib/sample.app/libCodeGuard.so': b'synthetic guard',
        b'/lib/sample.app/libImageDecoder.so': b'synthetic decoder',
        b'/data/sample.app/files/classes.dex': b'synthetic dex',
        b'/data/sample.app/files/META-INF/MANIFEST.MF': b'synthetic manifest',
        b'/data/sample.app/files/META-INF/CERT.SF': b'synthetic sf',
    }
    build = dict(MODEL='MODEL', ID='BUILD', RELEASE='14', TAGS='release-keys',
                 PRODUCT='product', MANUFACTURER='maker', BRAND='brand', DEVICE='device',
                 HARDWARE='hardware', FINGERPRINT='fingerprint')
    return EnvironmentSimulation(pid=pid, sdk=34, manager_class='android/app/ApplicationPackageManager',
        packages={('sample.app', flags): package for flags in (0, 1, 64)}, files=files,
        stat_results={f'/proc/{pid}/stat'.encode(): -1}, build=build, commands={}, file_existence={})


def native(env, kind, args):
    def steps():
        return (yield Effect(kind, args))
    return run_simulation_steps(project_native_value_steps(steps(), service=env.service,
                               certificate_values=True), env.resolve)


def calculate(env, *, challenge='TQ==', mix=False, split=False, key='AB'*32,
              rcl='[]', elapsed=7, etc_data=None, build_string=None):
    """One explicit completed-worker schedule; no timeout/queue assertion."""
    build = run_simulation_steps(build_string_steps(), env.resolve) if build_string is None else build_string
    state = ResponseState(ChallengeState(challenge, rule(), rcl_suffix=rcl),
        'SAMPLE', '1', str(env.pid), build, etc_data, 'E0', 'engine', None)
    device = ExtendedDeviceState()
    ticks = iter((100, 100 + elapsed))
    def resolve(effect):
        if effect.kind == 'oscheck_future':
            challenge, root, rooting, fourth, rcl, timeout = effect.args
            work = oscheck_steps(state, challenge=challenge, root_check=root,
                                rooting_info=rooting, fourth=fourth, rcl=rcl)
            return run_simulation_steps(project_device_steps(work, extended_state=device), env.resolve)
        if effect.kind == 'clock_ms': return next(ticks)
        if effect.kind == 'engine_version': return 'engine'
        if effect.kind == 'read_detail_enabled': return state.detail_enabled
        if effect.kind == 'device_detail': return device.detail
        if effect.kind == 'location_text': return ''
        return env.resolve(effect)
    frame = run_simulation_steps(project_native_value_steps(response_steps(state,
        root_check=True, rooting_info=False), service=env.service), resolve)
    second = native(env, 'native_get_nonce',
                    (key if key else fallback_nonce_key(challenge).decode(), challenge, mix, split))
    return {'native': frame.split('##')[2], 'os_status': state.os_status,
            'response': frame, 'response2': second}


def changed(before, after):
    return sorted(name for name in before if before[name] != after[name])


def variation_matrix(der):
    base = calculate(environment(der))
    rows = []
    def record(name, value, expected, reference=base):
        actual = changed(reference, value)
        rows.append(dict(scenario=name, changed=actual, expected=sorted(expected),
                         passed=actual == sorted(expected)))
    record('identical_inputs', calculate(environment(der)), [])
    record('pid_uid_and_install_directory', calculate(environment(der, pid=8765, uid=20234, directory='two')), [])
    record('elapsed_only', calculate(environment(der), elapsed=23), ['response'])
    record('wall_clock_moves_backwards', calculate(environment(der), elapsed=-3), ['response'])
    env = environment(der)
    env.build['MODEL'] = 'SECOND MODEL'
    record('build_at_construction', calculate(env), ['response'])
    record('cached_build_after_environment_change', calculate(env, build_string='MODEL/BUILD/14'), [])
    record('phone_field', calculate(environment(der), etc_data=base64.b64encode(b'SYNTHETIC').decode()), ['response'])
    record('challenge_nonmix_fixed_hash_key', calculate(environment(der), challenge='Tg=='), ['native', 'os_status', 'response'])
    record('challenge_mix_fixed_hash_key', calculate(environment(der), challenge='Tg==', mix=True),
           ['native', 'os_status', 'response', 'response2'], calculate(environment(der), mix=True))
    record('challenge_nonmix_fallback_key', calculate(environment(der), challenge='Tg==', key=''),
           ['native', 'os_status', 'response', 'response2'], calculate(environment(der), key=''))
    record('hash_key_only', calculate(environment(der), key='CD'*32), ['response2'])
    env = environment(der)
    env.files[env.packages[('sample.app', 0)].source_dir.encode()] += b'changed'
    record('whole_package_bytes', calculate(env), ['native', 'response'])
    env = environment(der)
    env.files[b'/data/sample.app/files/classes.dex'] += b'changed'
    record('prepared_dex_cancels_in_accumulator', calculate(env), [])
    env = environment(der)
    env.files[b'/lib/sample.app/libCodeGuard.so'] += b'changed'
    record('guard_library_cancels_in_accumulator', calculate(env), [])
    env = environment(der)
    env.files[b'/data/sample.app/files/META-INF/CERT.SF'] += b'changed'
    record('sf_cancels_in_accumulator', calculate(env), [])
    env = environment(der)
    env.files[b'/lib/sample.app/libImageDecoder.so'] += b'changed'
    record('decoder_library', calculate(env), ['response2'])
    env = environment(der)
    env.files[b'/data/sample.app/files/META-INF/MANIFEST.MF'] += b'changed'
    record('manifest', calculate(env), ['response2'])
    record('split_flag', calculate(environment(der), split=True), ['response2'])
    env = environment(der)
    env.files[b'/data/sample.app/files/META-INF/CERT.SF'] += b'changed'
    record('sf_ignored_when_split', calculate(env, split=True), [], calculate(environment(der), split=True))
    rcl = json.dumps([dict(description='test-keys', policy=13, osType=1, enabled=True)])
    env = environment(der)
    record('build_policy_no_match', calculate(env, rcl=rcl), [])
    env.build['TAGS'] = 'test-keys'
    record('build_policy_match', calculate(env, rcl=rcl), ['os_status', 'response'])
    return rows


class EnvironmentSimulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.der, cls.other_der, _ = synthetic_certificates()

    def test_variation_matrix(self):
        for row in variation_matrix(self.der):
            with self.subTest(scenario=row['scenario']):
                self.assertEqual(row['changed'], row['expected'])

    def test_unknown_pid_stops_native_lookup_instead_of_becoming_a_value(self):
        env = environment(self.der, pid=None)
        with self.assertRaisesRegex(AnalysisLimit, 'process PID not supplied'):
            env.process_id()
        with self.assertRaisesRegex(AnalysisLimit, 'process PID not supplied'):
            native(env, 'native_get_nonce', ('AB'*32, 'TQ==', False, False))
        self.assertNotIn('native_fopen', env.events)

    def test_native_outputs_match_independent_arithmetic_with_declared_files(self):
        env = environment(self.der)
        result = calculate(env)
        package = env.packages[('sample.app', 0)]
        self.assertEqual(result['native'], first_response_arithmetic(env.files[package.source_dir.encode()],
                                                                   'TQ==', rule(), 'SAMPLE', '1').decode())
        artifacts = NonceArtifacts(*(env.files[path] for path in (
            b'/lib/sample.app/libCodeGuard.so', b'/lib/sample.app/libImageDecoder.so',
            b'/data/sample.app/files/classes.dex', b'/data/sample.app/files/META-INF/MANIFEST.MF',
            b'/data/sample.app/files/META-INF/CERT.SF')), self.der)
        self.assertEqual(result['response2'], cg_auth_code(('AB'*32).encode(),
            nonce_artifact_codes(artifacts, 'TQ==', is_mix=False, is_split=False)))

    def test_changed_signer_changes_only_second_response(self):
        env = environment(self.der)
        base = calculate(env)
        env.packages[('sample.app', 64)] = replace(env.packages[('sample.app', 64)], signatures=(self.other_der,))
        self.assertEqual(changed(base, calculate(env)), ['response2'])

    def test_renamed_process_and_package_must_remain_consistent(self):
        env = environment(self.der, suffix=':worker')
        with self.assertRaises(AnalysisLimit): calculate(env)
        # getNonce strips every colon, while start strips only ':engine'.
        self.assertIsInstance(native(env, 'native_get_nonce', ('AB'*32, 'TQ==', False, False)), str)

    def test_path_mismatch_and_manager_class_mismatch_do_not_pass(self):
        for field, value in (('source_dir', '/unrelated'), ('data_dir', '/unrelated')):
            env = environment(self.der)
            env.packages[('sample.app', 0)] = replace(env.packages[('sample.app', 0)], **{field: value})
            with self.assertRaises(NativeLookupBoundary): calculate(env)
        env = environment(self.der)
        env.manager_class = 'different.PackageManager'
        with self.assertRaises(NativeLookupBoundary): calculate(env)

    def test_tracer_uid_relation_is_evaluated_instead_of_assumed_clean(self):
        env = environment(self.der)
        env.files[b'/proc/self/status'] = b'TracerPid:7\nUid:10001\n'
        env.files[b'/proc/7/status'] = b'Uid:20002\n'
        with self.assertRaises(NativeStartBoundary) as caught: calculate(env)
        self.assertEqual(caught.exception.native_code, 127)
        env.files[b'/proc/7/status'] = b'Uid:10001\n'
        self.assertEqual(calculate(env), calculate(environment(self.der)))

    def test_unknown_package_is_not_uninstalled_and_fallback_requires_outcome(self):
        env = environment(self.der)
        rcl = json.dumps([dict(description='sample.missing', policy=11, osType=1, enabled=True)])
        def run(): return run_simulation_steps(extended_device_steps(ExtendedDeviceState(), rcl), env.resolve)
        with self.assertRaises(AnalysisLimit): run()
        env.packages[('sample.missing', 1)] = fault('NameNotFoundException')
        with self.assertRaises(AnalysisLimit): run()
        env.commands['sample.missing'] = CommandOutcome(fault('IOException'), None)
        self.assertFalse(run())
        env.commands['sample.missing'] = CommandOutcome(None, None)
        self.assertTrue(run())

    def test_missing_file_is_unknown_unless_absence_was_explicit(self):
        env = environment(self.der)
        del env.files[b'/lib/sample.app/libCodeGuard.so']
        with self.assertRaises(AnalysisLimit): calculate(env)
        env.files[b'/lib/sample.app/libCodeGuard.so'] = None
        env.files[b'/data/sample.app/files/lib/libCodeGuard.so'] = b'synthetic guard'
        self.assertEqual(calculate(env), calculate(environment(self.der)))

    def test_stream_eof_full_read_and_open_snapshot_semantics(self):
        env = environment(self.der)
        env.files[b'/test'] = b'x'*1024
        stream = env.resolve(Effect('native_fopen', (b'/test', b'rb')))
        env.files[b'/test'] = b'new'
        self.assertEqual(env.resolve(Effect('native_fread', (stream, 1, 1024))), b'x'*1024)
        self.assertEqual(env.resolve(Effect('native_feof', (stream,))), 0)
        self.assertEqual(env.resolve(Effect('native_fread', (stream, 1, 1024))), b'')
        self.assertEqual(env.resolve(Effect('native_feof', (stream,))), 1)
        env.resolve(Effect('native_fclose', (stream,)))
        with self.assertRaises(AnalysisLimit): env.resolve(Effect('native_feof', (stream,)))

    def test_exists_and_fopen_failure_are_separate_inputs(self):
        env = environment(self.der)
        env.files[b'/test'] = None
        with self.assertRaises(AnalysisLimit): env.resolve(Effect('device_file_exists', ('/test',)))
        env.file_existence['/test'] = True
        self.assertTrue(env.resolve(Effect('device_file_exists', ('/test',))))
        self.assertIsNone(env.resolve(Effect('native_fopen', (b'/test', b'rb'))))

    def test_no_host_io_identity_commands_or_network(self):
        env = environment(self.der)
        with patch('builtins.open', side_effect=AssertionError('filesystem')), \
             patch('os.getpid', side_effect=AssertionError('host PID')), \
             patch('subprocess.Popen', side_effect=AssertionError('process')), \
             patch('socket.socket', side_effect=AssertionError('network')):
            self.assertIsInstance(calculate(env)['response2'], str)
        self.assertNotIn('sample.app', repr(env))
        self.assertNotIn('sample.app', json.dumps(env.events))


if __name__ == '__main__': unittest.main()
