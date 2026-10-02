"""Threaded Python execution with declared memory inputs and loopback TLS."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from io import BytesIO
import json
from itertools import count
from threading import Event, current_thread
import unittest
from urllib.parse import parse_qs, urlsplit
from zipfile import BadZipFile, ZipFile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from giro.codeguard_codec import java_seed_encrypt, java_seed_decrypt, RULE_KEY, RULE_IV
from giro.codeguard_crypto import CodeGuardCrypto
from giro.codeguard_first import first_response_arithmetic
from giro.codeguard_inputs import NonceArtifacts, nonce_artifact_codes
from giro.codeguard_lifecycle import ManagerConfig
from giro.codeguard_memory import MemoryPlatform
from giro.codeguard_nonce import cg_auth_code
from giro.codeguard_response import os_status_digest
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_runtime import PythonProtectionRuntime
from giro.login import ProtectionRuntime
from test_codeguard_fingerprint_values import bag
import test_codeguard_http as http_support
from test_codeguard_native_start import rule
from test_codeguard_simulation import environment


def memory_platform(der, *, dex=b'prepared dex' * 1000):
    env = environment(der)
    application = replace(env.packages[('sample.app', 0)], source_dir='/installed/sample.app/base.apk')
    for key in env.packages: env.packages[key] = application
    archive = BytesIO()
    with ZipFile(archive, 'w') as output:
        for name, data in (
            ('lib/arm64-v8a/libCodeGuard.so', b'prepared guard'),
            ('lib/arm64-v8a/libImageDecoder.so', b'prepared decoder'),
            ('classes.dex', dex),
            ('META-INF/MANIFEST.MF', b'prepared manifest'),
            ('META-INF/SIGNER.SF', b'prepared signer'),
            ('META-INF/CERT.RSA', bag([der]))):
            output.writestr(name, data)
    env.files[application.source_dir.encode()] = archive.getvalue()
    for path in tuple(env.files):
        if path.startswith(b'/data/sample.app/files/'): del env.files[path]
    # Declared fopen failure selects the prepared library directory.
    env.files[b'/lib/sample.app/libCodeGuard.so'] = None
    env.files[b'/lib/sample.app/libImageDecoder.so'] = None
    return MemoryPlatform(environment=env, application=application,
        files_dir='/data/sample.app/files',
        directories={'/installed/sample.app': ['base.apk'], '/data/sample.app/files': []},
        modified={application.source_dir: 10}, preferences={}, abi='arm64-v8a',
        phone=None, split_metadata=None, location='', write_time=lambda: 20)


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): http_support.HTTPTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls): http_support.HTTPTests.tearDownClass.__func__(cls)

    transport = http_support.HTTPTests.transport

    def setUp(self):
        self.server.calls, self.transports, self.runtimes, self.gates = [], [], [], []
        self.der = self.certificate.public_bytes(serialization.Encoding.DER)
        self.keys = []
        self.token_fields = lambda index: {'CODE_TOKEN': 'loopback-callback-%d' % index}
        self.rcl = json.dumps([dict(description='TAGS', policy=12, osType=1, enabled=True)])
        self.challenge_fields = lambda index: dict(CODE_CHALLENGE='TQ==::' + rule() + '::' + base64.b64encode(self.der).decode() + '::SYNTHETIC',
            CODE_RCL=base64.b64encode(('TQ==' + self.rcl).encode()).decode())
        self.server.reply = self.reply

    def tearDown(self):
        for gate in self.gates: gate.set()
        for runtime in self.runtimes: runtime.close()
        for transport in self.transports: transport.close()

    def reply(self, command, body, handler):
        headers = []
        if command == 101:
            document = dict(CERT=base64.b64encode(self.der).decode(), ENGINE_VERSION='runtime-test', ENGINE_MD='')
        elif command == 200:
            query = parse_qs(urlsplit(handler.path).query)
            key = self.private.decrypt(base64.b64decode(query['KEY'][0]), padding.PKCS1v15())
            self.keys.append(key)
            iv = b'I' * 16
            document = self.challenge_fields(len(self.keys))
            document['HASH_KEY'] = base64.b64encode(java_seed_encrypt(b'H' * 32, key, iv)).decode() + '::' + base64.b64encode(iv).decode()
            headers = [('Set-Cookie', 'exchange=%d' % len(self.keys))]
        else:
            count = sum(call[0] == 300 for call in self.server.calls)
            document = self.token_fields(count)
        return 200, headers, json.dumps(document).encode()

    def runtime(self, *, platform_transform=None, **inputs):
        platform = memory_platform(self.der, **inputs)
        platform.environment.file_existence['TAGS'] = False
        if platform_transform is not None: platform = platform_transform(platform)
        runtime = PythonProtectionRuntime(config=ManagerConfig(platform.service, 'SAMPLE', '1', self.base, self.base),
            platform=platform, transport=self.transport(max_requests=12), crypto=CodeGuardCrypto(clock=count(1000).__next__),
            locale_language='ko', map_profile='aosp-8')
        self.runtimes.append(runtime)
        return runtime

    def ready(self):
        runtime = self.runtime()
        runtime.initialize()
        runtime.wait_for_initialization(timeout=3)
        return runtime

    def test_large_prepared_file_is_not_limited_by_experiment_effect_budget(self):
        dex = b'large synthetic data' * (320 * 1024)
        runtime = self.runtime(dex=dex)
        runtime.initialize()
        runtime.wait_for_initialization(timeout=10)
        self.assertEqual(runtime.token(timeout=10), 'loopback-callback-1')
        self.assertEqual(runtime.platform.environment.files[b'/data/sample.app/files/classes.dex'], dex)
        self.assertGreater(runtime.platform.events.count('package_java:input.read'), 6000)

    def test_unknown_pid_preserves_initialization_but_stops_before_challenge(self):
        runtime = self.runtime()
        runtime.platform.environment.pid = None
        runtime.initialize()
        runtime.wait_for_initialization(timeout=3)
        self.assertTrue(runtime.process.is_init)
        with self.assertRaisesRegex(AnalysisLimit, 'process PID not supplied'):
            runtime.token(timeout=3)
        self.assertEqual([call[0] for call in self.server.calls], [101])

    def test_initialize_then_two_callbacks_reuse_state_and_calculate_both_responses(self):
        runtime = self.ready()
        self.assertIsInstance(runtime, ProtectionRuntime)
        self.assertTrue(runtime.process.is_init)
        self.assertIsNone(runtime.process.agent.main.instance)
        self.assertEqual(runtime.token(timeout=3), 'loopback-callback-1')
        main = runtime.process.agent.main.instance
        first_task = runtime.manager.task
        key = runtime.process.agent.material.key
        runtime.platform.environment.build['MODEL'] = 'CHANGED AFTER CONSTRUCTION'
        self.assertEqual(runtime.token(timeout=3), 'loopback-callback-2')
        self.assertIs(runtime.process.agent.main.instance, main)
        self.assertIsNot(runtime.manager.task, first_task)
        self.assertIsNot(runtime.process.agent.updater, main.updater)
        self.assertEqual(main.response.build_string, 'MODEL/BUILD/14')
        self.assertEqual(self.keys, [key, runtime.process.agent.material.key])
        self.assertNotEqual(*self.keys)
        self.assertEqual(main.updater.data.key, self.keys[-1])
        self.assertEqual([call[0] for call in self.server.calls], [101, 200, 300, 200, 300])
        self.assertEqual(runtime.events.count('main_load_library'), 2)
        posts = [call for call in self.server.calls if call[0] == 300]
        self.assertEqual([dict(call[3])['Cookie'] for call in posts], ['exchange=1', 'exchange=2'])
        files = runtime.platform.environment.files
        artifacts = NonceArtifacts(*(files[('/data/sample.app/files' + suffix).encode()] for suffix in (
            '/lib/libCodeGuard.so', '/lib/libImageDecoder.so', '/classes.dex',
            '/META-INF/MANIFEST.MF', '/META-INF/CERT.SF')), self.der)
        expected = cg_auth_code((b'H' * 32).hex().upper().encode(),
            nonce_artifact_codes(artifacts, 'TQ==', is_mix=False, is_split=False))
        for call in posts:
            form = parse_qs(call[4].decode())
            self.assertEqual(form['CODE_RESPONSE2'], [expected])
            frame = java_seed_decrypt(base64.b64decode(form['CODE_RESPONSE'][0]), RULE_KEY, RULE_IV).decode()
            expected_first = first_response_arithmetic(files[runtime.platform.application.source_dir.encode()],
                                                       'TQ==', rule(), 'SAMPLE', '1').decode()
            self.assertEqual(frame.split('##')[2], expected_first)
        self.assertEqual(runtime.extended.detail, '')
        self.assertEqual(main.response.os_status, os_status_digest('TQ=='))
        self.assertEqual(runtime.platform.preferences['apk_last'], 10)
        self.assertEqual(runtime.platform.preferences['app_version'], '1')
        self.assertEqual(sum(j.kind == 'oscheck' and j.work.phase == 'returned' for j in runtime.jobs), 2)
        for coarse in ('native_start', 'native_get_nonce', 'check_fingerprint', 'check_zip_os14'):
            self.assertNotIn(coarse, runtime.events)
        self.assertNotIn('certificateFactory.generateCertificate', runtime.platform.events)
        self.assertNotIn('loopback-callback', repr(runtime.jobs) + repr(runtime.events))

    def test_initialize_does_not_wait_and_delayed_update_keeps_separate_receiver(self):
        runtime = self.runtime()
        gate, entered = Event(), Event()
        self.gates.append(gate)
        resolve = runtime.platform.resolve
        def delayed(effect):
            if current_thread().name == 'cg-update' and effect.kind == 'preference_read':
                entered.set()
                if not gate.wait(5): raise AssertionError('update gate not released')
            return resolve(effect)
        runtime.platform.resolve = delayed
        runtime.initialize()
        self.assertTrue(entered.wait(1))
        self.assertFalse(next(j.future for j in runtime.jobs if j.kind == 'update').done())
        self.assertEqual(runtime.token(timeout=3), 'loopback-callback-1')
        main_updater = runtime.process.agent.main.instance.updater
        gate.set()
        runtime.wait_for_initialization(3)
        self.assertIs(runtime.process.agent.main.instance.updater, main_updater)
        self.assertEqual([call[0] for call in self.server.calls], [101, 200, 300, 101])
        self.assertEqual(runtime.token(timeout=3), 'loopback-callback-2')

    def test_login_initialization_waits_for_update_notification(self):
        runtime = self.runtime()
        gate, entered, initialized = Event(), Event(), Event()
        self.gates.append(gate)
        initialize = runtime.initialize
        def tracked_initialize():
            initialize()
            initialized.set()
        runtime.initialize = tracked_initialize
        resolve = runtime.platform.resolve
        def delayed(effect):
            if current_thread().name == 'cg-update' and effect.kind == 'preference_read':
                entered.set()
                if not gate.wait(5): raise AssertionError('update gate not released')
            return resolve(effect)
        runtime.platform.resolve = delayed
        with ThreadPoolExecutor(max_workers=1) as pool:
            ready = pool.submit(runtime.initialize_for_login, timeout=3)
            try:
                self.assertTrue(entered.wait(1))
                # The update worker may reach its first read before the UI
                # thread finishes initialize(). Observe both independently.
                self.assertTrue(initialized.wait(1))
                self.assertTrue(runtime.process.is_init)
                self.assertFalse(ready.done())
            finally:
                gate.set()
            self.assertIsNone(ready.result(3))
        self.assertEqual(runtime.events.count('manager_update_listener'), 1)
        self.assertEqual([call[0] for call in self.server.calls], [101])

    def test_login_initialization_does_not_join_zip_work(self):
        runtime = self.runtime()
        gate, entered = Event(), Event()
        self.gates.append(gate)
        resolve = runtime.resolve
        def delayed(effect):
            if current_thread().name == 'cg-zip' and effect.kind == 'package_java':
                entered.set()
                if not gate.wait(5): raise AssertionError('ZIP gate not released')
            return resolve(effect)
        runtime.resolve = delayed
        try:
            self.assertIsNone(runtime.initialize_for_login(timeout=3))
            self.assertTrue(entered.wait(1))
            self.assertFalse(next(j.future for j in runtime.jobs if j.kind == 'zip').done())
            self.assertEqual(runtime.events.count('manager_update_listener'), 1)
        finally:
            gate.set()

    def test_login_initialization_provider_failure_is_not_a_callback(self):
        runtime = self.runtime()
        resolve = runtime.platform.resolve
        def broken(effect):
            if current_thread().name == 'cg-update' and effect.kind == 'preference_read':
                raise ValueError('synthetic update observation missing')
            return resolve(effect)
        runtime.platform.resolve = broken
        with self.assertRaisesRegex(ValueError, 'synthetic update observation missing'):
            runtime.initialize_for_login(timeout=3)
        self.assertNotIn('manager_update_listener', runtime.events)
        self.assertEqual(self.server.calls, [])

    def test_login_initialization_preserves_notification_before_later_error(self):
        runtime = self.runtime()
        resolve = runtime.resolve
        def late_error(effect):
            value = resolve(effect)
            if effect.kind == 'update_send_empty_message':
                raise ValueError('synthetic late diagnostic failure')
            return value
        runtime.resolve = late_error
        self.assertIsNone(runtime.initialize_for_login(timeout=3))
        runtime.close()
        self.assertEqual(runtime.events.count('manager_update_listener'), 1)
        update = next(j for j in runtime.jobs if j.kind == 'update')
        self.assertIsInstance(update.future.exception(), ValueError)

    def test_missing_token_uses_local_error_callback_without_retry(self):
        self.token_fields = lambda _: {}
        runtime = self.ready()
        value = json.loads(runtime.token(timeout=3))
        self.assertEqual(value['CODE_APP_INFO'], 'CG_CONN_ENGINE01')
        self.assertEqual(value['CODE_GUARD_OS_RESULT'], 'UNKNOWN')
        self.assertEqual([call[0] for call in self.server.calls], [101, 200, 300])

    def test_second_challenge_keeps_omitted_certificate_rcl_hash_and_mix_flag(self):
        self.challenge_fields = lambda _: dict(CODE_CHALLENGE='TQ==::' + rule() + '::' +
            base64.b64encode(self.der).decode() + '::SYNTHETIC',
            CODE_RCL=base64.b64encode(('TQ==' + self.rcl).encode()).decode(), CODE_RESPONSE2_VER='isMix')
        runtime = self.ready()
        runtime.token(timeout=3)
        main = runtime.process.agent.main.instance
        cert, rcl, hash_key = main.response.challenge.certificate, main.updater.data.rcl, main.updater.data.hash_key
        reply = self.server.reply
        def omit(command, body, handler):
            status, headers, payload = reply(command, body, handler)
            if command == 200:
                payload = json.dumps({'CODE_CHALLENGE': 'Tg==::' + rule()}).encode()
            return status, headers, payload
        self.server.reply = omit
        self.assertEqual(runtime.token(timeout=3), 'loopback-callback-2')
        self.assertIs(main.response.challenge.certificate, cert)
        self.assertEqual(main.response.challenge.fourth, 'SYNTHETIC')
        self.assertEqual(main.updater.data.rcl, rcl)
        self.assertEqual(main.updater.data.hash_key, hash_key)
        self.assertTrue(main.updater.data.is_mix)
        self.assertEqual([call[0] for call in self.server.calls], [101, 200, 300, 200, 300])
        form = parse_qs(self.server.calls[-1][4].decode())
        self.assertEqual(form['CODE_RESPONSE2_VER'], ['isMix'])
        self.assertEqual(main.response.os_status, os_status_digest('Tg=='))

    def test_python_timeout_in_provider_is_not_oscheck_timeout_fallback(self):
        runtime = self.ready()
        resolve = runtime.platform.resolve
        def broken(effect):
            if effect.kind == 'device_file_exists': raise TimeoutError('synthetic provider error')
            return resolve(effect)
        runtime.platform.resolve = broken
        with self.assertRaisesRegex(TimeoutError, 'synthetic provider error'):
            runtime.token(timeout=3)
        self.assertNotIn('manager_token_listener', runtime.events)
        self.assertEqual([call[0] for call in self.server.calls], [101, 200])

    def test_unresolved_zip_failure_releases_python_lock_without_invented_java_cleanup(self):
        runtime = self.runtime()
        runtime.platform.environment.files[runtime.platform.application.source_dir.encode()] = b'not a ZIP'
        runtime.initialize()
        with self.assertRaises(BadZipFile): runtime.wait_for_initialization(3)
        # The failed ZIP initializer cannot leave a Python lock deadlocking
        # the next task. Its error also must not become SDK success/failure.
        with self.assertRaises(BadZipFile): runtime.token(timeout=3)
        self.assertEqual(runtime.events.count('processing_monitor_cleanup'), 2)
        self.assertNotIn('manager_token_listener', runtime.events)
        self.assertFalse(any(call[0] == 300 for call in self.server.calls))

    def test_caller_timeout_does_not_cancel_or_allow_overlapping_new_request(self):
        runtime = self.ready()
        gate, entered = Event(), Event()
        self.gates.append(gate)
        resolve = runtime.platform.resolve
        def delayed(effect):
            if effect.kind == 'device_file_exists':
                entered.set()
                if not gate.wait(5): raise AssertionError('caller gate not released')
            return resolve(effect)
        runtime.platform.resolve = delayed
        with self.assertRaises(TimeoutError): runtime.token(timeout=0.01)
        self.assertTrue(entered.wait(1))
        with self.assertRaisesRegex(RuntimeError, 'still pending'): runtime.token(timeout=3)
        self.assertEqual([call[0] for call in self.server.calls], [101, 200])
        gate.set()
        self.assertEqual(runtime._pending.result(3), 'loopback-callback-1')
        self.assertEqual(runtime.token(timeout=3), 'loopback-callback-2')

    def test_bad_challenge_certificate_remains_processing_boundary(self):
        self.challenge_fields = lambda _: dict(CODE_CHALLENGE='TQ==::' + rule() + '::YmFk::SYNTHETIC')
        runtime = self.ready()
        with self.assertRaises(AnalysisLimit): runtime.token(timeout=3)
        self.assertEqual([call[0] for call in self.server.calls], [101, 200])
        challenge = runtime.process.agent.main.instance.response.challenge
        self.assertEqual(challenge.certificate_text, 'YmFk')
        self.assertIsNone(challenge.certificate)
        self.assertIsNone(challenge.fourth)

    def test_verification_failure_clears_prepared_memory_files_and_delivers_unchanged_callback(self):
        token = 'SYNTHETIC-CODEGUARD_VERIFICATION_TOKEN_FAIL'
        self.token_fields = lambda _: {'CODE_TOKEN':token}
        runtime = self.ready()
        platform = runtime.platform
        original = platform.environment.files[platform.application.source_dir.encode()]
        preferences = dict(platform.preferences)
        self.assertIn(b'/data/sample.app/files/classes.dex', platform.environment.files)
        self.assertEqual(runtime.token(timeout=3), token)
        self.assertEqual([call[0] for call in self.server.calls], [101,200,300])
        self.assertEqual(platform.environment.files[platform.application.source_dir.encode()], original)
        self.assertEqual(platform.preferences, preferences)
        for suffix in ('classes.dex', 'META-INF/MANIFEST.MF', 'META-INF/CERT.SF',
                       'lib/libCodeGuard.so', 'lib/libImageDecoder.so'):
            self.assertNotIn(('/data/sample.app/files/'+suffix).encode(), platform.environment.files)
        self.assertEqual(platform.events.count('package_java:file.delete'), 5)
        self.assertEqual(runtime.events.count('manager_token_listener'), 1)
        self.assertEqual(next(j.work.phase for j in runtime.jobs if j.kind == 'task'), 'returned')

    def test_unknown_environment_failure_is_processing_error_without_callback_or_post(self):
        runtime = self.ready()
        del runtime.platform.environment.file_existence['TAGS']
        with self.assertRaises(AnalysisLimit): runtime.token(timeout=3)
        self.assertEqual([call[0] for call in self.server.calls], [101, 200])
        self.assertNotIn('manager_token_listener', runtime.events)
        self.assertEqual(next(j.work.phase for j in runtime.jobs if j.kind == 'task'), 'unresolved')

    def test_real_oscheck_timeout_keeps_worker_and_late_detail_write(self):
        runtime = self.ready()
        gate, entered = Event(), Event()
        self.gates.append(gate)
        resolve = runtime.platform.resolve
        def delayed(effect):
            if effect.kind == 'device_file_exists':
                entered.set()
                if not gate.wait(10): raise AssertionError('OSCheck gate not released')
            return resolve(effect)
        runtime.platform.environment.file_existence['TAGS'] = True
        runtime.platform.resolve = delayed
        self.assertEqual(runtime.token(timeout=8), 'loopback-callback-1')
        self.assertTrue(entered.is_set())
        work = next(j for j in runtime.jobs if j.kind == 'oscheck')
        self.assertFalse(work.future.done())
        self.assertEqual(work.work.phase, 'running')
        self.assertEqual(runtime.process.agent.main.instance.response.os_status, os_status_digest('TQ=='))
        gate.set()
        work.future.result(2)
        self.assertEqual(work.work.phase, 'returned')
        self.assertEqual(runtime.extended.detail, 'TAGS')
        self.assertTrue(runtime.process.agent.main.instance.response.detail_enabled)
        self.assertFalse(work.future.cancelled())


if __name__ == '__main__': unittest.main()
