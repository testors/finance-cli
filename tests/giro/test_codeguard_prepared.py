"""Standalone compiled content parity and boundaries on loopback TLS."""
import base64
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs
from zipfile import ZipFile

from giro.codeguard_artifacts import FileDigests
from giro.codeguard_codec import java_seed_decrypt, RULE_KEY, RULE_IV
from giro.codeguard_crypto import CodeGuardCrypto
from giro.codeguard_lifecycle import ManagerConfig
from giro.codeguard_prepared import prepare_content
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_runtime import PythonProtectionRuntime
from giro.protection_profile import ProtectionProfile
import test_codeguard_runtime as support
from test_codeguard_certificate_values import synthetic_certificates
from test_codeguard_fingerprint_values import bag


def profile(platform):
    env = platform.environment
    frames = {path: (env.files[path],) * count for path, count in (
        (b'/proc/self/status', 2), (f'/proc/{env.pid}/cmdline'.encode(), 3))}
    return ProtectionProfile.from_prepared(prepare_content(platform, version='1'), read_frames=frames,
        app_info='SAMPLE', version='1', locale_language='ko', map_profile='aosp-8',
        provenance={'scope': 'synthetic loopback inputs', 'fresh_device_observation': False})


def roundtrip(platform):
    return ProtectionProfile.from_document(json.loads(json.dumps(profile(platform).document()))).platform


class PreparedTests(unittest.TestCase):
    setUpClass = classmethod(support.RuntimeTests.setUpClass.__func__)
    tearDownClass = classmethod(support.RuntimeTests.tearDownClass.__func__)
    setUp = support.RuntimeTests.setUp
    tearDown = support.RuntimeTests.tearDown
    transport = support.RuntimeTests.transport
    reply = support.RuntimeTests.reply

    def runtime(self, *, compiled, source=None):
        platform = source or support.memory_platform(self.der)
        platform.environment.file_existence['TAGS'] = False
        if compiled: platform = roundtrip(platform)
        runtime = PythonProtectionRuntime(config=ManagerConfig(platform.service, 'SAMPLE', '1', self.base, self.base),
            platform=platform, transport=self.transport(max_requests=12), crypto=CodeGuardCrypto(),
            locale_language='ko', map_profile='aosp-8')
        self.runtimes.append(runtime)
        runtime.initialize()
        runtime.wait_for_initialization(timeout=3)
        return runtime

    def test_three_fresh_tokens_match_byte_backend_without_executable_content(self):
        replies = []
        for compiled in (False, True):
            self.server.calls, self.keys = [], []
            runtime = self.runtime(compiled=compiled)
            for index in range(1, 4):
                self.assertEqual(runtime.token(timeout=3), 'loopback-callback-%d' % index)
            self.assertEqual([c[0] for c in self.server.calls], [101, 200, 300, 200, 300, 200, 300])
            posts = [parse_qs(c[4].decode()) for c in self.server.calls if c[0] == 300]
            # Elapsed time differs; the actual native and OS results must not.
            frames = [java_seed_decrypt(base64.b64decode(p['CODE_RESPONSE'][0]), RULE_KEY, RULE_IV).decode()
                      for p in posts]
            replies.append([(f.split('##')[2], p['CODE_RESPONSE2']) for f, p in zip(frames, posts)])
            self.assertEqual(len(set(self.keys)), 3)
            if compiled:
                for path, value in runtime.platform.environment.files.items():
                    if not path.startswith(b'/proc/'):
                        self.assertTrue(value is None or isinstance(value, FileDigests))
                self.assertNotIn('package_java:fileOutput.new', runtime.platform.events)
                self.assertEqual(runtime.platform.events.count('package_java:zip.new'), 3)
                self.assertEqual(sorted(runtime.platform.environment.replayed_reads.values()), [6, 9])
        self.assertEqual(*replies)

    def test_fingerprint_mismatch_is_still_sent_as_original_local_error(self):
        source = support.memory_platform(self.der)
        other, _, _ = synthetic_certificates()
        data = BytesIO()
        with ZipFile(data, 'w') as archive: archive.writestr('META-INF/OTHER.RSA', bag([other]))
        parent = source.application.source_dir.rsplit('/', 1)[0]
        source.directories[parent].append('second.apk')
        source.environment.files[(parent + '/second.apk').encode()] = data.getvalue()
        runtime = self.runtime(compiled=True, source=source)
        self.assertEqual(runtime.token(timeout=3), 'loopback-callback-1')
        post = parse_qs(self.server.calls[-1][4].decode())
        self.assertIn('CG_CONN_ENGINE01', post['CODE_RESPONSE'][0])
        self.assertNotEqual(runtime.platform.errors['FingerPrint'], '')

    def test_verification_failure_delivers_token_before_content_requires_repreparation(self):
        runtime = self.runtime(compiled=True)
        token = 'SYNTHETIC-CODEGUARD_VERIFICATION_TOKEN_FAIL'
        self.token_fields = lambda _: {'CODE_TOKEN': token}
        self.assertEqual(runtime.token(timeout=3), token)
        self.assertNotIn(b'/data/sample.app/files/classes.dex', runtime.platform.environment.files)
        with self.assertRaises(AnalysisLimit): runtime.token(timeout=3)
        self.assertEqual([c[0] for c in self.server.calls], [101, 200, 300, 200])

    def test_missing_archive_is_not_assumed_absent_or_same_signer(self):
        source = support.memory_platform(self.der)
        parent = source.application.source_dir.rsplit('/', 1)[0]
        source.directories[parent].append('unobserved.apk')
        with self.assertRaises(AnalysisLimit): prepare_content(source, version='1')

    def test_live_or_consumed_platform_cannot_be_recompiled(self):
        runtime = self.runtime(compiled=False)
        with self.assertRaises(AnalysisLimit): prepare_content(runtime.platform, version='1')

    def test_private_profile_roundtrip_does_not_overwrite_or_report_sensitive_values(self):
        prepared = profile(support.memory_platform(self.der))
        prepared.platform.phone = 'SYNTHETIC-PRIVATE-PHONE'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve()/'profile.json'
            prepared.save(path)
            with self.assertRaises(FileExistsError): prepared.save(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            restored = ProtectionProfile.load(path)
            self.assertEqual(restored.platform.phone, prepared.platform.phone)
            self.assertNotIn(prepared.platform.phone, json.dumps(restored.report()))
            path.chmod(0o644)
            with self.assertRaises(AnalysisLimit): ProtectionProfile.load(path)

    def test_unknown_profile_mode_or_record_type_cannot_enable_runtime(self):
        for change in ({'mode': 'fresh-android-observation'}, {'schema_version': 2},
                       {'environment': ['exec', 'never executed']}):
            document = profile(support.memory_platform(self.der)).document()
            document.update(change)
            with self.assertRaises(AnalysisLimit): ProtectionProfile.from_document(document)
