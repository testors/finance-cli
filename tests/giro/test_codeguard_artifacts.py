"""Complete immutable content parity; no device or institution access."""
import base64
import hashlib
import unittest

from giro.codeguard_artifacts import DigestRead, FileDigests
from giro.codeguard_effects import Effect
from giro.codeguard_native_io import package_digest_file_steps
from giro.codeguard_native_nonce import nonce_file_digest_steps
from giro.codeguard_platform import _digest_after_one_read, engine_exists_steps
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_simulation import run_simulation_steps
from cg_exchange_fixture import sample_state
from test_codeguard_certificate_values import synthetic_certificates
from test_codeguard_runtime import memory_platform
from test_codeguard_simulation import calculate, environment


def compile_files(env):
    # Proc reads must still consume their explicit bytes, not content digests.
    for path, value in tuple(env.files.items()):
        if not path.startswith(b'/proc/') and type(value) is bytes:
            env.files[path] = FileDigests.from_bytes(value)


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.der, _, _ = synthetic_certificates()

    def test_complete_hashes_match_raw_reads_at_both_loop_boundaries(self):
        for size in (0, 1, 1023, 1024, 1025, 0x7ffff, 0x80000, 0x80001, 0x100001):
            data = (bytes(range(256)) * (size // 256 + 1))[:size]
            for compiled in (False, True):
                with self.subTest(size=size, compiled=compiled):
                    env = environment(self.der)
                    path = env.packages[('sample.app', 0)].source_dir.encode()
                    env.files[path] = FileDigests.from_bytes(data) if compiled else data
                    first = run_simulation_steps(package_digest_file_steps(path, b'sample.app'), env.resolve)
                    stream = env.resolve(Effect('native_fopen', (path, b'rb')))
                    second = run_simulation_steps(nonce_file_digest_steps(stream), env.resolve)
                    self.assertEqual(first, hashlib.sha256(data).digest())
                    self.assertEqual(second, first)

    def test_full_challenge_responses_match_and_still_change_with_challenge(self):
        results = []
        for challenge in ('TQ==', 'Tg=='):
            for mix in (False, True):
                for split in (False, True):
                    raw, compiled = environment(self.der), environment(self.der)
                    compile_files(compiled)
                    options = dict(challenge=challenge, mix=mix, split=split)
                    expected = calculate(raw, **options)
                    self.assertEqual(calculate(compiled, **options), expected)
                    results.append(expected['response'])
        self.assertGreater(len(set(results)), 1)

    def test_compiled_files_do_not_supply_missing_process_or_policy_observations(self):
        env = environment(self.der)
        compile_files(env)
        del env.files[b'/proc/self/status']
        with self.assertRaises(AnalysisLimit): calculate(env)
        env = environment(self.der)
        compile_files(env)
        with self.assertRaises(AnalysisLimit):
            calculate(env, rcl='[{"description":"unobserved","policy":12,"osType":1,"enabled":true}]')

    def test_engine_hash_check_keeps_sha_md5_tail_and_mismatch_semantics(self):
        for compiled in (False, True):
            platform = memory_platform(self.der)
            path = platform.application.library_dir + '/libCodeGuard.so'
            platform.environment.files[path.encode()] = b'synthetic engine'
            if compiled: compile_files(platform.environment)
            for md5, hashfn in ((False, hashlib.sha256), (True, hashlib.md5)):
                for expected, matches in ((hashfn(b'synthetic engine').digest(), True),
                                          (hashfn(b'synthetic engine').digest()[-3:], True),
                                          (b'mismatch', False)):
                    state = sample_state()
                    result = run_simulation_steps(engine_exists_steps(state, platform.application,
                        base64.b64encode(expected).decode(), md5), platform.resolve)
                    self.assertEqual(result, matches)
                    self.assertTrue(state.status_log.endswith(',E19.7' if matches else ',E19.8'))

    def test_digest_backend_rejects_arbitrary_reads_reuse_and_wrong_owner(self):
        env, other = environment(self.der), environment(self.der)
        compile_files(env)
        path = env.packages[('sample.app', 0)].source_dir.encode()
        stream = env.resolve(Effect('native_fopen', (path, b'rb')))
        for effect in (Effect('native_fread', (stream, 1, 1)),
                       Effect('native_fgets', (stream, 256)),
                       Effect('immutable_file_sha256', (stream, stream.data.size - 1))):
            with self.assertRaises(AnalysisLimit): env.resolve(effect)
        with self.assertRaises(AnalysisLimit): other.resolve(Effect('native_fclose', (stream,)))
        self.assertEqual(env.resolve(Effect('immutable_file_sha256', (stream, stream.data.size))), stream.data.sha256)
        with self.assertRaises(AnalysisLimit): env.resolve(Effect('immutable_file_sha256', (stream, stream.data.size)))
        env.resolve(Effect('native_fclose', (stream,)))
        with self.assertRaises(AnalysisLimit): env.resolve(Effect('native_ftell', (stream,)))

    def test_metadata_requires_complete_immutable_file(self):
        valid = FileDigests.from_bytes(b'abc')
        for args in ((-1, valid.sha256, valid.md5), (2**31, valid.sha256, valid.md5),
                     (True, valid.sha256, valid.md5), (3, b'', valid.md5), (3, valid.sha256, b'')):
            with self.assertRaises(AnalysisLimit): FileDigests(*args)
        with self.assertRaises(AnalysisLimit): DigestRead(None)
        with self.assertRaises(AnalysisLimit): FileDigests.from_bytes(bytearray(b'abc'))
        with self.assertRaises(AnalysisLimit): _digest_after_one_read(2, DigestRead(valid), False)
