import base64
import hashlib
from pathlib import Path
import shutil
import subprocess
import unittest
from giro.codeguard_effects import LinkFault
from giro.codeguard_platform import key_bytes_from_seed, ReadOnce, engine_exists_steps
from giro.codeguard_rule import AnalysisLimit
from cg_exchange_fixture import drive, sample_state, fault, Transcript
from giro.codeguard_updater import wrapped_key_steps

class RandomTests(unittest.TestCase):

    def test_synthetic_vectors_against_independent_jdk(self):
        java = shutil.which('java')
        if java is None:
            self.skipTest('optional reference JDK unavailable on PATH')
        source = Path(__file__).parent / 'java/RandomVectors.java'
        seeds = (0, 1, -1, 123456789, 2 ** 63 - 1, -2 ** 63, 2 ** 48, 1730000000000)
        result = subprocess.run([java, str(source), *(str(x) for x in seeds)], capture_output=True, text=True, timeout=30, check=True)
        self.assertEqual(result.stdout.splitlines(), [key_bytes_from_seed(x).hex() for x in seeds])

    def test_all_sixteen_bytes_depend_only_on_explicit_setseed_value(self):
        self.assertEqual(key_bytes_from_seed(0).hex(), '60b420bb3851d9d47acb933dbe70399b')
        self.assertEqual(key_bytes_from_seed(0), key_bytes_from_seed(2 ** 48))
        self.assertNotEqual(key_bytes_from_seed(1), key_bytes_from_seed(2))

    def test_missing_or_wrong_seed_not_clock_default(self):
        for value in (None, True, '1', 2 ** 63, -2 ** 63 - 1):
            with self.assertRaises(AnalysisLimit):
                key_bytes_from_seed(value)

    def test_arithmetic_adapter_connects_to_wrapped_key_sequence(self):
        t = Transcript(overrides={'clock_ms': 123456789, 'java_random_seed_and_bytes': lambda e: key_bytes_from_seed(e.args[1])})
        t.run(wrapped_key_steps(t.runtime, t.agent))
        self.assertEqual(t.agent.key, key_bytes_from_seed(123456789))

class EngineTests(unittest.TestCase):

    def run_engine(self, expected, *, md5=False, overrides=None):
        (self.state, self.effects) = (sample_state(), [])
        replies = {'application_native_library_dir': '/synthetic/lib', 'file_exists': True, 'open_file_input': 'stream', 'file_available': 3, 'file_read_once': ReadOnce(3, b'abc'), 'close_file_input': None}
        replies.update(overrides or {})

        def reply(e):
            self.effects.append(e)
            return replies[e.kind]
        return drive(engine_exists_steps(self.state, 'observed application info', expected, md5), reply)

    def test_sha256_and_md5_use_base64_digest(self):
        for (md5, hashfun) in ((False, hashlib.sha256), (True, hashlib.md5)):
            self.assertTrue(self.run_engine(base64.b64encode(hashfun(b'abc').digest()).decode(), md5=md5))
            self.assertEqual(self.state.status_log, 'E0,E19.1,E19.6,E19.7')

    def test_bytesutil_f_is_suffix_match_not_added_full_length_requirement(self):
        expected = base64.b64encode(hashlib.sha256(b'abc').digest()[-3:]).decode()
        self.assertTrue(self.run_engine(expected))
        self.assertFalse(self.run_engine(base64.b64encode(b'bad').decode()))
        self.assertTrue(self.state.status_log.endswith(',E19.8'))

    def test_single_short_read_hashes_observed_prefix_and_zero_tail(self):
        expected = base64.b64encode(hashlib.sha256(b'a\x00\x00').digest()).decode()
        self.assertTrue(self.run_engine(expected, overrides={'file_read_once': ReadOnce(1, b'a')}))
        self.assertEqual([e.kind for e in self.effects].count('file_read_once'), 1)

    def test_observed_eof_not_unknown_buffer_is_all_zero(self):
        expected = base64.b64encode(hashlib.sha256(bytes(3)).digest()).decode()
        self.assertTrue(self.run_engine(expected, overrides={'file_read_once': ReadOnce(-1, b'')}))
        with self.assertRaises(AnalysisLimit):
            self.run_engine(expected, overrides={'file_read_once': None})

    def test_null_and_oversized_decoded_expected_do_not_append_mismatch_log(self):
        for expected in (None, '', base64.b64encode(bytes(33)).decode()):
            self.assertFalse(self.run_engine(expected))
            self.assertEqual(self.state.status_log, 'E0,E19.1,E19.6')

    def test_directory_null_and_missing_file_return_without_open(self):
        for overrides in ({'application_native_library_dir': None}, {'file_exists': False}):
            self.assertFalse(self.run_engine('anything', overrides=overrides))
            self.assertNotIn('open_file_input', [e.kind for e in self.effects])
            self.assertEqual(self.state.status_log, 'E0,E19.1')

    def test_read_exception_skips_close_but_unknown_error_is_not_false(self):
        self.assertFalse(self.run_engine('anything', overrides={'file_read_once': fault('IOException')}))
        self.assertNotIn('close_file_input', [e.kind for e in self.effects])
        for error in (AnalysisLimit('unknown'), LinkFault(), TypeError('bug')):
            with self.assertRaises(type(error)):
                self.run_engine('anything', overrides={'file_exists': error})

    def test_negative_available_caught_before_read_close(self):
        self.assertFalse(self.run_engine('anything', overrides={'file_available': -1}))
        self.assertNotIn('file_read_once', [e.kind for e in self.effects])

    def test_unknown_or_incomplete_read_not_zero_filled_as_clean(self):
        for observation in (ReadOnce(2, b'a'), ReadOnce(4, b'abcd'), ReadOnce(-1, b'a')):
            with self.assertRaises(AnalysisLimit):
                self.run_engine('anything', overrides={'file_read_once': observation})
