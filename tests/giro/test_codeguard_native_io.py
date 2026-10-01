import base64
import hashlib
import unittest
from unittest.mock import patch

from giro.codeguard_codec import RULE_IV, RULE_KEY, java_seed_encrypt
from giro.codeguard_first import first_response_arithmetic, first_response_read_steps
from giro.codeguard_native_io import (PACKAGE_CHUNK_SIZE, native_paths_match,
    native_pid_stat_steps, native_process_check_steps, native_process_name,
    package_digest_read_steps)
from giro.codeguard_rule import AnalysisLimit


def finish(generator, observations):
    effects, value = [], None
    replies = iter(observations)
    while True:
        try:
            effect = generator.send(value)
        except StopIteration as completed:
            if next(replies, 'END') != 'END':
                raise AssertionError('unused observation')
            return completed.value, effects
        effects.append((effect.kind, effect.args))
        value = next(replies)


class PackageReadTests(unittest.TestCase):
    def digest(self, size, reads):
        return finish(package_digest_read_steps(size), reads)

    def test_full_reads_and_exact_boundary_have_no_extra_read(self):
        for size in (1, PACKAGE_CHUNK_SIZE-1, PACKAGE_CHUNK_SIZE,
                     PACKAGE_CHUNK_SIZE+1, 2*PACKAGE_CHUNK_SIZE):
            data = bytes(i % 251 for i in range(size))
            chunks = [data[i:i+PACKAGE_CHUNK_SIZE] for i in range(0, size, PACKAGE_CHUNK_SIZE)]
            result, effects = self.digest(size, chunks)
            self.assertEqual(result, hashlib.sha256(data).digest())
            self.assertEqual([args[0] for _, args in effects], list(map(len, chunks)))

    def test_zero_size_still_performs_one_zero_length_read(self):
        result, effects = self.digest(0, [b''])
        self.assertEqual(result, hashlib.sha256(b'').digest())
        self.assertEqual(effects, [('native_package_fread', (0,))])

    def test_first_short_read_retains_initial_zeros_without_retry(self):
        result, effects = self.digest(6, [b'ab'])
        self.assertEqual(result, hashlib.sha256(b'ab\0\0\0\0').digest())
        self.assertEqual(len(effects), 1)

    def test_later_short_read_retains_previous_buffer_bytes(self):
        first = b'abcdef' + b'X' * (PACKAGE_CHUNK_SIZE-6)
        result, effects = self.digest(PACKAGE_CHUNK_SIZE+6, [first, b'12'])
        self.assertEqual(result, hashlib.sha256(first+b'12cdef').digest())
        self.assertEqual(len(effects), 2)

    def test_eof_does_not_shorten_hash_or_stop_remaining_requested_reads(self):
        result, _ = self.digest(2*PACKAGE_CHUNK_SIZE+3, [b'a', b'', b''])
        block = b'a' + bytes(PACKAGE_CHUNK_SIZE-1)
        self.assertEqual(result, hashlib.sha256(block+block+b'a\0\0').digest())

    def test_unknown_reads_and_overflow_are_not_native_rejections(self):
        for size in (-1, 2**31, None, True):
            with self.assertRaises(AnalysisLimit):
                next(package_digest_read_steps(size))
        for data in (None, bytearray(b'a'), b'too long'):
            with self.assertRaises(AnalysisLimit):
                self.digest(2, [data])

    def test_read_stage_connects_to_first_response_without_rehashing(self):
        rule = base64.b64encode(java_seed_encrypt(b'HEADER00'+b'\x02'*40, RULE_KEY, RULE_IV)).decode()
        expected = first_response_arithmetic(b'ab\0\0', 'TQ==', rule, 'a', 'v')
        result, effects = finish(first_response_read_steps(4, 'TQ==', rule, 'a', 'v'), [b'ab'])
        self.assertEqual(result, expected)
        self.assertEqual(len(effects), 1)


class NativeProcessTests(unittest.TestCase):
    def check(self, observations):
        return finish(native_process_check_steps(), observations)

    def test_two_distinct_status_reads_are_preserved(self):
        result, effects = self.check(['one', b'TracerPid:\t0\n', None,
                                      'two', b'TracerPid:\t0\n', None])
        self.assertEqual(result, 0)
        self.assertEqual([e for e in effects if e[0] == 'native_fopen'],
                         [('native_fopen', (b'/proc/self/status', b'r'))]*2)
        self.assertEqual(len(effects), 6)

    def test_first_failure_is_127_but_observed_second_open_failure_continues(self):
        self.assertEqual(self.check([None])[0], 127)
        self.assertEqual(self.check(['one', b'TracerPid:0\n', None, None])[0], 0)

    def test_second_pass_can_detect_a_change(self):
        result, effects = self.check(['one', b'TracerPid:0\n', None,
            'two', b'TracerPid:44\n', b'Uid:\t100\t100\n', None,
            'tracer', b'Uid:\t200\t200\n', None])
        self.assertEqual(result, 127)
        self.assertIn(('native_fopen', (b'/proc/44/status', b'r')), effects)

    def test_uid_check_is_raw_substring_not_integer_equality(self):
        result, _ = self.check(['one', b'TracerPid:44\n', b'Uid:100\t100\t100\n', None,
            'tracer', b'Uid:100\n', None, 'two', b'TracerPid:0\n', None])
        self.assertEqual(result, 0)
        self.assertEqual(self.check(['one', b'TracerPid:44\n', b'Uid:\t100\n', None,
            'tracer', b'Uid:100\t100\n', None])[0], 127)

    def test_eof_without_tracer_is_not_an_added_failure(self):
        self.assertEqual(self.check(['one', None, None, 'two', None, None])[0], 0)

    def test_original_prefix_match_delimiters_and_atoi(self):
        # Prefix comparison + atoi(non-numeric)=0; no numeric validator added.
        result, _ = self.check(['one', b'TracerPidExtra:::not-a-number\n', None,
                               'two', b'TracerPid: +0tail\n', None])
        self.assertEqual(result, 0)

    def test_uid_before_tracer_ends_the_pass(self):
        self.assertEqual(self.check(['one', b'Uid:100\n', None,
                                    'two', b'Uid:100\n', None])[0], 0)

    def test_tracer_status_eof_is_rejected(self):
        self.assertEqual(self.check(['one', b'TracerPid:44\n', b'Uid:100\n', None,
                                    'tracer', None, None])[0], 127)

    def test_outer_fclose_null_is_unmodeled_not_a_clean_result(self):
        with self.assertRaises(AnalysisLimit):
            self.check(['one', b'TracerPid:44\n', b'Uid:100\n', None, None])
        self.assertEqual(self.check(['one', b'TracerPid:0\n', None,
            'two', b'TracerPid:44\n', b'Uid:100\n', None, None])[0], 0)

    def test_unresolved_native_memory_is_not_a_rejection_or_fallback(self):
        for line in (b':', b'\0', b'TracerPid:', b'TracerPid:99999999999999'):
            with self.assertRaises(AnalysisLimit):
                self.check(['one', line])
        with self.assertRaises(AnalysisLimit):
            self.check(['one', b'TracerPid:44\n', None, None,
                        'tracer', b'Uid:100\n'])

    def test_cmdline_transform_differs_between_start_and_nonce(self):
        for raw, start, nonce in ((b'pkg:worker\0arg', b'pkg:worker', b'pkg'),
                                  (b'pkg:engine:worker', b'pkg', b'pkg'),
                                  (b'pkg\n', b'pkg\n', b'pkg\n')):
            self.assertEqual(native_process_name(raw, nonce=False), start)
            self.assertEqual(native_process_name(raw, nonce=True), nonce)
        with self.assertRaises(AnalysisLimit):
            native_process_name(None, nonce=False)

    def test_path_checks_are_substrings_without_path_normalization(self):
        self.assertTrue(native_paths_match(b'pkg', b'/data/pkg-extra/base', b'/data/pkg'))
        self.assertTrue(native_paths_match(b'', b'/any/path'))
        self.assertFalse(native_paths_match(b'pkg', b'/path\0pkg'))
        with self.assertRaises(AnalysisLimit):
            native_paths_match(b'pkg', None)

    def test_pid_validation_keeps_stat_but_ignores_its_result(self):
        for pid in ('', '0', '1', 'x', 'null'):
            self.assertEqual(finish(native_pid_stat_steps(pid), []), (123, []))
        for result in (0, -1, None, object()):
            code, effects = finish(native_pid_stat_steps('not-numeric'), [result])
            self.assertEqual(code, 0)
            self.assertEqual(effects, [('native_stat', (b'/proc/not-numeric/stat',))])
        with self.assertRaises(AnalysisLimit):
            next(native_pid_stat_steps(None))

    def test_no_host_identity_io_or_sdk_is_used(self):
        with patch('builtins.open', side_effect=AssertionError('no files')), \
             patch('socket.socket', side_effect=AssertionError('no network')), \
             patch('os.getpid', side_effect=AssertionError('no host identity')), \
             patch('ctypes.CDLL', side_effect=AssertionError('no SDK')):
            self.assertEqual(self.check(['one', b'TracerPid:0\n', None,
                                        'two', b'TracerPid:0\n', None])[0], 0)


if __name__ == '__main__':
    unittest.main()
