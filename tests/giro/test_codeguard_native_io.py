import base64
import hashlib
import unittest
from unittest.mock import patch

from giro.codeguard_codec import RULE_IV, RULE_KEY, java_seed_encrypt
from giro.codeguard_first import first_response_arithmetic, first_response_file_steps, first_response_read_steps
from giro.codeguard_native_io import (PACKAGE_CHUNK_SIZE, native_paths_match,
    native_pid_stat_steps, native_process_check_steps, native_process_name,
    package_digest_read_steps, package_digest_file_steps, native_cmdline_steps,
    native_digest_probe_path, FailedCmdlineRead)
from giro.codeguard_rule import AnalysisLimit, NativeRuleError


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

    def test_repeated_tracer_zero_does_not_clear_previous_nonzero_flag(self):
        result, effects = self.check(['one', b'TracerPid:44\n', b'TracerPid:0\n', None,
                                      'tracer', None, None])
        self.assertEqual(result, 127)
        self.assertIn(('native_fopen', (b'/proc/44/status', b'r')), effects)
        result, effects = self.check(['one', b'TracerPid:0\n', None,
                                      'two', b'TracerPid:44\n', b'TracerPid:0\n', None])
        self.assertEqual(result, 127)
        self.assertEqual(len([e for e in effects if e[0] == 'native_fopen']), 2)

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


class NativeFileSequenceTests(unittest.TestCase):
    def file(self, observations, process=b'pkg'):
        return finish(package_digest_file_steps(b'/installed/pkg/base\0ignored', process), observations)

    def test_file_order_and_secondary_open_do_not_change_hash(self):
        for probe in (None, 'secondary'):
            result, effects = self.file(['package', 0, 3, None, b'abc', probe, -1]
                                       + ([] if probe is None else [-1]))
            self.assertEqual(result, hashlib.sha256(b'abc').digest())
            self.assertEqual(effects, [
                ('native_fopen', (b'/installed/pkg/base', b'rb')),
                ('native_fseek', ('package', 0, 2)),
                ('native_ftell', ('package',)), ('native_rewind', ('package',)),
                ('native_fread', ('package', 1, 3)),
                ('native_fopen', (b'/data/data/pkg/files/libCodeGuard.so', b'rb')),
                ('native_fclose', ('package',))]
                + ([] if probe is None else [('native_fclose', ('secondary',))]))

    def test_seek_and_close_status_do_not_override_a_digest(self):
        result, _ = self.file(['package', -1, 3, None, b'a', None, -1])
        self.assertEqual(result, hashlib.sha256(b'a\0\0').digest())

    def test_low_32_bits_of_ftell_drive_read_lengths(self):
        for size in (3, 2**32 + 3):
            result, effects = self.file(['package', 0, size, None, b'abc', None, None])
            self.assertEqual(result, hashlib.sha256(b'abc').digest())
            self.assertEqual(effects[4], ('native_fread', ('package', 1, 3)))

    def test_unknown_or_negative_size_remains_unresolved_after_rewind(self):
        for position in (-1, None, True, 2**63):
            generator = package_digest_file_steps(b'/package', b'pkg')
            self.assertEqual(next(generator).kind, 'native_fopen')
            self.assertEqual(generator.send('stream').kind, 'native_fseek')
            self.assertEqual(generator.send(0).kind, 'native_ftell')
            self.assertEqual(generator.send(position).kind, 'native_rewind')
            with self.assertRaises(AnalysisLimit): generator.send(None)

    def test_actual_open_failure_does_not_become_safe_code11_return(self):
        generator = package_digest_file_steps(b'/package', b'pkg')
        next(generator)
        with self.assertRaises(AnalysisLimit): generator.send(None)

    def test_unknown_probe_does_not_become_null_or_trigger_cleanup_retry(self):
        generator = package_digest_file_steps(b'/package', b'pkg')
        values = [None, 'stream', 0, 0, None, b'']
        for value in values: effect = generator.send(value)
        self.assertEqual(effect.args[0], b'/data/data/pkg/files/libCodeGuard.so')
        with self.assertRaises(AnalysisLimit): generator.throw(AnalysisLimit('no observation'))
        with self.assertRaises(StopIteration): next(generator)

    def test_probe_path_is_c_string_concatenation_not_data_dir_resolution(self):
        self.assertEqual(native_digest_probe_path(b'pkg:worker\0ignored'),
                         b'/data/data/pkg:worker/files/libCodeGuard.so')
        self.assertIn(b'../pkg', native_digest_probe_path(b'../pkg'))
        self.assertEqual(len(native_digest_probe_path(b'x'*222)), 255)
        with self.assertRaises(AnalysisLimit): native_digest_probe_path(b'x'*223)
        with self.assertRaises(AnalysisLimit): native_digest_probe_path(None)

    def test_io_completes_before_even_invalid_challenge_is_examined(self):
        generator = first_response_file_steps(b'/package', b'pkg', None, None, None, None)
        kinds, value = [], None
        replies = iter(['stream', 0, 0, None, b'', None, -1])
        with self.assertRaises(NativeRuleError) as caught:
            while True:
                effect = generator.send(value)
                kinds.append(effect.kind)
                value = next(replies)
        self.assertEqual(caught.exception.native_code, 20)
        self.assertEqual(kinds[-2:], ['native_fopen', 'native_fclose'])

    def test_file_stage_composes_into_arithmetic_after_close(self):
        rule = base64.b64encode(java_seed_encrypt(b'HEADER00'+b'\x02'*40, RULE_KEY, RULE_IV)).decode()
        result, _ = finish(first_response_file_steps(b'/package', b'pkg', 'TQ==', rule, 'a', 'v'),
                          ['stream', 0, 4, None, b'ab', None, None])
        self.assertEqual(result, first_response_arithmetic(b'ab\0\0', 'TQ==', rule, 'a', 'v'))

    def test_cmdline_failures_differ_between_outer_and_inner(self):
        for outer, open_code, read_code in ((True, 124, 126), (False, 15, 16)):
            result, effects = finish(native_cmdline_steps(123, outer=outer), [None])
            self.assertEqual(result, (open_code, b''))
            self.assertEqual(effects, [('native_fopen', (b'/proc/123/cmdline', b'r'))])
            result, effects = finish(native_cmdline_steps(123, outer=outer), ['s', FailedCmdlineRead(b'\0'), -1])
            self.assertEqual(result, (read_code, b''))
            self.assertEqual(effects[-1], ('native_fclose', ('s',)))

    def test_failed_outer_fgets_does_not_assume_its_buffer_is_unchanged(self):
        for read in (None, FailedCmdlineRead(None), FailedCmdlineRead(b''),
                     FailedCmdlineRead(b'x'*256), FailedCmdlineRead(b'\0'*257)):
            with self.assertRaises(AnalysisLimit):
                finish(native_cmdline_steps(123, outer=True), ['s', read, 0])
        self.assertEqual(finish(native_cmdline_steps(123, outer=False), ['s', None, 0])[0], (16, b''))

    def test_failed_outer_fgets_uses_explicit_buffer_without_replacing_it(self):
        read = FailedCmdlineRead(b'partial:engine\0')
        self.assertEqual(finish(native_cmdline_steps(123, outer=True), ['s', read, 0])[0], (126, b'partial'))
        self.assertNotIn('partial', repr(read))

    def test_cmdline_success_retains_source_transform_and_single_read(self):
        for outer in (True, False):
            result, effects = finish(native_cmdline_steps(-2, outer=outer), ['s', b'pkg:engine\0arg', 0])
            self.assertEqual(result, (0, b'pkg'))
            self.assertEqual(effects[0][1][0], b'/proc/-2/cmdline')
            self.assertEqual(len(effects), 3)

    def test_cmdline_unknown_or_malformed_is_not_an_empty_name(self):
        for pid in (None, True, '123', 2**31):
            with self.assertRaises(AnalysisLimit): next(native_cmdline_steps(pid, outer=True))
        for data in (b'', b'x'*256, 'pkg'):
            with self.assertRaises(AnalysisLimit): finish(native_cmdline_steps(123, outer=True), ['s', data, None])
        generator = native_cmdline_steps(123, outer=True)
        next(generator)
        with self.assertRaises(AnalysisLimit): generator.throw(AnalysisLimit('unavailable'))

    def test_no_actual_files_host_identity_or_sdk_are_used(self):
        with patch('builtins.open', side_effect=AssertionError('no files')), \
             patch('socket.socket', side_effect=AssertionError('no network')), \
             patch('os.getpid', side_effect=AssertionError('no host identity')), \
             patch('ctypes.CDLL', side_effect=AssertionError('no SDK')):
            self.file(['stream', 0, 0, None, b'', None, None])
            finish(native_cmdline_steps(123, outer=True), [None])


if __name__ == '__main__':
    unittest.main()
