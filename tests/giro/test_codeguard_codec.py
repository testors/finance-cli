import base64
import hashlib
import hmac
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from giro import codeguard_codec as cg
from giro.codeguard_rule import AnalysisLimit, NativeRuleError, RulePlan, parse_rule, parsing_positions
from giro.crypto import _cbc

class StringCodecTests(unittest.TestCase):

    def test_java_utf8_and_jni_are_different_for_nul_and_supplementary(self):
        self.assertEqual(cg.java_utf8('A\x00😀'), b'A\x00\xf0\x9f\x98\x80')
        self.assertEqual(cg.jni_modified_utf8('A\x00😀'), b'A\xc0\x80\xed\xa0\xbd\xed\xb8\x80')
        self.assertEqual(cg.jni_modified_utf8('한'), '한'.encode())

    def test_explicit_surrogates_and_null(self):
        self.assertEqual(cg.java_utf8('\ud83d\ude00'), '😀'.encode())
        self.assertEqual(cg.java_utf8('\ud800'), b'?')
        self.assertEqual(cg.jni_modified_utf8('\ud800'), b'\xed\xa0\x80')
        self.assertIsNone(cg.jni_modified_utf8(None))
        with self.assertRaises(cg.CodeGuardCodecError):
            cg.java_utf8(None)

    def test_java_urlencoder_not_okhttp_formbody(self):
        self.assertEqual(cg.java_form_encode('a b+~*/=&한'), 'a+b%2B%7E*%2F%3D%26%ED%95%9C')

    def test_java_base64_normal_binary_roundtrip(self):
        for size in range(1, 80):
            data = bytes(range(size))
            self.assertEqual(cg.java_base64_decode(base64.b64encode(data).decode()), data)

    def test_java_base64_empty_and_bad_length_are_null(self):
        for data in ('', 'A', 'AA', 'AAA', 'AAAA\n'):
            self.assertIsNone(cg.java_base64_decode(data))

    def test_java_base64_unknown_sextets_zero_not_skipped_or_rejected(self):
        self.assertEqual(cg.java_base64_decode('!!!!'), bytes(3))
        self.assertEqual(cg.java_base64_decode('===='), bytes(1))
        self.assertEqual(cg.java_base64_decode('T Q='), b'L\x04')
        self.assertEqual(cg.java_base64_decode('😀'), bytes(3))

    def test_java_base64_inner_padding_is_not_truncation(self):
        self.assertEqual(cg.java_base64_decode('TQ==AAAA'), b'M\x00\x00\x00\x00\x00')

    def test_native_base64_normal_binary_roundtrip(self):
        for size in range(1, 80):
            data = bytes(range(size))
            self.assertEqual(cg.native_base64_decode(base64.b64encode(data)), data)

    def test_native_base64_trailing_whitespace_and_nul_c_string(self):
        self.assertEqual(cg.native_base64_decode(b'TQ==\r\n '), b'M')
        self.assertEqual(cg.native_base64_decode(b'TQ==\x00IGNORE'), b'M')
        with self.assertRaises(cg.NativeBase64Error):
            cg.native_base64_decode(b'TQ==\t')

    def test_native_base64_7bit_alias_not_java_decoder(self):
        encoded = bytes((b | 128 for b in b'TWFu'))
        self.assertEqual(cg.native_base64_decode(encoded), b'Man')

    def test_native_base64_leading_space_keeps_original_padding_pointer(self):
        self.assertEqual(cg.native_base64_decode(b'    TQ=='), b'M\x00\x00')
        with self.assertRaises(cg.NativeBase64Error):
            cg.native_base64_decode(b' TQ==')

    def test_native_base64_invalid_and_zero_result_codes(self):
        for (encoded, code) in ((b'T Q=', -1), (b'!!!!', -1), (b'AAA', -1), (b'A===', 100)):
            with self.subTest(encoded=encoded), self.assertRaises(cg.NativeBase64Error) as caught:
                cg.native_base64_decode(encoded)
            self.assertEqual(caught.exception.native_code, code)

    def test_native_base64_memory_boundaries_are_not_invented_sdk_errors(self):
        for encoded in (b'', b' ', b'===='):
            with self.subTest(encoded=encoded), self.assertRaises(AnalysisLimit):
                cg.native_base64_decode(encoded)

@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto unavailable')
class SeedCodecTests(unittest.TestCase):
    (key, iv) = (bytes(range(16)), bytes(range(16, 32)))

    def ciphertext(self, plain):
        return _cbc(self.key, self.iv, plain)

    def test_java_seed_roundtrip_including_empty_and_aligned(self):
        for size in (0, 1, 15, 16, 17, 32, 33):
            plain = bytes(range(size))
            cipher = cg.java_seed_encrypt(plain, self.key, self.iv)
            self.assertEqual(cg.java_seed_decrypt(cipher, self.key, self.iv), plain)

    def test_java_key_and_iv_read_first_sixteen_not_exact_array_length(self):
        cipher = cg.java_seed_encrypt(b'plain', self.key, self.iv)
        self.assertEqual(cg.java_seed_encrypt(b'plain', self.key + b'ignored', self.iv + b'ignored'), cipher)
        self.assertEqual(cg.java_seed_decrypt(cipher, self.key + b'ignored', self.iv + b'ignored'), b'plain')

    def test_java_short_key_and_iv_fail_original_array_access(self):
        for (key, iv) in ((None, self.iv), (b'short', self.iv), (self.key, None), (self.key, b'short')):
            with self.assertRaises(cg.CodeGuardCodecError):
                cg.java_seed_encrypt(b'plain', key, iv)

    def test_java_padding_subtracts_only_last_byte(self):
        plain = b'x' * 15 + b'\x02'
        self.assertEqual(cg.java_seed_decrypt(self.ciphertext(plain), self.key, self.iv), plain[:-2])

    def test_java_padding_zero_and_larger_than_block(self):
        for (plain, expected) in ((b'x' * 15 + b'\x00', b'x' * 15 + b'\x00'), (b'x' * 31 + b'\x11', b'x' * 15), (bytes((16,)) * 16, b'')):
            self.assertEqual(cg.java_seed_decrypt(self.ciphertext(plain), self.key, self.iv), expected)

    def test_java_non_aligned_tail_zero_fill(self):
        block = self.ciphertext(b'x' * 16)
        self.assertEqual(cg.java_seed_decrypt(block + b'anything', self.key, self.iv), b'x' * 16 + bytes(8))

    def test_java_actual_array_errors(self):
        for cipher in (None, b'', b'x' * 15, self.ciphertext(b'x' * 15 + b'\xff')):
            with self.assertRaises(cg.CodeGuardCodecError):
                cg.java_seed_decrypt(cipher, self.key, self.iv)

    def test_native_padding_valid_removed_but_invalid_not_rejected(self):
        for (plain, expected) in ((b'x' * 14 + b'\x02\x02', b'x' * 14), (b'x' * 15 + b'\x02', b'x' * 15 + b'\x02'), (b'x' * 15 + b'\xff', b'x' * 15 + b'\xff'), (b'x' * 15 + b'\x00', b'x' * 15 + b'\x00'), (bytes((16,)) * 16, b'')):
            self.assertEqual(cg.native_seed_decrypt(self.ciphertext(plain), self.key, self.iv), expected)

    def test_native_partial_block_not_guessed(self):
        for cipher in (b'', b'x' * 8, b'x' * 24):
            with self.assertRaises(AnalysisLimit):
                cg.native_seed_decrypt(cipher, self.key, self.iv)
        with self.assertRaises(cg.CodeGuardCodecError):
            cg.native_seed_decrypt(b'x' * 17, self.key, self.iv)

    def test_decode_rule_drops_exactly_eight_bytes(self):
        plain = b'HEADER00' + bytes(range(40))
        encoded = base64.b64encode(cg.java_seed_encrypt(plain, cg.RULE_KEY, cg.RULE_IV))
        self.assertEqual(cg.decode_rule(encoded), plain[8:])

    def test_decode_rule_error_codes_and_short_plaintext_limit(self):
        for (encoded, code) in ((None, 30), (b'!!!!', 31), (b'AAAA', 32)):
            with self.assertRaises(NativeRuleError) as caught:
                cg.decode_rule(encoded)
            self.assertEqual(caught.exception.native_code, code)
        encoded = base64.b64encode(cg.java_seed_encrypt(b'short', cg.RULE_KEY, cg.RULE_IV))
        with self.assertRaises(AnalysisLimit):
            cg.decode_rule(encoded)

    def test_decode_rule_eight_byte_plaintext_returns_empty_not_error(self):
        encoded = base64.b64encode(cg.java_seed_encrypt(b'HEADER00', cg.RULE_KEY, cg.RULE_IV))
        self.assertEqual(cg.decode_rule(encoded), b'')

    def test_derive_plan_connects_native_decode_and_selection(self):
        (challenge, rule) = (b'ABCDE', bytes(range(40)))
        encoded = base64.b64encode(cg.java_seed_encrypt(b'HEADER00' + rule, cg.RULE_KEY, cg.RULE_IV)).decode()
        result = cg.derive_rule_plan(encoded, base64.b64encode(challenge).decode(), 'app', '1.0')
        self.assertEqual(result, parse_rule(rule, parsing_positions(challenge, b'app', b'1.0')))

    def test_cli_inspects_rule_without_echoing_inputs_or_response(self):
        import contextlib
        import io
        import json
        from giro.__main__ import main
        encoded = base64.b64encode(cg.java_seed_encrypt(b'HEADER00' + bytes(range(40)), cg.RULE_KEY, cg.RULE_IV)).decode()
        data = {'encoded_challenge': base64.b64encode(b'SYNTHETIC CHALLENGE').decode(), 'encoded_rule': encoded, 'app_info': 'SYNTHETIC APP', 'version': 'SYNTHETIC VERSION'}
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch('sys.stdin', io.StringIO(json.dumps(data))), patch('socket.socket', side_effect=AssertionError('network forbidden')):
            code = main(['auth', 'inspect-rule', '--input', '-'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertFalse(result['server_token_generated'])
        self.assertFalse(result['plan']['response_generated'])
        for value in data.values():
            self.assertNotIn(value, output.getvalue())

    def test_derive_plan_challenge_errors_precede_rule_errors(self):
        for (challenge, code) in ((None, 20), ('!!!!', 21)):
            with self.assertRaises(NativeRuleError) as caught:
                cg.derive_rule_plan(None, challenge, 'app', '1.0')
            self.assertEqual(caught.exception.native_code, code)

    def test_wrap_preserves_null_and_engine_error_before_etoken(self):
        for text in (None, 'prefix E101_ENGINE_LOAD_ERROR suffix'):
            self.assertEqual(cg.wrap_response(text, encrypted_token=True), text)

    def test_wrap_applies_etoken_then_java_seed_and_base64(self):
        for text in ('', 'synthetic 한글 😀'):
            for flag in (False, True):
                encoded = cg.wrap_response(text, encrypted_token=flag)
                plain = cg.java_seed_decrypt(base64.b64decode(encoded), cg.RULE_KEY, cg.RULE_IV)
                self.assertEqual(plain, cg.java_utf8(('[ETOKEN]' if flag else '') + text))

class RuleEvaluationTests(unittest.TestCase):

    def test_all_hmac_algorithms_use_right_as_key_including_long_key(self):
        for (opcode, alg) in ((0, 'sha256'), (1, 'md5'), (5, 'sha1')):
            for key in (b'', b'key', b'K' * 100):
                self.assertEqual(cg.combine(opcode, b'message', key), hmac.digest(key, b'message', alg))

    def test_concat_keeps_binary_nuls(self):
        self.assertEqual(cg.combine(2, b'a\x00', b'b\x00'), b'a\x00b\x00')

    def test_bitwise_repeats_shorter_in_either_order(self):
        (a, b) = (bytes.fromhex('55aaff'), bytes.fromhex('0ff0'))
        for (opcode, expected) in ((3, '5ffaff'), (4, '05a00f'), (6, '5a5af0')):
            self.assertEqual(cg.combine(opcode, a, b).hex(), expected)
            self.assertEqual(cg.combine(opcode, b, a).hex(), expected)

    def test_zero_length_bitwise_is_explicit_analysis_limit(self):
        for opcode in (3, 4, 6):
            with self.assertRaises(AnalysisLimit):
                cg.combine(opcode, b'', b'A')

    def test_alternating_parallel_hash_inputs_and_order(self):
        plan = RulePlan((0, 2), (2, 0, 2), ())
        start = b'leftchallenge'
        first = hmac.digest(hashlib.sha256(start).digest(), hashlib.sha1(start).digest(), 'sha256')
        expected = hashlib.sha256(first).digest() + hashlib.sha1(first).digest()
        self.assertEqual(cg.evaluate_rule(plan, b'left', b'challenge'), expected)

    def test_extra_uses_c_string_and_empty_is_not_absent(self):
        plan = RulePlan((0, 1), (0, 2, 2), ())
        self.assertEqual(cg.evaluate_rule(plan, b'a', b'b', extra=b'c\x00ignored'), cg.evaluate_rule(plan, b'a', b'b', extra=b'c'))
        self.assertNotEqual(cg.evaluate_rule(plan, b'a', b'b', extra=None), cg.evaluate_rule(plan, b'a', b'b', extra=b''))

    def test_no_network_or_sdk_needed(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            plan = parse_rule(bytes(range(40)), (0, 0, 0))
            result = cg.evaluate_rule(plan, b'SYNTHETIC LEFT', b'SYNTHETIC CHALLENGE')
        self.assertIsInstance(result, bytes)
ROOT = Path(__file__).resolve().parents[1]
