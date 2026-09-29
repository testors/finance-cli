import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from giro.codeguard_codec import RULE_KEY, RULE_IV, java_seed_encrypt
from giro.codeguard_first import first_response_arithmetic, java_response_frame
from giro.codeguard_rule import AnalysisLimit, NativeRuleError

@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto unavailable')
class FirstArithmeticTests(unittest.TestCase):

    def rule(self):
        return base64.b64encode(java_seed_encrypt(b'HEADER00' + b'\x02' * 40, RULE_KEY, RULE_IV)).decode()

    def test_package_rule_and_three_part_payload(self):
        (package, challenge) = (b'synthetic package', b'synthetic challenge')
        challenge_text = base64.b64encode(challenge).decode()
        digest = hashlib.sha256(package).digest()
        current = digest + challenge
        for i in range(1, 5):
            (left, right) = (hashlib.sha256, hashlib.sha1) if i % 2 else (hashlib.sha1, hashlib.sha256)
            current = left(current).digest() + right(current).digest()
        expected = b'::'.join((base64.b64encode(current), base64.b64encode(digest), challenge_text.encode()))
        self.assertEqual(first_response_arithmetic(package, challenge_text, self.rule(), 'app', 'version'), expected)

    def test_encoded_challenge_is_preserved_not_canonicalized(self):
        raw = 'TQ==\r\n '
        result = first_response_arithmetic(b'package', raw, self.rule(), 'a', 'v')
        self.assertEqual(result.split(b'::')[2], raw.encode())

    def test_no_pid_is_appended_as_optional_operand(self):
        with patch('giro.codeguard_first.evaluate_rule', return_value=b'computed') as operation:
            result = first_response_arithmetic(b'package', 'TQ==', self.rule(), 'a', 'v')
        self.assertEqual(operation.call_args.kwargs, {'extra': None})
        self.assertTrue(result.startswith(b'Y29tcHV0ZWQ=::'))

    def test_no_network_sdk_or_automatic_artifact_reads(self):
        rule = self.rule()
        with patch('builtins.open', side_effect=AssertionError('no I/O')), patch('socket.socket', side_effect=AssertionError('no network')), patch('ctypes.CDLL', side_effect=AssertionError('no SDK')):
            self.assertIsInstance(first_response_arithmetic(b'package', 'TQ==', rule, 'a', 'v'), bytes)

    def test_codec_error_and_analysis_boundary_remain_separate(self):
        with self.assertRaises(NativeRuleError) as exc:
            first_response_arithmetic(b'package', None, self.rule(), 'a', 'v')
        self.assertEqual(exc.exception.native_code, 20)
        with self.assertRaises(NativeRuleError) as exc:
            first_response_arithmetic(b'package', '!', self.rule(), 'a', 'v')
        self.assertEqual(exc.exception.native_code, 21)
        with self.assertRaises(AnalysisLimit):
            first_response_arithmetic(None, 'TQ==', self.rule(), 'a', 'v')

class FrameTests(unittest.TestCase):

    def frame(self, **changes):
        data = dict(app_info='APP', version='VERSION', engine_version='engine', cached_engine_version='cached', build_string='build', elapsed_ms=123, etc_data=None, detail_enabled=False, rcl='', device_detail='device', device_detail_ex='extended', os_status='actual-status', native_return='native-result', location_text='')
        data.update(changes)
        return java_response_frame(**data)

    def test_exact_delimiters_and_original_trailing_empty_location(self):
        self.assertEqual(self.frame(), 'APP::VERSION##engine/build@123*actual-status##native-result##')

    def test_empty_etc_is_not_missing_and_takes_precedence_over_device(self):
        self.assertIn('@123!*', self.frame(etc_data='', detail_enabled=True))
        self.assertIn('@123!given*', self.frame(etc_data='given', detail_enabled=True))

    def test_device_details_are_java_utf8_base64_and_rcl_selects_extended(self):
        self.assertIn('!ZGV2aWNl*', self.frame(detail_enabled=True))
        self.assertIn('!ZXh0ZW5kZWQ=*', self.frame(detail_enabled=True, rcl='r'))
        self.assertIn('!APCfmIA=*', self.frame(detail_enabled=True, device_detail='\x00😀'))

    def test_java_null_and_negative_measured_duration_are_not_extra_rejections(self):
        self.assertEqual(self.frame(app_info=None, version=None, engine_version='', cached_engine_version=None, os_status=None, elapsed_ms=-1, build_string=None), 'null::null##null/null@-1*null##native-result##')

    def test_existing_engine_and_location_are_not_normalized(self):
        self.assertIn('##engine/build', self.frame(cached_engine_version='ignored'))
        self.assertTrue(self.frame(location_text='37.0##127.0').endswith('##37.0##127.0'))

    def test_unknown_error_side_effects_are_analysis_limits_not_sdk_rejections(self):
        for value in (None, 'E101_ENGINE_LOAD_ERROR0_120_x', 'UnsatisfiedLinkError'):
            with self.assertRaises(AnalysisLimit):
                self.frame(native_return=value)
        self.assertIn('E101_ENGINE_LOAD_ERROR0_123', self.frame(native_return='E101_ENGINE_LOAD_ERROR0_123'))
