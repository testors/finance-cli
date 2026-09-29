import base64
from email.parser import Parser
import importlib.util
import json
import unittest
from unittest.mock import patch
from giro.codeguard_material import projected_response_headers, inspect_cookie_material, inspect_challenge_material
from giro import codeguard_challenge_probe as probe
from giro.codeguard_codec import RULE_KEY, RULE_IV, java_seed_encrypt
from giro.codeguard_exchange import UpdaterState
from giro.codeguard_rule import AnalysisLimit
from giro.errors import GiroError
import test_codeguard_challenge_probe as exchange_support

class CookieMaterialTests(unittest.TestCase):

    def message(self, text):
        return Parser().parsestr(text + '\r\n\r\n', headersonly=True)

    def test_ascii_unfolded_projection_matches_java_trim_and_order(self):
        message = self.message('set-cookie: a=1  \r\nSet-Cookie:\tb=2\t')
        self.assertEqual(projected_response_headers(message).get('Set-Cookie'), ('a=1', 'b=2'))

    def test_fold_nonascii_missing_colon_and_envelope_are_boundaries(self):
        for text in ('Set-Cookie:a=1\r\n ; Path=/x', 'Set-Cookie:한글', 'broken\r\nSet-Cookie:a=1', 'From synthetic\r\nSet-Cookie:a=1'):
            with self.assertRaises(AnalysisLimit):
                projected_response_headers(self.message(text))

    def test_original_cookie_failures_ignored_no_new_required_cookie_gate(self):
        result = inspect_cookie_material(self.message('Set-Cookie:broken'), locale_language='ko')
        self.assertTrue(result['cookie_values_processed'])
        self.assertFalse(result['cookie_string_present'])

    def test_no_cookie_header_is_valid_empty_projection(self):
        result = inspect_cookie_material(self.message('X:test'), locale_language='ko')
        self.assertEqual(result['set_cookie_header_count'], 0)
        self.assertTrue(result['cookie_values_processed'])

    def test_valid_cookie_present_without_exposing_name_or_value(self):
        result = inspect_cookie_material(self.message('sET-cOOKIE:PRIVATE-NAME=PRIVATE-VALUE;Path=/'), locale_language='ko')
        self.assertTrue(result['cookie_values_processed'])
        self.assertTrue(result['cookie_string_present'])
        self.assertFalse(result['cookie_forwarded'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_unknown_date_boundary_preserves_partial_cookie_state(self):
        result = inspect_cookie_material(self.message('Set-Cookie:a=1\r\nSet-Cookie:b=2;Expires=PRIVATE'), locale_language='ko')
        self.assertEqual(result['analysis_status'], 'cookie_value_adapter_boundary')
        self.assertFalse(result['cookie_values_processed'])
        self.assertTrue(result['cookie_string_present'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_unknown_header_input_not_faked_as_empty_cookie(self):
        result = inspect_cookie_material(None, locale_language='ko')
        self.assertEqual(result['analysis_status'], 'header_projection_boundary')
        self.assertFalse(result['cookie_values_processed'])

class PlanAndGuardTests(unittest.TestCase):

    def test_material_requires_explicit_locale_before_network(self):
        with patch('socket.socket', side_effect=AssertionError('offline')):
            with self.assertRaises(GiroError):
                probe.probe_challenge('arm64-v8a', inspect_material=True)
        result = probe.plan('arm64-v8a', inspect_material=True, locale_language='ko')
        self.assertEqual(result['maximum_requests'], 2)
        self.assertTrue(result['inspect_material'])
        self.assertFalse(result['network_attempted'])

    def test_cli_plan_material_no_network_and_live_explicit_parameters(self):
        from giro.__main__ import parser, run
        args = parser().parse_args(['auth', 'codeguard-challenge', '--abi', 'arm64-v8a', '--inspect-material', '--locale', 'ko'])
        with patch.object(probe, 'probe_challenge', side_effect=AssertionError('no network')):
            (result, code) = run(args)
        self.assertTrue(result['offline'])
        self.assertEqual(code, 0)
        args.live = True
        with patch.object(probe, 'probe_challenge', return_value={'analysis_status': 'incomplete'}) as call:
            run(args)
        call.assert_called_once_with('arm64-v8a', inspect_material=True, locale_language='ko')

    def test_optional_diagnostic_failure_does_not_reverse_body_parse(self):
        with patch('giro.codeguard_material.inspect_challenge_material', side_effect=ValueError('PRIVATE')):
            result = probe.inspect_challenge_body(b'{CODE_CHALLENGE:"c::r"}', UpdaterState(), inspect_material=True)
        self.assertEqual(result['analysis_status'], 'cmd200_body_processed')
        self.assertTrue(result['cmd200_body_processed'])
        self.assertEqual(result['initial_material']['analysis_status'], 'local_material_inspection_boundary')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_network_prefix_stops_material_decoding_not_body_classification(self):
        result = probe.inspect_challenge_body(b'{CODE_CHALLENGE:"E101_NET_ERROR_PRIVATE"}', UpdaterState(), inspect_material=True)
        self.assertTrue(result['cmd200_body_processed'])
        self.assertEqual(result['initial_material']['analysis_status'], 'mainservice_prefix_stop')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_empty_challenge_is_not_new_app_rejection(self):
        result = probe.inspect_challenge_body(b'{}', UpdaterState(), inspect_material=True)
        self.assertTrue(result['cmd200_body_processed'])
        self.assertEqual(result['initial_material']['analysis_status'], 'no_assigned_challenge_rule')

    def test_original_rcl_substring_failure_before_rule_codec(self):
        with patch('giro.codeguard_material.derive_rule_plan', side_effect=AssertionError('later')):
            result = inspect_challenge_material('long::rule', UpdaterState(rcl='a'), app_info='APP', version='1')
        self.assertEqual(result['analysis_status'], 'rcl_substring_original_exception')

@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto unavailable')
class RuleMaterialTests(unittest.TestCase):

    def material(self, state=None):
        encoded = base64.b64encode(java_seed_encrypt(b'HEADER00' + bytes(range(40)), RULE_KEY, RULE_IV)).decode()
        challenge = base64.b64encode(b'PRIVATE-CHALLENGE').decode()
        result = inspect_challenge_material(challenge + '::' + encoded, state or UpdaterState(), app_info='APP', version='1')
        return (result, challenge, encoded)

    def test_rule_plan_count_only_without_response_or_decoded_inputs(self):
        (result, challenge, encoded) = self.material()
        self.assertEqual(result['analysis_status'], 'rule_plan_decoded')
        self.assertIn(result['operation_count'], (3, 4, 5))
        self.assertFalse(result['native_checks_performed'])
        self.assertFalse(result['native_response_generated'])
        self.assertFalse(result['server_token_generated'])
        for value in ('PRIVATE', challenge, encoded):
            self.assertNotIn(value, json.dumps(result))
        self.assertNotIn('selected_offsets', result)
        self.assertNotIn('operation_ids', result)

    def test_key_source_report_never_prints_hash_or_computes_native_nonce(self):
        (result, _, _) = self.material(UpdaterState(hash_key='PRIVATE'))
        self.assertEqual(result['nonce_key_source'], 'server_HASH_KEY')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_native_rule_error_is_local_diagnostic_not_fake_app_failure(self):
        result = probe.inspect_challenge_body(b'{CODE_CHALLENGE:"!!!!::also-bad"}', UpdaterState(), inspect_material=True)
        self.assertTrue(result['cmd200_body_processed'])
        self.assertEqual(result['initial_material']['analysis_status'], 'rule_codec_native_error')
        self.assertEqual(result['initial_material']['native_code'], 21)

    def test_unparseable_third_certificate_not_giro_trust_rejection(self):
        (_, challenge, encoded) = self.material()
        result = inspect_challenge_material(challenge + '::' + encoded + '::AAAA', UpdaterState(), app_info='APP', version='1')
        self.assertEqual(result['analysis_status'], 'rule_plan_decoded')
        self.assertIn('challenge_certificate', result)
        self.assertFalse(result['android_certificate_equivalence_verified'])

    def test_rcl_inventory_failure_does_not_change_rule_plan(self):
        challenge = base64.b64encode(b'PRIVATE-CHALLENGE').decode()
        (result, _, _) = self.material(UpdaterState(rcl=challenge + 'NOT-AN-ARRAY'))
        self.assertEqual(result['analysis_status'], 'rule_plan_decoded')
        self.assertEqual(result['rcl_requirements']['analysis_status'], 'rcl_original_json_exception')

    def test_rcl_policy_inventory_is_pure_and_sanitized(self):
        challenge = base64.b64encode(b'PRIVATE-CHALLENGE').decode()
        suffix = '[{description:"PRIVATE-CMD",policy:14,osType:1,enabled:true}]'
        with patch('subprocess.Popen', side_effect=AssertionError('no process')):
            (result, _, _) = self.material(UpdaterState(rcl=challenge + suffix))
        self.assertEqual(result['rcl_requirements']['android_policy_counts']['runtime_exec'], 1)
        self.assertNotIn('PRIVATE', json.dumps(result))

@unittest.skipUnless(exchange_support.CRYPTO, 'optional crypto unavailable')
class MaterialProbeTests(unittest.TestCase):

    def test_two_request_probe_inspects_all_material_without_additional_network(self):
        exchange_support.ExchangeTests.setUpClass()
        support = exchange_support.ExchangeTests()
        support.setUp()
        self.addCleanup(support.doCleanups)
        encoded = base64.b64encode(java_seed_encrypt(b'HEADER00' + bytes(range(40)), RULE_KEY, RULE_IV)).decode()
        challenge = base64.b64encode(b'PRIVATE-CHALLENGE').decode()
        support.second.read.return_value = json.dumps({'CODE_CHALLENGE': challenge + '::' + encoded + '::' + support.cert, 'CODE_RCL': base64.b64encode((challenge + '[{description:"PRIVATE",policy:11,osType:1,enabled:true}]').encode()).decode()}).encode()
        support.second.msg = Parser().parsestr('Set-Cookie:PRIVATE=PRIVATE;Path=/\r\n\r\n', headersonly=True)
        with patch.object(exchange_support.transport.http.client, 'HTTPSConnection', side_effect=support.connections) as factory:
            result = probe.probe_challenge('arm64-v8a', inspect_material=True, locale_language='ko')
        self.assertEqual(factory.call_count, 2)
        self.assertEqual(result['requests_attempted'], 2)
        second = result['requests'][1]
        self.assertTrue(second['cookie_material']['cookie_values_processed'])
        self.assertEqual(second['initial_material']['analysis_status'], 'rule_plan_decoded')
        self.assertTrue(second['initial_material']['rcl_suffix_present'])
        self.assertTrue(second['initial_material']['rcl_requirements']['possible_process_execution'])
        self.assertFalse(second['initial_material']['rcl_requirements']['environment_checks_performed'])
        self.assertTrue(second['initial_material']['challenge_certificate']['rsa_public_key'])
        self.assertFalse(result['token_request_submitted'])
        self.assertFalse(result['environment_response_submitted'])
        for value in ('PRIVATE', challenge, encoded, support.cert):
            self.assertNotIn(value, json.dumps(result))
