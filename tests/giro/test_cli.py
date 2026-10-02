import contextlib
import io
import json
import unittest
from unittest.mock import patch
from giro.__main__ import main
from test_bills import page

class CliTests(unittest.TestCase):

    def call(self, args, data=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch('sys.stdin', io.StringIO(json.dumps(data))), patch('socket.socket', side_effect=AssertionError('network forbidden')):
            code = main(args)
        return (code, json.loads(output.getvalue()))

    def test_catalog_and_auth_plan_offline(self):
        for args in (['api', 'list'], ['auth', 'plan'], ['request', 'local.list']):
            (code, _) = self.call(args)
            self.assertEqual(code, 0)

    def test_registration_plan_is_offline_without_identity_creation(self):
        with patch('giro.registration_flow.EnrollmentStore.identity', side_effect=AssertionError('no ID')):
            code, result = self.call(['auth', 'registration-plan'])
        self.assertEqual(code, 0)
        self.assertFalse(result['network_used'])
        self.assertFalse(result['live_registration_tested'])
        self.assertTrue(result['default_runtime_available'])
        self.assertEqual(result['max_business_requests'], 10)

    def test_login_registration_query_and_payment_default_to_no_io_plans(self):
        for command in (['auth', 'login'], ['auth', 'register'], ['bills', 'list', '--type', 'national'], ['payment', 'pay']):
            with patch('giro.auth_flow.login_dependencies', side_effect=AssertionError('no dependencies')), \
                 patch('giro.session_store.SessionStore.use', side_effect=AssertionError('no session')):
                code, result = self.call(command)
            self.assertEqual(code, 0)
            self.assertFalse(result['network_used'])
            self.assertTrue(result['plan_only'])

    def test_explicit_auth_requires_private_terminal_before_dependencies(self):
        with patch('giro.auth_flow.login_dependencies', side_effect=AssertionError('no dependencies')):
            code, result = self.call(['auth', 'login', '--send'])
        self.assertEqual(code, 2)
        self.assertEqual(result['error'], 'validation_error')

    def test_auth_exit_distinguishes_rejection_preparation_and_saved_success(self):
        cases = (
            ('register', {'steps': [{'service_decision': 'failure'}]}, 2),
            ('register', {'registration_service_decision': 'failure'}, 2),
            ('register', {'registration_service_decision': 'success',
                          'login': {'last_response_service_decision': 'failure'}}, 2),
            ('login', {'last_response_service_decision': 'failure'}, 2),
            ('login', {'last_response_service_decision': 'success',
                       'next_action': 'sms_identity_verification'}, 4),
            ('register', {'steps': [{'service_decision': 'success'}],
                          'next_action': 'member_join'}, 4),
            ('register', {'registration_service_decision': 'success',
                          'login_service_decision': 'success',
                          'processing_issues': ['session_save_incomplete']}, 0),
        )
        for action, observed, expected in cases:
            with self.subTest(action=action, observed=observed), \
                 patch('giro.auth_cli.private_terminal'), \
                 patch('giro.auth_cli.authenticate', return_value=observed):
                code, result = self.call(['auth', action, '--send'])
                self.assertEqual(code, expected)
                self.assertEqual(result, observed)

    def test_bootstrap_offline_unless_live_explicit(self):
        (code, result) = self.call(['auth', 'bootstrap'])
        self.assertEqual(code, 0)
        self.assertFalse(result['network_attempted'])

    def test_inspect_rule_reports_native_error_not_giro_response_code(self):
        (code, result) = self.call(['auth', 'inspect-rule', '--input', '-'], {})
        self.assertEqual(code, 2)
        self.assertEqual(result['native_code'], 20)
        self.assertNotIn('response_code', result)

    def test_inspect_rule_unknown_memory_not_app_rejection(self):
        (code, result) = self.call(['auth', 'inspect-rule', '--input', '-'], {'encoded_challenge': ''})
        self.assertEqual(code, 0)
        self.assertEqual(result['analysis_status'], 'unmodeled_memory_boundary')

    def test_inspect_rule_local_schema_error(self):
        for data in ([], {'encoded_challenge': 123}):
            (code, result) = self.call(['auth', 'inspect-rule', '--input', '-'], data)
            self.assertEqual(code, 2)

    def test_inspect_nonce_completes_without_disclosing_inputs_or_result(self):
        (code, result) = self.call(['auth', 'inspect-nonce', '--input', '-'], {'key_hex': '0' * 64, 'codes': [None] * 6})
        self.assertEqual(code, 0)
        self.assertEqual(result['analysis_status'], 'arithmetic_completed')
        self.assertEqual(result['dispatch_functions_implemented'], 100)
        self.assertFalse(result['live_login_ready'])
        self.assertNotIn('0' * 64, json.dumps(result))
        self.assertNotIn('nonce', result)

    def test_inspect_nonce_memory_limit_not_giro_failure(self):
        (code, result) = self.call(['auth', 'inspect-nonce', '--input', '-'], {'key_hex': 'short', 'codes': []})
        self.assertEqual(code, 0)
        self.assertEqual(result['analysis_status'], 'unmodeled_memory_boundary')

    def test_inspect_nonce_local_schema_error(self):
        for data in ([], {'codes': None}, {'codes': [12]}):
            (code, _) = self.call(['auth', 'inspect-nonce', '--input', '-'], data)
            self.assertEqual(code, 2)

    def test_live_bootstrap_exit_follows_app_decision_not_diagnostics(self):
        for (success, expected) in ((True, 0), (False, 2), (None, 0)):
            with patch('giro.bootstrap.probe_server_cert', return_value={'app_success': success}):
                (code, result) = self.call(['auth', 'bootstrap', '--live'])
            self.assertEqual(code, expected)
            self.assertIs(result['app_success'], success)

    def test_successful_import(self):
        (code, result) = self.call(['bills', 'list', '--type', 'national', '--input', '-'], page())
        self.assertEqual(code, 0)
        self.assertEqual(result['loaded_count'], 1)

    def test_missing_timezone_preserves_app_success_and_unfiltered_bills(self):
        from zoneinfo import ZoneInfoNotFoundError
        with patch('giro.__main__.ZoneInfo', side_effect=ZoneInfoNotFoundError('PRIVATE-PATH')):
            (code, result) = self.call(['bills', 'due', '--type', 'national', '--input', '-'], page())
        self.assertEqual(code, 0)
        self.assertTrue(result['app_success'])
        self.assertIsNone(result['bills'])
        self.assertEqual(len(result['unfiltered_bills']), 1)
        self.assertFalse(result['filter_applied'])
        self.assertFalse(result['filter_complete'])
        self.assertIsNone(result['as_of'])
        self.assertNotIn('PRIVATE-PATH', json.dumps(result))

    def test_missing_timezone_does_not_turn_null_into_empty_list(self):
        from zoneinfo import ZoneInfoNotFoundError
        with patch('giro.__main__.ZoneInfo', side_effect=ZoneInfoNotFoundError('missing')):
            (code, result) = self.call(['bills', 'due', '--type', 'local', '--input', '-'], {'responseCode': '000'})
        self.assertEqual(code, 0)
        self.assertIsNone(result['unfiltered_bills'])

    def test_explicit_today_needs_no_timezone_data(self):
        with patch('giro.__main__.ZoneInfo', side_effect=AssertionError('must not read host timezone')) as zone:
            (code, result) = self.call(['bills', 'due', '--type', 'customs', '--input', '-', '--today', '2026-09-29'], page())
        self.assertEqual(code, 0)
        self.assertTrue(result['filter_applied'])
        self.assertEqual(result['bills'][0]['days_until_due'], 1)
        zone.assert_not_called()

    def test_missing_timezone_does_not_mask_app_error(self):
        with patch('giro.__main__.ZoneInfo') as zone:
            (code, result) = self.call(['bills', 'due', '--type', 'national', '--input', '-'], {'responseCode': '999'})
        self.assertEqual(code, 2)
        self.assertFalse(result['app_success'])
        zone.assert_not_called()

    def test_missing_pages_do_not_override_app_success(self):
        (code, result) = self.call(['bills', 'list', '--type', 'local', '--input', '-'], page(1, 2, 2))
        self.assertEqual(code, 0)
        self.assertTrue(result['app_success'])
        self.assertFalse(result['complete'])

    def test_unknown_due_is_diagnostic_not_request_failure(self):
        (code, result) = self.call(['bills', 'due', '--type', 'customs', '--input', '-', '--today', '2026-09-27'], page(due='미정'))
        self.assertEqual(code, 0)
        self.assertEqual(len(result['unparsed_bills']), 1)

    def test_server_error_nonzero(self):
        (code, result) = self.call(['bills', 'list', '--type', 'national', '--input', '-'], {'responseCode': '999'})
        self.assertEqual(code, 2)
        self.assertEqual(result['response_code'], '999')

    def test_cli_preserves_errorinfo_and_callback_code(self):
        (code, result) = self.call(['bills', 'list', '--type', 'national', '--input', '-'], {'responseCode': '999', 'errorInfo': {'errorCode': '001', 'errorMessage': '서비스 오류'}})
        self.assertEqual(code, 2)
        self.assertEqual(result['callback_code'], '001')
        self.assertEqual(result['error_info']['errorMessage'], '서비스 오류')

    def test_cli_null_list_not_changed_to_empty(self):
        (code, result) = self.call(['bills', 'list', '--type', 'national', '--input', '-'], {'responseCode': '000'})
        self.assertEqual(code, 0)
        self.assertIsNone(result['bills'])

    def test_pin_not_read_from_noninteractive_stdin(self):
        (code, result) = self.call(['auth', 'encode-pin', '--key-file', 'does-not-exist'])
        self.assertEqual(code, 2)
        self.assertNotIn('pin_ciphertext', result)

    def test_invalid_json(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch('sys.stdin', io.StringIO('not-json')):
            code = main(['bills', 'list', '--type', 'national', '--input', '-'])
        self.assertEqual(code, 2)

    def test_missing_file_no_traceback_or_file_contents(self):
        (code, result) = self.call(['bills', 'list', '--type', 'national', '--input', '/not-a-real-giro-test-file'])
        self.assertEqual(code, 2)
        self.assertEqual(result['error'], 'validation_error')
