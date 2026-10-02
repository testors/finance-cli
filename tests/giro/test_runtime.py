import contextlib
from datetime import timedelta, timezone
import importlib.util
import io
import json
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfoNotFoundError
from giro import runtime
from giro.__main__ import main
from giro.protocol import auth_plan

class RuntimeTests(unittest.TestCase):

    def test_target_does_not_require_android_or_host_identity(self):
        plan = auth_plan()['deployment']
        self.assertEqual(plan['target'], 'non_android_headless_server')
        for key in ('android_runtime_required', 'adb_required', 'jvm_required', 'original_sdk_execution_required', 'host_identity_autofill', 'live_login_ready'):
            self.assertIs(plan[key], False)

    def test_schema_and_nonce_resources_are_exercised(self):
        self.assertTrue(runtime._models())
        self.assertTrue(runtime._nonce())

    def test_explicit_timezone_not_host_local_time(self):
        with patch('giro.runtime.ZoneInfo', return_value=timezone(timedelta(hours=9))) as zone:
            self.assertTrue(runtime._timezone())
        zone.assert_called_once_with('Asia/Seoul')
        with patch('giro.runtime.ZoneInfo', return_value=timezone.utc):
            self.assertFalse(runtime._timezone())

    def test_no_network_process_or_identity_collection(self):
        with contextlib.ExitStack() as stack:
            denied = [stack.enter_context(patch(name, side_effect=AssertionError('forbidden'))) for name in ('socket.socket', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system', 'os.getpid', 'os.getuid', 'platform.node', 'platform.machine')]
            report = runtime.check_runtime()
            for call in denied:
                call.assert_not_called()
        self.assertFalse(report['network_attempted'])
        self.assertFalse(report['host_identity_collected'])
        self.assertFalse(report['device_checks_performed'])
        self.assertFalse(report['server_token_generated'])
        self.assertFalse(report['certificate_validation_performed'])
        self.assertFalse(report['live_login_ready'])
        self.assertNotIn('app_success', report)

    def test_missing_resources_are_diagnostics_without_exception_text(self):
        with patch('giro.runtime._models', side_effect=OSError('PRIVATE-PATH')):
            report = runtime.check_runtime()
        self.assertEqual(report['checks'][0]['status'], 'warning')
        self.assertNotIn('PRIVATE-PATH', json.dumps(report))
        self.assertNotIn('response_code', report)

    def test_missing_crypto_and_timezone_dont_hide_other_checks(self):
        with patch('giro.runtime._seed_pin', side_effect=ImportError('PRIVATE')), patch('giro.runtime._cms', side_effect=ImportError('PRIVATE')), patch('giro.runtime.ZoneInfo', side_effect=ZoneInfoNotFoundError('PRIVATE')):
            report = runtime.check_runtime()
        self.assertEqual(report['warning_count'], 3)
        self.assertEqual([c['status'] for c in report['checks']], ['passed', 'passed', 'warning', 'warning', 'passed', 'warning'])
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_synthetic_mismatch_is_not_a_pass(self):
        with patch('giro.runtime._nonce', return_value=False):
            report = runtime.check_runtime()
        self.assertEqual(report['checks'][1]['status'], 'warning')

    @unittest.skipUnless(importlib.util.find_spec('cryptography') and importlib.util.find_spec('asn1crypto'), 'optional crypto packages unavailable')
    def test_crypto_synthetic_roundtrips(self):
        self.assertTrue(runtime._seed_pin())
        self.assertTrue(runtime._cms())

    def test_cli_warning_is_not_nonzero_or_app_failure(self):
        output = io.StringIO()
        with patch('giro.runtime._nonce', return_value=False), contextlib.redirect_stdout(output):
            status = main(['runtime', 'check'])
        report = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertGreaterEqual(report['warning_count'], 1)
        self.assertNotIn('app_success', report)

    def test_cli_does_not_disclose_synthetic_crypto_material(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(['runtime', 'check'])
        for text in ('012345', 'SYNTHETIC DEPLOYMENT CHECK', 'F8A5FE289232', 'session_key', 'ciphertext', 'com.termux', 'hostname'):
            self.assertNotIn(text, output.getvalue())
