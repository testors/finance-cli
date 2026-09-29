import gzip
import http.client
import importlib.util
import io
import json
import os
import ssl
import unittest
from unittest.mock import MagicMock, patch
from giro import bootstrap

class BootstrapTests(unittest.TestCase):

    def setUp(self):
        self.socket_patch = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        self.socket_patch.start()
        self.addCleanup(self.socket_patch.stop)
        self.connection = MagicMock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.length = None
        self.response.getheaders.return_value = [('Content-Type', 'application/json'), ('Set-Cookie', 'secret-cookie')]
        self.response.read.return_value = b'{"responseCode":"000","sessionInfo":{"userId":"private-id"},"serverCert":null}'

    def run_probe(self):
        with patch.object(bootstrap.http.client, 'HTTPSConnection', return_value=self.connection) as factory:
            result = bootstrap.probe_server_cert()
        self.factory = factory
        return result

    def test_only_fixed_post_no_cookie_device_pin_or_token_verified_tls(self):
        result = self.run_probe()
        self.assertTrue(result['app_success'])
        self.assertFalse(result['live_login_ready'])
        self.assertTrue(result['tls_endpoint_verified'])
        self.assertFalse(result['certificate_validation_performed'])
        self.factory.assert_called_once()
        self.assertEqual(self.factory.call_args.args, ('m.giro.or.kr', 443))
        context = self.factory.call_args.kwargs['context']
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.connection.connect.assert_called_once_with()
        self.connection.request.assert_called_once_with('POST', '/home/mQryServerCert.m', body=b'appVersion=4.9.5', headers={'Content-Type': 'application/x-www-form-urlencoded', 'Accept-Encoding': 'gzip', 'Connection': 'close', 'User-Agent': 'GiroCLI-bootstrap/0.1 (public-cert-probe)'})
        self.connection.close.assert_called_once_with()

    def test_no_session_cookie_response_or_error_text_leaks(self):
        result = self.run_probe()
        for marker in ('secret-cookie', 'private-id', 'sessionInfo', 'serverCert', 'Set-Cookie'):
            self.assertNotIn(marker, json.dumps(result))

    def test_missing_certificate_does_not_override_000(self):
        result = self.run_probe()
        self.assertTrue(result['app_success'])
        self.assertFalse(result['recipient']['present'])

    def test_partial_certificate_failure_does_not_override_000(self):
        self.response.read.return_value = b'{"responseCode":"000","serverCert":"secret-invalid-cert"}'
        result = self.run_probe()
        self.assertTrue(result['app_success'])
        self.assertIn(result['recipient']['analysis_status'], ('original_input_structure_error', 'backend_unmodeled'))
        self.assertNotIn('secret-invalid-cert', json.dumps(result))

    def test_gzip_and_lenient_gson_use_original_success_rules(self):
        self.response.getheaders.return_value.append(('Content-Encoding', 'gzip'))
        self.response.read.return_value = gzip.compress(b"{responseCode:'000', unknown:'private-id'}")
        self.assertTrue(self.run_probe()['app_success'])

    def test_no_redirect_retry_or_body_read_on_non2xx(self):
        for status in (302, 404, 503):
            with self.subTest(status=status):
                self.response.status = status
                result = self.run_probe()
                self.assertFalse(result['app_success'])
                self.assertEqual(result['response_code'], str(status))
                self.response.read.assert_not_called()
        self.assertEqual(self.connection.request.call_count, 3)

    def test_application_errors_and_disconnection_preserved(self):
        for code in ('999', '300', '301', '302'):
            self.response.read.return_value = json.dumps({'responseCode': code, 'errorInfo': {'errorCode': '81', 'errorMessage': 'PRIVATE ERROR'}}).encode()
            result = self.run_probe()
            self.assertFalse(result['app_success'])
            self.assertEqual(result['callback'], 'failure' if code == '999' else 'disconnected_session')
            self.assertNotIn('PRIVATE', json.dumps(result))
            self.assertNotIn('recipient', result)

    def test_non_numeric_code_is_redacted_without_altering_decision(self):
        self.response.read.return_value = b'{"responseCode":"SECRET","errorInfo":{"errorCode":"TOKEN"}}'
        result = self.run_probe()
        self.assertFalse(result['app_success'])
        self.assertIsNone(result['response_code'])
        self.assertTrue(result['response_code_redacted'])
        self.assertTrue(result['callback_code_redacted'])
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('TOKEN', json.dumps(result))

    def test_http_success_malformed_json_is_original_605(self):
        self.response.read.return_value = b'<html>SECRET</html>'
        result = self.run_probe()
        self.assertFalse(result['app_success'])
        self.assertEqual(result['response_code'], '605')
        self.assertEqual(result['origin'], 'model_decode')

    def test_tls_failure_no_post_and_no_secret_exception(self):
        self.connection.connect.side_effect = ssl.SSLCertVerificationError('PRIVATE DETAILS')
        result = self.run_probe()
        self.assertIsNone(result['app_success'])
        self.assertFalse(result['tls_endpoint_verified'])
        self.assertEqual(result['probe_error'], 'tls_verification_failed')
        self.connection.request.assert_not_called()
        self.connection.close.assert_called_once_with()
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_timeout_not_fabricated_app_failure_and_no_retry(self):
        self.connection.getresponse.side_effect = TimeoutError('PRIVATE')
        result = self.run_probe()
        self.assertIsNone(result['app_success'])
        self.assertEqual(result['probe_error'], 'probe_timeout')
        self.connection.request.assert_called_once()
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_transport_and_body_io_do_not_log_partial_data(self):
        for method in (self.connection.getresponse, self.response.read):
            with self.subTest(method=str(method)):
                method.side_effect = http.client.IncompleteRead(b'SECRET', 100)
                result = self.run_probe()
                self.assertIsNone(result['app_success'])
                self.assertEqual(result['probe_error'], 'network_or_http_io')
                self.assertNotIn('SECRET', json.dumps(result))
                method.side_effect = None

    def test_oversized_entity_is_probe_limit_not_app_failure(self):
        self.response.read.return_value = b'x' * (bootstrap.MAX_ENTITY + 1)
        result = self.run_probe()
        self.assertIsNone(result['app_success'])
        self.assertEqual(result['analysis_limit'], 'response_size_budget')

    def test_oversized_declared_length_not_read_or_invented_app_failure(self):
        self.response.length = bootstrap.MAX_ENTITY + 1
        result = self.run_probe()
        self.assertIsNone(result['app_success'])
        self.assertEqual(result['analysis_limit'], 'response_size_budget')
        self.response.read.assert_not_called()

    def test_short_content_length_not_accepted_just_because_json_is_complete(self):
        sock = MagicMock()
        sock.makefile.return_value = io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"responseCode":"000"}')
        response = http.client.HTTPResponse(sock)
        response.begin()
        self.connection.getresponse.return_value = response
        result = self.run_probe()
        self.assertIsNone(result['app_success'])
        self.assertEqual(result['probe_error'], 'network_or_http_io')

    def test_oversized_gzip_is_probe_limit_not_app_failure(self):
        self.response.getheaders.return_value.append(('Content-Encoding', 'gzip'))
        self.response.read.return_value = gzip.compress(b'x' * (bootstrap.MAX_INFLATED + 1))
        result = self.run_probe()
        self.assertIsNone(result['app_success'])
        self.assertEqual(result['analysis_limit'], 'response_size_budget')

    def test_nonstandard_gzip_header_still_honors_memory_budget(self):
        self.response.getheaders.return_value.append(('Content-Encoding', 'gzip'))
        body = bytearray(gzip.compress(b'x' * (bootstrap.MAX_INFLATED + 1)))
        (body[2], body[3]) = (0, 224)
        self.response.read.return_value = bytes(body)
        result = self.run_probe()
        self.assertIsNone(result['app_success'])
        self.assertEqual(result['analysis_limit'], 'response_size_budget')

    def test_tls_secrets_never_logged_by_environment_variable(self):
        with patch.dict(os.environ, {'SSLKEYLOGFILE': '/not-a-real-dir/no-keylog'}):
            context = bootstrap._tls_context()
        self.assertIsNone(context.keylog_filename)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_unknown_charset_is_analysis_limit_not_server_code(self):
        self.response.getheaders.return_value = [('Content-Type', 'application/json; charset=unknown-android')]
        result = self.run_probe()
        self.assertIsNone(result['app_success'])
        self.assertEqual(result['analysis_limit'], 'unmodeled_local_boundary')

    def test_plan_has_no_network_and_scope_not_login(self):
        result = bootstrap.plan()
        self.assertTrue(result['offline'])
        self.assertFalse(result['network_attempted'])
        self.assertFalse(result['live_login_ready'])

    @unittest.skipUnless(importlib.util.find_spec('cryptography') and importlib.util.find_spec('asn1crypto'), 'optional certificate packages unavailable')
    def test_public_cert_profile_is_partial_and_does_not_disclose_identity(self):
        from datetime import datetime, timezone, timedelta
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'SYNTHETIC DO NOT PRINT')])
        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(12345).not_valid_before(now - timedelta(days=2)).not_valid_after(now - timedelta(days=1)).add_extension(x509.KeyUsage(False, False, True, False, False, False, False, False, False), False).sign(private, hashes.SHA256())
        pem = cert.public_bytes(serialization.Encoding.PEM).decode('ascii')
        self.response.read.return_value = json.dumps({'responseCode': '000', 'serverCert': pem}).encode()
        result = self.run_probe()
        self.assertTrue(result['app_success'])
        self.assertFalse(result['live_login_ready'])
        self.assertEqual(result['recipient']['analysis_status'], 'partial')
        self.assertFalse(result['recipient']['public_certificate']['within_validity_at_probe_time'])
        self.assertFalse(result['recipient']['inspection']['certificate_validation_performed'])
        self.assertNotIn('SYNTHETIC', json.dumps(result))
        self.assertNotIn('BEGIN CERTIFICATE', json.dumps(result))
        self.assertNotIn('serial_number', json.dumps(result))
