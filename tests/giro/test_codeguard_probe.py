import base64
import contextlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from giro import codeguard_probe as probe
from giro.errors import GiroError
import test_cert_path as certificates

class PlanTests(unittest.TestCase):

    def test_app_base_plus_sdk_suffix_not_normalized(self):
        result = probe.plan('arm64-v8a')
        self.assertEqual(result['url'], 'https://m.giro.or.kr/CodeGuard/CodeGuard/check.jsp?CODEGUARD_CMD=101&OS=CG1&ABI=arm64-v8a&CODE_APP_INFO=IGIROMOBILE4.9.5_2091&CERT=yes')
        self.assertEqual(result['method'], 'GET')
        self.assertFalse(result['network_attempted'])
        self.assertFalse(result['token_request_submitted'])
        self.assertFalse(result['sdk_initialization_verified'])
        self.assertFalse(result['live_login_ready'])

    def test_no_arbitrary_abi_path_or_query_injection(self):
        for value in (None, 'x86', 'arm64-v8a&CODEGUARD_CMD=300', '../', '\r\nCookie: private'):
            with patch('socket.socket', side_effect=AssertionError('offline')), self.assertRaises(GiroError):
                probe.probe_cmd101(value)

    def test_cli_offline_default_and_explicit_live_only(self):
        from giro.__main__ import parser, run
        args = parser().parse_args(['auth', 'codeguard-bootstrap', '--abi', 'arm64-v8a'])
        with patch.object(probe, 'probe_cmd101', side_effect=AssertionError('no probe')):
            (result, status) = run(args)
        self.assertEqual(status, 0)
        self.assertTrue(result['offline'])
        args.live = True
        with patch.object(probe, 'probe_cmd101', return_value={'analysis_status': 'incomplete'}) as called:
            self.assertEqual(run(args), ({'analysis_status': 'incomplete'}, 0))
        called.assert_called_once_with('arm64-v8a')

class BodyTests(unittest.TestCase):

    def test_lenient_android_fields_without_giro_success_code(self):
        result = probe.inspect_body(b'{ENGINE_VERSION:7, ENGINE_MD:true, CERT:null} trailing')
        self.assertTrue(result['cmd101_fields_decoded'])
        self.assertTrue(result['engine_version_present'])
        self.assertTrue(result['engine_digest_present'])
        self.assertFalse(result['certificate_present'])
        self.assertNotIn('app_success', result)

    def test_empty_fields_are_not_an_original_rejection(self):
        result = probe.inspect_body(b'{}')
        self.assertTrue(result['cmd101_fields_decoded'])
        self.assertFalse(result['certificate_present'])
        self.assertFalse(result['engine_file_verification_performed'])

    def test_json_exception_does_not_disclose_body(self):
        result = probe.inspect_body(b'<html>PRIVATE</html>')
        self.assertEqual(result['analysis_status'], 'cmd101_json_exception')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_utf8_boundary_is_not_an_android_json_exception(self):
        result = probe.inspect_body(b'\xff')
        self.assertEqual(result['analysis_status'], 'cmd101_value_adapter_boundary')

    def test_unknown_double_rendering_remains_diagnostic(self):
        result = probe.inspect_body(b'{ENGINE_VERSION:1e99}')
        self.assertEqual(result['analysis_status'], 'cmd101_value_adapter_boundary')

    def test_unparseable_certificate_does_not_undo_cmd101_fields(self):
        result = probe.inspect_body(b'{CERT:PRIVATE}')
        self.assertTrue(result['cmd101_fields_decoded'])
        self.assertTrue(result['certificate_present'])
        self.assertEqual(result['codeguard_certificate']['analysis_status'], 'base64_returned_null')
        self.assertNotIn('PRIVATE', json.dumps(result))

    @unittest.skipUnless(importlib.util.find_spec('cryptography') and importlib.util.find_spec('asn1crypto'), 'crypto unavailable')
    def test_public_certificate_diagnostic_neither_trusts_nor_rejects_expiration(self):
        certificates.SuppliedPathTests.setUpClass()
        fixture = certificates.SuppliedPathTests()
        cert = fixture.cert(1, valid=False)
        body = json.dumps({'CERT': base64.b64encode(cert.data).decode(), 'ENGINE_MD': 'PRIVATE'}).encode()
        result = probe.inspect_body(body)
        self.assertTrue(result['cmd101_fields_decoded'])
        self.assertEqual(result['codeguard_certificate']['analysis_status'], 'local_public_certificate_parsed')
        self.assertTrue(result['codeguard_certificate']['rsa_public_key'])
        self.assertFalse(result['codeguard_certificate']['certificate_validation_performed'])
        for private in ('PRIVATE', 'synthetic', base64.b64encode(cert.data).decode()):
            self.assertNotIn(private, json.dumps(result))

class ProbeTests(unittest.TestCase):

    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('no real network'))
        guard.start()
        self.addCleanup(guard.stop)
        self.connection = MagicMock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.length = None
        self.response.getheader.return_value = None
        self.response.read.return_value = b'{ENGINE_VERSION:"PRIVATE",ENGINE_MD:"PRIVATE",CERT:""}'

    def run_probe(self):
        with patch.object(probe.http.client, 'HTTPSConnection', return_value=self.connection) as factory:
            result = probe.probe_cmd101('arm64-v8a')
        self.factory = factory
        return result

    def test_exactly_one_fixed_request_verified_tls_no_identity_or_pin(self):
        result = self.run_probe()
        self.assertTrue(result['tls_endpoint_verified'])
        self.assertTrue(result['network_attempted'])
        self.assertTrue(result['cmd101_fields_decoded'])
        self.assertFalse(result['offline'])
        self.factory.assert_called_once()
        self.assertEqual(self.factory.call_args.args, ('m.giro.or.kr', 443))
        context = self.factory.call_args.kwargs['context']
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.connection.request.assert_called_once_with('GET', '/CodeGuard/CodeGuard/check.jsp?CODEGUARD_CMD=101&OS=CG1&ABI=arm64-v8a&CODE_APP_INFO=IGIROMOBILE4.9.5_2091&CERT=yes', headers={'User-Agent': probe.USER_AGENT, 'Connection': 'close', 'Accept-Encoding': 'identity'})
        self.connection.close.assert_called_once_with()
        for key in ('pin_used', 'device_id_used', 'phone_number_used', 'environment_response_submitted', 'token_request_submitted'):
            self.assertFalse(result[key])
        self.assertNotIn('app_success', result)

    def test_no_cookie_response_or_error_text_disclosure(self):
        self.response.getheaders.return_value = [('Set-Cookie', 'PRIVATE')]
        result = self.run_probe()
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.response.getheaders.assert_not_called()

    def test_redirect_neither_followed_nor_replaced_with_single_path(self):
        for status in (301, 302, 303, 307, 308):
            self.response.status = status
            result = self.run_probe()
            self.assertEqual(result['analysis_status'], 'redirect_not_followed')
            self.response.read.assert_not_called()
        self.assertEqual(self.connection.request.call_count, 5)

    def test_non2xx_not_fabricated_as_giro_response_code(self):
        for status in (400, 401, 403, 404, 500):
            self.response.status = status
            result = self.run_probe()
            self.assertEqual(result['analysis_status'], 'http_input_stream_path_not_replayed')
            self.assertNotIn('response_code', result)
            self.response.read.assert_not_called()

    def test_get_response_status_is_not_separate_success_gate_for_body(self):
        self.response.status = 204
        self.response.read.return_value = b'{}'
        self.assertTrue(self.run_probe()['cmd101_fields_decoded'])

    def test_unknown_content_encoding_not_parsed_as_utf8(self):
        self.response.getheader.return_value = 'gzip'
        result = self.run_probe()
        self.assertEqual(result['analysis_status'], 'http_content_encoding_boundary')
        self.response.read.assert_not_called()

    def test_declared_and_actual_size_limits_do_not_create_sdk_errors(self):
        self.response.length = probe.MAX_ENTITY + 1
        self.assertEqual(self.run_probe()['analysis_status'], 'response_size_budget')
        self.response.read.assert_not_called()
        self.response.length = None
        self.response.read.return_value = b'x' * (probe.MAX_ENTITY + 1)
        result = self.run_probe()
        self.assertEqual(result['analysis_status'], 'response_size_budget')
        self.assertNotIn('sdk_error', result)

    def test_declared_short_body_is_not_valid_even_with_complete_json_prefix(self):
        sock = MagicMock()
        sock.makefile.return_value = io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n{}')
        response = http.client.HTTPResponse(sock)
        response.begin()
        self.connection.getresponse.return_value = response
        result = self.run_probe()
        self.assertEqual(result['probe_error'], 'network_or_http_io')

    def test_tls_failure_stops_before_request_without_details(self):
        self.connection.connect.side_effect = ssl.SSLCertVerificationError('PRIVATE')
        result = self.run_probe()
        self.assertEqual(result['probe_error'], 'tls_verification_failed')
        self.assertFalse(result['tls_endpoint_verified'])
        self.connection.request.assert_not_called()
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_timeout_no_retry_and_no_python_exception_in_wire(self):
        self.connection.getresponse.side_effect = TimeoutError('PRIVATE')
        result = self.run_probe()
        self.assertEqual(result['probe_error'], 'probe_timeout')
        self.connection.request.assert_called_once()
        self.connection.close.assert_called_once()
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_tls_context_failure_is_not_network_attempt(self):
        with patch.object(probe, '_tls_context', side_effect=OSError('PRIVATE')):
            result = self.run_probe()
        self.assertFalse(result['network_attempted'])
        self.connection.connect.assert_not_called()
        self.assertEqual(result['incomplete_stage'], 'tls_context')

    def test_sslkeylog_environment_never_enables_key_logging(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'keys'
            with patch.dict(os.environ, {'SSLKEYLOGFILE': str(path)}):
                self.run_probe()
            self.assertFalse(path.exists())
            self.assertIsNone(self.factory.call_args.kwargs['context'].keylog_filename)
