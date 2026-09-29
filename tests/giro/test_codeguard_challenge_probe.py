import base64
import http.client
import importlib.util
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit
from giro import codeguard_challenge_probe as probe
from giro import codeguard_probe as transport
from giro.codeguard_codec import java_seed_encrypt
from giro.codeguard_exchange import UpdaterState, WireRequest
from giro.codeguard_platform import key_bytes_from_seed
from giro.errors import GiroError
import test_cert_path as certificates
CRYPTO = importlib.util.find_spec('cryptography') and importlib.util.find_spec('asn1crypto')

class PlanTests(unittest.TestCase):

    def test_plan_offline_and_no_sensitive_query_template(self):
        with patch('socket.socket', side_effect=AssertionError('offline')):
            result = probe.plan('arm64-v8a')
        self.assertEqual(result['commands'], [101, 200])
        self.assertEqual(result['maximum_requests'], 2)
        self.assertEqual(result['requests_attempted'], 0)
        self.assertEqual(result['endpoint'], 'https://m.giro.or.kr/CodeGuard/CodeGuard/check.jsp')
        self.assertNotIn('KEY=', json.dumps(result))
        self.assertFalse(result['network_attempted'])
        self.assertFalse(result['live_login_ready'])
        self.assertFalse(result['server_token_generated'])

    def test_cli_explicit_live_separate_from_cmd101(self):
        from giro.__main__ import parser, run
        args = parser().parse_args(['auth', 'codeguard-challenge', '--abi', 'arm64-v8a'])
        with patch.object(probe, 'probe_challenge', side_effect=AssertionError('no network')):
            (result, code) = run(args)
        self.assertTrue(result['offline'])
        self.assertEqual(code, 0)
        args.live = True
        with patch.object(probe, 'probe_challenge', return_value={'analysis_status': 'incomplete'}) as call:
            self.assertEqual(run(args), ({'analysis_status': 'incomplete'}, 0))
        call.assert_called_once_with('arm64-v8a')

    def test_bad_abi_rejected_before_clock_key_or_network(self):
        with patch.object(probe, '_wrap_new_key', side_effect=AssertionError('no key')), patch('socket.socket', side_effect=AssertionError('offline')):
            for abi in (None, 'x86', 'arm64-v8a&CODEGUARD_CMD=300', '\r\nCookie:x'):
                with self.assertRaises(GiroError):
                    probe.probe_challenge(abi)

    def test_transport_cannot_send_other_commands_or_endpoints(self):
        urls = ('http://m.giro.or.kr/CodeGuard/CodeGuard/check.jsp?CODEGUARD_CMD=200&x=y', 'https://elsewhere.test/CodeGuard/CodeGuard/check.jsp?CODEGUARD_CMD=200&x=y', 'https://m.giro.or.kr/CodeGuard/check.jsp?CODEGUARD_CMD=200&x=y', 'https://m.giro.or.kr/CodeGuard/CodeGuard/check.jsp?CODEGUARD_CMD=300&x=y', 'https://m.giro.or.kr/CodeGuard/CodeGuard/check.jsp?CODEGUARD_CMD=200&x=y#extra')
        with patch('socket.socket', side_effect=AssertionError('offline')):
            for url in urls:
                with self.assertRaises(GiroError):
                    transport._fetch_request(WireRequest(200, 'GET', url, (), None), {})
            url = probe.plan('arm64-v8a')['endpoint'] + '?CODEGUARD_CMD=300&x=y'
            with self.assertRaises(GiroError):
                transport._fetch_request(WireRequest(300, 'GET', url, (), None), {})

class BodyTests(unittest.TestCase):

    def test_empty_fields_do_not_reject_original_challenge(self):
        result = probe.inspect_challenge_body(b'{}', UpdaterState())
        self.assertTrue(result['cmd200_body_processed'])
        self.assertFalse(result['challenge_present'])
        self.assertTrue(result['mainservice_prefix_guard_continues'])
        self.assertNotIn('app_success', result)

    def test_android_primitives_not_python_stringification(self):
        result = probe.inspect_challenge_body(b'{CODE_CHALLENGE:7,CODE_RESPONSE2_VER:true} tail', UpdaterState())
        self.assertTrue(result['cmd200_body_processed'])
        self.assertTrue(result['challenge_present'])
        self.assertFalse(result['is_mix'])

    def test_prefix_error_not_exposed_or_reinterpreted_as_empty(self):
        result = probe.inspect_challenge_body(b'{CODE_CHALLENGE:"E101_NET_ERROR_PRIVATE"}', UpdaterState())
        self.assertTrue(result['cmd200_body_processed'])
        self.assertFalse(result['mainservice_prefix_guard_continues'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_split_drops_trailing_empty_parts(self):
        result = probe.inspect_challenge_body(b'{CODE_CHALLENGE:"a::b::::"}', UpdaterState())
        self.assertEqual(result['challenge_part_count'], 2)

    def test_rcl_exception_precedes_mix_and_hash_conversion(self):
        state = UpdaterState()
        result = probe.inspect_challenge_body(b'{CODE_RCL:"A",CODE_RESPONSE2_VER:"isMix",HASH_KEY:1e99}', state)
        self.assertEqual(result['analysis_status'], 'cmd200_original_field_exception')
        self.assertEqual(result['field_stage'], 'rcl_null_byte_array')
        self.assertFalse(state.is_mix)

    def test_hash_conversion_boundary_preserves_earlier_rcl_and_mix(self):
        state = UpdaterState()
        result = probe.inspect_challenge_body(b'{CODE_RCL:"cmNs",CODE_RESPONSE2_VER:"isMix-isSplit",HASH_KEY:1e99}', state)
        self.assertEqual(result['analysis_status'], 'cmd200_value_adapter_boundary')
        self.assertEqual(state.rcl, 'rcl')
        self.assertTrue(result['is_mix'])
        self.assertTrue(result['is_split'])

    def test_hash_separator_error_is_original_stage_not_probe_gate(self):
        result = probe.inspect_challenge_body(b'{CODE_RESPONSE2_VER:"isMix",HASH_KEY:"PRIVATE"}', UpdaterState())
        self.assertEqual(result['field_stage'], 'hash_key_substring')
        self.assertTrue(result['is_mix'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_bad_hash_cipher_returns_empty_without_rejecting_challenge(self):
        result = probe.inspect_challenge_body(b'{CODE_CHALLENGE:"a::b",HASH_KEY:"AAAA::AAAA"}', UpdaterState(key=b'k' * 16))
        self.assertTrue(result['cmd200_body_processed'])
        self.assertFalse(result['hash_key_present'])

    def test_absent_fields_keep_state_and_sticky_flags(self):
        state = UpdaterState(rcl='PRIVATE', hash_key='PRIVATE', is_mix=True, is_split=True)
        result = probe.inspect_challenge_body(b'{CODE_RESPONSE2_VER:"",HASH_KEY:null}', state)
        self.assertTrue(result['cmd200_body_processed'])
        for name in ('rcl_present', 'hash_key_present', 'is_mix', 'is_split'):
            self.assertTrue(result[name])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_invalid_json_and_utf8_distinct_without_raw_diagnostics(self):
        for (data, status) in ((b'<PRIVATE>', 'cmd200_json_exception'), (b'\xffPRIVATE', 'cmd200_value_adapter_boundary')):
            result = probe.inspect_challenge_body(data, UpdaterState())
            self.assertEqual(result['analysis_status'], status)
            self.assertNotIn('PRIVATE', json.dumps(result))

    def test_local_crypto_failure_not_forged_as_original_empty_hash(self):
        with patch('giro.codeguard_exchange.java_seed_decrypt', side_effect=GiroError('PRIVATE')):
            result = probe.inspect_challenge_body(b'{HASH_KEY:"AAAA::AAAA"}', UpdaterState(key=b'k' * 16))
        self.assertEqual(result['analysis_status'], 'cmd200_local_crypto_adapter_boundary')
        self.assertFalse(result['cmd200_body_processed'])
        self.assertNotIn('PRIVATE', json.dumps(result))

@unittest.skipUnless(CRYPTO, 'optional crypto unavailable')
class ExchangeTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        certificates.SuppliedPathTests.setUpClass()
        fixture = certificates.SuppliedPathTests()
        cls.cert = base64.b64encode(fixture.cert(1, valid=False).data).decode()
        cls.private = fixture.keys[1]

    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('no real network'))
        guard.start()
        self.addCleanup(guard.stop)
        self.connections = [MagicMock(), MagicMock()]
        for connection in self.connections:
            response = connection.getresponse.return_value
            response.status = 200
            response.length = None
            response.getheader.return_value = None
            response.getheaders.return_value = [('Set-Cookie', 'PRIVATE-COOKIE'), ('Set-Cookie', 'PRIVATE-COOKIE2')]
        (self.first, self.second) = [c.getresponse.return_value for c in self.connections]
        self.first.read.return_value = json.dumps({'CERT': self.cert, 'ENGINE_VERSION': 'PRIVATE-VERSION'}).encode()
        self.second.read.return_value = b'{CODE_CHALLENGE:"PRIVATE-CHALLENGE::PRIVATE-RULE"}'

    def run_probe(self):
        with patch.object(transport.http.client, 'HTTPSConnection', side_effect=self.connections) as factory, patch.object(probe.time, 'time_ns', return_value=1234567890123):
            result = probe.probe_challenge('arm64-v8a')
        self.factory = factory
        return result

    def test_exact_two_requests_rsa_unwrap_and_hash_key_response(self):
        from cryptography.hazmat.primitives.asymmetric import padding

        def respond_to_key(method, path, *, headers):
            query = parse_qs(urlsplit(path).query)
            self.assertEqual(set(query), {'CODEGUARD_CMD', 'CODE_APP_INFO', 'ABI', 'KEY', 'isMix'})
            self.assertEqual(query['CODEGUARD_CMD'], ['200'])
            self.assertEqual(query['CODE_APP_INFO'], ['IGIROMOBILE4.9.5_2091'])
            self.assertEqual(query['isMix'], ['false'])
            self.assertNotIn('Cookie', headers)
            self.assertEqual(headers['Content-Type'], 'application/x-www-form-urlencoded')
            key = self.private.decrypt(base64.b64decode(query['KEY'][0]), padding.PKCS1v15())
            self.assertEqual(key, key_bytes_from_seed(1234567))
            self.wrapped = query['KEY'][0]
            iv = b'i' * 16
            encrypted = java_seed_encrypt(b'PRIVATE-HASH-KEY', key, iv)
            self.second.read.return_value = json.dumps({'CODE_CHALLENGE': 'PRIVATE-CHALLENGE::PRIVATE-RULE', 'CODE_RCL': base64.b64encode(b'PRIVATE-RCL').decode(), 'CODE_RESPONSE2_VER': 'isMix-isSplit', 'HASH_KEY': base64.b64encode(encrypted).decode() + '::' + base64.b64encode(iv).decode()}).encode()
        self.connections[1].request.side_effect = respond_to_key
        result = self.run_probe()
        self.assertEqual(result['analysis_status'], 'cmd200_body_processed')
        self.assertEqual(result['requests_attempted'], 2)
        self.assertEqual(self.factory.call_count, 2)
        for call in self.factory.call_args_list:
            self.assertEqual(call.args, ('m.giro.or.kr', 443))
            context = call.kwargs['context']
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
        for connection in self.connections:
            connection.request.assert_called_once()
            connection.close.assert_called_once()
        second = result['requests'][1]
        self.assertTrue(second['hash_key_present'])
        self.assertTrue(second['rcl_present'])
        self.assertTrue(second['is_mix'])
        self.assertEqual(second['set_cookie_header_count'], 2)
        self.assertFalse(second['cookie_processing_replayed'])
        for value in ('PRIVATE', self.cert, self.wrapped, key_bytes_from_seed(1234567).hex()):
            self.assertNotIn(value, json.dumps(result))
        for field in ('pin_used', 'device_id_used', 'environment_response_submitted', 'token_request_submitted', 'server_token_generated', 'live_login_ready', 'secrets_persisted'):
            self.assertFalse(result[field])

    def test_cmd101_redirect_stops_before_key_and_second_request(self):
        self.first.status = 302
        with patch.object(probe, '_wrap_new_key', side_effect=AssertionError('no key')):
            result = self.run_probe()
        self.assertEqual(result['requests_attempted'], 1)
        self.assertEqual(result['analysis_status'], 'cmd101_transport_incomplete')
        self.assertEqual(self.factory.call_count, 1)

    def test_cmd101_json_failure_stops_before_key_and_second_request(self):
        self.first.read.return_value = b'PRIVATE'
        with patch.object(probe, '_wrap_new_key', side_effect=AssertionError('no key')):
            result = self.run_probe()
        self.assertEqual(result['analysis_status'], 'cmd101_fields_unavailable')
        self.assertEqual(self.factory.call_count, 1)

    def test_cmd101_empty_cert_not_forged_as_sdk_failure(self):
        self.first.read.return_value = b'{}'
        result = self.run_probe()
        self.assertTrue(result['requests'][0]['cmd101_fields_decoded'])
        self.assertEqual(result['analysis_status'], 'certificate_unavailable_for_probe')
        self.assertEqual(result['requests_attempted'], 1)
        self.assertNotIn('sdk_error', result)

    def test_local_rsa_backend_exception_no_secret_and_no_empty_key_request(self):
        with patch.object(probe, '_wrap_new_key', side_effect=ValueError('PRIVATE')):
            result = self.run_probe()
        self.assertEqual(result['analysis_status'], 'local_key_wrap_adapter_boundary')
        self.assertEqual(result['requests_attempted'], 1)
        self.assertEqual(self.factory.call_count, 1)
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_key_assigned_before_certificate_parse_failure(self):
        state = UpdaterState()
        with patch.object(probe.time, 'time_ns', return_value=123000000), self.assertRaises(ValueError):
            probe._wrap_new_key('AAAA', state)
        self.assertEqual(state.key, key_bytes_from_seed(123))

    def test_cmd200_redirect_stops_no_third_request(self):
        self.second.status = 307
        result = self.run_probe()
        self.assertEqual(result['requests_attempted'], 2)
        self.assertEqual(result['analysis_status'], 'cmd200_transport_incomplete')
        self.assertEqual(result['requests'][1]['analysis_status'], 'redirect_not_followed')
        self.second.read.assert_not_called()

    def test_cmd200_timeout_never_restarts_exchange(self):
        self.connections[1].getresponse.side_effect = TimeoutError('PRIVATE')
        result = self.run_probe()
        self.assertEqual(result['requests_attempted'], 2)
        self.assertEqual(self.factory.call_count, 2)
        self.assertEqual(result['requests'][1]['probe_error'], 'probe_timeout')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_second_tls_failure_no_cmd200_request(self):
        self.connections[1].connect.side_effect = ssl.SSLCertVerificationError('PRIVATE')
        result = self.run_probe()
        self.assertEqual(result['requests_attempted'], 1)
        self.assertTrue(result['network_attempted'])
        self.connections[1].request.assert_not_called()
        self.assertFalse(result['requests'][1]['tls_endpoint_verified'])

    def test_tls_context_failure_no_network_or_key(self):
        with patch.object(transport, '_tls_context', side_effect=OSError('PRIVATE')):
            result = self.run_probe()
        self.assertFalse(result['network_attempted'])
        self.assertEqual(result['requests_attempted'], 0)
        self.factory.assert_not_called()

    def test_cmd200_size_budget_and_encoding_are_diagnostics(self):
        for large in (False, True):
            self.second.getheader.return_value = None if large else 'gzip'
            self.second.length = transport.MAX_ENTITY + 1 if large else None
            result = self.run_probe()
            self.assertEqual(result['requests'][1]['analysis_status'], 'response_size_budget' if large else 'http_content_encoding_boundary')
            self.assertNotIn('response_code', result)
            self.second.read.assert_not_called()

    def test_truncated_cmd200_does_not_pass_complete_json_prefix(self):
        self.second.read.side_effect = http.client.IncompleteRead(b'PRIVATE', 100)
        result = self.run_probe()
        self.assertEqual(result['requests'][1]['probe_error'], 'network_or_http_io')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_sslkeylog_ignored_for_both_connections(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'keys'
            with patch.dict(os.environ, {'SSLKEYLOGFILE': str(path)}):
                self.run_probe()
            self.assertFalse(path.exists())
            for call in self.factory.call_args_list:
                self.assertIsNone(call.kwargs['context'].keylog_filename)
