from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import tempfile
from threading import Thread
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

from giro.cert_selectors import MaterialStore
from giro.client import AuthenticatedClient
from giro.crypto import PIN_IV, _cbc, decrypt_body, decrypt_text, encrypt_text
from giro.errors import GiroError
from giro.login import PinLogin, ProtectionRuntime, RecipientContext, _token_response
from giro.payment_flow import PaymentJournal, PaymentWorkflow
from giro.protocol import ENDPOINTS
import test_cert_acquisition as certificates
from test_payment_flow import BILL, DETAIL, ACCOUNTS


class SyntheticProtection(ProtectionRuntime):
    def __init__(self, steps):
        self.steps = steps
        self.values = ['DISCARDED SYNTHETIC CALLBACK', '{"CODE_RESPONSE":"SYNTHETIC-TOKEN"}']

    def initialize(self):
        self.steps.append('protection.initialize')

    def token(self):
        self.steps.append('codeguard.token')
        return self.values.pop(0)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        from asn1crypto import cms
        from cryptography.hazmat.primitives.asymmetric import padding
        form = parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode(), keep_blank_values=True)
        name = next(name for name, ep in ENDPOINTS.items() if ep.path == self.path)
        self.server.steps.append(name)
        if name == 'auth.server-cert':
            fields = form
        elif name in ('auth.device-status', 'auth.datetime') and not self.server.logged_in:
            envelope = cms.ContentInfo.load(bytes.fromhex(form['encryptedData'][0]))['content']
            wrapped = envelope['recipient_infos'][0].chosen['encrypted_key'].native
            self.server.key = self.server.private.decrypt(wrapped, padding.PKCS1v15())
            self.server.keys.append(self.server.key)
            fields = parse_qs(decrypt_body(envelope['encrypted_content_info']['encrypted_content'].native,
                                          self.server.key).decode('euc-kr'), keep_blank_values=True)
        else:
            fields = parse_qs(decrypt_text(form['encryptedData'][0], self.server.key), keep_blank_values=True)
        self.server.calls.append((name, fields, dict(self.headers), form))
        status, document = self.server.responses[name]
        if document == 'disconnect':
            self.close_connection = True
            return
        if name == 'auth.pin' and document.get('responseCode') == '000':
            self.server.logged_in = True
        raw = json.dumps(document, ensure_ascii=False)
        payload = raw.encode() if name == 'auth.server-cert' else encrypt_text(raw, self.server.key).hex().encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(payload)))
        if name != 'auth.server-cert':
            self.send_header('Mgiro-App-Encrypt', '1')
        cookie = 'CERT-ISOLATED' if name == 'auth.server-cert' else 'BUSINESS-COOKIE'
        self.send_header('Set-Cookie', 'SESSION=' + cookie + '; Path=/')
        self.send_header('Location', 'https://never-follow.invalid/')
        self.end_headers()
        self.wfile.write(payload)


class LoginTests(unittest.TestCase):
    cert = certificates.AcquisitionTests.cert
    crl = certificates.AcquisitionTests.crl
    target = certificates.AcquisitionTests.target

    @classmethod
    def setUpClass(cls):
        certificates.AcquisitionTests.setUpClass.__func__(cls)
        cls.at = datetime.now(timezone.utc)
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        self.server.calls, self.server.steps, self.server.keys = [], [], []
        self.server.key, self.server.logged_in = None, False
        self.server.private = self.keys[2]
        pem = x509.load_der_x509_certificate(self.target().data).public_bytes(serialization.Encoding.PEM).decode()
        self.server.responses = {
            'auth.server-cert': (200, {'responseCode': '000', 'serverCert': pem}),
            'auth.device-status': (200, {'responseCode': '000', 'deviceRegYn': 'Y', 'pinLoginYn': 'Y'}),
            'auth.datetime': (200, {'responseCode': '000', 'currentDateTime': '20261001120000'}),
            'auth.pin': (200, {'responseCode': '000', 'sessionInfo': {'payer': '합성납부자'}}),
            'national.list': (200, {'responseCode': '000', 'billList': [BILL]}),
            'national.detail': (200, deepcopy(DETAIL)),
            'accounts.payable': (200, deepcopy(ACCOUNTS)),
            'national.payment': (200, {'responseCode': '000', 'receiptItem': []}),
        }
        self.protection = SyntheticProtection(self.server.steps)
        self.context = RecipientContext((self.cert(0),),
            (MaterialStore((self.cert(1),), (self.crl(0), self.crl(1))),), 'ko')
        self.login = PinLogin(device_id='SYNTHETIC-DEVICE', user_agent='SYNTHETIC-CLIENT',
                              recipient=self.context, protection=self.protection)
        self.pin = Mock(return_value='012345')
        def loopback(host, *, timeout, context):
            self.assertEqual(host, 'm.giro.or.kr')
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertIsNone(context.keylog_filename)
            return http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=timeout)
        # Do not patch the shared stdlib module: the protection peer uses real TLS.
        patch('giro.client.http', SimpleNamespace(client=SimpleNamespace(
            HTTPSConnection=loopback, HTTPException=http.client.HTTPException))).start()
        self.addCleanup(patch.stopall)

    def run_login(self):
        return self.login.login(pin_provider=self.pin, send=True)

    def connect_python_protection(self, *, platform_transform=None):
        import test_codeguard_runtime as runtime_support
        # Each integration test owns a separate verified TLS CodeGuard peer.
        # Business traffic stays on the existing loopback CMS/SEED fixture.
        class Peer(runtime_support.RuntimeTests):
            pass
        Peer.setUpClass()
        self.addCleanup(Peer.tearDownClass)
        peer = Peer()
        peer.setUp()
        self.addCleanup(peer.tearDown)
        peer.token_fields = lambda index: {'CODE_TOKEN': json.dumps({
            'CODE_RESPONSE': 'SYNTHETIC-PYTHON-TOKEN-%d' % index})}
        runtime = peer.runtime(platform_transform=platform_transform)
        self.login.protection = runtime
        return peer, runtime

    def test_python_runtime_two_tokens_connect_to_pin_and_query(self):
        peer, runtime = self.connect_python_protection()
        result = self.run_login()
        self.assertTrue(result.report()['session_ready'], result.report())
        self.assertEqual([call[0] for call in peer.server.calls], [101, 200, 300, 200, 300])
        self.assertEqual(self.server.steps, ['auth.server-cert', 'auth.device-status',
            'auth.datetime', 'auth.pin'])
        posts = [call for call in peer.server.calls if call[0] == 300]
        self.assertEqual([dict(call[3])['Cookie'] for call in posts], ['exchange=1', 'exchange=2'])
        self.assertEqual(len(peer.keys), 2)
        self.assertNotEqual(*peer.keys)
        _, fields, headers, form = self.server.calls[-1]
        self.assertEqual(fields['CODE_RESPONSE'], ['SYNTHETIC-PYTHON-TOKEN-2'])
        self.assertEqual(json.loads(form['CODE_RESPONSE_TOKEN'][0]),
            {'CODE_RESPONSE': 'SYNTHETIC-PYTHON-TOKEN-2'})
        self.assertEqual(headers['Cookie'], 'SESSION=BUSINESS-COOKIE')
        self.assertEqual(result.session.key, self.server.keys[-1])
        self.assertEqual(runtime.events.count('manager_token_listener'), 2)
        self.assertNotIn('SYNTHETIC-PYTHON-TOKEN', repr(runtime.events) + repr(self.login.events))
        client = AuthenticatedClient(result.session)
        response = client.query('national.list', {'pageNo': '1'}, send=True)
        self.assertTrue(response.app_success)
        self.assertEqual([call[0] for call in peer.server.calls], [101, 200, 300, 200, 300])
        self.assertEqual(self.server.steps.count('auth.pin'), 1)
        with self.assertRaises(GiroError):
            self.run_login()

    def test_python_runtime_second_token_boundary_never_submits_pin(self):
        peer, runtime = self.connect_python_protection()
        challenge = peer.challenge_fields
        def fields(index):
            value = challenge(index)
            if index == 2:
                parts = value['CODE_CHALLENGE'].split('::')
                parts[2] = 'YmFk'  # Explicitly malformed synthetic certificate.
                value['CODE_CHALLENGE'] = '::'.join(parts)
            return value
        peer.challenge_fields = fields
        result = self.run_login()
        self.assertEqual(result.stage, 'codeguard.query')
        self.assertEqual(result.report()['login_service_decision'], 'unobserved')
        self.assertFalse(result.report()['session_ready'])
        self.assertEqual(result.processing_issues, ['stage_processing_incomplete'])
        self.assertEqual([call[0] for call in peer.server.calls], [101, 200, 300, 200])
        self.assertEqual(runtime.events.count('manager_token_listener'), 1)
        self.assertNotIn('auth.pin', self.server.steps)
        with self.assertRaises(GiroError):
            self.run_login()

    def test_login_query_and_payment_keep_last_key_and_business_cookies(self):
        attempt = self.run_login()
        self.assertTrue(attempt.report()['session_ready'], attempt.report())
        self.assertTrue(attempt.report()['login_app_success'])
        self.assertEqual(self.server.steps, ['auth.server-cert', 'protection.initialize',
            'auth.device-status', 'auth.datetime', 'codeguard.token', 'codeguard.token', 'auth.pin'])
        self.assertEqual(len(self.server.keys), 2)
        self.assertNotEqual(*self.server.keys)
        self.assertEqual(attempt.session.key, self.server.keys[-1])
        self.assertIs(attempt.session.cookies, self.login.cookies)
        for name, fields, headers, form in self.server.calls:
            self.assertEqual(fields['deviceId'], ['SYNTHETIC-DEVICE'])
            if name in ('auth.server-cert', 'auth.device-status'):
                self.assertNotIn('Cookie', headers)
            else:
                self.assertEqual(headers['Cookie'], 'SESSION=BUSINESS-COOKIE')
        _, fields, _, form = self.server.calls[-1]
        self.assertEqual(fields['CODE_RESPONSE'], ['SYNTHETIC-TOKEN'])
        self.assertEqual(form['CODE_RESPONSE_TOKEN'], ['{"CODE_RESPONSE":"SYNTHETIC-TOKEN"}'])
        for index, position in enumerate((10, 1, 2, 3, 4, 5)):
            cipher = bytes.fromhex(fields['pin'][0])[index*16:(index+1)*16]
            self.assertEqual(_cbc(attempt.session.key, PIN_IV, cipher, decrypt=True),
                             bytes((5, position)) + bytes(14))
        client = AuthenticatedClient(attempt.session)
        self.assertTrue(client.query('national.list', {}, send=True).app_success)
        with tempfile.TemporaryDirectory() as directory:
            workflow = PaymentWorkflow(client, journal=PaymentJournal(Path(directory).resolve()))
            draft = workflow.prepare(BILL, account_selector=lambda _: 1, send=True)
            result = workflow.pay(draft['draft_id'], account_password_provider=lambda: '1234', send=True)
        self.assertTrue(result['app_success'])
        self.assertEqual(len(self.server.keys), 2)  # Post-login datetime is ENCRYPT.
        self.assertEqual(self.server.steps.count('auth.server-cert'), 1)
        for secret in ('SYNTHETIC', '012345', 'BUSINESS-COOKIE', 'BEGIN CERTIFICATE'):
            self.assertNotIn(secret, json.dumps(self.login.events) + json.dumps(attempt.report()) + repr(attempt))

    def test_send_required_before_any_request_or_pin(self):
        with self.assertRaises(GiroError):
            self.login.login(pin_provider=self.pin)
        self.assertEqual(self.server.steps, [])
        self.pin.assert_not_called()
        self.assertFalse(self.login._used)

    def test_observed_empty_device_id_is_preserved_through_login_and_query(self):
        self.login = PinLogin(device_id='', user_agent='SYNTHETIC-CLIENT',
                              recipient=self.context, protection=self.protection)
        result = self.run_login()
        self.assertTrue(result.report()['session_ready'], result.report())
        self.assertEqual(result.session.device_id, '')
        self.assertTrue(AuthenticatedClient(result.session).query('national.list', {}, send=True).app_success)
        for name, fields, _, _ in self.server.calls:
            self.assertEqual(fields['deviceId'], [''])
            if name in ('auth.device-status', 'auth.pin'):
                self.assertEqual(fields['deviceUniqNo'], [''])

    def test_missing_device_observation_is_not_an_empty_identity(self):
        for value in (None, False, 0, object()):
            with self.subTest(type=type(value).__name__), self.assertRaises(GiroError):
                PinLogin(device_id=value, user_agent='SYNTHETIC-CLIENT',
                         recipient=self.context, protection=self.protection)
        self.assertEqual(self.server.steps, [])

    def test_recipient_rules_run_before_protection_device_or_pin(self):
        self.context.stores = (MaterialStore((self.cert(1),), (self.crl(0), self.crl(1, revoked=True))),)
        result = self.run_login()
        self.assertEqual(result.stage, 'recipient.validate')
        self.assertIn('recipient_validation_failed', result.processing_issues)
        self.assertTrue(result.response.app_success)  # Certificate JSON success survives.
        self.assertEqual(self.server.steps, ['auth.server-cert'])
        self.pin.assert_not_called()

    def test_missing_crl_is_unresolved_without_network_fallback(self):
        self.context.stores = (MaterialStore((self.cert(1),), (self.crl(0),)),)
        result = self.run_login()
        self.assertEqual(result.stage, 'recipient.validate')
        self.assertIn('recipient_validation_incomplete', result.processing_issues)
        self.assertEqual(self.server.steps, ['auth.server-cert'])
        self.pin.assert_not_called()

    def test_protection_initialization_error_stops_before_device_or_pin(self):
        self.protection.initialize = Mock(side_effect=RuntimeError('PRIVATE'))
        result = self.run_login()
        self.assertEqual(result.stage, 'protection.initialize')
        self.assertIsNone(result.report()['login_app_success'])
        self.pin.assert_not_called()
        self.assertEqual(self.server.steps, ['auth.server-cert'])
        self.assertNotIn('PRIVATE', json.dumps(result.report()))

    def test_prelogin_response_failure_stops_before_pin(self):
        self.server.responses['auth.datetime'] = (200, {'responseCode': '999'})
        result = self.run_login()
        self.assertEqual(result.stage, 'auth.datetime')
        self.assertFalse(result.response.app_success)
        self.assertIsNone(result.report()['login_app_success'])
        self.pin.assert_not_called()
        self.assertNotIn('codeguard.token', self.server.steps)

    def test_unregistered_device_routes_before_datetime_pin_or_token(self):
        for fields in ({'deviceRegYn': 'N'}, {'deviceRegYn': None},
                       {'deviceRegYn': 'y'}, {'deviceRegYn': True}, {}):
            with self.subTest(fields=fields):
                self.server.steps.clear()
                self.login = PinLogin(device_id='SYNTHETIC-DEVICE', user_agent='SYNTHETIC-CLIENT',
                                      recipient=self.context, protection=self.protection)
                self.server.responses['auth.device-status'] = (200, {'responseCode': '000', **fields})
                result = self.run_login()
                self.assertTrue(result.response.app_success)
                self.assertEqual(result.stage, 'device.registration')
                self.assertEqual(result.report()['next_action'], 'sms_identity_verification')
                self.assertIsNone(result.report()['login_app_success'])
                self.assertEqual(result.report()['login_service_decision'], 'unobserved')
                self.assertEqual(result.processing_issues, [])
                self.assertEqual(self.server.steps, ['auth.server-cert', 'protection.initialize',
                                                     'auth.device-status'])
                self.pin.assert_not_called()
                with self.assertRaises(GiroError):
                    self.run_login()

    def test_failed_device_query_is_not_registration_navigation(self):
        self.server.responses['auth.device-status'] = (200, {'responseCode': '999', 'deviceRegYn': 'N'})
        result = self.run_login()
        self.assertEqual(result.stage, 'auth.device-status')
        self.assertFalse(result.response.app_success)
        self.assertEqual(result.report()['last_response_service_decision'], 'failure')
        self.assertEqual(result.report()['login_service_decision'], 'unobserved')
        self.assertIsNone(result.report()['next_action'])
        self.pin.assert_not_called()

    def test_explicit_pin_route_has_no_extra_pin_flag_gate(self):
        self.server.responses['auth.device-status'] = (200, {'responseCode': '000',
            'deviceRegYn': 'Y', 'pinLoginYn': 'N', 'defaultLoginType': '0'})
        result = self.run_login()
        self.assertTrue(result.report()['session_ready'])
        self.assertIsNone(result.report()['next_action'])

    def test_success_without_session_preserves_success_but_cannot_pay(self):
        self.server.responses['auth.pin'] = (200, {'responseCode': '000'})
        result = self.run_login()
        self.assertTrue(result.report()['login_app_success'])
        self.assertFalse(result.report()['session_ready'])
        self.assertIn('login_state_incomplete', result.processing_issues)

    def test_login_rejection_and_expiry_remain_service_decisions(self):
        self.server.responses['auth.pin'] = (200, {'responseCode': '301'})
        result = self.run_login()
        self.assertFalse(result.report()['login_app_success'])
        self.assertTrue(result.response.clear_session)
        self.assertIsNone(result.session)

    def test_lost_response_is_unobserved_and_never_retried(self):
        self.server.responses['auth.pin'] = (200, 'disconnect')
        result = self.run_login()
        self.assertFalse(result.report()['login_app_success'])
        self.assertEqual(result.report()['login_service_decision'], 'unobserved')
        self.assertEqual(result.report()['last_response_service_decision'], 'unobserved')
        with self.assertRaises(GiroError):
            self.run_login()
        self.assertEqual(self.server.steps.count('auth.pin'), 1)

    def test_bad_second_callback_stops_before_login_request(self):
        self.protection.values[-1] = '{"CODE_RESPONSE":"x","CODE_RESPONSE":"y"}'
        result = self.run_login()
        self.assertIsNone(result.report()['login_app_success'])
        self.assertIn('stage_processing_incomplete', result.processing_issues)
        self.assertNotIn('auth.pin', self.server.steps)

    def test_null_callback_adds_no_synthetic_token(self):
        self.protection.values[-1] = None
        self.assertTrue(self.run_login().report()['session_ready'])
        _, fields, _, form = self.server.calls[-1]
        self.assertNotIn('CODE_RESPONSE', fields)
        self.assertNotIn('CODE_RESPONSE_TOKEN', form)

    def test_cookie_failure_does_not_erase_login_success(self):
        extract = self.login.cookies.extract_cookies
        def broken(wire, request):
            if request.full_url.endswith(ENDPOINTS['auth.pin'].path):
                raise OSError('PRIVATE-COOKIE')
            return extract(wire, request)
        self.login.cookies.extract_cookies = broken
        result = self.run_login()
        self.assertTrue(result.report()['login_app_success'])
        self.assertFalse(result.report()['session_ready'])
        self.assertIn('cookie_update_failed', result.processing_issues)

    def test_diagnostic_write_failure_does_not_erase_success(self):
        self.login.events = Mock()
        self.login.events.append.side_effect = OSError('PRIVATE-LOG')
        result = self.run_login()
        self.assertTrue(result.report()['session_ready'])
        self.assertIn('observation_failed', result.processing_issues)

    def test_concurrent_attempts_cannot_duplicate_login(self):
        def run():
            try:
                return self.run_login().report()['session_ready']
            except GiroError:
                return 'used'
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(lambda _: run(), range(2)))
        self.assertCountEqual(result, [True, 'used'])
        self.assertEqual(self.server.steps.count('auth.pin'), 1)

    def test_tls_key_logging_environment_is_not_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'keys.log'
            with patch.dict('os.environ', {'SSLKEYLOGFILE': str(path)}):
                self.assertTrue(self.run_login().report()['session_ready'])
            self.assertFalse(path.exists())


class TokenMapTests(unittest.TestCase):
    def test_all_map_values_use_string_adapter_and_duplicate_rules(self):
        self.assertEqual(_token_response('{"CODE_RESPONSE":42}'), '42')
        self.assertEqual(_token_response('{"CODE_RESPONSE":null,"CODE_RESPONSE":false}'), 'false')
        self.assertEqual(_token_response('[["CODE_RESPONSE","token"]]'), 'token')
        self.assertIsNone(_token_response('{}'))
        for text in ('null', '', '{"OTHER":{}}', '{"CODE_RESPONSE":"a","CODE_RESPONSE":null}',
                     '[[null,"value"]]'):
            with self.subTest(text=text), self.assertRaises(GiroError):
                _token_response(text)
