from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import http.client
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import tempfile
from threading import Thread
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

from giro.client import AuthenticatedClient, AuthenticatedSession
from giro.crypto import PIN_IV, _cbc, decrypt_text, encrypt_text
from giro.errors import GiroError
from giro.payment_flow import PaymentJournal, PaymentWorkflow, WorkflowStopped, national_payment_fields
from giro.protocol import ENDPOINTS
from giro.response import receive


KEY = bytes(range(16))
BILL = {'sortCode': '01', 'giroNo': 'SYNTHETIC-GIRO', 'elecNo': 'SYNTHETIC-BILL'}
DETAIL = {'responseCode': '000', 'serviceCode': 'SYNTHETIC', 'paymentData': {
    **BILL, 'key': 'SYNTHETIC-LOOKUP-KEY', 'companyName': '합성세무서',
    'payMny': '900000', 'taxName': '합성세', 'when': '1', 'mnyEditYn': 'N'}}
ACCOUNTS = {'responseCode': '000', 'myValidAccountList': [None, {
    'bankCode': '001', 'bankName': '합성은행', 'accountNo': 'SYNTHETIC-ACCOUNT-1234'}],
    'bankServiceList': [{'bankCode': '001', 'bankStatus': 'true'}]}


def session():
    login = receive('auth.pin', 200, [], json.dumps({
        'responseCode': '000', 'sessionInfo': {'payer': '합성납부자'}}))
    return AuthenticatedSession.from_login(login, device_id='SYNTHETIC-DEVICE', key=KEY,
        cookies=CookieJar(), user_agent='SYNTHETIC TEST CLIENT', login_type='PIN')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        name = next(name for name, entry in ENDPOINTS.items() if entry.path == self.path)
        plain = decrypt_text(parse_qs(body.decode())['encryptedData'][0], KEY)
        self.server.calls.append((name, parse_qs(plain, keep_blank_values=True), dict(self.headers), body))
        status, response = self.server.responses[name]
        if response == 'disconnect':
            self.close_connection = True
            return
        payload = (b'not-json' if response == 'malformed' else
                   encrypt_text(json.dumps(response, ensure_ascii=False), KEY).hex().encode())
        self.send_response(status)
        self.send_header('Mgiro-App-Encrypt', '1')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Set-Cookie', 'TESTSESSION=PRIVATE-COOKIE; Path=/')
        self.send_header('Location', 'https://untrusted.invalid/')
        self.end_headers()
        self.wfile.write(payload)


class PaymentFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.calls = []
        self.server.responses = {
            'national.detail': (200, deepcopy(DETAIL)),
            'accounts.payable': (200, deepcopy(ACCOUNTS)),
            'auth.datetime': (200, {'responseCode': '000', 'currentDateTime': '20261001120000'}),
            'national.payment': (200, {'responseCode': '000', 'receiptItem': []}),
            'receipts.list': (200, {'responseCode': '000', 'receiptList': []}),
            'receipts.detail': (200, {'responseCode': '000', 'receiptItem': []}),
        }
        def loopback(host, *, timeout, context):
            self.assertEqual(host, 'm.giro.or.kr')
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            return http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=timeout)
        self.connection = patch('giro.client.http.client.HTTPSConnection', side_effect=loopback).start()
        self.addCleanup(patch.stopall)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.journal = PaymentJournal(Path(self.temp.name).resolve() / 'payments')
        self.client = AuthenticatedClient(session())
        self.flow = PaymentWorkflow(self.client, journal=self.journal)

    def prepare(self, flow=None, **kwargs):
        return (flow or self.flow).prepare(BILL, account_selector=lambda options: 1, send=True, **kwargs)

    def pay(self, draft, flow=None, **kwargs):
        return (flow or self.flow).pay(draft['draft_id'], account_password_provider=lambda: '1234',
                                       send=True, **kwargs)

    def test_end_to_end_encryption_cookies_order_and_private_journal(self):
        draft = self.prepare()
        self.assertEqual(draft['amount'], 900000)
        self.assertEqual(draft['bank_name'], '합성은행')
        self.assertEqual(draft['issuer'], '합성세무서')
        self.assertEqual(draft['tax_name'], '합성세')
        self.assertNotIn('SYNTHETIC-BILL', json.dumps(draft))
        self.assertNotIn('SYNTHETIC-ACCOUNT', json.dumps(draft))
        self.assertFalse(draft['payment_sent'])
        result = self.pay(draft)
        self.assertEqual(result['service_decision'], 'success')
        self.assertTrue(result['result_saved'])
        self.assertEqual([c[0] for c in self.server.calls],
                         ['national.detail', 'accounts.payable', 'auth.datetime', 'national.payment'])
        for name, fields, headers, body in self.server.calls:
            self.assertEqual(fields['deviceId'], ['SYNTHETIC-DEVICE'])
            self.assertNotIn(b'SYNTHETIC', body)
            if name != 'national.detail':
                self.assertEqual(headers['Cookie'], 'TESTSESSION=PRIVATE-COOKIE')
        fields = self.server.calls[-1][1]
        self.assertEqual(fields['납부금액'], ['900000'])
        self.assertEqual(fields['거래일시'], ['20261001120000'])
        self.assertEqual(fields['계좌번호'], ['SYNTHETIC-ACCOUNT-1234'])
        self.assertEqual(fields['납부자명'], ['합성납부자'])
        self.assertEqual(fields['addCertMethod'], ['0'])
        for key in ('sessionInfo', 'responseCode', 'addUserAcntYn', 'manageName'):
            self.assertNotIn(key, fields)
        for i, position in enumerate((1, 2, 3, 4)):
            cipher = bytes.fromhex(fields['acntPwd'][0])[i*16:(i+1)*16]
            self.assertEqual(_cbc(KEY, PIN_IV, cipher, decrypt=True), bytes((5, position)) + bytes(14))
        saved = next(self.journal.root.iterdir())
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        for secret in ('SYNTHETIC', 'PRIVATE-COOKIE', '1234', 'acntPwd', '합성납부자'):
            self.assertNotIn(secret, saved.read_text())
        self.assertNotIn('SYNTHETIC', repr(self.client.session))
        for secret in ('SYNTHETIC', 'PRIVATE-COOKIE', 'acntPwd', '합성납부자'):
            self.assertNotIn(secret, json.dumps(self.client.events))
        self.assertEqual([event['endpoint'] for event in self.client.events],
                         [call[0] for call in self.server.calls])

    def test_additional_pin_uses_six_blocks_same_key_without_extra_request(self):
        self.server.responses['national.detail'][1]['paymentData']['payMny'] = '1000010'
        draft = self.prepare()
        self.assertTrue(draft['additional_pin_required'])
        result = self.pay(draft, additional_pin_provider=lambda: '012345')
        self.assertTrue(result['app_success'])
        fields = self.server.calls[-1][1]
        self.assertEqual(fields['addCertMethod'], ['2'])
        encoded = bytes.fromhex(fields['encAddCertValue'][0])
        self.assertEqual(len(encoded), 96)
        self.assertEqual(len(self.server.calls), 4)
        for i, position in enumerate((10, 1, 2, 3, 4, 5)):
            self.assertEqual(_cbc(KEY, PIN_IV, encoded[i*16:(i+1)*16], decrypt=True),
                             bytes((5, position)) + bytes(14))

    def test_explicit_send_before_network_or_secret_input(self):
        provider = Mock()
        with self.assertRaises(GiroError):
            self.flow.prepare(BILL, account_selector=provider)
        with self.assertRaises(GiroError):
            self.client.query('national.list', {})
        with self.assertRaises(GiroError):
            self.flow.pay('any', account_password_provider=provider)
        self.assertEqual(self.server.calls, [])
        provider.assert_not_called()

    def test_missing_additional_provider_or_unsupported_auth_does_not_collect_password(self):
        self.server.responses['national.detail'][1]['paymentData']['payMny'] = '1000010'
        for login_type in ('PIN', 'CERT', 'FIDO', 'FINCERT'):
            self.client.session.login_type = login_type
            draft = self.prepare()
            provider = Mock()
            with self.assertRaises(GiroError):
                self.flow.pay(draft['draft_id'], account_password_provider=provider, send=True)
            provider.assert_not_called()
        self.assertFalse(self.journal.root.exists())
        self.assertNotIn('national.payment', [c[0] for c in self.server.calls])

    def test_invalid_password_does_not_reserve_or_send(self):
        draft = self.prepare()
        with self.assertRaises(GiroError):
            self.flow.pay(draft['draft_id'], account_password_provider=lambda: '123456', send=True)
        self.assertFalse(self.journal.root.exists())
        self.assertEqual(len(self.server.calls), 3)

    def test_success_without_receipt_and_save_failure_still_succeeds(self):
        self.server.responses['national.payment'] = (200, {'responseCode': '000'})
        draft = self.prepare()
        with patch.object(self.journal, 'finish', side_effect=OSError('PRIVATE-ERROR')):
            result = self.pay(draft)
        self.assertTrue(result['app_success'])
        self.assertEqual(result['service_decision'], 'success')
        self.assertEqual(result['receipt_state'], 'null_or_missing')
        self.assertFalse(result['result_saved'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        with self.assertRaises(GiroError):
            self.pay(draft)
        self.assertEqual(len(self.server.calls), 4)

    def test_unknown_transport_result_blocks_replay_even_new_session_and_query_key(self):
        self.server.responses['national.payment'] = (200, 'disconnect')
        result = self.pay(self.prepare())
        self.assertEqual(result['service_decision'], 'unobserved')
        self.assertFalse(result['automatic_retry'])
        self.server.responses['national.detail'][1]['paymentData']['key'] = 'NEW-LOOKUP-KEY'
        second = PaymentWorkflow(AuthenticatedClient(session()), journal=self.journal)
        draft = self.prepare(second)
        provider = Mock()
        with self.assertRaises(GiroError):
            second.pay(draft['draft_id'], account_password_provider=provider, send=True)
        provider.assert_not_called()
        self.assertEqual([c[0] for c in self.server.calls].count('national.payment'), 1)

    def test_server_failure_expiry_redirect_and_malformed_response_are_distinct(self):
        for index, (status, response, decision) in enumerate((
                (200, {'responseCode': '91'}, 'failure'),
                (200, {'responseCode': '301'}, 'failure'),
                (302, {'responseCode': '000'}, 'unobserved'),
                (200, 'malformed', 'unobserved'))):
            with self.subTest(status=status, response=response):
                self.server.responses['national.payment'] = (status, response)
                client = AuthenticatedClient(session())
                flow = PaymentWorkflow(client, journal=PaymentJournal(Path(self.temp.name).resolve() / str(index)))
                before = len(self.server.calls)
                result = self.pay(self.prepare(flow), flow)
                self.assertEqual(result['service_decision'], decision)
                self.assertEqual(len(self.server.calls) - before, 4)
                if isinstance(response, dict) and response.get('responseCode') == '301':
                    self.assertFalse(client.session.active)
                    with self.assertRaises(GiroError):
                        client.query('receipts.list', {}, send=True)

    def test_reservation_failure_stops_before_payment(self):
        draft = self.prepare()
        with patch.object(self.journal, 'reserve', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.pay(draft)
        self.assertEqual(len(self.server.calls), 3)

    def test_timeout_is_unobserved_and_never_retried(self):
        draft = self.prepare()
        with patch('giro.client._post', side_effect=TimeoutError) as post:
            result = self.pay(draft)
        self.assertEqual(result['response_code'], '601')
        self.assertEqual(result['service_decision'], 'unobserved')
        post.assert_called_once()
        with self.assertRaises(GiroError):
            self.pay(draft)

    def test_cookie_bookkeeping_failure_does_not_erase_payment_success(self):
        draft = self.prepare()
        with patch.object(self.client.session.cookies, 'extract_cookies', side_effect=RuntimeError):
            result = self.pay(draft)
        self.assertTrue(result['app_success'])
        self.assertIn('cookie_update_failed', result['processing_issues'])
        self.assertFalse(self.client.session.active)

    def test_failed_preparation_preserves_response_and_stops_remaining_requests(self):
        self.server.responses['accounts.payable'] = (200, {'responseCode': '301'})
        with self.assertRaises(WorkflowStopped) as caught:
            self.prepare()
        self.assertEqual(caught.exception.stage, 'accounts.payable')
        self.assertTrue(caught.exception.response.clear_session)
        self.assertEqual(len(self.server.calls), 2)

    def test_receipt_queries_do_not_resend_or_infer_prior_payment(self):
        self.server.responses['national.payment'] = (200, 'disconnect')
        self.pay(self.prepare())
        result = self.client.query('receipts.list', {'startDate': '20261001', 'endDate': '20261001',
                                                    'page': '1', 'pageSize': '10'}, send=True)
        self.assertTrue(result.app_success)
        self.assertEqual(result.query['receiptList'], [])
        self.assertEqual([c[0] for c in self.server.calls].count('national.payment'), 1)
        saved = json.loads(next(self.journal.root.iterdir()).read_text())
        self.assertEqual(saved['service_decision'], 'unobserved')

    def test_payment_endpoint_cannot_use_read_query(self):
        with self.assertRaises(GiroError):
            self.client.query('national.payment', {}, send=True)
        self.assertEqual(self.server.calls, [])

    def test_concurrent_workflows_reserve_the_bill_only_once(self):
        second = PaymentWorkflow(AuthenticatedClient(session()), journal=self.journal)
        first_draft, second_draft = self.prepare(), self.prepare(second)
        def submit(flow, draft):
            try:
                return self.pay(draft, flow)
            except GiroError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda pair: submit(*pair),
                                   [(self.flow, first_draft), (second, second_draft)]))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual([c[0] for c in self.server.calls].count('national.payment'), 1)

    def test_observation_failure_does_not_erase_payment_success(self):
        draft = self.prepare()
        self.client.events = Mock()
        self.client.events.append.side_effect = OSError('PRIVATE-ERROR')
        result = self.pay(draft)
        self.assertTrue(result['app_success'])
        self.assertIn('observation_failed', result['processing_issues'])
        self.assertNotIn('PRIVATE', json.dumps(result))


class FieldTests(unittest.TestCase):
    def fields(self, detail, amount=None):
        return national_payment_fields(detail, session_info={'payer': 'SYNTHETIC-PAYER'},
                                       current_datetime='20261001120000', amount=amount)

    def test_detail_fields_and_edit_limits(self):
        detail = deepcopy(DETAIL)
        detail.update(giroNo='TOP-LEVEL', elecNo='TOP-BILL')
        detail['paymentData'].update(giroNo=None, elecNo=None)
        self.assertEqual(self.fields(detail)['giroNo'], 'TOP-LEVEL')
        self.assertEqual(self.fields(detail)['거래번호'], 'TOP-BILL')
        with self.assertRaises(GiroError):
            self.fields(detail, '100')
        detail['paymentData'].update(mnyEditYn='P', remainPayMny='200')
        self.assertEqual(self.fields(detail, '100')['납부금액'], '100')
        for invalid in ('210', '101', '0', '-10'):
            with self.assertRaises(GiroError):
                self.fields(detail, invalid)
        detail['paymentData']['mnyEditYn'] = 'Y'
        self.assertEqual(self.fields(detail, '1,000')['납부금액'], '1000')

    def test_missing_successful_detail_is_a_local_error(self):
        with self.assertRaises(GiroError):
            self.fields({'responseCode': '000'})

    def test_unsuccessful_login_cannot_create_session(self):
        with self.assertRaises(GiroError):
            AuthenticatedSession.from_login(receive('auth.pin', 200, [], '{"responseCode":"301"}'),
                device_id='SYNTHETIC', key=KEY, cookies=CookieJar(), user_agent='TEST', login_type='PIN')
