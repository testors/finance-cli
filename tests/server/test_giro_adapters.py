"""Synthetic Giro transport through real web workers, sessions and payment journal."""
from copy import deepcopy
from http.cookiejar import CookieJar
import io
import json
from unittest.mock import patch
from urllib.parse import parse_qs

from support import ServerCase
from finance_cli.core import storage
from finance_cli.server import jobs, model, worker
from finance_cli.server.config import private_directory
from finance_cli.server.adapters import giro_live
from giro.client import AuthenticatedSession, WireResponse
from giro.crypto import decrypt_text
from giro.payment_flow import PaymentJournal
from giro.protocol import ENDPOINTS
from giro.session_store import SessionStore

KEY = bytes(range(16))
BILL = 'SYNTHETIC-BILL-1234'
ACCOUNT = 'SYNTHETIC-ACCOUNT-5678'
PAGE = {'responseCode': '000', 'paymentList': [{'elecNo': BILL, 'sortCode': '01', 'giroNo': 'SYNTHETIC',
    'companyName': '합성세무서', 'taxName': '합성세', 'payMny': '2000000', 'payLimitDate': '20261031'}],
    'pageNaviMap': {'currentPage': '1', 'totalPage': '1', 'totalCount': '1'}}
DETAIL = {'responseCode': '000', 'serviceCode': 'SYNTHETIC', 'paymentData': {
    'elecNo': BILL, 'sortCode': '01', 'giroNo': 'SYNTHETIC', 'key': 'SYNTHETIC-QUERY-KEY',
    'companyName': '합성세무서', 'payMny': '2000000', 'taxName': '합성세', 'mnyEditYn': 'N'}}
ACCOUNTS = {'responseCode': '000', 'myValidAccountList': [None, {'bankCode': '001', 'bankName': '합성은행',
    'accountNo': ACCOUNT, 'manageName': '합성 생활비'}], 'bankServiceList': [{'bankCode': '001', 'bankStatus': 'true'}]}


class GiroTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.enroll()
        self.connection = self.post('/logins', {'institution': 'giro', 'method': 'pin', 'name': '합성 지로'}).json()
        storage.directory(self.home / 'giro')
        self.session_root = private_directory('sessions', 'giro') / 'synthetic'
        self.session = AuthenticatedSession('SYNTHETIC-DEVICE', KEY, CookieJar(), 'SYNTHETIC/1', 'PIN',
            {'hasUIDInfoYn': 'Y', 'payer': 'SYNTHETIC-PAYER'})
        SessionStore(self.session_root).save(self.session)
        with self.db.write() as con:
            self.session_id = model.add_session(con, login_id=self.connection['id'],
                location=str(self.session_root.relative_to(self.home)), revision=1, job_id=None)
            model.set_pointer(con, self.connection['id'], self.session_id)
        self.calls = []
        self.responses = deepcopy({'national.list': PAGE, 'national.detail': DETAIL, 'accounts.payable': ACCOUNTS,
            'auth.datetime': {'responseCode': '000', 'currentDateTime': '20261003120000'},
            'national.payment': {'responseCode': '000', 'receiptItem': []},
            'receipts.list': {'responseCode': '000', 'receiptList': [{'paidDate': '20261003', 'paidMny': '2000000',
                'companyName': '합성세무서', 'sortCode': '01', 'giroNo': 'SYNTHETIC', 'key': 'SYNTHETIC-RECEIPT-KEY'}]},
            'receipts.detail': {'responseCode': '000', 'receiptItem': [{'n': '세목', 'v': '합성세'}]},
            'accounts.registered': {'responseCode': '000', 'userAcntList': [{'bankName': '합성은행',
                'acntNo': ACCOUNT, 'manageName': '합성 생활비'}]}})
        self.enterContext(patch('giro.client._post', self.exchange))

    def exchange(self, path, body, headers):
        name = next(n for n, e in ENDPOINTS.items() if e.path == path)
        plain = decrypt_text(parse_qs(body.decode())['encryptedData'][0], KEY)
        self.calls.append((name, parse_qs(plain, keep_blank_values=True)))
        value = self.responses[name]
        if isinstance(value, Exception):
            raise value
        return WireResponse(200, [], json.dumps(value, ensure_ascii=False).encode())

    def submit(self, name, **fields):
        return jobs.submit(self.db, name=name, origin='web:test', login_id=self.connection['id'], **fields)[0]

    def run_job(self, job, inputs=None):
        with self.db.read() as con:
            job = jobs.get(con, job['id'])
        worker.run(self.db, job['id'], job['step'], control=io.StringIO(),
                   stdin=io.StringIO(json.dumps(inputs) + '\n' if inputs is not None else ''))
        return self.get('/jobs/' + job['id']).json()

    def prepare(self):
        bills = self.run_job(self.submit('giro.bills.list'))
        self.assertEqual(bills['outcome'], 'success', bills)
        options = self.run_job(self.submit('giro.payment.options', parent_job_id=bills['id'], input={'ref': '0'}))
        self.assertEqual(options['outcome'], 'success', options)
        job = self.run_job(self.submit('giro.payment.prepare', parent_job_id=options['id'], input={'account_index': 1}))
        self.assertEqual(job['status'], 'awaiting_input', job)
        return job

    def confirm(self, job):
        jobs.accept_confirmation(self.db, job['id'], job['awaiting']['digest'], 'web:test')
        fields = {'account_password': '5678'}
        if 'pin' in job['awaiting']['requires']:
            fields['pin'] = '654321'
        return self.run_job(job, fields)

    def assert_private(self, value):
        text = json.dumps(value, ensure_ascii=False)
        for secret in (BILL, ACCOUNT, 'SYNTHETIC-QUERY-KEY', 'SYNTHETIC-RECEIPT-KEY',
                       'SYNTHETIC-DEVICE', 'SYNTHETIC-PAYER', '654321'):
            self.assertNotIn(secret, text)

    def test_selection_confirmation_encryption_no_reinitialization_or_replay(self):
        job = self.prepare()
        self.assertEqual(job['awaiting']['requires'], ['account_password', 'pin'])
        self.assertEqual(job['awaiting']['preview']['account_alias'], '합성 생활비')
        self.assertEqual(job['awaiting']['preview']['amount'], '2000000')
        self.assertEqual([n for n, _ in self.calls], ['national.list', 'national.detail', 'accounts.payable', 'auth.datetime'])
        self.assert_private(job)
        result = self.confirm(job)
        self.assertEqual(result['outcome'], 'success', result)
        self.assertTrue(result['result']['payment_attempted'])
        self.assertEqual(self.calls[-1][0], 'national.payment')
        self.assertEqual(self.calls[-1][1]['계좌번호'], [ACCOUNT])
        self.assertNotIn('manageName', self.calls[-1][1])
        self.assertNotEqual(self.calls[-1][1]['encAddCertValue'], ['654321'])
        self.assert_private(result)
        self.assert_private(self.get('/jobs').json())
        before = len(self.calls)
        self.run_job(job, {'account_password': '5678', 'pin': '654321'})
        self.assertEqual(len(self.calls), before)
        second = self.prepare()
        result = self.confirm(second)
        self.assertEqual(result['local']['stopped'], 'giro_operation_stopped')
        self.assertEqual([n for n, _ in self.calls].count('national.payment'), 1)
        for path in (self.home / 'server' / 'jobs').glob('*/giro.sealed'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assert_private(path.read_bytes().hex())

    def test_receipts_and_accounts_hide_identifiers_keep_alias_and_never_reset_payment(self):
        result = self.confirm(self.prepare())
        reservation = next((self.home / 'giro' / 'payments').glob('*.json'))
        before = reservation.read_bytes()
        receipts = self.run_job(self.submit('giro.receipts.list', input={'start_date': '2026-10-01', 'end_date': '2026-10-03'}))
        self.assertEqual(receipts['outcome'], 'success', receipts)
        self.assert_private(receipts)
        detail = self.run_job(self.submit('giro.receipts.detail', parent_job_id=receipts['id'], input={'ref': '0'}))
        self.assertEqual(detail['result']['items'], [{'name': '세목', 'value': '합성세'}])
        accounts = self.run_job(self.submit('giro.accounts.list'))
        self.assertEqual(accounts['result']['accounts'][0]['name'], '합성 생활비')
        for verified in (receipts, detail, accounts):
            self.assertEqual(verified['verification'], 'live_verified')
            self.assertIn('웹', verified['verification_note'])
        # Existing stored jobs also project the current review on listing.
        listed = {j['id']: j for j in self.get('/jobs').json()['jobs']}
        self.assertEqual(listed[accounts['id']]['verification'], 'live_verified')
        self.assert_private(accounts)
        self.assertEqual(reservation.read_bytes(), before)

    def test_missing_receipt_or_journal_write_failure_never_erases_payment_success(self):
        job = self.prepare()
        self.responses['national.payment'] = {'responseCode': '000'}
        with patch.object(PaymentJournal, 'finish', side_effect=OSError('SYNTHETIC-SECRET')):
            result = self.confirm(job)
        self.assertEqual(result['outcome'], 'success', result)
        self.assertFalse(result['result']['result_saved'])
        self.assertEqual(result['result']['receipt_state'], 'null_or_missing')
        self.assertIn('result_save_failed', result['local']['processing_issues'])

    def test_lost_response_is_unknown_with_durable_reservation(self):
        job = self.prepare()
        self.responses['national.payment'] = TimeoutError()
        result = self.confirm(job)
        self.assertEqual(result['outcome'], 'unknown', result)
        self.assertEqual(result['service_verdict']['service_decision'], 'unobserved')
        self.assertTrue(next((self.home / 'giro' / 'payments').glob('*.json')).exists())

    def test_no_bills_311_retains_failure_and_null_without_fabricated_zero(self):
        self.responses['national.list'] = {'responseCode': '311', 'errorInfo': {'errorName': '고지내용 없음'}}
        job = self.run_job(self.submit('giro.bills.list'))
        self.assertEqual(job['outcome'], 'rejected', job)
        self.assertTrue(job['result']['no_bills_reported'])
        self.assertEqual(job['verification'], 'live_partial')
        self.assertIsNone(job['result']['bills'])
        self.assertNotIn('total_count', job['result'])
        # The verdict stays the institution's failure; the flag only lets lists name the answer.
        self.assertEqual((job['service_verdict']['app_success'], job['service_verdict']['response_code'],
                          job['service_verdict']['service_decision']), (False, '311', 'failure'))
        listed = {j['id']: j for j in self.get('/jobs').json()['jobs']}[job['id']]
        self.assertIs(listed['service_verdict']['no_bills_reported'], True)
        self.assertNotIn('result', listed)
        self.responses['national.list']['errorInfo']['errorName'] = '다른 오류'
        other = self.run_job(self.submit('giro.bills.list'))
        self.assertFalse(other['result']['no_bills_reported'])
        self.assertIs(other['service_verdict']['no_bills_reported'], False)
        self.assertEqual(other['outcome'], 'rejected')
        # Other Giro queries keep the plain verdict fields.
        self.assertNotIn('no_bills_reported', self.run_job(self.submit('giro.accounts.list'))['service_verdict'])

    def test_expiry_marks_session_and_does_not_login(self):
        self.responses['national.list'] = {'responseCode': '301'}
        result = self.run_job(self.submit('giro.bills.list'))
        self.assertEqual(result['service_verdict']['callback'], 'disconnected_session')
        self.assertEqual(self.get('/logins').json()['logins'][0]['readiness'], 'login_required')
        self.assertEqual([n for n, _ in self.calls], ['national.list'])

    def test_null_success_and_partial_pages_remain_distinct(self):
        self.responses['national.list'] = {'responseCode': '000'}
        job = self.run_job(self.submit('giro.bills.list'))
        self.assertEqual(job['service_verdict']['app_success'], True)
        self.assertEqual(job['outcome'], 'partial_success')
        self.assertIsNone(job['result']['bills'])

    def test_session_save_failure_preserves_query_and_invalidates_saved_session(self):
        with patch.object(SessionStore, '_save', side_effect=OSError('SYNTHETIC-SECRET')):
            job = self.run_job(self.submit('giro.bills.list'))
        self.assertEqual(job['outcome'], 'success', job)
        self.assertTrue(job['result']['bills'])
        self.assertEqual(self.get('/logins').json()['logins'][0]['session']['state'], 'stale')
        self.assertNotIn('SYNTHETIC-SECRET', json.dumps(job))

    def test_cli_lock_blocks_web_before_secret_delivery_or_network(self):
        job = self.submit('giro.login')
        control, inputs = io.StringIO(), io.StringIO('{"pin":"654321"}\n')
        with storage.lock(self.home / 'giro' / 'session.lock'):
            result = worker.run(self.db, job['id'], job['step'], control=control, stdin=inputs)
        self.assertEqual(result, 'busy')
        self.assertEqual(inputs.tell(), 0)
        self.assertNotIn('ready', control.getvalue())
        self.assertEqual(self.calls, [])

    def test_tampered_draft_or_expired_confirmation_sends_no_payment(self):
        job = self.prepare()
        path = worker.job_directory(job['id']) / 'giro.sealed'
        path.write_bytes(path.read_bytes()[:-1] + b'x')
        result = self.confirm(job)
        self.assertEqual(result['local']['stopped'], 'giro_preparation_changed')
        self.assertNotIn('national.payment', [n for n, _ in self.calls])
        job = self.prepare()
        with patch('finance_cli.server.jobs.now', return_value=job['expires_at'] + 1):
            with self.assertRaises(jobs.NotReady):
                jobs.accept_confirmation(self.db, job['id'], job['awaiting']['digest'], 'web:test')

    def test_changed_session_or_login_settings_invalidates_payment(self):
        job = self.prepare()
        with self.db.write() as con:
            model.mark_session(con, self.session_id, 'consumed', 'new_login')
        result = self.confirm(job)
        self.assertEqual(result['local']['stopped'], 'fixed_session_not_usable')
        self.assertNotIn('national.payment', [n for n, _ in self.calls])

    def test_unsupported_certificate_auth_never_asks_password_or_pays(self):
        self.responses.update({'local.provinces': {'responseCode': '000', 'provinceList': [{'areaCode': '11'}]},
            'local.districts': {'responseCode': '000', 'districtList': [{'sortCode': '01', 'giroNo': 'SYNTHETIC'}]},
            'local.list': deepcopy(PAGE), 'local.detail': deepcopy(DETAIL)})
        self.responses['local.detail']['paymentData']['certOnlyYn'] = 'Y'
        bills = self.run_job(self.submit('giro.bills.list', input={'tax_type': 'local'}))
        options = self.run_job(self.submit('giro.payment.options', parent_job_id=bills['id'], input={'ref': '0'}))
        job = self.run_job(self.submit('giro.payment.prepare', parent_job_id=options['id'], input={'account_index': 1}))
        self.assertEqual(job['local']['stopped'], 'giro_payment_auth_unsupported')
        self.assertEqual(job['outcome'], 'not_started')
        self.assertEqual(job['service_verdict']['preparation_service_decision'], 'success')
        self.assertIsNone(job['awaiting'])
        self.assertNotIn('national.payment', [n for n, _ in self.calls])

    def test_login_uses_existing_device_saves_encrypted_session_and_preserves_success(self):
        root = storage.directory(self.home / 'giro' / 'enrollment')
        storage.atomic_json(root / 'identity.json', {'schema': 1, 'source': 'cli-generated', 'device_id': '0123456789abcdef'})
        def authenticate(**kwargs):
            self.assertEqual(kwargs['pin_provider'](), '654321')
            kwargs['session_store'].save(self.session)
            return {'login_service_decision': 'success', 'session_saved': True, 'processing_issues': []}
        with patch.object(giro_live.auth_flow, 'authenticate', side_effect=authenticate):
            result = self.run_job(self.submit('giro.login'), {'pin': '654321'})
        self.assertEqual(result['outcome'], 'success', result)
        self.assertTrue(result['result']['session_id'])
        self.assert_private(result)
        with patch.object(giro_live.auth_flow, 'authenticate', return_value={'login_service_decision': 'success',
                'session_saved': False, 'processing_issues': ['session_save_incomplete']}):
            result = self.run_job(self.submit('giro.login'), {'pin': '654321'})
        self.assertEqual(result['outcome'], 'success')
        self.assertIsNone(result['result']['session_id'])

    def test_recipient_lookup_failure_keeps_login_unknown_and_shows_stage(self):
        from giro.registration_flow import EnrollmentStore
        EnrollmentStore().identity()
        with patch.object(giro_live.auth_flow, 'authenticate', return_value={
                'stage': 'recipient.validate', 'login_service_decision': 'unobserved',
                'session_saved': False, 'processing_issues': ['recipient_validation_failed',
                                                            'recipient_public_lookup_failed']}) as authenticate:
            result = self.run_job(self.submit('giro.login'), {'pin': '654321'})
        authenticate.assert_called_once()
        self.assertEqual(result['outcome'], 'unknown')
        self.assertEqual(result['local']['stage'], 'recipient.validate')
        self.assertIn('recipient_public_lookup_failed', result['local']['processing_issues'])
        self.assertIsNone(result['result']['session_id'])

    def test_unregistered_device_and_raw_browser_payment_fields_rejected_without_network(self):
        job = self.run_job(self.submit('giro.login'), {'pin': '654321'})
        self.assertEqual(job['local']['stopped'], 'giro_device_registration_required')
        self.assertEqual(self.calls, [])
        self.assertFalse((self.home / 'giro' / 'enrollment' / 'identity.json').exists())
        bad = self.post('/jobs', {'name': 'giro.payment.prepare', 'login_id': self.connection['id'],
                               'input': {'account_index': 1, 'account_number': ACCOUNT}})
        self.assertEqual(bad.status_code, 400)
        asset = self.client.get('/static/giro.js')
        self.assertEqual(asset.status_code, 200)
        self.assertIn('giroViews', asset.text)
        row = self.get('/capabilities').json()
        features = {f['id']: f for f in row['features']}
        self.assertEqual(features['giro-pay']['status'], 'available')
        self.assertEqual(features['giro-pay']['verification'], 'live_partial')

    def test_session_extension_is_one_time_query_and_ten_idle_minutes_count_as_logged_out(self):
        import time
        from finance_cli.server import session_activity
        row = lambda: self.get('/logins').json()['logins'][0]
        job = self.run_job(self.submit('giro.session.extend'))
        self.assertEqual(job['outcome'], 'success', job)
        self.assertEqual([name for name, _ in self.calls], ['auth.datetime'])
        self.assertEqual((job['result']['request_accepted'], job['result']['login_extension_accepted'],
                          job['result']['extension_effect']), (True, None, 'unverified'))
        self.assertNotIn('20261003120000', json.dumps(job, ensure_ascii=False))
        self.assertGreater(row()['session']['idle_expires_at'], time.time() + 590)
        self.assertEqual(row()['readiness'], 'ready')
        with patch.object(session_activity, 'now', return_value=time.time() + 601):
            self.assertEqual(row()['readiness'], 'login_required')
            with self.assertRaisesRegex(jobs.NotReady, '^session_idle_expired$'):
                self.submit('giro.accounts.list')
            with self.assertRaisesRegex(jobs.NotReady, '^session_idle_expired$'):
                self.submit('giro.session.extend')
        self.assertEqual(len(self.calls), 1, 'an idle session is neither queried nor revived')
