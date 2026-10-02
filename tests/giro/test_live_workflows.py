from pathlib import Path
from datetime import date
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from giro.client import AuthenticatedClient
from giro.errors import GiroError
from giro.payment_cli import run_payment
from giro.payment_flow import PaymentJournal
from giro.query_flow import collect_bills, list_bills, list_receipts
from giro.session_store import SessionStore
import test_login as support
from test_bills import page


class LiveWorkflowTests(unittest.TestCase):
    cert, crl, target = support.LoginTests.cert, support.LoginTests.crl, support.LoginTests.target
    setUpClass = classmethod(support.LoginTests.setUpClass.__func__)
    tearDownClass = classmethod(support.LoginTests.tearDownClass.__func__)

    def setUp(self):
        support.LoginTests.setUp(self)
        self.server.responses['auth.pin'][1]['sessionInfo']['hasUIDInfoYn'] = 'Y'
        result = self.login.login(pin_provider=self.pin, send=True)
        self.session = result.session
        self.assertIsNotNone(self.session, result.report())
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.store, self.journal = SessionStore(root/'giro'), PaymentJournal(root/'payments')
        self.store.save(self.session)
        self.server.responses['national.list'] = (200, dict(responseCode='000',
            paymentList=[dict(support.BILL, companyName='합성세무서', payMny='900000', payLimitDate='20261010')],
            pageNaviMap={'currentPage': '1', 'totalPage': '1', 'totalCount': '1'}))

    def test_three_tax_types_use_existing_key_cookie_and_own_uid(self):
        for tax_type in ('national', 'local', 'customs'):
            self.server.responses[tax_type+'.list'] = self.server.responses['national.list']
            result = list_bills(tax_type, send=True, store=self.store)
            self.assertTrue(result['app_success'], result)
            self.assertTrue(result['complete'], result)
            _, fields, headers, _ = self.server.calls[-1]
            self.assertEqual(fields['useUIDInfoYn'], ['Y'])
            self.assertEqual(fields['page'], ['1'])
            self.assertEqual(headers['Cookie'], 'SESSION=BUSINESS-COOKIE')
        self.assertEqual(self.server.steps.count('auth.pin'), 1)
        self.assertEqual(len(self.server.keys), 2)

    def test_missing_own_uid_stops_at_registration_prompt_without_query(self):
        self.session.info.pop('hasUIDInfoYn')
        before = list(self.server.calls)
        result = collect_bills(AuthenticatedClient(self.session), 'national')
        self.assertEqual(result['next_action'], 'identity_registration_required')
        self.assertIsNone(result['app_success'])
        self.assertEqual(self.server.calls, before)

    def test_paging_preserves_first_success_when_later_page_disconnects(self):
        client = AuthenticatedClient(self.session)
        query = client.query
        def pages(name, fields, **kwargs):
            self.server.responses[name] = (200, page(1, 2, 2) if fields['page'] == '1' else {'responseCode': '300'})
            return query(name, fields, **kwargs)
        with patch.object(client, 'query', side_effect=pages): result = collect_bills(client, 'national')
        self.assertTrue(result['app_success'])
        self.assertEqual(result['service_decision'], 'partial_success')
        self.assertEqual(result['loaded_count'], 1)
        self.assertFalse(result['complete'])
        self.assertFalse(self.session.active)
        self.assertEqual(self.server.steps.count('national.list'), 2)

    def test_disconnection_is_saved_and_next_command_does_not_login_or_query(self):
        self.server.responses['national.list'] = (200, {'responseCode': '301'})
        result = list_bills('national', send=True, store=self.store)
        self.assertFalse(result['app_success'])
        before = list(self.server.calls)
        with self.assertRaises(GiroError): list_bills('national', send=True, store=self.store)
        self.assertEqual(self.server.calls, before)

    def test_empty_receipt_page_does_not_release_unknown_payment(self):
        reservation = self.journal.reserve('synthetic-unknown-payment')
        self.server.responses['receipts.list'] = (200, {'responseCode': '000', 'receiptList': [],
            'pageNaviMap': {'currentPage': '1', 'totalPage': '0', 'totalCount': '0'}})
        result = list_receipts(date(2026,10,1), date(2026,10,3), send=True, store=self.store)
        self.assertTrue(result['app_success'])
        self.assertEqual(result['receipts'], [])
        self.assertFalse(result['payment_reservation_changed'])
        self.assertTrue(reservation.exists())
        self.assertEqual(self.server.calls[-1][1]['startDate'], ['20261001'])
        self.assertEqual(self.server.steps.count('auth.pin'), 1)

    def payment(self, confirm):
        from giro.payment_flow import PaymentWorkflow
        def workflow(client): return PaymentWorkflow(client, journal=self.journal)
        with patch('giro.payment_cli.private_terminal'), patch('giro.payment_cli.SessionStore', return_value=self.store), \
             patch('giro.payment_cli.PaymentWorkflow', side_effect=workflow), \
             patch('giro.payment_cli.answer', return_value=confirm) as approval, \
             patch('giro.payment_cli.secret', return_value='1234') as secret:
            result = run_payment(SimpleNamespace(live=True, amount=None))
        return result, approval, secret

    def test_cancelled_review_never_collects_password_or_sends_payment(self):
        (result, code), approval, secret = self.payment('취소')
        self.assertEqual(code, 0)
        self.assertFalse(result['payment_attempted'])
        self.assertIn('900,000', approval.call_args[0][0])
        secret.assert_not_called()
        self.assertNotIn('national.payment', self.server.steps)

    def test_reviewed_single_payment_and_duplicate_prevention_survive_commands(self):
        (result, code), _, secret = self.payment('납부')
        self.assertEqual(code, 0, result)
        self.assertEqual(result['service_decision'], 'success')
        secret.assert_called_once()
        self.assertEqual(self.server.steps.count('national.payment'), 1)
        (second, code), _, secret = self.payment('납부')
        self.assertEqual(code, 2)
        self.assertFalse(second['payment_attempted'])
        secret.assert_not_called()
        self.assertEqual(self.server.steps.count('national.payment'), 1)
        self.assertEqual(self.server.steps.count('auth.pin'), 1)
