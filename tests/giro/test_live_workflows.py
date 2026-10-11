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
from giro.query_flow import collect_bills, list_bills, list_receipts, list_regions, registered_accounts, receipt_detail
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
        self.server.responses['local.provinces'] = (200, {'responseCode': '000',
            'provinceList': [{'areaCode': 'SYNTHETIC-AREA', 'areaName': '합성시도'}]})
        self.server.responses['local.districts'] = (200, {'responseCode': '000',
            'districtList': [{'sortCode': 'SYNTHETIC-SORT', 'giroNo': 'SYNTHETIC-GIRO',
                              'sigunguName': '합성지자체'}]})

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
            if tax_type == 'local':
                self.assertEqual(fields['sortCode'], ['SYNTHETIC-SORT'])
                self.assertEqual(fields['giroNo'], ['SYNTHETIC-GIRO'])
                self.assertEqual(result['query_region'], {'province': '합성시도', 'district': '합성지자체'})
        self.assertEqual(self.server.steps.count('auth.pin'), 1)
        self.assertEqual(len(self.server.keys), 2)

    def test_local_region_initialization_happens_once_across_multiple_pages(self):
        client = AuthenticatedClient(self.session)
        query = client.query
        def pages(name, fields, **kwargs):
            if name == 'local.list': self.server.responses[name] = (200, page(int(fields['page']), 2, 2))
            return query(name, fields, **kwargs)
        with patch.object(client, 'query', side_effect=pages): result = collect_bills(client, 'local')
        self.assertTrue(result['app_success'])
        self.assertEqual(self.server.steps.count('local.provinces'), 1)
        self.assertEqual(self.server.steps.count('local.districts'), 1)
        self.assertEqual(self.server.steps.count('local.list'), 2)
        self.assertEqual(self.server.steps.count('auth.pin'), 1)

    def test_local_region_failure_or_null_list_stops_before_bill_query(self):
        for response in ({'responseCode':'311'}, {'responseCode':'000'},
                         {'responseCode':'000','provinceList':[]},
                         {'responseCode':'000','provinceList':[None]}):
            self.server.responses['local.provinces'] = (200, response)
            result = collect_bills(AuthenticatedClient(self.session), 'local')
            self.assertIsNone(result['app_success'])
            self.assertEqual(result['preparation_response']['app_success'], response['responseCode']=='000')
            self.assertEqual(result['next_action'], 'local_region_unavailable')
        self.assertNotIn('local.districts', self.server.steps)
        self.assertNotIn('local.list', self.server.steps)

    def test_region_codes_command_lists_codes_on_the_saved_session_and_queries_no_bill(self):
        from giro.__main__ import parser, run
        before = len(self.server.steps)
        result = list_regions('local', send=True, store=self.store)
        self.assertTrue(result['app_success'], result)
        self.assertEqual(result['provinces'], [{'area_code': 'SYNTHETIC-AREA', 'name': '합성시도'}])
        self.assertEqual(result['districts'], [{'district_code': 'SYNTHETIC-SORT', 'district_giro_no': 'SYNTHETIC-GIRO',
                                                'name': '합성지자체'}])
        self.assertEqual(result['session_processing_issues'], [])
        self.assertNotIn('SYNTHETIC', str(result['events']))
        self.assertEqual(self.server.steps[before:], ['local.provinces', 'local.districts'])
        self.assertEqual(self.server.calls[-1][1]['areaCode'], ['SYNTHETIC-AREA'])
        with patch('giro.query_flow.SessionStore', return_value=self.store):
            result, code = run(parser().parse_args(['bills', 'regions', '--type', 'local', '--area-code', 'SYNTHETIC-AREA', '--send']))
            self.assertEqual((code, result['area_code']), (0, 'SYNTHETIC-AREA'))
            result, code = run(parser().parse_args(['bills', 'regions', '--type', 'local', '--area-code', 'UNLISTED', '--live']))
            self.assertEqual((code, result['next_action'], result['districts']), (0, 'local_region_unavailable', None))
            self.server.responses['local.provinces'] = (200, {'responseCode': '311'})
            result, code = run(parser().parse_args(['bills', 'regions', '--type', 'local', '--send']))
            self.assertEqual((code, result['app_success'], result['provinces']), (2, False, None))
        self.assertNotIn('local.list', self.server.steps)
        self.assertEqual(self.server.steps.count('auth.pin'), 1, 'the saved login is used as it is')

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
        self.assertEqual(self.server.calls[-1][1]['startDate'], ['2026-10-01'])
        self.assertEqual(self.server.calls[-1][1]['endDate'], ['2026-10-03'])
        self.assertEqual(self.server.steps.count('auth.pin'), 1)

    def test_receipt_period_uses_hyphenated_dates_and_preserves_null(self):
        self.server.responses['receipts.list'] = (200, {'responseCode': '000', 'receiptList': None})
        result = list_receipts(date(2026,4,12), date(2026,10,9), send=True, store=self.store)
        self.assertTrue(result['app_success'])
        self.assertIsNone(result['receipts'])
        fields = self.server.calls[-1][1]
        self.assertEqual(fields['startDate'], ['2026-04-12'])
        self.assertEqual(fields['endDate'], ['2026-10-09'])
        self.assertEqual(fields['page'], ['1'])
        self.assertEqual(self.server.steps.count('receipts.list'), 1)

    def test_receipt_detail_uses_selected_identifiers_without_releasing_reservation(self):
        reserved = self.journal.reserve('synthetic-payment')
        self.server.responses['receipts.detail'] = (200, {'responseCode': '000', 'receiptItem':
            [None, {'n': '납부액', 'v': '100'}, {'n': 'unknown label', 'v': None}]})
        ids = {'sortCode': '01', 'giroNo': 'SYNTHETIC', 'key': 'KEY', 'paidDate': '20261003'}
        result = receipt_detail({**ids, 'acntPwd': 'DO-NOT-SEND'}, send=True, store=self.store)
        self.assertTrue(result['app_success'])
        self.assertEqual(result['items'], [None, {'name':'납부액','value':'100'},
                                          {'name':'unknown label','value':None}])
        fields = self.server.calls[-1][1]
        for key, value in ids.items(): self.assertEqual(fields[key], [value])
        self.assertNotIn('acntPwd', fields)
        self.assertFalse(result['payment_reservation_changed'])
        self.assertTrue(reserved.exists())
        self.assertNotIn('national.payment', self.server.steps)

    def test_registered_account_query_masks_numbers_and_retains_nulls(self):
        self.server.responses['accounts.registered'] = (200, {'responseCode': '000',
            'userAcntList': [None, {'acntNo':'SYNTHETIC-1234', 'bankName':'합성은행',
                                  'acntStatus': 'unknown-status', 'manageName': '이름'}]})
        result = registered_accounts(send=True, store=self.store)
        self.assertTrue(result['app_success'])
        self.assertIsNone(result['accounts'][0])
        self.assertEqual(result['accounts'][1]['account_status'], 'unknown-status')
        self.assertEqual(result['accounts'][1]['account_masked'], '**********1234')
        self.assertNotIn('SYNTHETIC-1234', str(result))
        self.assertEqual(self.server.steps.count('auth.pin'), 1)

    def payment(self, confirm, action='pay'):
        from giro.payment_flow import PaymentWorkflow
        def workflow(client): return PaymentWorkflow(client, journal=self.journal)
        with patch('giro.payment_cli.private_terminal'), patch('giro.payment_cli.SessionStore', return_value=self.store), \
             patch('giro.payment_cli.PaymentWorkflow', side_effect=workflow), \
             patch('giro.payment_cli.answer', return_value=confirm) as approval, \
             patch('giro.payment_cli.secret', return_value='1234') as secret:
            result = run_payment(SimpleNamespace(live=True, amount=None, action=action, type='national'))
        return result, approval, secret

    def test_cancelled_review_never_collects_password_or_sends_payment(self):
        accounts = self.server.responses['accounts.payable'][1]['myValidAccountList']
        next(row for row in accounts if row is not None)['manageName'] = '생활비(합성)'
        (result, code), approval, secret = self.payment('취소')
        self.assertEqual(code, 0)
        self.assertFalse(result['payment_attempted'])
        self.assertIn('900,000', approval.call_args[0][0])
        self.assertIn('생활비(합성) · ', approval.call_args[0][0])
        self.assertEqual(result['review']['account_alias'], '생활비(합성)')
        secret.assert_not_called()
        self.assertNotIn('national.payment', self.server.steps)

    def test_prepare_returns_review_without_payment_confirmation_password_or_reservation(self):
        (result, code), approval, secret = self.payment('납부', action='prepare')
        self.assertEqual(code, 0, result)
        self.assertEqual(result['next_action'], 'review_ready')
        self.assertEqual(result['review']['amount'], 900000)
        self.assertFalse(result['payment_attempted'])
        approval.assert_not_called()
        secret.assert_not_called()
        self.assertFalse(self.journal.root.exists())
        self.assertEqual([event['endpoint'] for event in result['events']],
                         ['national.list', 'national.detail', 'accounts.payable', 'auth.datetime'])

    def test_normalization_error_preserves_service_success(self):
        with patch('giro.query_flow.normalize_pages', side_effect=ValueError('PRIVATE')):
            result = list_bills('national', send=True, store=self.store)
        self.assertTrue(result['app_success'])
        self.assertEqual(result['service_decision'], 'success')
        self.assertFalse(result['complete'])
        self.assertIsNone(result['bills'])
        self.assertIn('bill_normalization_incomplete', result['processing_issues'])
        self.assertNotIn('PRIVATE', str(result))
        self.assertEqual(self.server.steps.count('national.list'), 1)

    def test_later_python_error_preserves_first_page_and_never_retries(self):
        client = AuthenticatedClient(self.session)
        self.server.responses['national.list'] = (200, page(1, 2, 2))
        first = client.query('national.list', {}, send=True)
        with patch.object(client, 'query', side_effect=[first, OSError('PRIVATE')]) as query:
            result = collect_bills(client, 'national')
        self.assertTrue(result['app_success'])
        self.assertEqual(result['service_decision'], 'partial_success')
        self.assertEqual(result['loaded_count'], 1)
        self.assertFalse(result['complete'])
        self.assertEqual(query.call_count, 2)
        self.assertIn('query_processing_incomplete', result['processing_issues'])
        self.assertNotIn('PRIVATE', str(result))

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
