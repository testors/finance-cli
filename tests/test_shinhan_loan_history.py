"""Loan-only history selection, pagination and monthly evidence; no bank traffic."""
import base64
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.core import storage
from finance_cli.services.shinhan import loan_history, loan_history_protocol as protocol, setup, transport
import test_shinhan_loan_detail as fixtures
from test_shinhan import PrivateHome, settings


ROW = {'trxSno': 1, 'ysTrxKS20': 'SYN-REPAYMENT', 'tramt': '1,100', 'pramt': '1,000',
       'intAmt': '100', 'trxafDcJan': '99,000', 'trxdt': '2025.01.20'}
INTEREST = {'trxSno': 1, 'ysTrxKS20': '', 'intKS20': 'SYN-INTEREST', 'intAmt': '25',
            'sjdt': '2025.01.01', 'endt': '2025.01.19', 'iyul': '4.25'}


class LoanHistoryTests(PrivateHome):
    selected = fixtures.LoanDetailTests.selected
    save = fixtures.LoanDetailTests.save
    answer = fixtures.LoanDetailTests.answer
    react = fixtures.LoanDetailTests.react

    def setUp(self):
        super().setUp()
        self.install()
        self.settings = setup.load() | {'menu': fixtures.menu()}
        storage.atomic_json(setup.root()/'settings.json', self.settings)
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.state = {'cookie': 'JSESSIONID=SYN-COOKIE', 'authenticated': True, 'credential': 'SYN-CERT',
                      'login': {'user': {'membGdS2': '02', 'loginLevS2': '8'}}}
        self.calls, self.replies = [], []
        def send(payload, cookie, *, show_message=None):
            document = json.loads(payload); key = bytes.fromhex(settings()['bank_key'])
            body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(document['dataBody'])), 16))
            self.calls.append((document['dataHeader'], body, show_message))
            return self.replies.pop(0)
        self.enterContext(patch.object(transport, 'post_web', side_effect=send))
        self.react()

    def test_year_auto_selects_loan_fetches_all_pages_and_saves_months_privately(self):
        self.answer({'grid04': [ROW], 'nextYnL1': 1, 'nxtTrxSnoN10': 9})
        self.answer({'grid04': [INTEREST], 'nextYnL1': 0})
        code, out, err = self.call(['loan-transactions', '--year', '2025', '--send'])
        report = json.loads(out)['result']
        self.assertEqual((code, report['bank_result'], report['query_complete'], report['count']), (0, 'success', True, 1))
        self.assertEqual(report['pages_available'], 2)
        self.assertFalse(report['has_next'])
        self.assertEqual([call[0]['trxCd'] for call in self.calls], [protocol.TRANSACTION]*2)
        self.assertEqual(self.calls[0][1], protocol.request('SYN-SELECTED', '20250101', '20251231'))
        self.assertEqual(self.calls[1][1]['nxtTrxSnoN10'], 9)
        data = storage.read_json(report['data_file'])
        self.assertEqual(data['transactions'][0][1][0]['interestAmount'], '125')
        self.assertEqual(len(data['months']), 12)
        jan, feb = data['months'][:2]
        self.assertEqual(jan['interest_periods'][0]['iyul'], '4.25')
        self.assertEqual(jan['month_end_balance'], '99,000')
        self.assertEqual(feb['month_end_balance'], '99,000')
        self.assertEqual(feb['month_end_balance_status'], 'derived_from_last_transaction')
        self.assertIsNone(jan['month_end_rate'])
        self.assertEqual(Path(report['data_file']).stat().st_mode & 0o777, 0o600)
        for secret in ('SYN-SELECTED', '99,000', 'SYN-REPAYMENT', '4.25'):
            self.assertNotIn(secret, out+err)

    def test_empty_success_produces_twelve_unknown_balances_not_zeroes(self):
        self.answer({'grid04': []})
        report = loan_history.run(year=2025)
        self.assertEqual((report['bank_result'], report['count']), ('success', 0))
        months = storage.read_json(report['data_file'])['months']
        self.assertTrue(all(m['month_end_balance'] is None and m['month_end_rate'] is None for m in months))

    def test_string_next_flag_is_not_coerced_and_unknown_bank_result_can_map(self):
        self.answer({'grid04': [ROW], 'nextYnL1': '1', 'nxtTrxSnoN10': 9}, 'SYN-UNKNOWN')
        report = loan_history.run(year=2025)
        self.assertEqual((report['bank_result'], report['processing_status'], len(self.calls)), ('unknown', 'complete', 1))
        self.assertEqual(report['count'], 1)

    def test_second_page_rejection_preserves_first_page_and_no_month_end_claim(self):
        self.answer({'grid04': [ROW], 'nextYnL1': 1, 'nxtTrxSnoN10': 9})
        self.answer({}, 'FAIL', resultCode='MCM00005')
        report = loan_history.run(year=2025)
        self.assertEqual((report['bank_result'], report['page_result']), ('partial_success', 'failure'))
        self.assertEqual(report['required_action'], 'session_notice')
        self.assertFalse(report['query_complete'])
        data = storage.read_json(report['data_file'])
        self.assertEqual(len(data['pages']), 1)
        self.assertEqual(report['count'], 1)
        self.assertTrue(all(m['month_end_balance'] is None for m in data['months']))
        self.assertEqual(len(self.calls), 2)

    def test_repeated_cursor_stops_without_resending_same_page(self):
        self.answer({'grid04': [ROW], 'nextYnL1': 1, 'nxtTrxSnoN10': 9})
        self.answer({'grid04': [INTEREST], 'nextYnL1': 1, 'nxtTrxSnoN10': 9})
        report = loan_history.run(year=2025)
        self.assertEqual(report['required_action'], 'loan_history_cursor_repeated')
        self.assertEqual(report['bank_result'], 'success')
        self.assertFalse(report['query_complete'])
        self.assertEqual(len(self.calls), 2)

    def test_consumer_errors_preserve_success_and_raw_response(self):
        for body in ({}, {'grid04': None}, {'grid04': [INTEREST]}, None):
            self.answer(body)
            report = loan_history.run(year=2025)
            self.assertEqual((report['bank_result'], report['error']), ('success', 'loan_history_mapping_error'))
            self.assertNotIn('count', report)
            self.assertEqual(storage.read_json(report['data_file'])['pages'], [body])

    def test_file_failure_does_not_stop_paging_or_change_bank_acceptance(self):
        self.answer({'grid04': [ROW], 'nextYnL1': 1, 'nxtTrxSnoN10': 9})
        self.answer({'grid04': [INTEREST]})
        original = storage.atomic_json
        def write(path, value):
            if Path(path).name == 'loan-transactions.json':
                raise OSError('SYN-PRIVATE')
            return original(path, value)
        with patch.object(storage, 'atomic_json', side_effect=write):
            report = loan_history.run(year=2025)
        self.assertEqual((report['bank_result'], report['processing_status'], report['local_status']), ('success', 'complete', 'incomplete'))
        self.assertEqual(len(self.calls), 2)

    def test_scope_login_guards_and_different_destination(self):
        self.selected()
        self.assertEqual(loan_history.run(year=2025)['required_action'], 'loan_history_destination_not_implemented')
        self.react(); self.state['accounts']['credential'] = 'SYN-OTHER'; self.save()
        self.assertEqual(loan_history.run(year=2025)['required_action'], 'loan_list_required')
        self.state['authenticated'] = False; self.save()
        self.assertEqual(json.loads(self.call(['loan-transactions', '--year', '2025', '--send'])[1])['result']['error'], 'login_required')
        self.assertEqual(self.calls, [])

    def test_no_send_and_invalid_dates_do_not_read_settings(self):
        with patch.object(setup, 'load', side_effect=AssertionError('Settings read')):
            self.assertEqual(json.loads(self.call(['loan-transactions', '--year', '2025'])[1])['result']['error'], 'send_required')
            for args in ([], ['--year', '0'], ['--year', '2025', '--start-date', '2025-01-01'],
                         ['--start-date', '2025-02-29', '--end-date', '2025-12-31'], ['--year', '2025', '--loan', '0']):
                code, out, _ = self.call(['loan-transactions', *args, '--send'])
                self.assertEqual(code, 2)
                self.assertFalse(json.loads(out)['result']['network_used'])
        self.assertEqual(self.calls, [])

    def test_date_range_and_sort_only_change_date_filter_and_display_order(self):
        self.answer({'grid04': [ROW, {**ROW, 'trxSno': 2, 'trxdt': '2025.02.28'}]})
        code, out, _ = self.call(['loan-transactions', '--loan', '1', '--start-date', '2025-01-01',
                                 '--end-date', '2025-02-28', '--sort', 'latest', '--send'])
        self.assertEqual(code, 0)
        self.assertEqual(self.calls[0][1], protocol.request('SYN-SELECTED', '20250101', '20250228'))
        data = storage.read_json(json.loads(out)['result']['data_file'])
        self.assertEqual(data['transactions'][0][0], '2025.02.28')


class MonthlyEvidenceTests(unittest.TestCase):
    def months(self, rows, complete=True, end='20251231'):
        pages = [{'grid04': rows}]
        return protocol.monthly(pages, protocol.transactions(pages), '20250101', end, complete)

    def test_no_opening_balance_and_no_same_day_order_assumption(self):
        rows = [{**ROW, 'trxdt': '2025.02.28'}, {**ROW, 'trxSno': 2, 'trxdt': '2025.02.28', 'trxafDcJan': '98,000'}]
        months = self.months(rows)
        self.assertIsNone(months[0]['month_end_balance'])
        self.assertIsNone(months[1]['month_end_balance'])
        self.assertIsNone(months[2]['month_end_balance'])

    def test_partial_month_or_unknown_dates_cannot_justify_month_end_balance(self):
        self.assertIsNone(self.months([ROW], end='20250120')[0]['month_end_balance'])
        months = self.months([ROW, {**ROW, 'trxSno': 2, 'trxdt': 'SYN-UNKNOWN'}])
        self.assertIsNone(months[0]['month_end_balance'])
        self.assertEqual(months[0]['unassigned_transaction_count'], 1)

    def test_rate_segments_are_accrual_periods_not_payment_date_snapshots(self):
        rows = [{**ROW, 'trxdt': '2025.03.10'}, {**INTEREST, 'sjdt': '2025.02.10', 'endt': '2025.03.09'}]
        months = self.months(rows)
        self.assertEqual(months[1]['transaction_count'], 0)
        self.assertEqual(months[1]['interest_periods'][0]['iyul'], '4.25')
        self.assertEqual(months[2]['transaction_count'], 1)
        self.assertIsNone(months[1]['month_end_rate'])
