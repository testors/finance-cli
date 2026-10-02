"""Corporate business fixtures never connect to an institution."""
import contextlib
from datetime import date
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from finance_cli.cli.main import main
from finance_cli.core import storage
from finance_cli.services.hana_corporate import protocol, queries, store


class QueryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(Path(temp.name).resolve())}))
        self.enterContext(patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden')))
        self.cookies = [{'name': 'SYNTHETIC-CORPORATE', 'value': 'SYNTHETIC-COOKIE'}]
        self.calls = []
        self.responses = {}

    def session(self, name='company'):
        store.create(name, store.default_device())
        path = store.session_path(name)
        store.record(path / 'login-attempt.json', {'login_method': '1'})
        store.record(path / 'session.json', {'channel': 'corporate', 'login_verified': True,
                     'login_method': '1', 'cookies': self.cookies})
        return path

    def exchange(self, scope, method, url, headers, body, cookies, timeout):
        stage = next(k for k, p in protocol.PATHS.items() if p == urlsplit(url).path)
        self.assertEqual(urlsplit(url).netloc, 'cmb.hanabank.com')
        self.assertEqual(cookies, self.cookies)
        values = parse_qs((body or b'').decode(), keep_blank_values=True)
        self.calls.append((stage, values))
        defaults = {'server-time': {'date': '20261003', 'time': '120000'},
                    'account-info': {'outMap': {'ACCT_NO': '000101', 'ACCT_INFO': {'accountSequntialNo': '00001', 'currencyCode': 'KRW'}}},
                    'balance': {'PRS_BAL': '1200', 'CUR_CD': 'KRW'}, 'customer-type': {},
                    'loan-sequences': {'rec': [{'ACCT_SEQ_NO': '00001'}, {'ACCT_SEQ_NO': '00002'}]},
                    'loan-detail': {'ciq0011Output': {'PRS_BAL': '1000'}},
                    'accounts': {'outRec01': []}}
        response = self.responses.get(stage, defaults.get(stage))
        if callable(response):
            response = response(values)
        if isinstance(response, Exception):
            raise response
        self.assertIsNotNone(response, stage)
        if 'headerData' not in response:
            response = {'headerData': {'status': '200'}, 'data': response}
        return 200, [], json.dumps(response).encode(), self.cookies

    def test_no_send_reads_nothing(self):
        with patch.object(store, 'select', side_effect=AssertionError('state accessed')):
            self.assertFalse(queries.accounts()['network_used'])
            self.assertFalse(queries.history('000101')['network_used'])
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(main(['--format', 'json-v1', 'hana', 'corporate', 'accounts']), 0)
            self.assertEqual(json.loads(stdout.getvalue())['result']['processing_status'], 'planned')

    def test_missing_session_is_actionable(self):
        output = queries.accounts(send=True, exchange=self.exchange)
        self.assertEqual(output['error'], 'corporate_login_required')
        self.assertFalse(output['network_used'])

    def test_automatic_recent_login_and_account_link(self):
        first = self.session()
        latest = self.session('latest')
        os.utime(first / 'login-attempt.json', (1, 1))
        self.responses['accounts'] = {'outRec01': [{'ACCT_NO': '000101', 'ACCT_SEQ_NO': '00001',
                                                 'BAL': '000.00', 'CUR_CD': 'KRW', 'TOKEN': 'SYNTHETIC-SECRET'}]}
        output = queries.accounts(send=True, exchange=self.exchange)
        self.assertEqual(output['session'], 'latest')
        self.assertTrue(output['accepted'])
        self.assertEqual(output['accounts'][0]['BAL'], '000.00')
        self.assertNotIn('SYNTHETIC-SECRET', json.dumps(output))
        self.assertEqual(storage.read_json(latest / 'session.json')['accounts']['withdrawal'], output['accounts'])

    def test_empty_missing_and_rejected_are_different(self):
        self.session()
        for response, verdict, complete in [({'outRec01': []}, True, True), ({}, True, False),
                ({'headerData': {'status': '500', 'errorCode': 'AUTH_58'}, 'data': {}}, False, False)]:
            with self.subTest(response=response):
                self.responses['accounts'] = response
                output = queries.accounts(send=True, exchange=self.exchange)
                self.assertEqual(output['accepted'], verdict)
                self.assertEqual(output['complete'], complete)

    @staticmethod
    def page(next_flag='N', rows=None):
        return {'REC_CNT': 1, 'ciq0015Output': {'PRS_BAL1': '1000', 'BIZ.SIQ0001.OUT.REC1':
                rows if rows is not None else [{'TRSC_DT': '20261001', 'TRSC_AMT': '001.00', 'BAL_FLCT_DV_CD': '1'}]},
                'nextTrscYn': next_flag, 'trscSeqNo': '00009', 'dtlsSeqNo': '00002', 'wdrwDstnDt': '20260930'}

    def history(self, **kwargs):
        return queries.history('000101', send=True, exchange=self.exchange, **kwargs)

    def test_continuation_retains_strings_and_first_page_fields(self):
        self.session()
        self.responses['history-krw'] = lambda v: self.page('Y' if v['PAGE_NO'] == ['1'] else 'N')
        output = self.history()
        self.assertTrue(output['complete'], output)
        self.assertEqual(len(output['transactions']), 2)
        requests = [v for k, v in self.calls if k == 'history-krw']
        self.assertEqual(requests[0]['NEXT_TRSC_YN'], [''])
        self.assertEqual(requests[0]['INQ_STR_DT'], ['20260927'])
        self.assertNotIn('PAGE_CD', requests[0])
        self.assertNotIn('WDRW_DSTN_DT', requests[0])
        self.assertEqual(requests[1]['TRSC_SEQ_NO'], ['00009'])
        self.assertEqual(requests[1]['DTLS_SEQ_NO'], ['00002'])
        self.assertEqual(output['transactions'][0]['TRSC_AMT'], '001.00')

    def test_later_page_failure_preserves_accepted_rows(self):
        self.session()
        self.responses['history-krw'] = lambda v: self.page('Y') if v['PAGE_NO'] == ['1'] else {
            'headerData': {'status': '500', 'errorCode': 'FRU0001'}, 'data': {}}
        output = self.history()
        self.assertIs(output['accepted'], True)
        self.assertFalse(output['complete'])
        self.assertEqual(len(output['transactions']), 1)
        self.assertEqual(output['error'], 'session_required')
        self.assertEqual(len([k for k, _ in self.calls if k == 'history-krw']), 2)

    def test_customer_type_failure_does_not_gate_query(self):
        self.session()
        self.responses['customer-type'] = {'headerData': {'status': '500'}, 'data': {}}
        self.responses['history-krw'] = self.page()
        output = self.history()
        self.assertTrue(output['complete'], output)
        self.assertIn('customer_type_unavailable', output['warnings'])

    def test_storage_failure_is_warning_and_query_continues(self):
        self.session()
        original = store.record
        def record(path, value):
            if path.name == 'response.json':
                raise OSError('SYNTHETIC-PRIVATE')
            return original(path, value)
        self.responses['history-krw'] = self.page()
        with patch.object(store, 'record', side_effect=record):
            output = self.history()
        self.assertTrue(output['accepted'])
        self.assertTrue(output['complete'], output)
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(output))

    def test_zero_and_repeated_continuation_never_loop(self):
        self.session()
        for empty in (True, False):
            self.calls.clear()
            self.responses['history-krw'] = {**self.page('Y'), **({'REC_CNT': 0} if empty else {})}
            output = self.history()
            self.assertIs(output['accepted'], True)
            self.assertFalse(output['complete'])
            self.assertEqual(len([k for k, _ in self.calls if k == 'history-krw']), 1 if empty else 2)

    def test_period_boundaries_and_past_display(self):
        self.assertEqual(queries.storage_boundaries(date(2024, 2, 29)), (date(2022, 2, 28), date(2021, 3, 1)))
        self.assertEqual(queries.periods('20241003', '20251003', date(2026, 10, 3), 'krw', 'latest'),
                         [('20241003', '20251003', 'N')])
        self.assertEqual(queries.periods('20230930', '20231001', date(2026, 10, 3), 'krw', 'latest'),
                         [('20231001', '20231001', 'Y'), ('20230930', '20230930', 'Y')])
        rows, _, _ = queries.history_page({'REC_CNT': 1, 'ciq0104Output': {'BIZ.CIQ0104.OUT.REC': [
            {'TRSC_DT': '20231001', 'TRSC_AMT': '0', 'PAYM_AMT': '00020', 'DLVY_SNTC_CTT1': '합성'}]}}, 'krw', 'Y', 1)
        self.assertEqual(rows[0]['TRSC_AMT'], '0')
        self.assertEqual(rows[0]['display'], {'TRSC_AMT': '00020', 'BAL_FLCT_DV_CD': '2', 'NW_SUMM_PSBK_RMRK': '합성'})

    def test_fund_foreign_loan_request_and_response(self):
        for kind, nested, field, count in [('fund', 'ciq0016Output', 'BIZ.CIQ0016.OUT.REC', 'REC_CNT'),
                ('foreign', 'ciq0015Output', 'BIZ.SIQ0001.OUT.REC1', None),
                ('loan', 'cln0003Output', 'BIZ.CLN0003.OUT.REC', 'REC_NCNT')]:
            body = queries.history_body(kind, '000101', '00001', 'USD', '20260926', '20261003', 'N')
            self.assertNotIn('PAGE_CD', body)
            value = {nested: {field: [{'TRSC_DT': '20261001'}]}, 'nextTrscYn': 'Y', 'cntnTrscDat': '000XYZ'}
            (value[nested] if count else value)[count or 'REC_CNT'] = 1
            rows, cursor, _ = queries.history_page(value, kind, 'N', 1)
            self.assertEqual(len(rows), 1)
            if kind != 'foreign':
                self.assertEqual(cursor['CNTN_TRSC_DAT'], '000XYZ')
            else:
                self.assertEqual(body['FAST_INQ_YN'], '')
                self.assertEqual(body['LN_DPS_TRSC_KIND_DTLS_CD'], '0007')

    def test_all_history_types_run_with_their_own_continuation(self):
        self.session()
        for account, kind, nested, field, count in [('000113', 'fund', 'ciq0016Output', 'BIZ.CIQ0016.OUT.REC', 'REC_CNT'),
                ('000138', 'foreign', 'ciq0015Output', 'BIZ.SIQ0001.OUT.REC1', None),
                ('000140', 'loan', 'cln0003Output', 'BIZ.CLN0003.OUT.REC', 'REC_NCNT')]:
            with self.subTest(kind=kind):
                self.calls.clear()
                def response(values):
                    value = {nested: {field: [{'TRSC_DT': '20261001'}]}, 'cntnTrscDat': '000XYZ',
                             'nextTrscYn': 'Y' if values['PAGE_NO'] == ['1'] else 'N',
                             'trscSeqNo': '00002', 'dtlsSeqNo': '00003', 'wdrwDstnDt': '20261001'}
                    (value[nested] if count else value)[count or 'REC_CNT'] = 1
                    return value
                self.responses['history-' + kind] = response
                self.responses['currencies'] = {'cfx0388Output': {'BIZ.CFX0388.OUT.REC': [{'CUR_CD': 'USD'}]}}
                output = queries.history(account, currency='USD' if kind == 'foreign' else None, send=True, exchange=self.exchange)
                self.assertTrue(output['complete'], output)
                self.assertEqual(len(output['transactions']), 2)
                bodies = [v for k, v in self.calls if k == 'history-' + kind]
                if kind == 'foreign':
                    self.assertEqual(bodies[0]['CUR_CD'], ['USD'])
                    self.assertEqual(bodies[1]['TRSC_SEQ_NO'], ['00002'])
                else:
                    self.assertEqual(bodies[1]['CNTN_TRSC_DAT'], ['000XYZ'])
                if kind == 'loan':
                    self.assertEqual(bodies[0]['ACCT_SEQ_NO'], ['00002'])
                    self.assertEqual(len([k for k, _ in self.calls if k == 'loan-detail']), 2)

    def test_display_clock_failure_uses_local_date_without_rejecting_history(self):
        self.session()
        self.responses['server-time'] = RuntimeError('SYNTHETIC-PRIVATE')
        self.responses['history-krw'] = self.page()
        output = self.history(start='20261001', end='20261003')
        self.assertTrue(output['accepted'], output)
        self.assertTrue(output['complete'])
        self.assertIn('server_time_unavailable_using_local_time', output['warnings'])


if __name__ == '__main__':
    unittest.main()
