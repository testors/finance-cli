"""Loan/evidence queries against synthetic bank responses; sockets are forbidden."""
import json
from unittest.mock import patch
import unittest
import urllib.request

import test_hana_sessions as fixture
from finance_cli.services.hana import loan_evidence_protocol as wire
from finance_cli.services.hana import login, onesign_queries, onesign_transfer, store
from finance_cli.services.hana.hana_protocol import API, decode_header
from finance_cli.services.hana.onesign_state import State

ACCOUNT = fixture.ACCOUNT
INFO = {'acctNo': ACCOUNT, 'acctSeqNo': '2', 'accountSequentialNo': 2, 'tailNo': '41',
        'acctNm': '합성 대출', 'curCd': 'KRW', 'acctBal': '90000', 'irrt': '4.5',
        'lonExecDt': '20200101', 'expiDt': '20300101'}
LOANS = {'lonAcctList': [INFO], 'butnList': [{'acctNo': ACCOUNT, 'butnDv': 'B0040'}]}
ROW = {'trscDt': '20261001', 'trscSeqNo': '7', 'lnDpsTrscKindCd': '211', 'lnDpsTrscKindNm': '상환',
       'rpayAmt': '-10000', 'orgnInt': '-125', 'commAmt': 0, 'trscAfBal': '90000'}
DOCUMENT = {'vcertDvCd': '03', 'issuRqstNo': 'SYNTHETIC-DOCUMENT',
            'vcertIssuRqstNo': 'SYNTHETIC-APPLICATION', 'apcDt': '20261010', 'apcTm': '150000'}


class ProtocolTests(unittest.TestCase):
    def test_dates_cursor_types_and_omissions(self):
        self.assertEqual(wire.period('20261015'), {'inqStrDt': '20260416', 'inqEndDt': '20261015'})
        self.assertEqual(wire.period('20260831', certificates=True)['inqStrDt'], '20260601')
        first = wire.page_body(ACCOUNT, 2, wire.period('20261015'))
        self.assertEqual([first[k] for k in ('pageNo', 'inqRqreNcnt', 'trscSeqNo', 'dtlsSeqNo')], [1, 20, '0', '0'])
        for flag in ('N', '', None, True, 1, 'y'):
            self.assertIsNone(wire.next_body(first, {'nextTrscYn1': flag}))
        next_ = wire.next_body(first, {'nextTrscYn1': 'Y', 'nextTrscDt1': '20261001', 'trscSeqNo1': 7, 'dtlsSeqNo1': 0})
        self.assertEqual([next_[k] for k in ('pageNo', 'trscSeqNo', 'dtlsSeqNo')], [1, '7', '0'])
        omitted = wire.next_body(first, {'nextTrscYn1': 'Y', 'trscSeqNo1': None})
        self.assertFalse({'wdrwDstnDt', 'trscSeqNo', 'dtlsSeqNo'} & set(omitted))
        self.assertEqual(wire.account_request({'acctNo': ACCOUNT, 'acctSeqNo': 0})[0], 'account')
        self.assertEqual(wire.account_request(INFO)[0], 'loan-account')
        with self.assertRaises(ValueError):
            wire.period('20261015', '20260101', certificates=True)

    def test_detail_matching_and_summary_preserve_values(self):
        rows = [{'trscSeqNo': x} for x in ('7', 7, None, True)]
        self.assertEqual(wire.interest_rows({'gridId': rows}, ROW), [rows[0]])
        self.assertEqual(wire.interest_rows({'gridId': rows}, {'trscSeqNo': 1}), [])
        self.assertIsNone(wire.interest_body({}, {'lnDpsTrscKindCd': 211}))
        loan = wire.loan_summary(INFO, {'apclIrrt1': 0, 'newTrscAmt1': '100000'})
        self.assertEqual((loan['rate'], loan['display_rate'], loan['principal']), (0, '4.5', '100000'))
        self.assertIsNone(loan['contract_period'])
        self.assertEqual(wire.transaction(ROW)['interest'], '-125')

    def test_certificate_codes_sorting_and_identifier(self):
        body = wire.certificate_body('debt', wire.period('20261015', certificates=True))
        self.assertEqual((body['srchDvCd'], body['srchDvNm']), ('2', '부채증명원'))
        older = {**DOCUMENT, 'apcDt': '20261009'}
        rows = wire.certificate_rows({'rslt1': {'sub1': [older], 'gridId1Rowcount': 99},
                                      'rslt2': {'sub1': [DOCUMENT], 'gridId1Rowcount': '0'}})
        self.assertEqual(rows, [DOCUMENT, older])
        self.assertEqual(wire.link_body(DOCUMENT)['issuRqstNo'], 'SYNTHETIC-DOCUMENT')
        self.assertNotIn('vcertIssuRqstNo', wire.link_body(DOCUMENT))
        self.assertEqual(wire.certificate_rows({'rslt1': None, 'rslt2': {'sub1': None}}), [])
        self.assertEqual(wire.certificate_count({'rslt1': {'gridId1Rowcount': '2'}}), '20')


class QueryTests(unittest.TestCase):
    # Reuse synthetic certificates/session setup without inheriting unrelated tests.
    setUpClass = classmethod(fixture.HanaSessions.setUpClass.__func__)
    run_cli = fixture.HanaSessions.run_cli
    logged_in = fixture.HanaSessions.logged_in

    def setUp(self):
        fixture.HanaSessions.setUp(self)
        self.bank.overrides.update({
            '/retrieveMainAcctInfo': fixture.business({'mainAcctList': [
                {'acctNo': ACCOUNT, 'curCd': 'KRW', 'tailNo': '01'}], 'lginYn': 'Y'}),
            '/retrieveOurFundExcnAcct': fixture.business(LOANS),
            '/retrieveLoanSessAcctInfo': fixture.business({'acctInfo': INFO}),
            '/retrieveLonIntList': fixture.business({'lonAccountList': [INFO]}),
            '/retrieveLonExecNo': fixture.business({'grid': [{'acctSeqNo': 88}, {'acctSeqNo': 99}]}),
            '/retrievetxnLon': fixture.business({'grid1': [ROW], 'newTrscAmt1': '100000',
                                                'apclIrrt1': 0, 'newDt1': '20200101'}),
            '/retrievedtlLonInt': fixture.business({'gridId': [
                {'trscSeqNo': 7, 'orgnInt': '999'},
                {'trscSeqNo': '7', 'orgnInt': '-125', 'intCalcStrDt': '20260901',
                 'intCalcEndDt': '20260930', 'apclIrrt': '4.5'}]}),
            '/retrievetxnCersIssuApc': fixture.business({'rslt1': {'sub1': [DOCUMENT]}}),
            '/retrieveProcRslt': fixture.business({'rducUrlAdr': 'https://synthetic.example.invalid/document?secret=synthetic'}),
        })

    def ready(self):
        self.logged_in()
        self.run_cli('accounts', '--session', 's1', '--send')
        self.bank.requests.clear()

    def history(self, *options):
        return self.run_cli('loans', '--account', ACCOUNT, '--send', *options)

    def test_default_session_history_summary_and_receipts(self):
        self.ready()
        code, result = self.run_cli('loans', '--account', ACCOUNT[:6] + '-' + ACCOUNT[6:], '--send')
        self.assertEqual((code, result['accepted'], result['complete']), (0, True, True), result)
        self.assertEqual([url.rsplit('/', 1)[1] for _, url, _, _ in self.bank.requests], [
            'retrieveOurFundExcnAcct', 'retrieveCurrDtm', 'retrieveLonIntList', 'retrieveLonExecNo', 'retrievetxnLon'])
        self.assertEqual(result['loan']['principal'], '100000')
        self.assertEqual(result['loan']['balance'], '90000')
        self.assertEqual(result['loan']['display_rate'], '4.5')
        self.assertEqual(result['execution'], 2)
        self.assertEqual(result['executions'], [{'execution': 1, 'reported_sequence': 88}, {'execution': 2, 'reported_sequence': 99}])
        self.assertEqual(result['transactions'][0]['interest'], '-125')
        request = self.bank.requests[-1]
        self.assertEqual(decode_header(request[2]['hana-com-header'])['CNL_HDPT']['SCRN_ID'], 'INQB0201001001')
        self.assertEqual(json.loads(request[3])['acctSeqNo'], 2)
        for path in store.session_path('s1').glob('loan-query-*/body.bin'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_default_lists_loans_without_a_main_accounts_query(self):
        self.logged_in()
        self.bank.requests.clear()
        code, result = self.run_cli('loans', '--send')
        self.assertEqual((code, result['accepted'], result['complete']), (0, True, True), result)
        self.assertEqual(len(self.bank.requests), 1)
        _, url, headers, body = self.bank.requests[0]
        self.assertTrue(url.endswith('/retrieveOurFundExcnAcct'))
        self.assertIsNone(body)
        self.assertNotIn('content-type', headers)
        self.assertEqual(decode_header(headers['hana-com-header'])['CNL_HDPT']['SCRN_ID'], 'INQB0101001001')
        self.assertEqual([(r['account'], r['name'], r['row']) for r in result['loans']], [(ACCOUNT, '합성 대출', 1)])

    def test_no_deposit_fallback_for_empty_missing_or_unselectable_loan_list(self):
        self.ready()
        for data in ({'lonAcctList': [], 'butnList': LOANS['butnList']},
                     {'dmpyAcctList': [INFO], 'butnList': LOANS['butnList']},
                     {'lonAcctList': [INFO]}):
            self.bank.overrides['/retrieveOurFundExcnAcct'] = fixture.business(data)
            self.bank.requests.clear()
            code, result = self.run_cli('loans', '--send')
            self.assertEqual((code, result['accepted'], result['loans']), (0, True, []))
            self.bank.requests.clear()
            code, result = self.history()
            self.assertEqual((code, result['error']), (2, 'loan_not_in_loan_list'))
            self.assertEqual(len(self.bank.requests), 1)
            self.assertTrue(result['stages'][0]['accepted'])
            self.assertNotIn('transactions', result)

    def test_saved_list_row_selects_duplicate_account_without_requery(self):
        self.ready()
        self.bank.overrides['/retrieveOurFundExcnAcct'] = fixture.business({**LOANS,
            'lonAcctList': [INFO, {**INFO, 'acctSeqNo': '3', 'accountSequentialNo': 3}]})
        code, result = self.history()
        self.assertEqual((code, result['error']), (2, 'loan_selection_ambiguous_use_saved_row'))
        _, listed = self.run_cli('loans', 'list', '--send')
        self.bank.requests.clear()
        code, result = self.run_cli('loans', '--previous', listed['receipt'], '--row', '2', '--send')
        self.assertEqual((code, result['execution']), (0, 3), result)
        self.assertEqual(result['source_receipt'], listed['receipt'])
        self.assertTrue(all(not url.endswith(('/retrieveOurFundExcnAcct', '/retrieveSessAcctInfo',
                                              '/retrieveLoanSessAcctInfo')) for _, url, _, _ in self.bank.requests))
        self.bank.requests.clear()
        code, result = self.run_cli('loans', 'executions', '--previous', listed['receipt'], '--row', '1', '--send')
        self.assertEqual((code, len(self.bank.requests)), (0, 1))
        self.assertTrue(self.bank.requests[0][1].endswith('/retrieveLonExecNo'))

    def test_saved_loan_selection_validation_and_list_storage_failure(self):
        self.ready()
        _, listed = self.run_cli('loans', 'list', '--send')
        self.bank.requests.clear()
        code, result = self.run_cli('loans', '--previous', listed['receipt'], '--row', '2', '--send')
        self.assertEqual((code, result['error'], self.bank.requests), (2, 'saved_loan_row_out_of_range', []))
        self.bank.overrides['/retrieveOurFundExcnAcct'] = fixture.business({**LOANS,
            'lonAcctList': [{**INFO, 'tailNo': '01'}]})
        code, result = self.history()
        self.assertEqual((code, result['error'], len(self.bank.requests)),
                         (2, 'selected_loan_does_not_use_loan_history', 1))
        original = store.write_new

        def write(path, value):
            if path.name == 'body.bin' and 'loan-query-loan-list-' in str(path):
                raise OSError('SYNTHETIC-PRIVATE-ERROR')
            return original(path, value)

        with patch.object(store, 'write_new', write):
            code, result = self.run_cli('loans', '--send')
        self.assertEqual((code, result['accepted'], result['service_status']), (2, True, 'accepted'))
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(result))

    def test_pagination_keeps_duplicates_and_does_not_increase_page_number(self):
        self.ready()
        original = self.bank.open

        def open_(req, timeout=None):
            if req.full_url.endswith('/retrievetxnLon'):
                self.bank.overrides['/retrievetxnLon'] = fixture.business({'grid1': [ROW],
                    'nextTrscYn1': 'Y' if not json.loads(req.data)['nextTrscYn'] else 'N',
                    'nextTrscDt1': '20261001', 'trscSeqNo1': 7, 'dtlsSeqNo1': 0})
            return original(req, timeout)

        with patch.object(self.bank, 'open', open_):
            code, result = self.history('--start', '2020-01-01')
        self.assertEqual((code, len(result['transactions']), result['complete']), (0, 2, True))
        bodies = [json.loads(raw) for _, url, _, raw in self.bank.requests if url.endswith('/retrievetxnLon')]
        self.assertEqual([body['pageNo'] for body in bodies], [1, 1])
        self.assertEqual(bodies[1]['trscSeqNo'], '7')
        self.assertEqual(bodies[0]['inqStrDt'], '20200101')

    def test_repeated_cursor_stops_after_preserving_accepted_pages(self):
        self.ready()
        self.bank.overrides['/retrievetxnLon'] = fixture.business({'grid1': [ROW], 'nextTrscYn1': 'Y',
            'nextTrscDt1': '20261001', 'trscSeqNo1': 7, 'dtlsSeqNo1': 0})
        code, result = self.history()
        self.assertEqual((code, result['accepted'], result['complete'], len(result['pages'])), (2, True, False, 2))
        self.assertIn('repeated_continuation_cursor', result['warnings'])
        self.assertEqual(len(result['transactions']), 2)

    def test_later_rejection_or_transport_loss_keeps_first_page(self):
        self.ready()
        original = self.bank.open
        for interrupted in (False, True):
            def open_(req, timeout=None):
                if req.full_url.endswith('/retrievetxnLon'):
                    if json.loads(req.data)['nextTrscYn']:
                        if interrupted:
                            raise OSError('SYNTHETIC-PRIVATE-TIMEOUT')
                        self.bank.overrides['/retrievetxnLon'] = fixture.business(None, code='1')
                    else:
                        self.bank.overrides['/retrievetxnLon'] = fixture.business({'grid1': [ROW], 'nextTrscYn1': 'Y',
                            'nextTrscDt1': '20261001', 'trscSeqNo1': 7, 'dtlsSeqNo1': 0})
                return original(req, timeout)
            with patch.object(self.bank, 'open', open_):
                code, result = self.history()
            self.assertEqual((code, result['accepted'], result['complete'], len(result['transactions'])), (2, True, False, 1))
            self.assertEqual(result['stages'][-1]['accepted'], None if interrupted else False)
            self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(result))

    def test_auxiliary_failure_does_not_gate_history(self):
        self.ready()
        self.bank.overrides['/retrieveLonExecNo'] = fixture.business(None, code='1')
        self.bank.overrides['/retrieveLonIntList'] = fixture.business(None)
        code, result = self.history()
        self.assertEqual((code, result['accepted'], result['complete']), (0, True, True))
        self.assertIn('executions_unavailable', result['warnings'])
        self.assertIn('loan-accounts_unavailable', result['warnings'])

    def test_success_survives_unusable_body_and_storage_failure(self):
        self.ready()
        self.bank.overrides['/retrievetxnLon'] = fixture.business(None)
        code, result = self.history()
        self.assertEqual((code, result['accepted'], result['service_status']), (2, True, 'accepted'))
        self.bank.overrides['/retrievetxnLon'] = fixture.business({'grid1': [ROW]})
        original = store.write_new

        def write(path, value):
            if path.name == 'body.bin' and 'loan-query-page-' in str(path):
                raise OSError('SYNTHETIC-PRIVATE-ERROR')
            return original(path, value)

        with patch.object(store, 'write_new', write):
            code, result = self.history()
        self.assertEqual((code, result['accepted'], result['service_status']), (2, True, 'accepted'))
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(result))

    def test_interest_uses_saved_row_strict_sequence_and_no_extra_page(self):
        self.ready()
        _, history = self.history()
        receipt = history['transactions'][0]['receipt']
        count = len(self.bank.requests)
        code, result = self.run_cli('loans', 'interest', '--previous', receipt, '--row', '1', '--send')
        self.assertEqual((code, len(self.bank.requests) - count), (0, 1))
        self.assertEqual(result['interest_periods'], [{'start_date': '20260901', 'end_date': '20260930',
            'rate': '4.5', 'interest': '-125', 'remark': None}])
        body = json.loads(self.bank.requests[-1][3])
        self.assertEqual(body, {'acctNo': ACCOUNT, 'acctSeqNo': 2, 'inqStrDt': '20261001', 'inqEndDt': '20261001',
            'inqRqreNcnt': '100', 'lnDpsTrscKindDtlsCd1': '0017', 'nextInqStrRowNo': '0'})
        self.bank.overrides['/retrievetxnLon'] = fixture.business({'grid1': [{**ROW, 'lnDpsTrscKindCd': '121'}]})
        _, history = self.history()
        count = len(self.bank.requests)
        _, local = self.run_cli('loans', 'interest', '--previous', history['pages'][0]['receipt'], '--row', '1', '--send')
        self.assertEqual((len(self.bank.requests), local['network_used'], local['detail_status']), (count, False, 'not_applicable'))

    def test_certificates_link_and_not_ready_do_not_issue_or_fetch(self):
        self.ready()
        code, result = self.run_cli('certificates', '--type', 'debt', '--send', versioned=True)
        self.assertEqual(code, 0)
        result = result['result']
        body = json.loads(self.bank.requests[-1][3])
        self.assertEqual((body['srchDvCd'], body['srchDvNm']), ('2', '부채증명원'))
        for url in ('https://synthetic.example.invalid/document', ''):
            self.bank.overrides['/retrieveProcRslt'] = fixture.business({'rducUrlAdr': url})
            count = len(self.bank.requests)
            code, linked = self.run_cli('certificates', 'link', '--previous', result['receipt'], '--row', '1', '--send')
            self.assertEqual((code, linked['accepted'], linked['complete']), (0, True, True))
            self.assertEqual(linked['document_status'], 'link_available' if url else 'not_ready')
            self.assertEqual(linked['download_status'], 'not_attempted')
            self.assertEqual(len(self.bank.requests), count + 1)
            self.assertEqual(json.loads(self.bank.requests[-1][3]), wire.link_body(DOCUMENT))
        self.assertTrue(all(url.startswith(API) for _, url, _, _ in self.bank.requests))

    def test_null_certificate_list_and_strict_business_rejection(self):
        self.ready()
        for business_code, accepted, exit_code in [('0', True, 0), (1, True, 0), ('2', True, 0), ('1', False, 2)]:
            self.bank.overrides['/retrievetxnCersIssuApc'] = fixture.business(None, code=business_code)
            code, result = self.run_cli('certificates', '--type', 'financial', '--send')
            self.assertEqual((code, result['accepted']), (exit_code, accepted))
            if accepted:
                self.assertEqual(result['certificates'], [])

    def test_invalid_or_foreign_receipt_does_not_send(self):
        self.ready()
        _, result = self.history()
        receipt = result['pages'][0]['receipt']
        path = store.session_path('s1') / receipt / 'request.json'
        saved = json.loads(path.read_text())
        saved['headers']['one-access-token'] = 'SYNTHETIC-OTHER-LOGIN'
        path.write_text(json.dumps(saved))
        count = len(self.bank.requests)
        code, result = self.run_cli('loans', 'interest', '--previous', receipt, '--row', '1', '--send')
        self.assertEqual((code, len(self.bank.requests)), (2, count))
        self.assertIsNone(result['accepted'])

    def test_no_send_and_input_errors_do_not_open_credentials(self):
        from finance_cli.services.hana import onesign_cli
        with patch.object(onesign_cli, 'password', side_effect=AssertionError('Must not ask')), \
                patch.object(State, '__enter__', side_effect=AssertionError('Must not open')):
            for command in (['loans', '--name', 'missing'],
                            ['loans', '--name', 'missing', '--account', ACCOUNT],
                            ['loans', '--name', 'missing', '--previous', 'saved', '--row', '1'],
                            ['certificates', '--name', 'missing', '--type', 'debt'],
                            ['certificates', 'link', '--name', 'missing', '--previous', 'saved', '--row', '1']):
                for versioned in (False, True):
                    code, result = self.run_cli(*command, versioned=versioned)
                    self.assertEqual(code, 0)
                    self.assertFalse((result['result'] if versioned else result)['network_used'])
            code, result = self.run_cli('loans', '--name', 'missing', '--account', ACCOUNT,
                                       '--start', 'SYNTHETIC-PRIVATE', '--send', versioned=True)
            self.assertEqual(code, 2)
            self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(result))
        self.assertEqual(self.bank.requests, [])

    def test_loan_list_and_selection_conflicts_are_rejected_before_io(self):
        for options in (['list', '--account', ACCOUNT], ['list', '--previous', 'saved', '--row', '1'],
                        ['history'], ['--previous', 'saved'], ['--row', '1'],
                        ['--previous', 'saved', '--row', '1', '--account', ACCOUNT],
                        ['--execution', '2']):
            code, result = self.run_cli('loans', *options, '--send', versioned=True)
            self.assertEqual(code, 2, options)
        self.assertEqual(self.bank.requests, [])

    def test_onesign_query_uses_sealed_receipts_and_preserves_storage_failure(self):
        from finance_cli.services.hana import onesign_cli
        self.ready()
        headers = login.authenticated_session(store.session_path('s1'))['headers']
        identity = {'profile': {'device_id': 'SYNTHETIC-DEVICE', 'customer_number': 'SYNTHETIC-CUSTOMER'},
                    'runs': {}, 'sessions': {'s': {'signed_login': True, 'headers': headers, 'cookies': [],
                        'device_id': 'SYNTHETIC-DEVICE', 'customer_number': 'SYNTHETIC-CUSTOMER',
                        'certificate_sha256': 'SYNTHETIC-FINGERPRINT', 'accounts': {'mainAcctList': []}}}}
        with State('synthetic', 'vault-password', identity):
            pass

        def exchange(scope, method, url, headers, body, cookies, timeout):
            response = self.bank.open(urllib.request.Request(url, method=method, headers=headers, data=body))
            return response.code, list(response.headers.items()), response.body, cookies

        with patch.object(onesign_cli, 'password', return_value='vault-password'), \
                patch.object(onesign_queries, 'send_http', exchange), \
                patch.object(onesign_transfer, 'record', return_value=('synthetic', {'fingerprint': 'SYNTHETIC-FINGERPRINT'})):
            code, history = self.history('--name', 'synthetic')
            self.assertEqual((code, history['accepted'], history['complete']), (0, True, True), history)
            code, loans = self.run_cli('loans', '--name', 'synthetic', '--send')
            self.assertEqual((code, len(loans['loans'])), (0, 1))
            before = len(self.bank.requests)
            code, selected = self.run_cli('loans', '--name', 'synthetic', '--previous', loans['receipt'], '--row', '1', '--send')
            self.assertEqual((code, selected['execution'], len(self.bank.requests) - before), (0, 2, 4))
            code, listed = self.run_cli('certificates', '--name', 'synthetic', '--type', 'debt', '--send')
            self.assertEqual(code, 0)
            code, linked = self.run_cli('certificates', 'link', '--name', 'synthetic',
                                       '--previous', listed['receipt'], '--row', '1', '--send')
            self.assertEqual((code, linked['document_status']), (0, 'link_available'))
            original = State.record

            def record(state, run, name, value):
                if name.endswith('-response'):
                    raise OSError('SYNTHETIC-PRIVATE-FAILURE')
                return original(state, run, name, value)

            with patch.object(State, 'record', record):
                code, result = self.run_cli('certificates', 'link', '--name', 'synthetic',
                                           '--previous', listed['receipt'], '--row', '1', '--send')
            self.assertEqual((code, result['accepted'], result['service_status']), (2, True, 'accepted'))
        for path in (store.root('identities') / 'synthetic').rglob('*.json'):
            text = path.read_text()
            for secret in ('USER-TOKEN', ACCOUNT, 'synthetic.example.invalid', 'SYNTHETIC-CUSTOMER'):
                self.assertNotIn(secret, text)


if __name__ == '__main__':
    unittest.main()
