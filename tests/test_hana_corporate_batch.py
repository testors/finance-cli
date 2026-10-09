"""Monthly CSV batches: no bank calls, no per-recipient final submissions."""
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from finance_cli.cli.main import main
from finance_cli.core import storage
from finance_cli.services.hana_corporate import batch, protocol, store, transfers
import test_hana_corporate_queries as fixtures


class BatchTests(unittest.TestCase):
    setUp = fixtures.QueryTests.setUp
    session = fixtures.QueryTests.session
    exchange = fixtures.QueryTests.exchange

    def file(self, text):
        path = store.root() / 'payroll.csv'
        path.write_text(text, encoding='utf-8-sig')
        return path

    def fixture(self, count=2):
        self.path = self.session()
        self.items = []
        self.confirmation = {'acctNo': '000101', 'cts0003Output': {}, 'cts0004InRec': self.items}
        def added(values):
            self.items.append({k: v[0] for k, v in values.items()})
            self.items[-1].update(E_CHNL_TRSC_ACPN_NO=str(len(self.items)), DUP_YN='N', COMM='0')
            self.confirmation['totlTrnsAmt'] = sum(int(r['TRNS_AMT']) for r in self.items)
            return {}
        self.responses.update({
            'transfer-init': {'acctList': [{'accountNo': '000101', 'alias': '합성계좌'}, {'accountNo': '000102'}],
                              'custNm': '합성회사', 'owacNm': '합성회사', 'paymPossAmt': '99999999'},
            'transfer-withdrawal': {'custNm': '합성회사', 'owacNm': '합성회사', 'paymPossBal': '99999999'},
            'transfer-recipient': {'resResult': '합성직원'}, 'transfer-amount': {}, 'transfer-prepare': added,
            'transfer-confirm': lambda _: self.confirmation, 'transfer-clear': {},
            'unified-auth': {'LOGINED_TYPE_CD': '1', 'PW_VRFC_YN': 'N', 'SCRT_MDCL_VRFC_YN': 'N', 'SEND_CERT_SBMT_YN': 'N'},
            'transfer-execute': {},
            'transfer-result': lambda _: {'cts0004Output': {'SYNC_YN': 'Y', 'TRNS_EXEC_YN': 'Y',
                'BIZ.CTS0004.OUT.REC1': self.items}, 'cts0004InRec': self.items,
                'cts0004OutRec1': [{**row, 'ERR_CD': 'NCOM10058'} for row in self.items]}})
        return self.file('employee,to_bank,to_account,amount,credit_memo\n' + ''.join(
            f'합성직원{i},081,0002{i:02},1000,10월급여\n' for i in range(count)))

    def prepare(self, path):
        return batch.prepare('000101', path, send=True, exchange=self.exchange)

    def test_whole_batch_prepared_then_single_authorization_and_submission(self):
        output = self.prepare(self.fixture())
        self.assertEqual(output['transfer_status'], 'prepared', output)
        self.assertEqual(output['input_summary']['total_amount'], '2000')
        self.assertEqual(len(output['preview']['items']), 2)
        self.assertFalse(output['transfer_sent'])
        self.assertNotIn('unified-auth', [s for s, _ in self.calls])
        self.assertEqual([s for s, _ in self.calls], ['transfer-init', 'transfer-withdrawal', 'transfer-recipient',
            'transfer-amount', 'transfer-prepare', 'transfer-confirm', 'transfer-init', 'transfer-recipient',
            'transfer-amount', 'transfer-prepare', 'transfer-confirm'])
        init = [v for s, v in self.calls if s == 'transfer-init'][1]
        self.assertEqual(init, {'ACCT_NO': ['000101'], 'ADD_TRANS_YN': ['Y'], 'RE_TRANS_YN': ['N'],
                               'RCV_PSBK_MARK_CTT': [''], 'OWAC_NM': ['합성회사'], 'procGubn': ['']})
        bodies = [v for s, v in self.calls if s == 'transfer-prepare']
        self.assertIn('ACCT_NM', bodies[0])
        self.assertNotIn('ACCT_NM', bodies[1])
        self.assertEqual(bodies[1]['RCV_PSBK_MARK_CTT'], ['10월급여'])
        result = transfers.execute(send=True, exchange=self.exchange)
        self.assertEqual(result['transfer_status'], 'completed', result)
        auth = next(v for s, v in self.calls if s == 'unified-auth')
        self.assertEqual(auth['SIGNED_JSON[0][name]'], ['E_CHNL_TRSC_ACPN_NO_1'])
        self.assertEqual(auth['SIGNED_JSON[14][name]'], ['E_CHNL_TRSC_ACPN_NO_2'])
        self.assertEqual(len([s for s, _ in self.calls if s == 'transfer-execute']), 1)
        self.assertFalse(transfers.execute(send=True, exchange=self.exchange)['network_used'])

    def test_later_invalid_row_causes_no_partial_server_preparation(self):
        path = self.fixture()
        path.write_text('to_bank,to_account,amount\n081,000201,1000\n081,PRIVATE,1000\n')
        with self.assertRaisesRegex(batch.RowError, '^invalid_batch_row$') as raised:
            self.prepare(path)
        self.assertEqual(raised.exception.row, 2)
        self.assertFalse(self.calls)

    def test_mixed_banks_keep_each_clock_request_and_full_recipient_list(self):
        path = self.fixture(12)
        lines = path.read_text(encoding='utf-8-sig').splitlines()
        path.write_text('\n'.join(line.replace(',081,', ',004,') if index % 2 else line
                                  for index, line in enumerate(lines)) + '\n')
        output = self.prepare(path)
        self.assertEqual(output['prepared_items'], 12, output)
        self.assertEqual(len(output['preview']['items']), 12)
        self.assertEqual(len([s for s, _ in self.calls if s == 'server-time']), 6)
        self.assertNotIn('transfer-execute', [s for s, _ in self.calls])

    def test_interrupted_batch_cannot_execute_its_prepared_subset(self):
        path = self.fixture()
        seen = 0
        def recipient(_):
            nonlocal seen
            seen += 1
            if seen == 2:
                raise RuntimeError('PRIVATE')
            return {'resResult': '합성직원'}
        self.responses['transfer-recipient'] = recipient
        output = self.prepare(path)
        self.assertTrue(output['accepted'])
        self.assertEqual(output['prepared_items'], 1)
        self.assertEqual(output['preparing_item'], 2)
        self.assertNotIn('PRIVATE', json.dumps(output))
        self.assertFalse((self.path / 'transfers' / output['transfer'] / 'confirmation.json').exists())
        result = transfers.execute(send=True, exchange=self.exchange)
        self.assertFalse(result['network_used'])
        self.assertEqual(result['error'], 'transfer_preparation_incomplete_use_cancel')
        self.assertFalse(self.prepare(path)['network_used'])
        cancelled = transfers.cancel(send=True, exchange=self.exchange)
        self.assertEqual(cancelled['transfer_status'], 'preparation_cancelled')

    def test_partial_result_is_preserved_after_log_failure_and_never_resent(self):
        self.prepare(self.fixture())
        self.responses['transfer-result'] = {'cts0004Output': {'SYNC_YN': 'Y', 'TRNS_EXEC_YN': 'Y'},
            'cts0004InRec': self.items, 'allErrYn': 'N', 'errYn': 'Y', 'sussCnt': 1, 'errCnt': 1}
        record = store.record
        def failing(path, value):
            if path.name in ('finished.json', 'transfer-execute-received.json'):
                raise OSError('PRIVATE')
            return record(path, value)
        with patch.object(store, 'record', side_effect=failing):
            output = transfers.execute(send=True, exchange=self.exchange)
        self.assertTrue(output['accepted'])
        self.assertEqual(output['transfer_status'], 'partial')
        self.assertEqual(output['sussCnt'], 1)
        self.assertFalse(transfers.execute(send=True, exchange=self.exchange)['network_used'])

    def test_bank_count_difference_is_visible_without_overriding_acceptance(self):
        path = self.fixture()
        self.responses['transfer-confirm'] = {'acctNo': '000101', 'cts0004InRec': []}
        output = self.prepare(path)
        self.assertTrue(output['accepted'], output)
        self.assertIn('batch_confirmation_count_differs_review_bank_items', output['warnings'])

    def test_input_check_preserves_text_identifiers_bom_quoted_notes_and_duplicates(self):
        self.session()
        path = self.file('to_bank,to_account,amount,memo\n081,000201,001000,"합성,급여"\n081,000201,1000,\n')
        items = batch.read_items(path)
        self.assertEqual(items[0]['recipient'], '000201')
        self.assertEqual(items[0]['memo'], '합성,급여')
        output = batch.check(path)
        self.assertEqual(output['duplicate_rows'], [2])
        self.assertEqual(output['total_amount'], '2000')
        self.assertFalse(output['bank_verified'])
        self.assertFalse(self.calls)
        self.assertNotIn('000201', json.dumps(output))

    def test_malformed_or_unknown_columns_do_not_silently_change_payments(self):
        self.session()
        for text in ('to_bank,to_account,amount,amount\n081,000201,1000,2000\n',
                     'to_bank,to_account,amount,unexpected\n081,000201,1000,PRIVATE\n',
                     'to_bank,to_account,amount\n081,000201\n',
                     'to_bank,to_account,amount\n081,000201,1000,EXTRA\n',
                     'to_bank,to_account,amount\n081,000201,1e3\n',
                     'to_bank,to_account,amount\n'):
            with self.subTest(text=text), self.assertRaises(protocol.Stop):
                batch.check(self.file(text))

    def test_no_send_never_opens_csv_session_or_secret(self):
        with patch.object(Path, 'open', side_effect=AssertionError('file access')):
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                code = main(['--format', 'json-v1', 'hana', 'corporate', 'transfer', 'prepare-batch',
                             '--from-account', '000101', '--file', '/missing.csv'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())['result']['processing_status'], 'planned')

    def test_csv_cli_errors_are_json_and_do_not_echo_private_input(self):
        self.session()
        path = self.file('to_bank,to_account,amount\n081,PRIVATE-ACCOUNT,10\n')
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = main(['--format', 'json-v1', 'hana', 'corporate', 'transfer', 'check-batch', '--file', str(path)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue())['result']['error'], 'invalid_batch_row')
        self.assertEqual(json.loads(stdout.getvalue())['result']['input_row'], 1)
        self.assertNotIn('PRIVATE-ACCOUNT', stdout.getvalue())

    def test_duplicate_bank_confirmation_requires_explicit_review(self):
        self.prepare(self.fixture())
        value = storage.read_json(self.path / 'pending-transfer.json')
        path = self.path / 'transfers' / value['transfer'] / 'confirmation.json'
        confirmation = storage.read_json(path)
        confirmation['cts0004InRec'][1]['DUP_YN'] = 'Y'
        storage.atomic_json(path, confirmation)
        self.assertEqual(transfers.execute(send=True, exchange=self.exchange)['error'], 'duplicate_transfer_confirmation_required')
        self.assertEqual(transfers.execute(send=True, allow_duplicate=True, exchange=self.exchange)['transfer_status'], 'completed')


if __name__ == '__main__':
    unittest.main()
