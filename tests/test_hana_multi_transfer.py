"""Synthetic personal batch preparation, one CMS submission and partial outcomes."""
import copy
import io
import json
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch

import test_hana_onesign as fixture
from finance_cli.cli.main import main
from finance_cli.services.hana import onesign_cli, onesign_transfer as transfer, onesign_multi_transfer as batch
from finance_cli.services.hana import onesign_crypto as pin, hana_protocol
from finance_cli.services.hana.onesign_codec import encode


class Services(fixture.Services):
    def __init__(self, *args):
        super().__init__(*args)
        self.rows, self.signed = [], []
        self.failure_at = None
        self.execution = None
        self.changed = False

    def bank(self, path, body):
        if path == transfer.PATHS['withdrawal']:
            value = super().bank(path, body)
            value['ourAcctList'][0]['rmteNm'] = '합성출금인'
            return value
        if path == transfer.PATHS['recent_accounts']:
            return {'cmCertsYn': 'N', 'bot1TrnsLimAmt': 5000, 'dd1TrnsLimAmt': 10000, 'tdyTrnsAmt': 0}
        if path == batch.PATHS['recipient']:
            value = json.loads(body)
            assert value['trscDvCd'] == '2' and value['wthrNm'] == '합성출금인'
            return {'rmteNm': '합성수취인', 'rcvPsbkMarkCtt': '합성출금인', 'wdrwPsbkMarkCtt': '합성수취인',
                    'rcvAcctSefYn': 'Y' if self.own else 'N'}
        if path == batch.PATHS['multi_pretransaction']:
            value = json.loads(body)
            index = len(self.rows) + 1
            assert value['trnsNo'] == index and 'trnsSeqNo' not in value and 'addTrnsYn' not in value
            assert value['sessTrnsInfoIntzYn'] == ('Y' if index == 1 else 'N')
            if index == self.failure_at:
                raise RuntimeError('PRIVATE response')
            row = dict(self.row, wdrwAcctNo=value['paymAcctNo'], rcvBnkCd=value['rcvBnkCd'], rcvAcctNo=value['rcvAcctNo'],
                       trnsAmt=value['trnsAmt'], trnsSeqNo=index, delYn='N', saveYn='Y',
                       rcvPsbkMarkCtt=value['rcvPsbkMarkCtt'], wdrwPsbkMarkCtt=value['wdrwPsbkMarkCtt'],
                       slctDvCd=value['slctDvCd'], fncFrdDgnsNcsyYn='N')
            self.rows.append(row)
            rows = copy.deepcopy(self.rows)
            if self.changed:
                rows[-1]['rcvAcctNo'] = '0009999999'
            return {'trnsList': rows, 'totlTrnsAmt': sum(r['trnsAmt'] for r in self.rows),
                    'trnsRsevTrscTmsgUnqNo': 'SYNTHETIC-MULTI-ID', 'rcvAcctSefYn': 'Y' if self.own else 'N'}
        if path == transfer.PATHS['password']:
            assert 'wdrwAcctVrfcYn' not in json.loads(body)
            return super().bank(path, body)
        if path in (transfer.PATHS['execute_self'], transfer.PATHS['execute_other']):
            value = json.loads(body)
            assert value['tmsgUnqNo'] == 'SYNTHETIC-MULTI-ID'
            if self.own:
                assert set(value) == {'tmsgUnqNo'}
            else:
                signed = fixture.check_cms(value['elecSignVluDat'], self.cert)
                self.signed.append(signed)
                for index, row in enumerate(self.rows, 1):
                    assert f'[rcvAcctNo_{index}]' in signed and f'[trnsAmt_{index}]' in signed
                assert signed.count('[sign_sslsignctime]') == 1
            return self.execution if self.execution is not None else {'errNcnt': 0, 'cpltNcnt': len(self.rows),
                    'prgrNcnt': 0, 'trnsList': [dict(r, chnlTrscStCd='03') for r in self.rows]}
        if path == transfer.PATHS['history']:
            return {'rec': [dict(self.history, rcvBnkCd=r['rcvBnkCd'], rcvAcctNo=r['rcvAcctNo'],
                trscAmt=r['trnsAmt'], eChnlTrscAcpnNo=str(i)) for i, r in enumerate(self.rows)]}
        if path == transfer.PATHS['detail']:
            ident = json.loads(body)
            row = self.rows[int(ident['eChnlTrscAcpnNo'])]
            return {'rec': [dict(self.history, **ident, rcvBnkCd=row['rcvBnkCd'], rcvAcctNo=row['rcvAcctNo'], trscAmt=row['trnsAmt'])]}
        return super().bank(path, body)


class MultiTests(unittest.TestCase):
    setUpClass = classmethod(fixture.FlowTests.setUpClass.__func__)
    setUp = fixture.FlowTests.setUp
    op = fixture.FlowTests.op
    before_issue = fixture.FlowTests.before_issue
    enroll = fixture.FlowTests.enroll
    login = fixture.FlowTests.login

    def ready(self, count=2):
        self.services = Services(self.state, self.cert, self.public)
        self.login()
        self.items = [{'to_bank': '004' if i % 2 == 0 else '081', 'to_account': f'0002000000{i:02}',
                       'amount': str(100 + i), 'credit_memo': '10월급여'} for i in range(count)]

    def tr(self, action, **kwargs):
        return transfer.operate(self.state, action, send=True, inputs=self.inputs, exchange=self.services,
            intent={'source_account': fixture.SOURCE, 'items': self.items}, **kwargs)

    def test_whole_batch_then_single_signed_submission_and_reconciliation(self):
        self.ready()
        before = len(self.services.calls)
        prepared = self.tr('prepare-batch')
        self.assertEqual(prepared['state'], 'prepared', prepared)
        self.assertEqual(prepared['amount_krw'], 201)
        self.assertEqual(prepared['items'][0]['credit_memo'], '10월급여')
        paths = [c[1] for c in self.services.calls[before:]]
        self.assertEqual(paths, [transfer.PATHS[k] for k in ('withdrawal', 'session_accounts', 'recent_accounts')]
            + [batch.PATHS['recipient']] * 2 + [batch.PATHS['multi_pretransaction']] * 2
            + [transfer.PATHS[k] for k in ('keypad_key', 'password', 'auth_means')])
        for _, path, headers, _ in self.services.calls[before:]:
            if path != transfer.PATHS['keypad_key']:
                self.assertEqual(hana_protocol.decode_header(headers['hana-com-header'])['CNL_HDPT']['SCRN_ID'], batch.SCREEN)
        shown = transfer.operate(self.state, 'show')
        self.assertEqual(shown['items'], prepared['items'])
        self.assertFalse(shown['network_used'])
        result = self.tr('execute')
        self.assertEqual(result['transfer_status'], 'completed', result)
        self.assertEqual(len(self.services.signed), 1)
        observed = self.tr('reconcile')
        self.assertTrue(observed['candidate_complete'], observed)
        self.assertEqual(len(observed['items']), 2)
        self.assertFalse(observed['transfer_confirmed'])
        before = len(self.services.calls)
        rejected = self.tr('execute', transaction=prepared['transaction'])
        self.assertEqual(rejected['processing_status'], 'stopped')
        self.assertEqual(len(self.services.calls), before)

    def test_fifteen_rows_and_pin_signing(self):
        self.ready(15)
        self.services.auth['pinCertYn'] = 'Y'
        prepared = self.tr('prepare-batch')
        self.assertEqual(prepared['authentication']['bridge_type'], 'pinHalf', prepared)
        result = self.tr('execute')
        self.assertEqual(result['completed_count'], 15, result)
        self.assertIn('[rcvAcctNo_15]', self.services.signed[0])

    def test_all_self_accounts_skip_password_and_signing(self):
        self.ready()
        self.services.own = True
        before = len(self.services.calls)
        self.assertEqual(self.tr('prepare-batch')['state'], 'prepared')
        self.assertEqual(self.tr('execute')['transfer_status'], 'completed')
        paths = [c[1] for c in self.services.calls[before:]]
        self.assertNotIn(transfer.PATHS['password'], paths)
        self.assertNotIn(pin.BANK_NONCE_PATH, paths)
        self.assertEqual(paths.count(transfer.PATHS['execute_self']), 1)

    def test_interrupted_preparation_cannot_send_earlier_subset(self):
        self.ready()
        self.services.failure_at = 2
        prepared = self.tr('prepare-batch')
        self.assertEqual(prepared['error'], 'transport_interrupted_no_automatic_retry', prepared)
        self.assertNotIn('PRIVATE', json.dumps(prepared))
        ctx = self.state.snapshot()['transfers'][prepared['transaction']]
        self.assertEqual(ctx['prepared_items'], 1)
        before = len(self.services.calls)
        result = self.tr('execute', transaction=prepared['transaction'])
        self.assertEqual(result['error'], 'transfer_not_prepared_or_already_attempted')
        self.assertEqual(len(self.services.calls), before)

    def test_confirmation_cancel_precedes_nonce_and_can_be_reviewed_again(self):
        self.ready()
        p = self.tr('prepare-batch')
        self.inputs['confirm'] = lambda _: False
        before = len(self.services.calls)
        result = self.tr('execute')
        self.assertEqual(result['error'], 'transfer_confirmation_required')
        self.assertEqual(len(self.services.calls), before)
        self.assertEqual(self.state.snapshot()['transfers'][p['transaction']]['state'], 'prepared')

    def test_otp_route_remains_unavailable(self):
        self.ready()
        self.services.auth['otpCertYn'] = 'Y'
        p = self.tr('prepare-batch')
        self.assertEqual(p['state'], 'authentication_review', p)
        before = len(self.services.calls)
        self.assertEqual(self.tr('execute', transaction=p['transaction'])['processing_status'], 'stopped')
        self.assertEqual(len(self.services.calls), before)

    def test_partial_result_survives_response_storage_failure(self):
        self.ready()
        p = self.tr('prepare-batch')
        self.services.execution = {'errNcnt': 1, 'cpltNcnt': 1, 'prgrNcnt': 0,
            'trnsList': [{'chnlTrscStCd': '03'}, {'chnlTrscStCd': '06', 'errMsg': 'PRIVATE'}]}
        original = self.state.record
        def record(run, name, value):
            if name.endswith('-response') and value.get('execution_result'):
                raise OSError('PRIVATE storage')
            return original(run, name, value)
        with patch.object(self.state, 'record', side_effect=record):
            result = self.tr('execute')
        self.assertTrue(result['accepted'], result)
        self.assertEqual(result['execution_result']['transfer_status'], 'partial')
        self.assertFalse(result['execution_result']['original_result_success'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        before = len(self.services.calls)
        self.assertEqual(self.tr('execute', transaction=p['transaction'])['processing_status'], 'stopped')
        self.assertEqual(len(self.services.calls), before)

    def test_partial_result_persisted_and_followup_error_does_not_erase_it(self):
        self.ready()
        self.tr('prepare-batch')
        self.services.execution = {'errNcnt': 1, 'cpltNcnt': 0, 'prgrNcnt': 1}
        self.assertTrue(self.tr('execute')['partial_success'])
        self.services.override[transfer.PATHS['history']] = OSError('PRIVATE')
        result = self.tr('reconcile')
        self.assertTrue(result['execution_result']['partial_success'], result)
        self.assertTrue(result['accepted'], result)

    def test_bank_preview_differences_are_warnings(self):
        self.ready()
        self.services.changed = True
        result = self.tr('prepare-batch')
        self.assertEqual(result['state'], 'prepared', result)
        self.assertIn('bank_confirmation_differs_row_2', result['warnings'])
        self.assertEqual(result['items'][1]['recipient_account'], '0009999999')

    def test_duplicate_rows_cannot_reconcile_to_same_history_row(self):
        self.ready()
        self.items[1] = dict(self.items[0])
        self.assertEqual(self.tr('prepare-batch')['input_summary']['duplicate_rows'], [2])
        self.tr('execute')
        result = self.tr('reconcile')
        self.assertFalse(result['candidate_complete'])
        self.assertFalse(any(i['candidate_complete'] for i in result['items']))

    def test_invalid_later_row_is_rejected_before_bank_requests(self):
        self.ready()
        self.items[1]['amount'] = 'PRIVATE'
        before = len(self.services.calls)
        result = self.tr('prepare-batch')
        self.assertFalse(result['network_used'], result)
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertEqual(before, len(self.services.calls))

    def test_limits_block_before_preparation_requests(self):
        self.ready()
        self.items[0]['amount'] = '6000'
        result = self.tr('prepare-batch')
        self.assertEqual(result['error'], 'per_transfer_limit_exceeded', result)
        self.assertNotIn(batch.PATHS['multi_pretransaction'], [c[1] for c in self.services.calls])

    def test_cli_offline_csv_and_plan_do_not_open_vault(self):
        path = self.root / 'synthetic.csv'
        path.write_text('employee,to_bank,to_account,amount,credit_memo\n합성,004,000123,100,10월급여\n합성,004,000123,100,10월급여\n', encoding='utf-8-sig')
        self.assertEqual(batch.read_items(path)[0]['to_account'], '000123')
        with patch.object(onesign_cli, 'password', side_effect=AssertionError('Secret access forbidden')):
            for argv in [ ['check-batch', '--input', str(path)],
                         ['prepare-batch', '--name', 'absent', '--from-account', '000101', '--input', '/absent.csv'] ]:
                output = io.StringIO()
                with redirect_stdout(output):
                    code = main(['--format', 'json-v1', 'hana', 'transfer', *argv])
                self.assertEqual(code, 0, output.getvalue())
                self.assertFalse(json.loads(output.getvalue())['result']['network_used'])
        self.assertEqual(batch.check(path)['duplicate_rows'], [2])

    def test_csv_errors_are_stable_and_do_not_expose_rows(self):
        for text in ['to_bank,to_account,amount\n004,PRIVATE,100\n',
                     'to_bank,to_account,amount,to_bank\n004,000123,100,004\n',
                     'to_bank,to_account,amount\n' + '004,000123,100\n' * 16]:
            with self.subTest(text=text[:20]):
                path = self.root / 'bad.csv'
                path.write_text(text)
                output = io.StringIO()
                with redirect_stdout(output):
                    code = main(['--format', 'json-v1', 'hana', 'transfer', 'check-batch', '--input', str(path)])
                self.assertNotEqual(code, 0)
                self.assertNotIn('PRIVATE', output.getvalue())


class OutcomeTests(unittest.TestCase):
    def test_multi_form_has_twelve_fields_and_string_money_default(self):
        for value, expected in [(None, '0'), ('', ''), ({}, '[object Object]'), (True, 'true'), ([1, 2], '1,2')]:
            form = batch.forms([{'cshbUseAmt': value, 'trnsScheDt': '20261009', 'trnsScheTm': '12'}])[0]
            self.assertEqual(len(form), 12)
            self.assertEqual(form[10]['value'], expected)
            self.assertEqual(form[0]['name'], 'wdrwAcctNo')

    def test_status_and_javascript_strict_zero_semantics(self):
        cases = [({'errNcnt': 0}, 'completed', True, True),
                 ({'errNcnt': '0'}, 'unconfirmed', None, False),
                 ({'errNcnt': 2, 'cpltNcnt': 0, 'prgrNcnt': 0}, 'failed', False, False),
                 ({'errNcnt': 1, 'cpltNcnt': 1}, 'partial', True, False),
                 ({'errNcnt': 1, 'prgrNcnt': 1}, 'partial', True, False),
                 ({}, 'unconfirmed', None, None),
                 ({'trnsList': [{'chnlTrscStCd': '06'}]}, 'failed', False, False)]
        for value, status, accepted, original in cases:
            with self.subTest(value=value):
                result = batch.observe_execution(encode(value))['execution_result']
                self.assertEqual((result['transfer_status'], result['accepted'], result['original_result_success']),
                                 (status, accepted, original))
        value = {'trnsList': [{}, {'chnlTrscStCd': '03', 'errMsg': 'error'}, {'chnlTrscStCd': '07'}]}
        result = batch.observe_execution(encode(value))['execution_result']
        self.assertEqual([r['original_result_success'] for r in result['items']], [True, False, True])

    def test_no_send_service_accepts_no_state_or_secrets(self):
        self.assertFalse(transfer.operate(None, 'prepare-batch')['network_used'])


if __name__ == '__main__':
    unittest.main()
