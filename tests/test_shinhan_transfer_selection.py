"""Synthetic entry/list contracts and encrypted transport, with no bank IO."""
import base64
import json
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.services.shinhan import setup, transfer_selection as selection, transport
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, response


class SelectionTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))

    def test_requests_preserve_empty_and_hyphenated_account(self):
        self.assertEqual(selection.check_request(), {'srchNoS30': ''})
        self.assertEqual(selection.check_request(' SYN-01-02 '), {'srchNoS30': ' SYN-01-02 '})
        self.assertEqual(selection.withdrawal_request(), {})
        with self.assertRaises(ValueError):
            selection.check_request(None)

    def test_optional_null_retains_previous_value_but_null_row_is_rejected(self):
        value = selection.decode('{jiAcNo:first,jiAcNo:null,jiPsbAmt_originalValue:12.9,jiPsbAmt_originalValue:null}')
        self.assertEqual((value['jiAcNo'], value['jiPsbAmt_originalValue']), ('first', 12.9))
        self.assertEqual(selection.decode('{grid01:null}', selection.WITHDRAWAL), {'grid01': []})
        for raw in ('{grid01:[null]}', '{grid01:[true]}', '{grid01:{}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                selection.decode(raw, selection.WITHDRAWAL)

    def test_flags_use_endpoint_specific_fields_and_exact_Y(self):
        for flag in ('Y', 'y', ' Y', 'Y ', '', None):
            first = selection.initial(selection.decode(json.dumps({'shbBankYn': flag, 'handoLimitAcYn': flag})))
            body = selection.decode(json.dumps({'grid01': [{'bnkCS5': '088', 'obnkYn': flag, 'hndoLimtAcYnL1': flag}]}), selection.WITHDRAWAL)
            row = selection.withdrawals(body)[0]
            self.assertEqual(first['withdrawalAccount']['isShinhanBank'], flag == 'Y')
            self.assertEqual((row['isShinhan'], row['isLimitAccount']), (flag == 'Y', flag == 'Y'))
            self.assertEqual(selection.withdrawal_model(row)['needInquiryAmount'], flag != 'Y')

    def test_double_amount_rounding_truncation_and_saturation(self):
        for source, expected in [(12.9, 12), (-12.9, -12), (9007199254740993, 9007199254740992),
                                 (1e308, 2**63-1), (-1e308, -2**63), (-0.0, 0)]:
            value = selection.initial(selection.decode(json.dumps({'jiPsbAmt_originalValue': source})))
            self.assertEqual(value['withdrawalAccount']['withdrawalPossibleAmount'], expected)
        for token in ('NaN', 'Infinity', 'true', '""', '1e309'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                selection.decode('{jiPsbAmt_originalValue:'+token+'}')

    def test_server_limits_and_model_initial_limit_remain_distinct(self):
        value = selection.initial(selection.decode(json.dumps({
            'bf1DdIcheHndoAmtN13': 'SYN-DISPLAY', 'bf1DdIcheHndoAmtN13_originalValue': 1000.9,
            'jiPsbAmt': 'SYN-BALANCE', 'jiPsbAmt_originalValue': 17, 'myAccountList': [{'SYN': True}]})))
        self.assertEqual(value['limit']['day'], {'long': 1000, 'str': 'SYN-DISPLAY'})
        self.assertEqual(value['myAccountList'], [])
        model = selection.initial_model(value)
        self.assertEqual((model['limit']['day'], model['withdrawalAccount']['limit']), (1000, 2**63-1))
        self.assertEqual(model['withdrawalAccount']['withdrawalPossibleAmountDisplay'], '')
        self.assertEqual(value['withdrawalAccount']['withdrawalPossibleAmountDisplay'], 'SYN-BALANCE')

    def test_backup_route_is_not_native_and_has_its_own_program(self):
        for token, expected in [('"2"', 'BackUp'), ('2', 'BackUp'), ('"02"', 'Native'), ('" 2"', 'Native'), ('null', 'Native')]:
            model = selection.initial_model(selection.initial(selection.decode('{transferPrType:'+token+'}')))
            self.assertEqual(model['bridgeType'], expected)
            self.assertEqual(selection.bridge_program(model), 'SM0901S0025F01' if expected == 'BackUp' else '')

    def test_list_preserves_order_duplicates_and_display_rules_without_mutation(self):
        rows = selection.withdrawals(selection.decode(json.dumps({'grid01': [
            {'jiAcnoS20': 'SYN-B', 'jiPsbAmt': '\u00a0', 'jiPsbAmt_originalValue': -1234.5},
            {'jiAcnoS20': 'SYN-A', 'jiPsbAmt': '12원'}, {'jiAcnoS20': 'SYN-B', 'jiPsbAmt': '\u0085'}]}), selection.WITHDRAWAL))
        models = [selection.withdrawal_model(row, balance_error=True) for row in rows]
        self.assertEqual([row['accountNumber'] for row in models], ['SYN-B', 'SYN-A', 'SYN-B'])
        self.assertEqual([row['withdrawalPossibleAmountDisplay'] for row in models], ['-1,234원', '12원원', '\u0085원'])
        self.assertTrue(all(row['balanceErrorMessage'] == '계좌확인필요' for row in models))
        self.assertNotIn('balanceErrorMessage', rows[0])

    def test_entry_failures_are_exact_code_mappings(self):
        self.assertEqual(selection.entry_failure('MDE00001'), {'kind': 'LazyTransferException', 'program': 'CA0511S0011F01'})
        self.assertEqual(selection.entry_failure('MDE00002'), {'kind': 'RegisteredDeviceException', 'program': 'CA0514S0011F01'})
        self.assertEqual(selection.entry_failure('MDE00003'), {'kind': 'SafeTransactionException', 'program': None})
        for code in (None, '', 'mde00001', ' MDE00001', 'MDE00001 ', 'MDE00004'):
            self.assertEqual(selection.entry_failure(code), {'kind': None, 'program': None})

    def test_success_null_or_invalid_body_remains_bank_success(self):
        for parser, bodies in [(selection.parse_check, [None, {'jiAcNo': []}]),
                               (selection.parse_withdrawal, [None, {'grid01': [None]}])]:
            for body in bodies:
                verdict, document = parser(transport.Reply(200, [], response('SUCCESS', body)))
                self.assertEqual((verdict['bank_result'], verdict['processing_status']), ('success', 'incomplete'))
                self.assertIsNone(document['dataBody'])
            verdict, document = parser(transport.Reply(200, [], response('SUCCESS', {})))
            self.assertEqual((verdict['bank_result'], verdict['processing_status']), ('success', 'complete'))

    def test_http_failure_or_unknown_result_is_not_an_entry_denial_code(self):
        for reply in (transport.Reply(503, [], response('FAIL', {}, resultCode='MDE00001')),
                      transport.Reply(200, [], response('OTHER', {}, resultCode='MDE00001')),
                      transport.Reply(error='transport_error')):
            verdict, _ = selection.parse_check(reply)
            self.assertEqual(verdict['bank_result'], 'unknown')
            self.assertNotIn('bank_code', verdict)
        verdict, _ = selection.parse_check(transport.Reply(200, [], response('FAIL', {}, resultCode='MDE00001')))
        self.assertEqual((verdict['bank_result'], verdict['bank_code']), ('failure', 'MDE00001'))
        self.assertEqual(verdict['entry_error'], 'LazyTransferException')
        for parser, body in [(selection.parse_check, {'jiAcNo': []}), (selection.parse_withdrawal, {'grid01': [None]})]:
            verdict, _ = parser(transport.Reply(200, [], response('FAIL', body, resultCode='MDE00001')))
            self.assertEqual((verdict['bank_result'], verdict['processing_status']), ('failure', 'incomplete'))
            self.assertNotIn('entry_error', verdict)
        verdict, _ = selection.parse_withdrawal(transport.Reply(200, [], response('FAIL', {}, resultCode='MDE00001')))
        self.assertNotIn('entry_error', verdict)

    def test_exchange_encodes_exact_body_and_headers_without_retries_or_public_accounts(self):
        self.install(); settings = setup.load()
        state = {'cookie': 'JSESSIONID=SYN-COOKIE'}
        exchange = Exchange(settings, state, 'synthetic-transfer-entry')
        sent = []
        def send(payload, cookie, *, path):
            value = json.loads(payload); key = bytes.fromhex(settings['bank_key'])
            plain = unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(value['dataBody'])), 16)
            sent.append((value['dataHeader'], json.loads(plain), cookie, path))
            return transport.Reply(200, [], response('SUCCESS', {}))
        with patch.object(transport, 'post', side_effect=send):
            for stage, transaction, body, parser in [
                ('check', selection.CHECK_TRANSACTION, selection.check_request('SYN-ACCOUNT'), selection.parse_check),
                ('list', selection.WITHDRAWAL_TRANSACTION, selection.withdrawal_request(), selection.parse_withdrawal)]:
                step, document = exchange.bank(stage, transaction, body, path=selection.ENDPOINT, response_parser=parser)
                self.assertEqual(step['bank_result'], 'success')
        self.assertEqual(len(sent), 2)
        self.assertEqual([row[1] for row in sent], [{'srchNoS30': 'SYN-ACCOUNT'}, {}])
        for header, _, cookie, path in sent:
            self.assertEqual((header['uuid'], header['encG'], header['appG']), (settings['device']['device_id'], '1', 'supersol'))
            self.assertEqual((cookie, path), ('JSESSIONID=SYN-COOKIE', '/serviceEndpoint/httpDigital/'))
        public = json.dumps(exchange.report)
        self.assertNotIn('SYN-ACCOUNT', public)
        self.assertNotIn('SYN-COOKIE', public)
        self.assertFalse(exchange.report['automatic_retry'])
