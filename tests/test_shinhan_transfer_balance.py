"""Synthetic balance/limit responses and distinct transfer consumer updates."""
import base64
import json
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.services.shinhan import balance_protocol as balance, setup, transfer_balance as transfer, transfer_selection as selection, transport
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, response


def account():
    return {'accountName': 'SYN-NAME', 'accountNumber': 'SYN-AC', 'bankName': 'SYN-BANK',
        'bankCode': '088', 'bankClassification': '1', 'withdrawalPossibleAmount': 101,
        'isShinhan': True, 'isLimitAccount': True, 'limit': 202, 'needInquiryAmount': False,
        'balanceErrorMessage': 'SYN-ERROR', 'withdrawalPossibleAmountDisplay': 'SYN-DISPLAY',
        'withdrawalPossibleForeignAmount': 3.25, 'productCode': 'SYN-PRODUCT'}


class TransferBalanceTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))

    def test_balance_long_is_exact_while_limit_double_truncates_and_saturates(self):
        for amount in (-(2**63), -1, 0, 9007199254740993, 2**63-1):
            value = balance.entity(balance.decode(json.dumps({'jiUseAmtN182_originalValue': amount})))
            self.assertEqual(value['paymentAvailableBalance'], amount)
        for token in ('9223372036854775808', '-9223372036854775809', '1.0', '1e-1', 'NaN'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                balance.decode('{jiUseAmtN182_originalValue:'+token+'}')
        for amount, expected in [(12.9, 12), (-12.9, -12), (1e308, 2**63-1), (-1e308, -2**63)]:
            self.assertEqual(transfer.limit_amount(balance.decode(json.dumps({'dayJiHdamt': amount}), transfer.LIMIT)), expected)

    def test_optional_null_and_duplicate_fields_keep_previous_nested_values(self):
        body = balance.decode('{jiUseAmtN182_originalValue:7,jiUseAmtN182_originalValue:null,btnList:[{pgmLink:{pgmId:SYN},pgmLink:null}]}')
        self.assertEqual(body['jiUseAmtN182_originalValue'], 7)
        self.assertEqual(body['btnList'][0]['pgmLink'], {'pgmId': 'SYN', 'param': ''})
        for raw in ('{btnList:[null]}', '{btnList:{}}', '{btnList:[{pgmLink:[]}]}'):
            with self.assertRaises(ValueError):
                balance.decode(raw)

    def test_flags_and_error_fallback_do_not_collapse_distinct_error_types(self):
        for flag in (-1, 0, 1, 2):
            for message in ('', '\u00a0\t', '\u0085', 'SYN-MESSAGE'):
                body = balance.decode(json.dumps({'errYnN1': flag, 'errorMessage': message,
                    'isOpenbankingError': 1, 'isOpenbankingNotAvailable': 2, 'isMaintainanceError': 1, 'chkMdErrYn': 'y'}))
                value = balance.entity(body)
                self.assertEqual(value['isError'], flag == 1)
                self.assertEqual(value['balanceErrorMessage'], ('계좌확인필요' if flag == 1 else '') if message in ('', '\u00a0\t') else message)
                self.assertTrue(value['isOpenBankingError']); self.assertTrue(value['isMaintananceError'])
                self.assertFalse(value['isOpenbankingNotAvailable']); self.assertFalse(value['isErrorDuringInspection'])

    def test_button_order_duplicates_and_integer_bank_code_mapping(self):
        button = {'btnNmS100': 'SYN-BUTTON', 'pgmLink': {'pgmId': 'SYN-PROGRAM', 'param': 'SYN-PARAM'}}
        value = balance.entity(balance.decode(json.dumps({'bnkCN3': '0088', 'btnList': [button, {}, button]})))
        self.assertEqual(value['orgCode'], '88')
        self.assertEqual(value['buttonList'][0], value['buttonList'][2])
        self.assertEqual(value['buttonList'][1], {'buttonName': '', 'programLink': {'programId': '', 'param': ''}})

    def test_initial_balance_keeps_display_and_old_error_text_on_success(self):
        before = account()
        updated, status = transfer.initial_balance(before, {'isError': False, 'paymentAvailableBalance': 999})
        self.assertEqual(status, 'success')
        self.assertEqual(updated, {**before, 'withdrawalPossibleAmount': 999})
        updated, status = transfer.initial_balance(before, {'isError': True, 'balanceErrorMessage': 'SYN-NEW-ERROR'})
        self.assertEqual(status, 'error')
        self.assertEqual(updated, {**before, 'balanceErrorMessage': 'SYN-NEW-ERROR'})
        self.assertEqual(before, account())

    def test_limit_response_changes_only_limit_and_error_restores_model_default(self):
        before = account()
        self.assertEqual(transfer.apply_limit(before, -5), {**before, 'limit': -5})
        self.assertEqual(transfer.apply_limit(before), {**before, 'limit': 2**63-1})
        self.assertEqual(before, account())

    def test_list_filters_on_shinhan_flag_and_marks_only_other_accounts_for_inquiry(self):
        rows = selection.withdrawals(selection.decode(json.dumps({'grid01': [
            {'jiAcnoS20': 'SYN-DUP', 'bnkCS5': '088', 'obnkYn': 'N'},
            {'jiAcnoS20': 'SYN-DUP', 'bnkCS5': '999', 'obnkYn': 'Y'},
            {'jiAcnoS20': 'SYN-LAST', 'obnkYn': 'N'}]}), selection.WITHDRAWAL))
        all_rows = transfer.list_items(rows)
        self.assertEqual([row['balance_status'] for row in all_rows], ['loading', 'idle', 'loading'])
        shinhan_rows = transfer.list_items(rows, 'SHINHAN')
        self.assertEqual(len(shinhan_rows), 1)
        self.assertEqual(shinhan_rows[0]['account']['bankCode'], '999')
        self.assertEqual(shinhan_rows[0]['balance_status'], 'idle')

    def test_list_update_uses_index_and_keeps_bank_flags_even_after_success(self):
        before = [{'account': account(), 'balance_status': 'loading'} for _ in range(2)]
        value = balance.entity(balance.decode('{jiUseAmtN182_originalValue:9007199254740993,isOpenbankingError:1,isMaintainanceError:1}'))
        after = transfer.update_item(before, 1, value)
        self.assertEqual(after[0], before[0])
        self.assertEqual(after[1]['balance_status'], 'success')
        self.assertEqual(after[1]['account'], {**account(), 'withdrawalPossibleAmount': 9007199254740993,
            'withdrawalPossibleAmountDisplay': '9,007,199,254,740,993원'})
        self.assertEqual(before[1]['balance_status'], 'loading')
        self.assertEqual(transfer.update_item(before, -1, value), before)
        self.assertEqual(transfer.update_item(before, 2, value), before)

    def test_row_error_keeps_previous_account_and_other_rows(self):
        before = [{'account': account(), 'balance_status': 'loading'} for _ in range(2)]
        for value in (None, {'isError': True, 'balanceErrorMessage': 'SYN-NEW-ERROR'}):
            after = transfer.update_item(before, 0, value)
            self.assertEqual(after[0], {'account': account(), 'balance_status': 'error'})
            self.assertEqual(after[1], before[1])

    def test_envelope_success_survives_body_error_and_fail_is_not_entry_error(self):
        for parser, body in ((balance.parse, {'jiUseAmtN182_originalValue': 'bad'}),
                             (transfer.parse_limit, {'dayJiHdamt': 'bad'})):
            for result in ('SUCCESS', 'FAIL'):
                verdict, _ = parser(transport.Reply(200, [], response(result, body, resultCode='MDE00001')))
                self.assertEqual(verdict['bank_result'], 'success' if result == 'SUCCESS' else 'failure')
                self.assertEqual(verdict['processing_status'], 'incomplete')
                self.assertNotIn('entry_error', verdict)
            verdict, _ = parser(transport.Reply(200, [], response('SUCCESS', None)))
            self.assertEqual((verdict['bank_result'], verdict['processing_status']), ('success', 'incomplete'))

    def test_encrypted_requests_preserve_strings_and_endpoint_slashes(self):
        self.install(); settings = setup.load(); exchange = Exchange(settings, {}, 'synthetic-transfer-balance')
        sent = []
        def send(payload, cookie, *, path):
            wire = json.loads(payload); key = bytes.fromhex(settings['bank_key'])
            body = unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(wire['dataBody'])), 16)
            sent.append((wire['dataHeader']['trxCd'], json.loads(body), path))
            return transport.Reply(200, [], response('SUCCESS', {}))
        with patch.object(transport, 'post', side_effect=send):
            exchange.bank('balance', balance.TRANSACTION, balance.request(' SYN-AC ', '088', ''),
                          path=balance.ENDPOINT, response_parser=balance.parse)
            exchange.bank('limit', transfer.LIMIT_TRANSACTION, transfer.limit_request('SYN-AC'),
                          path=transfer.LIMIT_ENDPOINT, response_parser=transfer.parse_limit)
        self.assertEqual(sent, [('RSMDE1401A02', {'acno': ' SYN-AC ', 'bnkCN3': '088', 'bnkG': '', 'curCS3': ''}, '/serviceEndpoint/httpDigital'),
                                ('RSMDE0105A11', {'acno': 'SYN-AC'}, '/serviceEndpoint/httpDigital/')])
        self.assertNotIn('SYN-AC', json.dumps(exchange.report))
        self.assertFalse(exchange.report['automatic_retry'])
