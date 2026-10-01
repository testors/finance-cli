import contextlib
from copy import deepcopy
import io
import json
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

from giro.__main__ import main
from giro.compat import loads, read_model
from giro.crypto import PIN_IV, _cbc, decrypt_text, encode_account_password
from giro.errors import GiroError
from giro.payment import (account_options, authentication_route, encode_registered_payment,
                          payment_plan, payment_result, prepare_registered_payment)
from giro.protocol import build_query, endpoint, request_plan
from giro.response import receive, transport_failure


def accounts():
    return {'responseCode': '000', 'myValidAccountList': [
        {'bankCode': '001', 'bankName': '합성은행', 'accountNo': 'SYNTHETIC-ACCOUNT-1234',
         'manageName': 'PRIVATE-NICKNAME', 'bankStatus': 'false'}],
        'bankServiceList': [{'bankCode': '001', 'bankStatus': True, 'disableCode': ''}]}


def payment_fields(amount='1000000'):
    return {'serviceCode': 'SYNTHETIC', 'sortCode': '01', 'giroNo': 'SYNTHETIC-GIRO',
            'key': 'SYNTHETIC-BILL', 'when': '1', '납부금액': amount,
            '납부세액': amount, '거래일시': '20261001121212', 'feeGroup': 'SYNTHETIC'}


class AccountTests(unittest.TestCase):
    def test_screen_bank_status_overrides_account_metadata(self):
        result = account_options(accounts())
        self.assertTrue(result['app_success'])
        self.assertEqual(result['accounts'][0]['availability'], 'available')
        self.assertNotIn('SYNTHETIC-ACCOUNT', json.dumps(result))
        self.assertNotIn('PRIVATE-NICKNAME', json.dumps(result))

    def test_bank_conditions_do_not_erase_success(self):
        for status, disabled, expected in (
            (None, '92', 'unsupported_bank'), ('false', '91', 'bank_unavailable'),
            ('TRUE', '91', 'unsupported_bank'), ('true', '92', 'outside_bank_hours'),
            ('true', 'unrecognized', 'available'), ('Y', '', 'bank_unavailable')):
            with self.subTest(status=status, disabled=disabled):
                document = accounts()
                document['bankServiceList'][0].update(bankStatus=status, disableCode=disabled)
                result = account_options(document)
                self.assertTrue(result['app_success'])
                self.assertEqual(result['accounts'][0]['availability'], expected)

    def test_no_bank_data_is_not_treated_as_available(self):
        for banks, expected in ((None, 'unobserved'), ([], 'bank_not_listed'),
                                ([None], 'bank_not_listed'), ([{}], 'unobserved')):
            document = accounts()
            document['bankServiceList'] = banks
            result = account_options(document)
            self.assertTrue(result['app_success'])
            self.assertEqual(result['accounts'][0]['availability'], expected)

    def test_null_empty_null_rows_and_duplicates(self):
        for rows, expected in ((None, None), ([], 0), ([None], 0)):
            document = accounts()
            document['myValidAccountList'] = rows
            self.assertEqual(account_options(document)['loaded_count'], expected)
        document = accounts()
        item = document['myValidAccountList'][0]
        document['myValidAccountList'] = [None, item, item]
        self.assertEqual([a['index'] for a in account_options(document)['accounts']], [1, 2])

    def test_session_expiry_does_not_publish_stale_accounts(self):
        document = accounts()
        document['responseCode'] = '301'
        result = account_options(document)
        self.assertFalse(result['app_success'])
        self.assertTrue(result['clear_session'])
        self.assertIsNone(result['accounts'])

    def test_model_coercion_and_invalid_duplicate_are_retained(self):
        document = accounts()
        document['myValidAccountList'][0]['accountNo'] = 123456789
        self.assertEqual(account_options(document)['accounts'][0]['account_masked'], '*****6789')
        with self.assertRaises(GiroError):
            account_options(loads('{"responseCode":{},"responseCode":"000"}'))


class PreparationTests(unittest.TestCase):
    KEY = bytes(range(16))

    def test_four_digit_codec_has_independent_blocks(self):
        encoded = bytes.fromhex(encode_account_password('0019', self.KEY))
        self.assertEqual(len(encoded), 64)
        for i, position in enumerate((10, 10, 1, 9)):
            self.assertEqual(_cbc(self.KEY, PIN_IV, encoded[i*16:(i+1)*16], decrypt=True),
                             bytes((5, position)) + bytes(14))
        self.assertEqual(encoded[:16], encoded[16:32])
        for invalid in ('123456', '123', '１２３４', '1234\n', 1234):
            with self.subTest(invalid=invalid), self.assertRaises(GiroError):
                encode_account_password(invalid, self.KEY)

    def test_registered_account_is_bound_without_mutating_input(self):
        fields = payment_fields()
        fields.update(addUserAcntYn='Y', manageName='STALE', acntPwd='STALE-CIPHER')
        before = deepcopy(fields)
        prepared = prepare_registered_payment(fields, accounts(), 1)
        self.assertEqual(fields, before)
        self.assertEqual(prepared.fields['계좌번호'], 'SYNTHETIC-ACCOUNT-1234')
        self.assertEqual(prepared.fields['bankCode'], '001')
        self.assertEqual(prepared.fields['addCertMethod'], '0')
        self.assertEqual(prepared.fields['acntPaymentType'], '1')
        self.assertIsNone(prepared.fields['addUserAcntYn'])
        self.assertIsNone(prepared.fields['acntPwd'])
        self.assertNotIn('SYNTHETIC-BILL', repr(prepared))
        self.assertNotIn('SYNTHETIC-ACCOUNT', repr(prepared))

    def test_encoding_collects_one_account_password_and_sends_nothing(self):
        prepared = prepare_registered_payment(payment_fields(), accounts(), 1)
        password = Mock(return_value='0199')
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            body = encode_registered_payment(prepared, account_password_provider=password,
                                             key=self.KEY, device_id='SYNTHETIC-DEVICE')
        password.assert_called_once_with()
        inner = decrypt_text(parse_qs(body.decode())['encryptedData'][0], self.KEY)
        self.assertIn('계좌번호=SYNTHETIC-ACCOUNT-1234', inner)
        self.assertIn('acntPwd=' + encode_account_password('0199', self.KEY), inner)
        self.assertNotIn('addUserAcntYn', inner)
        self.assertNotIn('pin=', inner)
        self.assertIsNone(prepared.fields['acntPwd'])

    def test_additional_auth_boundary_and_missing_amount(self):
        self.assertEqual(authentication_route('1,000,000'), 'none')
        self.assertEqual(authentication_route('1000001'), 'additional')
        self.assertEqual(authentication_route('1', cert_only=True), 'certificate')
        self.assertEqual(authentication_route(None, link=True, verify_cert_yn='N'), 'none')
        for flag in ('Y', None, '', 'n'):
            self.assertEqual(authentication_route(None, link=True, verify_cert_yn=flag), 'link_certificate')
        for amount in (None, '1.1', '', str(2**63)):
            with self.subTest(amount=amount), self.assertRaises(GiroError):
                authentication_route(amount)

    def test_extra_auth_and_bad_key_do_not_collect_password(self):
        for amount, key in (('1000001', self.KEY), ('100', b'')):
            provider = Mock(side_effect=AssertionError('must not request secret'))
            prepared = prepare_registered_payment(payment_fields(amount), accounts(), 1)
            with self.assertRaises(GiroError):
                encode_registered_payment(prepared, account_password_provider=provider,
                                          key=key, device_id='SYNTHETIC')
            provider.assert_not_called()

    def test_selection_uses_display_order_and_blocks_unavailable(self):
        document = accounts()
        document['myValidAccountList'].insert(0, None)
        self.assertEqual(prepare_registered_payment(payment_fields(), document, 1).fields['bankCode'], '001')
        for index in (0, 2, True):
            with self.subTest(index=index), self.assertRaises(GiroError):
                prepare_registered_payment(payment_fields(), document, index)
        document['bankServiceList'][0]['disableCode'] = '92'
        with self.assertRaises(GiroError):
            prepare_registered_payment(payment_fields(), document, 1)


class PaymentResultTests(unittest.TestCase):
    def test_success_does_not_require_receipt_rows(self):
        for name in ('national.payment', 'hometax.payment'):
            for receipt, expected in ((None, None), ([], 0), ([None], 1)):
                result = payment_result(receive(name, 200, (), json.dumps(
                    {'responseCode': '000', 'receiptItem': receipt})))
                self.assertTrue(result['app_success'])
                self.assertEqual(result['service_decision'], 'success')
                self.assertEqual(result['receipt_count'], expected)

    def test_server_failure_session_expiry_and_timeout_remain_distinct(self):
        for name in ('national.payment', 'hometax.payment'):
            failed = receive(name, 200, (), '{"responseCode":"999","errorInfo":{"errorCode":"81"}}')
            self.assertEqual(payment_result(failed)['callback_code'], '81')
            expired = receive(name, 200, (), '{"responseCode":"300"}')
            self.assertEqual(payment_result(expired)['callback'], 'disconnected_session')
            timed_out = payment_result(transport_failure(name, timeout=True))
            self.assertEqual(timed_out['callback_code'], '601')
            self.assertEqual(timed_out['receipt_state'], 'unobserved')
            self.assertEqual(timed_out['service_decision'], 'unobserved')
            self.assertFalse(timed_out['automatic_retry'])

    def test_models_keep_receipt_and_ignore_unknown_data(self):
        value = read_model({'responseCode': '000', '납부금액': 0, 'unknown': {}}, 'national.payment')
        self.assertEqual(value['납부금액'], '0')
        self.assertNotIn('unknown', value)
        self.assertIn('납부금액=0', build_query('national.payment', value, device_id='SYNTHETIC'))
        self.assertFalse(endpoint('national.payment').describe()['network_enabled'])
        self.assertEqual(request_plan('accounts.payable')['known_defaults'], {'isReserve': 'N'})

    def test_cli_is_offline_and_does_not_expose_private_fields(self):
        for args, document in ((['accounts', 'list', '--input', '-'], accounts()),
                               (['payment', 'plan'], {}),
                               (['payment', 'result', '--type', 'national', '--input', '-'],
                                {'responseCode': '000', '계좌번호': 'PRIVATE-ACCOUNT',
                                 'signedval': 'PRIVATE-SIGNATURE', 'receiptItem': None})):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), patch('sys.stdin', io.StringIO(json.dumps(document))), \
                    patch('socket.socket', side_effect=AssertionError('network forbidden')):
                code = main(args)
            result = json.loads(stdout.getvalue())
            self.assertEqual(code, 0)
            self.assertFalse(result['network_used'])
            self.assertNotIn('PRIVATE-', stdout.getvalue())
        self.assertFalse(payment_plan()['live_payment_ready'])
        self.assertFalse(payment_plan()['hometax_link_uses_registered_account_list'])


if __name__ == '__main__':
    unittest.main()
