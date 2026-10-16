"""Issuance business sequencing, conditional requests, and partial success."""
import base64
import json
from unittest.mock import Mock, patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.services.shinhan import issuance_auth as auth, transport
from finance_cli.services.shinhan.enrollment import Pending
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, settings, response


class IssuanceAuthTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.install()
        self.state = {'enrollment': {'identity': {'birth': '900101', 'customerCI': 'SYN-CI',
                      'gender': '1', 'telecom': '1', 'phoneNumber': 'SYN-PHONE'},
                      'customer': {'customerNumber': 'SYN-NUMBER', 'customerName': 'Synthetic Person', 'isNewCIF': False},
                      'resident_identity': {'birth': '900101', 'secret': 'SYN-RRN-ENCRYPTED'},
                      'security_media': {'secrityMdiaGS1': '1', 'secrityCdBnkGS1': 'S'}}}
        self.exchange = Exchange(settings(), self.state, 'certificate_issue')
        self.replies, self.calls = [], []
        self.enterContext(patch.object(transport, 'post_web', self.server))

    def server(self, payload, cookie='', *, path=transport.ENDPOINT):
        envelope = json.loads(payload)
        key = bytes.fromhex(settings()['bank_key'])
        body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(envelope['dataBody'])), 16))
        self.calls.append({'transaction': envelope['dataHeader']['trxCd'], 'body': body,
                           'program': envelope['dataHeader']['programId']})
        return self.replies.pop(0)

    def answer(self, body=None, result='SUCCESS'):
        self.replies.append(transport.Reply(200, [], response(result, body)))

    def test_resident_identity_logged_out_refreshes_customer_after_success_even_if_refresh_rejected(self):
        self.answer({'trxnoS8': 'SYN-TRANSACTION'})
        self.answer({}, 'FAIL')
        result = auth.resident_identity(self.exchange, 'SYN-CIPHER')
        self.assertEqual([call['transaction'] for call in self.calls], ['RSMCM0000A05', 'RSMCM9000A08'])
        self.assertEqual(self.calls[0]['body'], {'trxGS2': '01', 'biryrMmddS6': '900101',
                                                'silno2': 'SYN-CIPHER', 'silnoBigyoYnS1': 'Y'})
        self.assertEqual(result['transactionNumber'], 'SYN-TRANSACTION')
        self.assertEqual(self.exchange.report['resident_identity_verification'], 'success')
        self.assertEqual(self.exchange.report['stages'][-1]['bank_result'], 'failure')

    def test_logged_in_ci_inquiry_failure_does_not_prevent_identity_log(self):
        self.answer({}, 'FAIL')
        self.answer({})
        self.state['enrollment']['customer']['isNewCIF'] = True
        result = auth.resident_identity(self.exchange, 'SYN-CIPHER', login_info={'synthetic': True})
        self.assertEqual([call['transaction'] for call in self.calls], ['RSMCM9000A32', 'RSMCM0000A05'])
        self.assertEqual(self.calls[-1]['body']['silnoBigyoYnS1'], 'N')
        self.assertIsNone(result['transactionNumber'])

    def test_identity_rejection_stops_before_refresh_and_missing_input_sends_nothing(self):
        with self.assertRaises(Pending):
            auth.resident_identity(self.exchange, '')
        self.assertEqual(self.calls, [])
        self.answer({}, 'FAIL')
        with self.assertRaises(Pending):
            auth.resident_identity(self.exchange, 'SYN-CIPHER')
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.exchange.report['resident_identity_verification'], 'failure')

    def test_fds_preserves_device_network_values_and_omits_absent_fields(self):
        self.answer({})
        auth.fds(self.exchange, {'APP_VERSION': '20.0.40', 'OS_TYPE': 'A', 'PHONE_OS': 'SYN-OS', 'PHONE_MODEL': 'SYN-MODEL'},
                 {'countryCode': 'kr', 'useVPN': False})
        self.assertEqual(self.calls[0]['body'], {'trxG': '07', 'appVersion': '20.0.40', 'osType': 'A',
             'osVersion': 'SYN-OS', 'phoneModel': 'SYN-MODEL', 'vpnYn': 'N', 'networkCntryCd': 'kr'})
        self.assertEqual(self.calls[0]['program'], auth.RRN_PROGRAM)
        self.answer({})
        auth.fds(self.exchange, {}, {'useVPN': []})
        self.assertEqual(self.calls[1]['body'], {'trxG': '07', 'vpnYn': 'Y'})

    def test_account_password_switches_only_original_foreign_currency_prefixes(self):
        for prefix in ('110', '180', '181', '185', '182'):
            with self.subTest(prefix=prefix):
                self.answer(None)
                auth.account_password(self.exchange, prefix+'SYN', 'SYN-ACCOUNT-CIPHER')
                call = self.calls[-1]
                foreign = prefix in ('180', '181', '185')
                self.assertEqual(call['transaction'], 'RSMFO0001A02' if foreign else 'RSMDE0301B01')
                self.assertEqual(call['body']['silno' if foreign else 'silnoS13'], 'SYN-RRN-ENCRYPTED')
                self.assertEqual(call['body']['scno6' if foreign else 'jiAcScno'], 'SYN-ACCOUNT-CIPHER')
                self.assertEqual(self.exchange.report['account_password_verification'], 'success')

    def test_password_cancellation_and_unknown_result_do_not_become_bank_rejection(self):
        with self.assertRaises(Pending):
            auth.account_password(self.exchange, '110SYN', None)
        self.assertEqual(self.calls, [])
        self.answer({}, None)
        with self.assertRaises(Pending):
            auth.account_password(self.exchange, '110SYN', '')
        self.assertEqual(self.exchange.report['account_password_verification'], 'unknown')
        self.assertEqual(len(self.calls), 1)

    def test_security_card_serial_binds_three_questions_and_two_ciphertexts(self):
        self.answer({})
        auth.security_card_serial(self.exchange, {'requestSerialNumberArray': ['3', '5', '7'],
            'responseSerialNumberArray': ['SYN-A', 'SYN-B', 'SYN-C'], 'firstPassword': 'SYN-P1', 'secondPassword': 'SYN-P2'})
        body = self.calls[0]['body']
        self.assertEqual(body['secrityCdMdiaGS1'], '1')
        self.assertEqual(body['secrityCdSerQry3S1'], '7')
        self.assertEqual(body['secrityCdSerResp3S1'], 'SYN-C')
        self.assertEqual(body['secrityCdPswd1S24'], 'SYN-P1')
        self.assertEqual(self.exchange.report['security_media_verification'], 'success')
        public = json.dumps(self.exchange.report)
        for secret in ('SYN-A', 'SYN-B', 'SYN-C', 'SYN-P1', 'SYN-P2'):
            self.assertNotIn(secret, public)

    def test_missing_serial_arrays_are_omitted_but_short_arrays_do_not_send(self):
        self.answer({})
        auth.security_card_serial(self.exchange, {'firstPassword': 'SYN-P1', 'secondPassword': 'SYN-P2'})
        self.assertNotIn('secrityCdSerQry1S1', self.calls[0]['body'])
        with self.assertRaises(Pending):
            auth.security_card_serial(self.exchange, {'requestSerialNumberArray': ['1'], 'firstPassword': 'SYN-P1', 'secondPassword': 'SYN-P2'})
        self.assertEqual(len(self.calls), 1)

    def test_additional_auth_number_zero_requires_callback_and_passes_original_keys(self):
        self.answer({'addAuthDsYnS1': 'Y', 'svcSeqS3': 0})
        callback = Mock(return_value={'인증여부': 'Y'})
        auth.additional_authentication(self.exchange, callback)
        callback.assert_called_once_with({'serviceSeq': 0, '고객번호': 'SYN-NUMBER', '고객성명': 'Synthetic Person'})
        self.assertTrue(self.state['enrollment']['additional_auth_complete'])
        self.assertEqual(self.exchange.report['additional_authentication'], 'success')

    def test_missing_additional_sequence_skips_popup_and_incomplete_callback_stops(self):
        for sequence in (None, '', []):
            self.answer({'addAuthDsYnS1': 'Y', 'svcSeqS3': sequence})
            callback = Mock()
            auth.additional_authentication(self.exchange, callback)
            callback.assert_not_called()
        self.answer({'addAuthDsYnS1': 'Y', 'svcSeqS3': '18'})
        with self.assertRaises(Pending):
            auth.additional_authentication(self.exchange, lambda _: {'인증여부': 'N'})

    def test_reference_preserves_optional_null_and_server_success_with_missing_values(self):
        self.answer({})
        result = auth.reference(self.exchange, account='SYN-ACCOUNT', bank='088', recommendation={'brnoS4': None})
        body = self.calls[0]['body']
        self.assertEqual(body['silnoBkstS7'], 'SYN-RRN-ENCRYPTED')
        self.assertEqual(body['biryrMmddS8'], '900101')
        self.assertEqual(body['reqKey'], body['reqKey2'])
        self.assertIsNone(body['mngBrnoS4'])
        self.assertNotIn('suggHwnno', body)
        self.assertIsNone(result['referenceNumber'])
        self.assertIsNone(result['authCode'])
        self.assertEqual(self.exchange.report['issuance_reference'], 'success')

    def test_reference_rejection_does_not_change_prior_identity_or_password_success(self):
        self.exchange.report.update(resident_identity_verification='success', account_password_verification='success')
        self.answer({}, 'FAIL')
        with self.assertRaises(Pending):
            auth.reference(self.exchange)
        self.assertEqual(self.exchange.report['resident_identity_verification'], 'success')
        self.assertEqual(self.exchange.report['account_password_verification'], 'success')
        self.assertNotIn('certificate_enrollment', self.state['enrollment'])
