"""Security-media sequencing against synthetic bank replies; no network."""
import base64
import json
from unittest.mock import Mock, patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.services.shinhan import security_media as media, transport
from finance_cli.services.shinhan.enrollment import Pending
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, response, settings


class SecurityMediaTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.install()
        self.context = {'resident_identity': {'birth': '900101', 'secret': 'SYN-RRN'},
                        'security_media': {'securityMediaType': 'SECURITY_CARD', 'secrityMdiaGS1': '1',
                         'secrityCdBnkGS1': 'S', 'comSecChal1': '04', 'comSecChal2': '09',
                         'secrityCdSerQry1S1': '01', 'secrityCdSerQry2S1': '3', 'secrityCdSerQry3S1': '5'}}
        self.exchange = Exchange(settings(), {'enrollment': self.context}, 'certificate_issue')
        self.calls, self.replies = [], []
        self.enterContext(patch.object(transport, 'post', self.server))
        self.enterContext(patch.object(transport, 'post_web', self.server))
        self.channel = Mock()
        self.channel.encrypt.side_effect = ['SYN-SERIAL-CIPHER', 'SYN-FIRST-CIPHER', 'SYN-SECOND-CIPHER']
        self.channel.read.side_effect = lambda provider, length: 'SYN-CIPHER-'+provider().decode()

    def server(self, payload, cookie='', *, path=transport.ENDPOINT):
        envelope = json.loads(payload)
        key = bytes.fromhex(settings()['bank_key'])
        body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(envelope['dataBody'])), 16))
        self.calls.append({'transaction': envelope['dataHeader']['trxCd'], 'body': body, 'path': path})
        return self.replies.pop(0)

    def answer(self, result='SUCCESS', body=None, code=None):
        self.replies.append(transport.Reply(200, [], response(result, body, **({'resultCode': code} if code else {}))))

    def test_card_consumes_three_serial_digits_then_two_encrypted_pairs(self):
        self.answer()
        provider = Mock(side_effect=[b'617', b'24', b'86'])
        media.authenticate(self.exchange, provider, channel=self.channel)
        self.channel.prepare.assert_called_once()
        self.assertEqual([call.args[0] for call in provider.call_args_list], ['card_serial', 'card_first', 'card_second'])
        self.assertEqual([call.args for call in self.channel.encrypt.call_args_list], [(b'617', 3), (b'24', 2), (b'86', 2)])
        self.assertEqual(self.calls, [{'transaction': 'RSMCM1100A09', 'path': transport.ENDPOINT, 'body': {
            'icheScnoGS1': '1', 'secrityCdMdiaGS1': '1', 'secrityCdBnkGS1': 'S',
            'secrityCdSerQry1S1': '1', 'secrityCdSerQry2S1': '3', 'secrityCdSerQry3S1': '5',
            'secrityCdSerResp1S1': '6', 'secrityCdSerResp2S1': '1', 'secrityCdSerResp3S1': '7',
            'secrityCdPswd1S24': 'SYN-FIRST-CIPHER', 'secrityCdPswd2S24': 'SYN-SECOND-CIPHER'}}])
        self.assertTrue(self.context['security_media_verified'])
        public = json.dumps(self.exchange.report)
        for value in ('SYN-FIRST-CIPHER', 'SYN-SECOND-CIPHER', 'SYN-RRN', '617'):
            self.assertNotIn(value, public)

    def test_otp_success_ignores_body_and_does_not_send_card_transaction(self):
        self.context['security_media'] = {'securityMediaType': 'OTP', 'secrityMdiaGS1': '2'}
        self.answer(body={'isOk': False})
        media.authenticate(self.exchange, lambda *_: b'246810', channel=self.channel)
        self.assertEqual(self.calls, [{'transaction': 'RSMCM1100A02', 'path': '/serviceEndpoint/httpDigital/',
            'body': {'otpCdPswdS200': 'SYN-CIPHER-246810', 'nxtSvcCS20': 'RSMCM1100A09'}}])
        self.assertEqual(self.channel.read.call_args.args[1], 6)
        self.assertEqual(self.exchange.report['security_media_verification'], 'success')

    def test_otp_null_success_body_is_success_even_when_session_save_fails(self):
        self.answer()
        with patch('finance_cli.core.storage.atomic_json', side_effect=[None, OSError(), None]):
            self.assertEqual(media.verify_otp(self.exchange, 'SYN-OTP')['state'], 'done')
        self.assertEqual(self.exchange.report['security_media_verification'], 'success')
        self.assertIn('session_save_error', self.exchange.report['warnings'])

    def test_native_failure_counts_and_correction_do_not_retry(self):
        for code, expected in [('RIB05540', {'maximum_count_exceeded': True}),
                               ('RIB05550', {'maximum_count_exceeded': True}),
                               ('RIB05543', {'count': 3, 'correction_required': False}),
                               ('RIB05552', {'count': 2, 'correction_required': True})]:
            with self.subTest(code=code):
                before = len(self.calls)
                self.answer('FAIL', code=code)
                with self.assertRaises(Pending):
                    media.verify_otp(self.exchange, 'SYN-OTP')
                self.assertEqual(self.exchange.report['otp_error'], expected)
                self.assertEqual(len(self.calls), before+1)
                self.assertEqual(self.exchange.report['security_media_verification'], 'failure')

    def test_malformed_error_count_keeps_observed_failure(self):
        self.answer('FAIL', code='RIB0554X')
        with self.assertRaises(ValueError):
            media.verify_otp(self.exchange, 'SYN-OTP')
        self.assertEqual(self.exchange.report['security_media_verification'], 'failure')

    def test_unknown_and_transport_error_are_not_inferred_failure(self):
        for reply in (transport.Reply(error='transport_error'), transport.Reply(200, [], response('OTHER'))):
            self.replies.append(reply)
            with self.assertRaises(Pending):
                media.verify_otp(self.exchange, 'SYN-OTP')
            self.assertEqual(self.exchange.report['security_media_verification'], 'unknown')

    def test_otp_null_cipher_or_bad_service_sends_nothing(self):
        with self.assertRaises(Pending):
            media.verify_otp(self.exchange, None)
        with self.assertRaises(ValueError):
            media.verify_otp(self.exchange, 'SYN-OTP', service='other')
        self.assertEqual(self.calls, [])

    def test_transfer_service_is_allowed_without_claiming_transfer_success(self):
        self.answer()
        media.verify_otp(self.exchange, 'SYN-OTP', service='RSMCM1100A04', next_service='SYN-NEXT')
        self.assertEqual(self.calls[0]['transaction'], 'RSMCM1100A04')
        self.assertEqual(self.calls[0]['body']['nxtSvcCS20'], 'SYN-NEXT')
        self.assertNotIn('transfer', self.exchange.report)

    def test_account_rejection_prevents_security_input(self):
        self.answer('FAIL')
        provider = Mock(return_value=b'1357')
        with self.assertRaises(Pending):
            media.account_authentication(self.exchange, '110000000', provider, channel=self.channel)
        self.assertEqual(len(provider.call_args_list), 1)
        self.assertEqual([call['transaction'] for call in self.calls], ['RSMDE0301B01'])

    def test_account_then_card_verification_order(self):
        self.answer()
        self.answer()
        provider = Mock(side_effect=[b'1357', b'617', b'24', b'86'])
        media.account_authentication(self.exchange, '180000000', provider, channel=self.channel)
        self.assertEqual([call['transaction'] for call in self.calls], ['RSMFO0001A02', 'RSMCM1100A09'])
        self.assertEqual(self.context['verified_account'], '180000000')

    def test_card_rejection_does_not_set_completion(self):
        self.answer('FAIL')
        with self.assertRaises(Pending):
            media.authenticate(self.exchange, Mock(side_effect=[b'617', b'24', b'86']), channel=self.channel)
        self.assertNotIn('security_media_verified', self.context)

    def test_mobile_otp_is_not_substituted_with_physical_otp(self):
        self.context['security_media']['securityMediaType'] = 'MOBILE_OTP'
        provider = Mock()
        with self.assertRaises(Pending) as stopped:
            media.authenticate(self.exchange, provider, channel=self.channel)
        self.assertEqual(stopped.exception.action, 'mobile_otp_authentication_required')
        provider.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_logged_in_challenge_pair_and_secret_char_override(self):
        self.exchange.state['web_challenges'] = ['12', '19']
        self.answer()
        provider = Mock(side_effect=[b'617', b'24', b'86'])
        media.authenticate(self.exchange, provider, channel=self.channel,
                           login_info={'secrityMdiaInfS1': '3', 'secretChar1': '07'})
        selected = provider.call_args_list[0].args[1]
        self.assertEqual((selected['firstNumber'], selected['secondNumber'], selected['cardType']), ('07', '19', '4'))

    def test_logged_in_otp_uses_default_service_when_page_did_not_set_one(self):
        selected = media.options(self.context['security_media'], login_info={'secrityMdiaInfS1': '5'})
        self.assertEqual(selected['serviceCode'], 'RSMCM1100A04')

    def test_serial_conversion_and_native_missing_question_consumer(self):
        self.assertEqual(media.serial_numbers(['01', '+3', '-5']), ['1', '3', '-5'])
        for values in ([None, '3', '5'], ['1', '3'], ['2147483648', '3', '5'], ['1.0', '3', '5']):
            with self.assertRaises(ValueError):
                media.serial_numbers(values)
        selected = media.options(self.context['security_media'])
        del selected['firstNumber']
        with self.assertRaises(KeyError):
            media.card_input(self.channel, selected, Mock())
        self.channel.prepare.assert_not_called()
