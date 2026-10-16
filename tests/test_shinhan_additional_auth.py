"""Telephone authentication: encrypted sequencing, interaction and partial success."""
import base64
import json
from unittest.mock import Mock, patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.services.shinhan import additional_auth as auth, issuance_auth, legacy_web, transport
from finance_cli.services.shinhan.enrollment import Pending
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, settings, response


class AdditionalAuthTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.install()
        self.state = {'cookie': 'JSESSIONID=SYNTHETIC'}
        self.exchange = Exchange(settings(), self.state, 'certificate_issue')
        self.calls, self.replies = [], []
        def post(payload, cookie='', *, show_message=None):
            envelope = json.loads(payload)
            key = bytes.fromhex(settings()['bank_key'])
            body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(envelope['dataBody'])), 16))
            self.calls.append({'header': envelope['dataHeader'], 'body': body, 'show': show_message, 'cookie': cookie})
            return self.replies.pop(0)
        self.enterContext(patch.object(transport, 'post_web', side_effect=post))

    def answer(self, body, result='SUCCESS', **header):
        self.replies.append(transport.Reply(200, [], response(result, body, **header)))

    def prepare(self, *, contact=None, result='Y', method='ars'):
        self.answer(contact if contact is not None else {'hpNoS12': '01000000000', 'hpDifrN1': '0'})
        self.answer({'getCurrentDateFmt': {'valueS20': '20000103 100000'}})
        self.answer({'isOpDate': {'valueS20': True}})
        self.answer({'sincNoS8': 'SYN-ARS-REFERENCE'})
        self.answer({'addAuthCpltYnS1': result, 'trdtC8': '20000103', 'ltrtmC6': '100003'})
        self.select = Mock(return_value={'method': method, 'kind': '0'})
        self.respond = Mock(return_value=True if method == 'ars' else '123456')

    def run_auth(self, params=None, **kwargs):
        return auth.authenticate(self.exchange, params or {'serviceSeq': '18'}, self.select, self.respond,
                                 monotonic=lambda: 0, sleep=lambda seconds: None, **kwargs)

    def test_ars_order_headers_no_auth_code_or_phone_in_report(self):
        self.prepare()
        result = self.run_auth()
        self.assertEqual([c['header']['trxCd'] for c in self.calls],
                         ['RSMCM0301A02', 'RSMCM9000A03', 'RSMCM9000A03', 'RSMCM1200A06', 'RSMCM1200A07'])
        self.assertEqual([c['show'] for c in self.calls], [True, False, False, True, True])
        self.assertEqual([c['header']['programId'] for c in self.calls], [auth.SELECT_PROGRAM]+[auth.AUTH_PROGRAM]*4)
        for call in self.calls:
            self.assertNotIn('language', call['header'])
            self.assertEqual(call['header']['uuid'], settings()['device']['device_id'])
            self.assertEqual(call['cookie'], 'JSESSIONID=SYNTHETIC')
        self.assertEqual(self.calls[-2]['header']['isNative'], True)
        self.assertEqual(self.calls[-2]['header']['addMsg'], '1')
        self.assertNotIn('isNative', self.calls[1]['header'])
        self.assertEqual(self.calls[-1]['body'], {'upmuSeqS5': '18', 'authTypeS1': '0',
                                                  'sincNoS8': 'SYN-ARS-REFERENCE', 'isLogin': False})
        self.assertEqual(result['인증여부'], 'Y')
        self.assertEqual(result['trdtC8'], '20000103')
        self.assertEqual(self.exchange.report['additional_authentication'], 'success')
        for secret in ('01000000000', 'SYN-ARS-REFERENCE', 'JSESSIONID', '20000103'):
            self.assertNotIn(secret, json.dumps(self.exchange.report))

    def test_sms_ignores_request_response_reference_and_uses_same_code_twice(self):
        self.prepare(method='sms')
        self.run_auth({'serviceSeq': '63', 'title': None, '서비스코드': 'SYN-CURRENT', 'NEXT_서비스코드': 'SYN-NEXT'},
                      login_info={'synthetic': True})
        request, verification = self.calls[-2:]
        self.assertEqual(request['header']['trxCd'], 'RSMCM1200A08')
        self.assertEqual(verification['header']['trxCd'], 'RSMCM1200A09')
        self.assertEqual(request['body']['nextSvcCS6'], 'SYN-NEXT')
        self.assertEqual(verification['body']['nextSvcCS6'], 'SYN-CURRENT')
        self.assertNotIn('sincNoS8', verification['body'])
        self.assertEqual(verification['body']['authNoS24'], verification['body']['authNoS30'])
        self.assertIsNone(request['body']['title'])
        self.assertNotIn('123456', json.dumps(self.exchange.report))

    def test_missing_mobile_blocks_before_hours_even_with_home(self):
        self.prepare(contact={'homeTelnoS12': '0200000000'})
        self.select.return_value['kind'] = '1'
        with self.assertRaises(Pending) as caught:
            self.run_auth()
        self.assertEqual(caught.exception.action, 'additional_auth_registered_phone_required')
        self.assertEqual(len(self.calls), 1)
        self.respond.assert_not_called()

    def test_selected_home_number_and_customer_name_not_renamed(self):
        self.prepare(contact={'hpNoS12': '01000000000', 'homeTelnoS12': '0200000000', 'cusnmS30': 'SYN-PERSON'})
        self.select.return_value['kind'] = '1'
        self.run_auth({'serviceSeq': '18', '고객성명': 'SYN-OLD'})
        self.assertEqual(self.calls[-2]['body']['hpNoS12'], '0200000000')
        self.assertEqual(self.calls[-2]['body']['addAuthTelGbn'], '1')
        self.assertNotIn('cusSungNmS30', self.calls[-2]['body'])

    def test_server_time_failure_does_not_use_local_time_or_send_authentication(self):
        self.prepare()
        self.replies[1] = transport.Reply(200, [], response('FAIL', {}))
        with self.assertRaises(Pending):
            self.run_auth()
        self.assertEqual(len(self.calls), 2)
        self.respond.assert_not_called()
        self.assertEqual(self.exchange.report['bank_result'], 'failure')

    def test_bad_server_time_is_consumer_error_after_bank_success(self):
        self.prepare()
        self.replies[1] = transport.Reply(200, [], response('SUCCESS', {'getCurrentDateFmt': {'valueS20': None}}))
        with self.assertRaises(AttributeError):
            self.run_auth()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.exchange.report['bank_result'], 'success')

    def test_sms_timeout_and_cancellation_never_verify_or_retry(self):
        self.prepare(method='sms')
        clock = iter((0, 181))
        with self.assertRaises(Pending) as caught:
            auth.authenticate(self.exchange, {'serviceSeq': '63'}, self.select, self.respond, monotonic=lambda: next(clock))
        self.assertEqual(caught.exception.action, 'additional_auth_code_expired')
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(self.exchange.report['additional_authentication'], 'unknown')
        self.calls.clear()
        self.replies.clear()
        self.prepare()
        self.respond.return_value = None
        with self.assertRaises(Pending) as caught:
            self.run_auth()
        self.assertEqual(caught.exception.action, 'additional_auth_cancelled')
        self.assertEqual(len(self.calls), 4)

    def test_ars_missing_reference_and_face_branch_do_not_verify(self):
        self.prepare()
        self.replies[3] = transport.Reply(200, [], response('SUCCESS', {'sincNoS8': None}))
        with self.assertRaises(Pending) as caught:
            self.run_auth()
        self.assertEqual(caught.exception.action, 'additional_auth_reference_missing')
        self.assertEqual(len(self.calls), 4)
        self.calls.clear()
        self.replies.clear()
        self.prepare()
        self.select.return_value = {'method': 'face'}
        with self.assertRaises(Pending) as caught:
            self.run_auth({'serviceSeq': '81'})
        self.assertEqual(caught.exception.action, 'additional_auth_face_required')
        self.assertEqual(len(self.calls), 1)

    def test_success_stays_success_when_final_private_save_fails(self):
        self.prepare()
        original = self.exchange.save
        def save():
            if self.exchange.report.get('additional_authentication') == 'success':
                raise OSError('synthetic local error')
            original()
        with patch.object(self.exchange, 'save', side_effect=save), self.assertRaises(OSError):
            self.run_auth()
        self.assertEqual(self.exchange.report['additional_authentication'], 'success')
        self.assertEqual(self.state['additional_auth']['verification'], 'success')

    def test_verification_not_completed_is_separate_from_business_success(self):
        self.prepare(result='N')
        result = self.run_auth()
        self.assertEqual(result['인증여부'], 'N')
        self.assertEqual(self.exchange.report['additional_authentication'], 'failure')
        self.assertEqual(self.exchange.report['bank_result'], 'success')

    def test_issuance_check_calls_phone_auth_and_only_continues_after_y(self):
        self.state['enrollment'] = {'customer': {'customerNumber': 'SYN-CUSTOMER', 'customerName': 'SYN-PERSON'}}
        # A04 invokes the ordinary telephone helper with the bank's sequence.
        self.answer({'addAuthDsYnS1': 'Y', 'svcSeqS3': '63'})
        self.prepare(method='sms')
        issuance_auth.additional_authentication(self.exchange, select=self.select, respond=self.respond)
        self.assertEqual(self.calls[0]['header']['trxCd'], 'RSMCM1005A04')
        self.assertEqual(self.calls[-2]['body']['upmuSeqS5'], '63')
        self.assertTrue(self.state['enrollment']['additional_auth_complete'])
        self.assertEqual(self.exchange.report['additional_authentication'], 'success')

    def test_legacy_challenge_pairs_do_not_mix_levels_and_save_failure_keeps_success(self):
        self.answer({'comSecChal2': 'SYN-BODY'}, secChal1='SYN-HEADER')
        legacy_web.request(self.exchange, 'synthetic', 'RSMCM9000A03', {}, program=auth.AUTH_PROGRAM)
        self.assertEqual(self.state['web_challenges'], ['SYN-HEADER', ''])
        self.answer({})
        with patch.object(legacy_web, 'update_challenges', side_effect=OSError('synthetic')):
            self.assertEqual(legacy_web.request(self.exchange, 'synthetic', 'RSMCM9000A03', {}, program=auth.AUTH_PROGRAM), {})
        self.assertEqual(self.exchange.report['bank_result'], 'success')
        self.assertIn('web_state_update_error', self.exchange.report['warnings'])

    def test_http_failure_does_not_consume_inner_business_or_challenge(self):
        reply = transport.Reply(503, [], response('FAIL', {}, resultCode='RIB80306'))
        result, _ = legacy_web.parse(reply, show_message=True)
        self.assertEqual(result['bank_result'], 'unknown')
        self.assertTrue(result['callback_ready'])
        self.assertFalse(result['bridge_success'])

    def test_transport_sets_legacy_http_flag_only_when_requested(self):
        # Reach the real transport function separately from the request fixture.
        import importlib
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location('synthetic_transport', transport.__file__))
        import sys
        self.enterContext(patch.dict(sys.modules, {'synthetic_transport': module}))
        module.__spec__.loader.exec_module(module)
        with patch.object(module, '_post', return_value=transport.Reply()) as post:
            module.post_web(b'synthetic', show_message=False)
            self.assertEqual(post.call_args.args[2]['isShowMsg'], 'N')
            module.post_web(b'synthetic')
            self.assertNotIn('isShowMsg', post.call_args.args[2])
