"""Issuance identity stages over encrypted synthetic HTTP, without bank traffic."""
import base64
import json
from unittest.mock import Mock, patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.core import storage
from finance_cli.services.shinhan import enrollment as enroll, setup, transport, web
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, response, settings


class EnrollmentTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.install()
        self.exchange = Exchange(settings(), {'cookie': 'JSESSIONID=SYN-COOKIE'}, 'certificate_issue')
        self.calls, self.replies = [], []
        self.post_web_original = transport.post_web
        self.enterContext(patch.object(transport, 'post_web', self.server))
        self.identity = {'name': ' Synthetic Person ', 'birth': '900101', 'gender': '1',
                         'telecom': '1', 'phoneNumber': '010-SYN1-SYN2'}

    def server(self, payload, cookie='', *, path=transport.ENDPOINT):
        document = json.loads(payload)
        key = bytes.fromhex(settings()['bank_key'])
        body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(document['dataBody'])), 16))
        self.calls.append((document['dataHeader'], body, cookie))
        return self.replies.pop(0)

    def answer(self, body, result='SUCCESS', **header):
        self.replies.append(transport.Reply(200, [], response(result, body, **header)))

    def answer_terms(self):
        self.answer({'grid01': [{'stplDocIdS22': term+'_SYN-V1', 'stplTtlS200': '[필수] Synthetic terms',
                                 'stplApdfUrlS200': 'https://synthetic.invalid/terms/'+term}
                                for term in reversed(enroll.TERM_IDS)]})

    def verified_identity(self):
        identity = {**self.identity, 'customerCI': 'SYN-CI', 'phoneNumber': 'SYN-PHONE'}
        self.exchange.state['enrollment'] = {'sms_verified': True, 'identity': identity}
        self.exchange.report['identity_verification'] = 'success'
        self.answer({'grid01': [{'cusno': '42', 'cusnm': identity['name'], 'drCusBL10': 1}], 'sbankEntYnS1': '1'})
        self.answer({'silnoG': 1})

    def route_inputs(self, *, phone='SYN-PHONE', certificates=None):
        self.verified_identity()
        self.answer({'hpNoS12': phone})
        self.answer({'sub01': [], 'sub02': []})
        self.answer({'accountList': []})
        if phone == 'SYN-PHONE':
            self.answer({'certList': certificates or []})

    def test_terms_sms_chain_preserves_order_private_values_and_separate_verdicts(self):
        self.answer_terms()
        self.answer({'authNatvNoS24': 'SYN-REFERENCE'})
        self.answer({'authConfRstS4': '0000', 'ciS88': 'SYN-CI'})
        consent, code = Mock(return_value=True), Mock(return_value='246802')
        identity = enroll.identify(self.exchange, self.identity, consent, code)
        self.assertEqual([call[0]['trxCd'] for call in self.calls], ['RSMCM9000C10', 'RSMCM0801A07', 'RSMCM0801A08'])
        self.assertEqual([call[0]['programId'] for call in self.calls], [enroll.TERMS_PROGRAM, enroll.PHONE_PROGRAM, enroll.PHONE_PROGRAM])
        self.assertEqual([d['id'] for d in consent.call_args.args[0]], list(enroll.TERM_IDS))
        self.assertEqual(self.calls[1][1]['cusnm'], 'Synthetic Person')
        self.assertEqual(identity['name'], self.identity['name'])
        self.assertEqual(self.calls[1][1]['rrgsNo2S7'], '1')
        self.assertEqual(self.calls[2][1]['authNatvNoS24'], 'SYN-REFERENCE')
        self.assertEqual(identity['customerCI'], 'SYN-CI')
        self.assertEqual(identity['phoneNumber'], '010SYN1SYN2')
        self.assertTrue(self.exchange.state['enrollment']['sms_verified'])
        self.assertEqual(self.exchange.report['identity_verification'], 'success')
        self.assertNotIn('certificate_issuance', self.exchange.report)
        public = json.dumps(self.exchange.report)
        for private in ('Synthetic Person', 'SYN-REFERENCE', 'SYN-CI', '246802', '900101', 'SYN-COOKIE'):
            self.assertNotIn(private, public)
        for file in self.exchange.run.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertEqual((setup.root()/'session.json').stat().st_mode & 0o777, 0o600)

    def test_declined_terms_do_not_send_sms_or_collect_code(self):
        self.answer_terms()
        code = Mock()
        with self.assertRaises(enroll.Pending) as stopped:
            enroll.identify(self.exchange, self.identity, lambda _: False, code)
        self.assertEqual(stopped.exception.action, 'terms_declined')
        self.assertEqual(len(self.calls), 1)
        code.assert_not_called()

    def test_missing_term_keeps_bank_success_but_cannot_imply_consent(self):
        self.answer({'grid01': []})
        consent, code = Mock(), Mock()
        with self.assertRaises(ValueError):
            enroll.identify(self.exchange, self.identity, consent, code)
        consent.assert_not_called()
        code.assert_not_called()
        self.assertEqual(self.exchange.report['stages'][0]['bank_result'], 'success')

    def test_sms_request_failure_never_asks_for_code_or_retries(self):
        self.answer_terms()
        self.answer({}, 'FAIL', resultCode='MCM00017')
        code = Mock()
        with self.assertRaises(enroll.Pending):
            enroll.identify(self.exchange, self.identity, lambda _: True, code)
        self.assertEqual(len(self.calls), 2)
        code.assert_not_called()

    def test_sms_confirmation_requires_both_original_success_fields(self):
        for header, code, expected in [('SUCCESS', '0001', 'failure'), ('FAIL', '0000', 'failure'),
                                        ('SUCCESS', None, 'unknown'), (None, '0000', 'unknown')]:
            with self.subTest(header=header, code=code):
                self.answer({'authNatvNoS24': 'SYN-REFERENCE'})
                enroll.request_sms(self.exchange, self.identity)
                self.answer({'authConfRstS4': code}, header)
                before = len(self.calls)
                with self.assertRaises(enroll.Pending):
                    enroll.verify_sms(self.exchange, '246802')
                self.assertEqual(len(self.calls), before+1)
                self.assertEqual(self.exchange.report['identity_verification'], expected)
                self.assertFalse(self.exchange.state['enrollment']['sms_verified'])

    def test_missing_ci_does_not_add_a_stricter_sms_success_condition(self):
        self.answer({'authNatvNoS24': 'SYN-REFERENCE'})
        enroll.request_sms(self.exchange, self.identity)
        self.answer({'authConfRstS4': '0000'})
        self.assertIsNone(enroll.verify_sms(self.exchange, '246802')['customerCI'])
        self.assertEqual(self.exchange.report['identity_verification'], 'success')

    def test_short_code_or_missing_reference_never_sends_verification(self):
        self.answer({})
        enroll.request_sms(self.exchange, self.identity)
        for code in ('', '12345', '246802'):
            with self.assertRaises(enroll.Pending):
                enroll.verify_sms(self.exchange, code)
        self.assertEqual(len(self.calls), 1)

    def test_body_challenge_survives_absent_native_header(self):
        self.replies.append(transport.Reply(200, [], json.dumps({'dataBody': {'COM_SEC_CHAL2': 'SYN-WEB'}}).encode()))
        verdict, _ = self.exchange.web('synthetic', 'SYN', {}, program='SYN-PAGE')
        self.assertEqual(verdict['bank_result'], 'unknown')
        self.assertTrue(verdict['bridge_success'])
        self.assertEqual(self.exchange.state['web_challenges'], ['', 'SYN-WEB'])

    def test_additional_auth_and_service_precheck_stop_consumption_without_retry(self):
        for result, body, header in [('SUCCESS', {'blklstG': '5'}, {}),
                                      ('FAIL', {}, {'resultCode': 'RIB80306'}),
                                      ('FAIL', {}, {'resultCode': 'RIB00057'})]:
            with self.subTest(result=result, header=header):
                self.answer(body, result, **header)
                before = len(self.calls)
                with self.assertRaises(enroll.Pending):
                    enroll.request_sms(self.exchange, self.identity)
                self.assertEqual(len(self.calls), before+1)
                self.assertEqual(self.exchange.report['stages'][-1]['bank_result'], result.lower().replace('fail', 'failure'))

    def test_save_errors_preserve_sms_verification_and_do_not_retransmit(self):
        self.answer({'authNatvNoS24': 'SYN-REFERENCE'})
        enroll.request_sms(self.exchange, self.identity)
        self.answer({'authConfRstS4': '0000', 'ciS88': 'SYN-CI'})
        original = storage.atomic_json
        def save(path, value):
            if path.name == 'session.json':
                raise OSError('SYN-PRIVATE')
            return original(path, value)
        with patch.object(storage, 'atomic_json', save):
            enroll.verify_sms(self.exchange, '246802')
        self.assertEqual(self.exchange.report['identity_verification'], 'success')
        self.assertEqual(self.exchange.report['local_status'], 'incomplete')
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn('SYN-PRIVATE', json.dumps(self.exchange.report))

    def test_customer_rejection_still_requests_identity_kind_and_consumes_body(self):
        self.answer({'grid01': [{'cusno': '42', 'cusnm': 'SYN-CUSTOMER', 'drCusBL10': 20}],
                     'sbankEntYnS1': '1'}, 'FAIL', resultCode='SYN-REJECT')
        self.answer({'silnoG': 1})
        info = enroll.customer(self.exchange, {'customerCI': 'SYN-CI'})
        self.assertEqual([call[0]['trxCd'] for call in self.calls], ['RSMCM9000A08', 'RSMCM0303A03'])
        self.assertEqual(info['customerNumber'], '0000000042')
        self.assertTrue(info['isSOLCustomer'])
        self.assertTrue(info['isNewCIF'])
        self.assertEqual(info['silnoG'], 1)
        self.assertEqual(self.exchange.report['stages'][0]['bank_result'], 'failure')

    def test_logged_in_customer_uses_mapped_user_and_alternate_inquiry(self):
        self.answer({'silnoG': 6}, None)
        info = enroll.customer(self.exchange, {}, login_info={'cusnoS10': 'SYN-NUMBER',
            'cusSungNmS30': 'SYN-NAME', 'ciNoS88': 'SYN-CI', 'newcifYn': 'N', 'smartBnkgEntSangtaeS1': '1'})
        self.assertEqual(self.calls[0][0]['trxCd'], 'RSMCM0303A01')
        self.assertEqual(info['customerNumber'], 'SYN-NUMBER')
        self.assertEqual(info['silnoG'], 6)
        self.assertTrue(info['isLoggedIn'])

    def test_contact_retains_returned_number_on_ordinary_business_failure(self):
        self.answer({'hpNoS12': 'SYN-REGISTERED'}, 'FAIL')
        info = enroll.contact(self.exchange, {'customerNumber': ''}, {'phoneNumber': 'SYN-ENTERED'})
        self.assertTrue(info['isPhoneNumberDifferent'])
        self.assertFalse(info['isTransactionSuccess'])
        self.assertEqual(self.calls[0][1], {'upmuGN1': 1, 'srchGN1': 1, 'bnkG': 1, 'srchNoS30': '',
                                           'hpNoS12': 'SYN-ENTERED', 'loginType': 'CERT'})

    def test_authentication_accounts_filter_match_and_preserve_registered_order(self):
        base = {'ipGnyn': 1, 'depK': 1, 'prdtC': 'SYN-PRODUCT', 'acno': '110-SYN',
                'acno_originalValue': '123000', 'guAcno': '123-999', 'prdtHngNmS50': 'Synthetic account'}
        self.answer({'sub01': [base, {**base, 'ipGnyn': True, 'acno_originalValue': '999000'},
                               {**base, 'prdtC': '110003101', 'acno_originalValue': '888000'}], 'sub02': []})
        self.answer({'accountList': [{'bankCd': '4', 'accountNumber': '456-000'},
                                     {'bankCd': '88', 'accountNumber': '123000'},
                                     {'bankCd': '88', 'accountNumber': '999000'},
                                     {'bankCd': '88', 'accountNumber': '888000'},
                                     {'bankCd': '88', 'accountNumber': '123-999'}]})
        self.answer({'grid01': [{'codeVS10': '4', 'codeHngNmS100': 'Synthetic Bank'}]})
        accounts = enroll.authentication_accounts(self.exchange)
        self.assertEqual([x['accountNumber'] for x in accounts], ['456000', '123999'])
        self.assertEqual([x['bankCode'] for x in accounts], ['004', '088'])
        self.assertEqual(self.calls[0][1], {'loginTrxGN1': '5'})
        self.assertEqual(len(self.calls), 3)

    def test_empty_registered_list_discards_initial_candidates_and_skips_bank_names(self):
        self.answer({'sub01': [], 'sub02': []})
        self.answer({'accountList': []})
        self.assertEqual(enroll.authentication_accounts(self.exchange), [])
        self.assertEqual(len(self.calls), 2)

    def test_missing_account_arrays_stops_before_registered_query(self):
        self.answer({'sub01': []})
        self.assertEqual(enroll.authentication_accounts(self.exchange), [])
        self.assertEqual(len(self.calls), 1)

    def test_cloud_list_keeps_only_present_certificates_in_original_order(self):
        self.answer({'certList': [None, {'existCloudCertYn': 'N', 'certSeqNo': 'SYN-NO'},
                                  {'existCloudCertYn': 'Y', 'certSeqNo': 'SYN-YES'}]})
        self.assertEqual(enroll.cloud_certificates(self.exchange),
                         [{'shSignSequenceNumber': 'SYN-YES', 'shSignExpirationTimestamp': None}])

    def test_malformed_cloud_list_is_processing_error_after_bank_success(self):
        for rows in ({'synthetic': True}, 0, False):
            with self.subTest(rows=rows):
                self.answer({'certList': rows})
                with self.assertRaises(ValueError):
                    enroll.cloud_certificates(self.exchange)
                self.assertEqual(self.exchange.report['stages'][-1]['bank_result'], 'success')

    def test_react_challenge_priority_and_empty_collections_follow_distinct_helpers(self):
        state = {}
        web.update_challenges(state, {'dataHeader': {'comSecChal1': 0, 'COM_SEC_CHAL1': 'SYN-ONE'},
                                      'dataBody': {'comSecChal1': 'LOWER', 'secChal2': 'SYN-TWO'}})
        self.assertEqual(state['web_challenges'], ['SYN-ONE', 'SYN-TWO'])
        web.update_challenges(state, {'dataHeader': {'comSecChal1': []}, 'dataBody': {'comSecChal1': 'BLOCKED'}})
        self.assertEqual(state['web_challenges'], ['SYN-ONE', 'SYN-TWO'])

    def test_web_transport_uses_web_content_type_and_one_attempt(self):
        with patch.object(transport, '_post', return_value=transport.Reply()) as post:
            self.post_web_original(b'SYN', 'JSESSIONID=SYN')
        post.assert_called_once_with(transport.BANK_HOST, b'SYN',
            {'Content-Type': 'application/json', 'Accept-Encoding': 'gzip', 'Cookie': 'JSESSIONID=SYN'}, transport.ENDPOINT, 60)

    def test_security_card_route_preserves_distinct_account_inquiries_and_failure_body(self):
        self.route_inputs()
        self.answer({'sub01': [{}]})
        self.answer({'secrityMdiaGS1': '1'}, 'FAIL')
        route = enroll.prepare_authentication(self.exchange, confirm=Mock(), age_for_rrn=lambda *_: 30)
        self.assertEqual(route, 'SELECT_AUTH')
        account_calls = [call for call in self.calls if call[0]['trxCd'] == 'RSMDE0106A03']
        self.assertEqual([call[1] for call in account_calls], [{'loginTrxGN1': '5'}, {}])
        self.assertEqual(self.exchange.report['stages'][-1]['bank_result'], 'failure')
        self.assertEqual(self.exchange.report['identity_verification'], 'success')

    def test_cloud_download_choice_stops_before_security_media_selection(self):
        self.route_inputs(certificates=[{'existCloudCertYn': 'Y', 'certSeqNo': 'SYN-CERT'}])
        confirm = Mock(return_value=True)
        self.assertEqual(enroll.prepare_authentication(self.exchange, confirm=confirm, age_for_rrn=lambda *_: 30), 'CLOUD_DOWNLOAD')
        self.assertEqual(confirm.call_args.args[0], 'download_cloud_certificate')
        self.assertEqual(len(self.calls), 6)
        self.assertNotIn('certificate_registration', self.exchange.report)

    def test_phone_difference_confirmed_follows_no_face_route_after_account_candidates(self):
        self.route_inputs(phone='SYN-OTHER')
        confirm = Mock(return_value=True)
        self.assertEqual(enroll.prepare_authentication(self.exchange, confirm=confirm, age_for_rrn=lambda *_: 30), 'NO_FACE_AUTH')
        self.assertEqual(confirm.call_args.args[0], 'phone_changed')
        self.assertEqual(len(self.calls), 5)
        self.assertNotIn('RSMCM0906A02', [call[0]['trxCd'] for call in self.calls])

    def test_underage_stops_after_customer_check_without_erasing_sms_success(self):
        self.verified_identity()
        with self.assertRaises(enroll.Pending) as stopped:
            enroll.prepare_authentication(self.exchange, confirm=Mock(), age_for_rrn=lambda *_: 13)
        self.assertEqual(stopped.exception.action, 'guardian_branch_visit_required')
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.exchange.report['identity_verification'], 'success')

    def test_unavailable_mobile_state_is_pending_instead_of_fake_absence(self):
        self.route_inputs()
        self.answer({'sub01': [{}]})
        self.answer({'secrityMdiaGS1': '2', 'comSecChal1': '31'})
        self.answer({})
        with self.assertRaises(enroll.Pending) as stopped:
            enroll.prepare_authentication(self.exchange, confirm=Mock(), age_for_rrn=lambda *_: 30)
        self.assertEqual(stopped.exception.action, 'mobile_otp_state_required')
        self.assertNotIn('authentication_route', self.exchange.state['enrollment'])
        self.assertEqual(len(self.calls), 9)

    def test_mobile_otp_route_requires_issue_info_then_precheck(self):
        self.route_inputs()
        self.answer({'sub01': [{}]})
        self.answer({'secrityMdiaGS1': '2', 'comSecChal1': '31'})
        self.answer({}, None)
        order = []
        def info():
            order.append('issue_info')
            return {'isOk': True, 'params': {'serialNumber': 'SYN-SERIAL'}}
        def precheck():
            order.append('precheck')
            return {'isSuccess': True}
        route = enroll.prepare_authentication(self.exchange, confirm=Mock(), age_for_rrn=lambda *_: 30,
                                               mobile_issue_info=info, mobile_precheck=precheck)
        self.assertEqual(route, 'SECURITY_MEDIA')
        self.assertEqual(order, ['issue_info', 'precheck'])

    def test_identity_kind_original_strict_number_does_not_accept_string_or_boolean(self):
        for kind in ('1', True):
            with self.subTest(kind=kind):
                self.verified_identity()
                self.replies[-1] = transport.Reply(200, [], response(body={'silnoG': kind}))
                before = len(self.calls)
                with self.assertRaises(enroll.Pending) as stopped:
                    enroll.prepare_authentication(self.exchange, confirm=Mock(), age_for_rrn=lambda *_: 30)
                self.assertEqual(stopped.exception.action, 'customer_identity_kind_unavailable')
                self.assertEqual(len(self.calls), before+2)
