"""First issue command through synthetic bank/ECDH/CMP and encrypted storage."""
import base64
import json
import math
from unittest.mock import Mock, patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives.asymmetric import ec

from finance_cli.core import storage
from finance_cli.credentials.registry import decode
from finance_cli.credentials.shinhan import Registry
from finance_cli.services.shinhan import cmp, crypto, device_phone, enrollment, issuance, issuance_input, pin_registration, setup, transport
from finance_cli.services.shinhan.exchange import Exchange
from finance_cli.services.shinhan.enrollment import Pending
from test_shinhan import PrivateHome, settings, response
import test_shinhan_issue as issue_fixtures
import test_shinhan_keypad as keypad_fixtures
from test_shinhan_login import certificate


class FirstIssuanceTests(PrivateHome):
    @classmethod
    def setUpClass(cls):
        cls.ca, cls.ca_private = certificate()

    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.install()
        self.password = b'SYN-VAULT-PASSWORD'
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.challenge, self.kr1 = b'SYNTHETIC-CHALLENGE', bytes(range(32, 64))
        self.calls, self.health, self.requests, self.inputs = [], [], [], []
        self.fail_health, self.ip_status, self.cert = False, 0, None
        self.confirm_response = cmp.wire(b'')
        self.card, self.account_failure, self.consent = True, False, True
        self.account = '110000000'
        self.overrides = {}
        storage.atomic_json(setup.root()/'session.json', {'cookie': 'JSESSIONID=SYN-BANK',
            'device_phone': {'verified': True, 'phone_number': '01000000000'}})
        self.enterContext(patch.object(transport, 'post', self.bank))
        self.enterContext(patch.object(transport, 'post_web', self.bank))
        self.enterContext(patch.object(transport, 'post_cmp', lambda payload, **kwargs: issue_fixtures.IssueTests.cmp_server(self, payload, **kwargs)))
        self.enterContext(patch.object(transport, 'post_certificate', self.ca_server))

    def bank(self, payload, cookie='', *, path=transport.ENDPOINT, **kwargs):
        wire = json.loads(payload); trx = wire['dataHeader']['trxCd']
        key = bytes.fromhex(settings()['bank_key'])
        body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(wire['dataBody'])), 16))
        self.requests.append((trx, body))
        if trx == 'RSMCM9006A03':
            return keypad_fixtures.KeypadTests.server(self, payload, cookie, path=path)
        self.calls.append(trx)
        result = 'SUCCESS'
        if trx == 'RSMCM0100C01': data = {}
        elif trx == 'RSMCM1200A02':
            data = ({'respTelnoS20': 'SYN-DESTINATION', 'authCS100': 'SYN-SMS'} if body['procStepGS1'] == '1'
                    else {'rstCS5': '000', 'respTelnoS20': '01000000000'})
        elif trx == 'RSMCM9009A06': data = {'cvalS30': 'N'}
        elif trx == 'RSMCM9000C10':
            data = {'grid01': [{'stplDocIdS22': term+'_SYN', 'stplTtlS200': 'Synthetic terms',
                               'stplApdfUrlS200': 'https://synthetic.invalid/terms'} for term in enrollment.TERM_IDS]}
        elif trx == 'RSMCM0801A07': data = {'authNatvNoS24': 'SYN-SMS-REF'}
        elif trx == 'RSMCM0801A08': data = {'authConfRstS4': '0000', 'ciS88': 'SYN-CI'}
        elif trx == 'RSMCM9000A08': data = {'grid01': [{'cusno': '42', 'cusnm': 'Synthetic Customer', 'drCusBL10': 1}], 'sbankEntYnS1': '1'}
        elif trx == 'RSMCM0303A03': data = {'silnoG': 1}
        elif trx == 'RSMCM9000A03': data = {'bdtInqrGS20': 'getCurrentDateFmt', 'getCurrentDateFmt': {'valueS20': '2026.10.17'}}
        elif trx == 'RSMCM0301B07': data = {'hpNoS12': '01000000000'}
        elif trx == 'RSMDE0106A03': data = {'sub01': [{'depK': 1, 'ipGnyn': 1, 'acno': '110000000', 'acno_originalValue': '110000000', 'prdtHngNmS50': 'Synthetic account'}], 'sub02': []}
        elif trx == 'RSMCM0800C01': data = {'accountList': [{'bankCd': '088', 'accountNumber': '110000000'}]}
        elif trx == 'RSMCM9009A01': data = {'grid01': []}
        elif trx == 'RSMCM0906A02': data = {'certList': []}
        elif trx == 'RSMCM1100A07': data = {'secrityMdiaGS1': '1' if self.card else '2', 'secrityCdBnkGS1': 'S', 'comSecChal1': '04', 'comSecChal2': '09', **{f'secrityCdSerQry{i}S1': str(i) for i in (1, 2, 3)}}
        elif trx in ('RSMCM1100B03', 'RSMCM0000A05', 'RSMCM1005A02', 'RSMCM1100A09', 'RSMCM1100A02'): data = {}
        elif trx == 'RSMDE0301B01':
            data = {}; result = 'FAIL' if self.account_failure else 'SUCCESS'
        elif trx == 'RSMCM1005A04': data = {'addAuthDsYnS1': 'N'}
        elif trx == 'RSMCM0890A01': data = {'refNoS20': 'SYN-REF', 'ingaCS20': 'SYN-AUTH'}
        elif trx == 'RSMCM1100D01':
            clear = unpad(AES.new(bytes(range(16)), AES.MODE_CBC, bytes(16)).decrypt(base64.b64decode(body['checkScnoS200'])), 16)
            self.assertEqual(base64.b64decode(clear), b'246802')
            data = {'birthDt': '19900101', 'hpnoMid': '0000', 'hpnoLst': '0000', 'rstS5': 'ignored'}
        elif trx == 'RSMCM0203A04': data = {}
        elif trx == 'RSMDE0219A02': data = {}; result = 'FAIL'
        else: self.fail('Unexpected synthetic transaction: '+trx)
        data = self.overrides.get(trx, data)
        headers = [('Set-Cookie', 'JSESSIONID=SYN-BANK')] if trx == 'RSMCM0100C01' else []
        return transport.Reply(200, headers, response(result, data))

    def ca_server(self, payload, cookie='', *, path):
        self.assertEqual(path, '/v1.1/prsn-cert/issue/regist-cert')
        body = json.loads(payload)
        self.assertEqual(body['REFERENCE_VALUE'], 'SYN-REF')
        self.assertEqual(body['CUST_ID'], '0000000042')
        material = Registry().load(Registry().list()[0]['name'], self.password)
        self.assertEqual(body['PIN_DATA_CON'], crypto.unique_value(b'246802', decode(material['pin_salt'])))
        self.calls.append(path)
        return transport.Reply(200, [], json.dumps({'ERR_CD': 'RA0000', 'ERR_MSG': 'Synthetic'}).encode())

    def ask(self, kind, value):
        self.inputs.append(kind)
        values = {'send_phone_sms': True, 'terms': self.consent, 'identity': {'name': 'Synthetic Customer', 'birth': '900101', 'gender': '1', 'telecom': '1'},
            'identity_sms': '246802', 'account_security_route': True, 'resident_identity': b'1000000',
            'network_info': {'useVPN': False, 'countryCode': 'kr'}, 'account': self.account,
            'account_password': b'2468', 'card_serial': b'617', 'card_first': b'24', 'card_second': b'86',
            'otp': b'248602', 'pin': b'246802', 'pin_repeat': b'246802', 'storage_password': self.password}
        self.assertIn(kind, values)
        return values[kind]

    def test_short_command_issues_certificate_with_real_cryptography_and_private_storage(self):
        with patch('sys.stdin.isatty', return_value=True), patch.object(issuance_input, 'factory', return_value=self.ask):
            code, out, err = self.call(['certificate', 'issue', '--send'])
        result = json.loads(out)['result']
        self.assertEqual((code, result['certificate_issuance'], result['certificate_registration']), (0, 'success', 'success'))
        self.assertEqual(result['simple_transfer_registration'], 'failure')
        self.assertEqual(Registry().load(result['credential'], self.password)['state'], 'issued')
        self.assertEqual(self.calls.count('RSMCM1100A09'), 1)
        self.assertEqual(self.calls.count('7E01'), 1)
        self.assertEqual(self.calls.count('7E06'), 4)  # RRN, account, card, PIN screens.
        self.assertLess(self.calls.index('RSMCM1100A09'), self.calls.index('RSMCM0890A01'))
        self.assertLess(self.calls.index('RSMCM1100D01'), self.calls.index('/v1.0/prsn-cert/issue/genm'))
        self.assertLess(self.inputs.index('pin'), self.inputs.index('pin_repeat'))
        for secret in ('Synthetic Customer', 'SYN-REF', 'SYN-CI', '246802', '110000000', '01000000000'):
            self.assertNotIn(secret, out+err)

    def test_physical_otp_route_does_not_run_security_card_transaction(self):
        self.card = False
        result = issuance.run(lambda _: self.ask)
        self.assertEqual(result['certificate_registration'], 'success')
        self.assertIn('RSMCM1100A02', self.calls)
        self.assertNotIn('RSMCM1100A09', self.calls)
        self.assertNotIn('card_serial', self.inputs)

    def test_account_failure_stops_before_security_and_certificate_reference(self):
        self.account_failure = True
        result = issuance.run(lambda _: self.ask)
        self.assertEqual(result['account_password_verification'], 'failure')
        self.assertNotIn('card_serial', self.inputs)
        self.assertNotIn('RSMCM0890A01', self.calls)
        self.assertEqual(Registry().list(), [])

    def test_first_command_prepares_session_and_verifies_phone_before_terms(self):
        (setup.root()/'session.json').unlink()
        verify = device_phone.verify
        with patch.object(device_phone, 'verify', side_effect=lambda exchange, send: verify(exchange, send, fallback_seconds=0)):
            result = issuance.run(lambda _: self.ask)
        self.assertEqual(result['certificate_registration'], 'success')
        self.assertEqual(result['startup']['bank_result'], 'success')
        self.assertEqual(self.calls[:5], ['RSMCM0100C01', 'RSMCM1200A02', 'RSMCM9009A06', 'RSMCM1200A02', 'RSMCM9000C10'])
        self.assertEqual(self.inputs[:2], ['send_phone_sms', 'terms'])

    def test_direct_account_entry_works_with_empty_remembered_account_list(self):
        self.overrides['RSMCM0800C01'] = {'accountList': []}
        self.account = '110111111'
        def ask(kind, value):
            if kind == 'account': self.assertEqual(value, [])
            return self.ask(kind, value)
        result = issuance.run(lambda _: ask)
        self.assertEqual(result['certificate_registration'], 'success')
        request = next(body for trx, body in self.requests if trx == 'RSMDE0301B01')
        self.assertEqual(request['jiAcno'], self.account)

    def test_unimplemented_routes_stop_before_account_password_or_issue(self):
        for data, action in [({'secrityMdiaGS1': '0'}, 'no_face_authentication_required'),
                             ({'secrityMdiaGS1': '2', 'comSecChal1': '31'}, 'mobile_otp_state_required')]:
            with self.subTest(action=action):
                self.inputs.clear(); self.calls.clear()
                self.overrides['RSMCM1100A07'] = data
                result = issuance.run(lambda _: self.ask)
                self.assertEqual(result['required_action'], action)
                self.assertNotIn('account_password', self.inputs)
                self.assertNotIn('RSMCM0890A01', self.calls)
                self.assertEqual(Registry().list(), [])

    def test_startup_success_survives_issuance_report_creation_failure(self):
        (setup.root()/'session.json').unlink()
        with patch.object(issuance, 'Exchange', side_effect=OSError('synthetic private error')):
            result = issuance.run(lambda _: self.ask)
        self.assertEqual(result['bank_result'], 'success')
        self.assertEqual(result['startup']['bank_result'], 'success')
        self.assertEqual(result['error'], 'issuance_prepare_error')
        self.assertEqual(self.calls, ['RSMCM0100C01'])
        self.assertNotIn('synthetic private error', json.dumps(result))

    def test_terminal_cancel_preserves_completed_steps_and_never_issues(self):
        def ask(kind, value):
            if kind == 'pin_repeat': raise KeyboardInterrupt()
            return self.ask(kind, value)
        result = issuance.run(lambda _: ask)
        self.assertEqual(result['error'], 'interrupted')
        self.assertEqual(result['security_media_verification'], 'success')
        self.assertEqual(self.calls.count('RSMCM1100D01'), 1)
        self.assertEqual(Registry().list(), [])

    def test_terminal_adapter_completes_short_command_and_keeps_choices_private(self):
        answers = ['y', 'Synthetic Customer', '900101', '1', '1', '246802', 'y', '1000000', 'n', 'kr',
                   '1', '2468', '617', '24', '86', '246802', '246802', self.password.decode(), self.password.decode()]
        with patch('sys.stdin.isatty', return_value=True), patch('getpass.getpass', side_effect=answers) as inputs:
            code, output, error = self.call(['certificate', 'issue', '--send'])
        self.assertEqual(code, 0)
        self.assertEqual(inputs.call_count, len(answers))
        files = list((setup.root()/'runs').glob('*/input-*.json'))
        self.assertTrue(files)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in files))
        for secret in ('Synthetic Customer', '246802', '110000000', '01000000000', self.password.decode()):
            self.assertNotIn(secret, output+error)

    def test_cloud_download_choice_stops_without_issuing_another_certificate(self):
        self.overrides['RSMCM0906A02'] = {'certList': [{'certSeqNo': 'SYN-CLOUD', 'certExpireTs': 'SYN-DATE', 'existCloudCertYn': 'Y'}]}
        def ask(kind, value):
            return True if kind == 'download_cloud_certificate' else self.ask(kind, value)
        result = issuance.run(lambda _: ask)
        self.assertEqual(result['required_action'], 'cloud_certificate_download_required')
        self.assertNotIn('RSMCM0890A01', self.calls)
        self.assertEqual(Registry().list(), [])

    def test_issued_certificate_save_failure_preserves_both_remote_successes(self):
        save = Registry.save
        def save_or_fail(registry, reference, password, material, **kwargs):
            if material['state'] == 'issued': raise OSError('Synthetic storage failure')
            return save(registry, reference, password, material, **kwargs)
        with patch.object(Registry, 'save', save_or_fail):
            result = issuance.run(lambda _: self.ask)
        self.assertEqual(result['certificate_issuance'], 'success')
        self.assertEqual(result['certificate_registration'], 'success')
        self.assertFalse(result['credential_saved'])
        self.assertEqual(result['local_status'], 'incomplete')
        self.assertEqual(self.calls.count('/v1.1/prsn-cert/issue/regist-cert'), 1)

    def test_terms_declined_never_sends_identity_sms(self):
        self.consent = False
        result = issuance.run(lambda _: self.ask)
        self.assertEqual(result['required_action'], 'terms_declined')
        self.assertEqual(self.calls, ['RSMCM9000C10'])

    def test_no_send_never_reads_settings_or_prompts(self):
        with patch.object(setup, 'load', side_effect=AssertionError()), patch.object(issuance_input, 'factory', side_effect=AssertionError()):
            code, out, _ = self.call(['certificate', 'issue'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)['result']['error'], 'send_required')

    def test_noninteractive_input_and_outdated_settings_stop_without_bank_calls(self):
        with patch('sys.stdin.isatty', return_value=False), patch.object(setup, 'load', side_effect=AssertionError()):
            self.assertEqual(json.loads(self.call(['certificate', 'issue', '--send'])[1])['result']['error'], 'interactive_input_required')
        old = setup.load(); old.pop('pin_check_key')
        storage.atomic_json(setup.root()/'settings.json', old)
        result = issuance.run(lambda _: self.ask)
        self.assertEqual(result['error'], 'issuance_settings_update_required')
        self.assertFalse(result['network_used'])
        self.assertEqual(self.calls, [])


class PinPolicyTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.install()
        self.exchange = Exchange(settings(), {}, 'certificate_issue')

    def test_input_checks_include_both_pin_entries_and_no_wrapped_sequences(self):
        for pin in (b'123802', b'248888', b'543680', b'12345', b'abcdef'):
            with self.assertRaises(Pending): pin_registration.validate(pin)
        pin_registration.validate(b'890246')
        pin_registration.validate(b'121212')

    def test_customer_failure_null_and_decode_error_permit_original_continuation(self):
        for result, body in [('FAIL', {}), ('SUCCESS', None), ('SUCCESS', {'birthDt': None}), ('SUCCESS', {'birthDt': []})]:
            with patch.object(transport, 'post', return_value=transport.Reply(200, [], response(result, body))):
                pin_registration.check_customer(self.exchange, b'246802')
            self.assertEqual(self.exchange.report['pin_customer_check'], 'allowed_after_lookup_error')

    def test_first_four_digits_check_birth_before_concatenated_phone(self):
        for data, action in [({'birthDt': '24680201', 'hpnoMid': '2468'}, 'pin_matches_birth'),
                             ({'hpnoMid': '0024', 'hpnoLst': '6800'}, 'pin_matches_phone')]:
            with patch.object(transport, 'post', return_value=transport.Reply(200, [], response(body=data))):
                with self.assertRaises(Pending) as stopped: pin_registration.check_customer(self.exchange, b'246802')
            self.assertEqual(stopped.exception.action, action)

    def test_mismatch_never_creates_certificate_or_repeats_customer_lookup(self):
        with patch.object(transport, 'post', return_value=transport.Reply(200, [], response(body={}))) as send:
            with self.assertRaises(Pending) as stopped:
                pin_registration.prepare(self.exchange, Mock(side_effect=[b'246802', b'248602']), channel=Mock())
        self.assertEqual(stopped.exception.action, 'pin_confirmation_mismatch')
        send.assert_called_once()
        self.assertEqual(Registry().list(), [])

    def test_age_uses_bank_date_and_distinguishes_empty_from_null(self):
        replies = [({'bdtInqrGS20': 'date', 'date': {'valueS20': '2026.10.17'}}, 'SUCCESS', 13.9999),
                   ({}, 'SUCCESS', 'NaN'), ({'bdtInqrGS20': 'date', 'date': {}}, 'SUCCESS', 'NaN'),
                   ({'bdtInqrGS20': 'date', 'date': {'valueS20': None}}, 'SUCCESS', 'error'),
                   ({}, 'FAIL', 'error')]
        for body, verdict, expected in replies:
            with patch.object(transport, 'post_web', return_value=transport.Reply(200, [], response(verdict, body))):
                if expected == 'error':
                    with self.assertRaises(ValueError): enrollment.age(self.exchange, '121018', '3')
                else:
                    actual = enrollment.age(self.exchange, '121018', '3')
                    self.assertTrue(math.isnan(actual)) if expected == 'NaN' else self.assertEqual(actual, expected)

    def test_terminal_account_can_be_entered_with_or_without_candidates(self):
        ask = issuance_input.factory(self.exchange)
        with patch('getpass.getpass', side_effect=['110111111']):
            self.assertEqual(ask('account', []), '110111111')
        with patch('getpass.getpass', side_effect=['0', '110222222']), patch('sys.stderr'):
            self.assertEqual(ask('account', [{'accountNumber': '110000000'}]), '110222222')
