"""Synthetic enrollment over the real CMS/SEED loopback service transport."""
import json
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import Mock

from giro.crypto import PIN_IV, _cbc
from giro.errors import GiroError
from giro.registration import DeviceRegistration, IdentityInput
from giro.registration_flow import EnrollmentStore, enroll_once
import test_login as support


class RegistrationTests(TestCase):
    cert, crl, target = support.LoginTests.cert, support.LoginTests.crl, support.LoginTests.target

    @classmethod
    def setUpClass(cls): support.LoginTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls): support.LoginTests.tearDownClass.__func__(cls)

    def setUp(self):
        support.LoginTests.setUp(self)
        self.now = 100.0
        self.registration = DeviceRegistration(device_id='SYNTHETIC-NEW-CLI',
            user_agent='SYNTHETIC-CLIENT', recipient=self.context, protection=self.protection,
            clock=lambda: self.now)
        self.person = IdentityInput(' 합성사용자 ', '19900102', '0', '1', 'SKT', '01000000000')
        self.protection.values = ['{"CODE_RESPONSE":"SYNTHETIC-REG-TOKEN"}']
        self.server.responses.update({
            'auth.device-status': (200, {'responseCode': '000', 'deviceRegYn': 'N'}),
            'registration.user-info': (200, {'responseCode': '000', 'nonce': 'user-nonce', 'memberStatus': '2'}),
            'registration.sms-send': (200, {'responseCode': '000', 'nonce': 'sent-nonce'}),
            'registration.sms-verify': (200, {'responseCode': '000', 'nonce': 'verified-nonce',
                'memberStatus': '0', 'deviceChgYn': 'Y'}),
            'registration.check-user': (200, {'responseCode': '000', 'nonce': 'checked-nonce'}),
            'registration.pin': (200, {'responseCode': '000', 'alertNumChgYn': 'Y', 'chgAlertNum': '01011111111'}),
        })

    def send_sms(self):
        self.assertEqual(self.registration.begin(send=True).next_action, 'identity_and_consent')
        result = self.registration.request_sms(self.person, terms_accepted=True, send=True)
        self.assertEqual(result.next_action, 'sms_code', result.report())

    def verify_sms(self):
        self.send_sms()
        return self.registration.verify_sms(code_provider=lambda: '123456', send=True)

    def check_pin(self):
        self.assertEqual(self.verify_sms().next_action, 'existing_pin')
        result = self.registration.check_existing_pin(pin_provider=lambda: '012345', send=True)
        self.assertEqual(result.next_action, 'new_pin', result.report())

    def register(self):
        return self.registration.register_pin(pin_provider=lambda: '234567',
            confirmation_provider=lambda: '234567', send=True)

    def fields(self, endpoint):
        return next(call[1] for call in self.server.calls if call[0] == endpoint)

    def test_existing_member_new_device_preserves_keys_cookies_nonce_and_one_token(self):
        self.check_pin()
        result = self.register()
        self.assertEqual(result.next_action, 'registered', result.report())
        self.assertEqual(result.report()['registration_service_decision'], 'success')
        self.assertFalse(result.report()['authenticated_session_created'])
        self.assertEqual(self.server.steps, ['auth.server-cert', 'protection.initialize',
            'auth.device-status', 'auth.datetime', 'codeguard.token', 'registration.user-info',
            'registration.sms-send', 'registration.sms-verify', 'registration.check-user', 'registration.pin'])
        self.assertEqual(len(self.server.keys), 2)
        self.assertNotEqual(*self.server.keys)
        self.assertEqual(self.registration.key, self.server.keys[-1])
        for name, fields, headers, _ in self.server.calls:
            self.assertEqual(fields['deviceId'], ['SYNTHETIC-NEW-CLI'])
            if name.startswith('registration.'):
                self.assertEqual(headers['Cookie'], 'SESSION=BUSINESS-COOKIE')
        self.assertEqual(self.fields('registration.sms-send')['nonce'], ['user-nonce'])
        self.assertEqual(self.fields('registration.sms-send')['name'], ['합성사용자'])
        self.assertEqual(self.fields('registration.sms-verify')['nonce'], ['sent-nonce'])
        self.assertEqual(self.fields('registration.check-user')['nonce'], ['verified-nonce'])
        self.assertEqual(self.fields('registration.check-user')['certType'], ['1'])
        fields = self.fields('registration.pin')
        self.assertEqual(fields['nonce'], ['checked-nonce'])
        self.assertEqual(fields['deviceUniqNo'], ['SYNTHETIC-NEW-CLI'])
        self.assertEqual(fields['pin'], fields['pin1'])
        cipher = bytes.fromhex(fields['pin'][0])
        for index, digit in enumerate((2, 3, 4, 5, 6, 7)):
            plain = _cbc(self.server.keys[-1], PIN_IV, cipher[index*16:(index+1)*16], decrypt=True)
            self.assertEqual(plain, bytes((5, digit)) + bytes(14))
        self.assertNotIn('auth.pin', self.server.steps)
        self.assertNotIn('01011111111', json.dumps(result.report()))
        with self.assertRaises(GiroError): self.register()

    def test_real_python_protection_connects_to_complete_enrollment(self):
        peer, runtime = support.LoginTests.connect_python_protection(self)
        self.registration.protection = runtime
        self.check_pin()
        self.assertEqual(self.register().next_action, 'registered')
        self.assertEqual([call[0] for call in peer.server.calls], [101, 200, 300])
        self.assertEqual(self.fields('registration.user-info')['CODE_RESPONSE'], ['SYNTHETIC-PYTHON-TOKEN-1'])
        for name, fields, _, form in self.server.calls:
            if name != 'registration.user-info':
                self.assertNotIn('CODE_RESPONSE', fields)
                self.assertNotIn('CODE_RESPONSE_TOKEN', form)

    def test_registration_already_exists_does_not_reset_or_send_sms(self):
        self.server.responses['auth.device-status'][1]['deviceRegYn'] = 'Y'
        self.assertEqual(self.registration.begin(send=True).next_action, 'login_existing_registration')
        self.assertEqual(self.server.steps, ['auth.server-cert', 'protection.initialize', 'auth.device-status'])
        with self.assertRaises(GiroError):
            self.registration.request_sms(self.person, terms_accepted=True, send=True)

    def test_no_device_change_needs_only_new_pin(self):
        self.server.responses['registration.sms-verify'][1]['deviceChgYn'] = 'N'
        self.assertEqual(self.verify_sms().next_action, 'new_pin')
        self.assertEqual(self.register().next_action, 'registered')
        self.assertNotIn('registration.check-user', self.server.steps)

    def test_member_and_carrier_routes_are_not_inferred_as_registration(self):
        self.send_sms()
        for carrier, member, route in (
            ('SKT', '1', 'member_join'), ('SKM', '2', 'member_unavailable'),
            ('LGT', None, 'member_status_unhandled'), ('LGM', 'unexpected', 'member_status_unhandled'),
            ('KTF', '0', 'carrier_certificate'), ('KTM', '1', 'carrier_certificate'),
            ('KTF', '2', 'member_unavailable')):
            with self.subTest(carrier=carrier, member=member):
                self.registration.next_action = 'sms_code'
                self.registration.phone_corp = carrier
                self.server.responses['registration.sms-verify'][1]['memberStatus'] = member
                result = self.registration.verify_sms(code_provider=lambda: '123456', send=True)
                self.assertEqual(result.next_action, route)
                self.assertEqual(result.report()['service_decision'], 'success')
                self.assertEqual(result.report()['registration_service_decision'], 'unobserved')
                provider = Mock(return_value='012345')
                with self.assertRaises(GiroError):
                    self.registration.register_pin(pin_provider=provider, confirmation_provider=provider, send=True)
                provider.assert_not_called()

    def test_sms_failure_retains_response_nonce_for_explicit_new_input(self):
        self.send_sms()
        self.server.responses['registration.sms-verify'] = (200, {'responseCode': '999', 'nonce': 'failure-nonce'})
        result = self.registration.verify_sms(code_provider=lambda: '000000', send=True)
        self.assertEqual(result.next_action, 'sms_code')
        self.assertEqual(self.registration.nonce, 'failure-nonce')
        self.assertEqual(self.server.steps.count('registration.sms-verify'), 1)

    def test_user_info_and_sms_send_failure_allow_only_explicit_resend(self):
        self.registration.begin(send=True)
        self.registration.nonce = 'prior'
        self.server.responses['registration.user-info'] = (200, {'responseCode': '999', 'nonce': 'ignored'})
        result = self.registration.request_sms(self.person, terms_accepted=True, send=True)
        self.assertEqual(result.next_action, 'identity_and_consent')
        self.assertEqual(self.registration.nonce, 'prior')
        self.assertNotIn('registration.sms-send', self.server.steps)
        self.protection.values.append('{"CODE_RESPONSE":"SYNTHETIC-REG-TOKEN"}')
        self.server.responses['registration.user-info'] = (200, {'responseCode': '000', 'nonce': 'user-nonce'})
        self.server.responses['registration.sms-send'] = (200, {'responseCode': '999', 'nonce': 'ignored'})
        result = self.registration.request_sms(self.person, terms_accepted=True, send=True)
        self.assertEqual(result.next_action, 'identity_and_consent')
        self.assertEqual(self.registration.nonce, 'user-nonce')
        with self.assertRaises(GiroError):
            self.registration.request_sms(self.person, terms_accepted=True, send=True)

    def workflow(self, store, **options):
        def factory(device_id):
            self.registration.device_id = device_id
            return self.registration
        return enroll_once(client_factory=factory, consent_provider=lambda: True,
            identity_provider=lambda: self.person, sms_provider=lambda: '123456',
            existing_pin_provider=lambda: '012345', new_pin_provider=lambda: '234567',
            confirmation_provider=lambda: '234567', store=store, **options)

    def test_workflow_persists_own_identity_before_sending_and_never_restarts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EnrollmentStore(Path(directory).resolve())
            result = self.workflow(store, send=True)
            self.assertEqual(result.registration_service_decision, 'success', result.report())
            identity = store.identity()
            self.assertRegex(identity, '^[0-9a-f]{16}$')
            self.assertEqual(self.fields('registration.pin')['deviceUniqNo'], [identity])
            self.assertEqual(json.loads((Path(directory)/'identity.json').read_text())['source'], 'cli-generated')
            receipt = (Path(directory)/'attempt.json').read_text()
            self.assertNotIn(identity, receipt)
            self.assertNotIn('합성사용자', receipt)
            self.assertNotIn('234567', receipt)
            before = list(self.server.calls)
            self.assertIn('enrollment_processing_incomplete', self.workflow(store, send=True).processing_issues)
            self.assertEqual(before, self.server.calls)
            self.assertEqual(store.identity(), identity)

    def test_workflow_preserves_registration_after_receipt_save_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EnrollmentStore(Path(directory).resolve())
            store.finish = Mock(side_effect=OSError('PRIVATE'))
            result = self.workflow(store, send=True)
            self.assertEqual(result.registration_service_decision, 'success')
            self.assertEqual(result.next_action, 'registered')
            self.assertEqual(result.processing_issues, ['enrollment_receipt_save_incomplete'])

    def test_workflow_without_send_does_not_access_store_or_inputs(self):
        store = Mock()
        with self.assertRaises(GiroError): self.workflow(store)
        store.identity.assert_not_called()
        self.assertEqual(self.server.calls, [])

    def test_identity_corruption_or_public_permissions_never_rotates_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EnrollmentStore(Path(directory).resolve())
            store.identity()
            path = Path(directory)/'identity.json'
            path.write_text('{"source":"observed-original-android-id"}')
            before = path.read_bytes()
            with self.assertRaises(GiroError): store.identity()
            self.assertEqual(path.read_bytes(), before)
            path.chmod(0o644)
            with self.assertRaises(ValueError): store.identity()

    def test_existing_pin_82_uses_callback_code_and_changes_authentication(self):
        self.verify_sms()
        self.server.responses['registration.check-user'] = (200, {'responseCode': '999',
            'nonce': 'failure-nonce', 'errorInfo': {'errorCode': '82'}})
        result = self.registration.check_existing_pin(pin_provider=lambda: '012345', send=True)
        self.assertEqual(result.next_action, 'choose_other_authentication')
        self.assertEqual(self.registration.nonce, 'failure-nonce')
        self.assertNotIn('registration.pin', self.server.steps)

    def test_pin_confirmation_mismatch_sends_nothing(self):
        self.check_pin()
        result = self.registration.register_pin(pin_provider=lambda: '234567',
            confirmation_provider=lambda: '765432', send=True)
        self.assertEqual(result.next_action, 'new_pin')
        self.assertEqual(result.processing_issues, ['pin_confirmation_mismatch'])
        self.assertNotIn('registration.pin', self.server.steps)

    def test_registration_rejection_preserves_nonce_and_does_not_retry(self):
        self.check_pin()
        self.server.responses['registration.pin'] = (200, {'responseCode': '999', 'nonce': 'new-pin-nonce'})
        result = self.register()
        self.assertEqual(result.report()['registration_service_decision'], 'failure')
        self.assertEqual(result.next_action, 'new_pin')
        self.assertEqual(self.registration.nonce, 'new-pin-nonce')
        self.assertEqual(self.server.steps.count('registration.pin'), 1)

    def test_registration_transport_loss_is_unobserved_never_retried(self):
        self.check_pin()
        self.server.responses['registration.pin'] = (200, 'disconnect')
        result = self.register()
        self.assertEqual(result.report()['registration_service_decision'], 'unobserved')
        self.assertEqual(self.server.steps.count('registration.pin'), 1)

    def test_disconnection_has_no_screen_failure_nonce_replay(self):
        self.send_sms()
        self.server.responses['registration.sms-verify'] = (200, {'responseCode': '300', 'nonce': 'not-consumed'})
        result = self.registration.verify_sms(code_provider=lambda: '123456', send=True)
        self.assertEqual(result.next_action, 'session_ended')
        self.assertEqual(self.registration.nonce, 'sent-nonce')

    def test_missing_nonce_and_pin_response_fields_do_not_invent_failure(self):
        self.server.responses['registration.sms-verify'][1]['deviceChgYn'] = None
        self.server.responses['registration.sms-verify'][1].pop('nonce')
        self.assertEqual(self.verify_sms().next_action, 'new_pin')
        self.server.responses['registration.pin'] = (200, {'responseCode': '000'})
        result = self.register()
        self.assertEqual(result.next_action, 'registered')
        self.assertNotIn('nonce', self.fields('registration.pin'))

    def test_diagnostic_and_cookie_failure_preserve_registration_success(self):
        self.check_pin()
        self.registration.events = Mock()
        self.registration.events.append.side_effect = OSError('SYNTHETIC-PRIVATE-LOG')
        extract = self.registration.cookies.extract_cookies
        def broken(wire, request):
            if request.full_url.endswith('/mRegPin.m'): raise OSError('SYNTHETIC-PRIVATE-COOKIE')
            return extract(wire, request)
        self.registration.cookies.extract_cookies = broken
        result = self.register()
        self.assertEqual(result.next_action, 'registered')
        self.assertEqual(result.report()['registration_service_decision'], 'success')
        self.assertIn('observation_failed', result.processing_issues)
        self.assertIn('cookie_update_failed', result.processing_issues)
        self.assertNotIn('PRIVATE', json.dumps(result.report()))

    def test_send_and_consent_required_before_network_or_input(self):
        with self.assertRaises(GiroError): self.registration.begin()
        self.assertEqual(self.server.calls, [])
        self.registration.begin(send=True)
        before = list(self.server.steps)
        with self.assertRaises(GiroError): self.registration.request_sms(self.person, send=True)
        provider = Mock(return_value='012345')
        for method in ('check_existing_pin', 'register_pin'):
            kwargs = dict(pin_provider=provider)
            if method == 'register_pin': kwargs['confirmation_provider'] = provider
            with self.assertRaises(GiroError): getattr(self.registration, method)(**kwargs)
        provider.assert_not_called()
        self.assertEqual(self.server.steps, before)

    def test_manual_resend_requires_cooldown_and_gets_a_new_user_nonce(self):
        self.send_sms()
        with self.assertRaises(GiroError):
            self.registration.request_sms(self.person, terms_accepted=True, send=True)
        self.assertEqual(self.server.steps.count('codeguard.token'), 1)
        self.now += 10
        self.protection.values = ['{"CODE_RESPONSE":"SYNTHETIC-REG-TOKEN-2"}']
        self.server.responses['registration.user-info'][1]['nonce'] = 'fresh-user-nonce'
        result = self.registration.request_sms(self.person, terms_accepted=True, send=True)
        self.assertEqual(result.next_action, 'sms_code')
        self.assertEqual(self.server.calls[-1][1]['nonce'], ['fresh-user-nonce'])

    def test_sensitive_inputs_and_responses_are_absent_from_public_report(self):
        self.check_pin()
        result = self.register()
        text = json.dumps(result.report()) + repr(self.person) + repr(result) + repr(self.registration.events)
        for secret in ('합성사용자', '19900102', '01000000000', 'SYNTHETIC-NEW-CLI',
                       'checked-nonce', '012345', '234567', 'BUSINESS-COOKIE', 'SYNTHETIC-REG-TOKEN'):
            self.assertNotIn(secret, text)
