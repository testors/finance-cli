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
from giro.client import AuthenticatedClient
from giro.payment_flow import PaymentJournal, PaymentWorkflow
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

    def test_enrollment_login_query_and_payment_share_three_token_runtime(self):
        from test_codeguard_prepared import roundtrip
        peer, runtime = support.LoginTests.connect_python_protection(self, platform_transform=roundtrip)
        self.registration.protection = runtime
        with tempfile.TemporaryDirectory() as directory:
            store = EnrollmentStore(Path(directory).resolve()/'enrollment')
            result = self.workflow(store, login_pin_provider=lambda: '234567', send=True)
            self.assertEqual(result.registration_service_decision, 'success', result.report())
            self.assertTrue(result.report()['login']['session_ready'], result.report())
            self.assertEqual(result.next_action, 'authenticated')
            self.assertEqual([call[0] for call in peer.server.calls], [101, 200, 300, 200, 300, 200, 300])
            self.assertEqual(runtime.events.count('manager_update_listener'), 1)
            self.assertEqual(runtime.events.count('manager_token_listener'), 3)
            self.assertEqual(self.server.steps.count('auth.server-cert'), 1)
            self.assertEqual(self.server.steps.count('auth.device-status'), 1)
            self.assertEqual(len(self.server.keys), 3)
            self.assertEqual(len(set(self.server.keys)), 3)
            self.assertIs(result.session.cookies, self.registration.cookies)
            self.assertEqual(self.fields('auth.pin')['CODE_RESPONSE'], ['SYNTHETIC-PYTHON-TOKEN-3'])
            self.assertEqual(self.fields('auth.pin')['deviceUniqNo'], [store.identity()])
            from giro.session_store import SessionStore
            sessions = SessionStore(Path(directory).resolve()/'session')
            sessions.save(result.session)
            with sessions.use() as (restored, issues):
                self.assertEqual(restored.device_id, result.session.device_id)
                self.assertEqual(restored.key, result.session.key)
                self.assertEqual([(c.name, c.value) for c in restored.cookies],
                                 [(c.name, c.value) for c in result.session.cookies])
                self.assertTrue(AuthenticatedClient(restored).query('national.list', {'page': '1'}, send=True).app_success)
            self.assertEqual(issues, [])
            client = AuthenticatedClient(restored)
            self.assertTrue(client.query('national.list', {'page': '1'}, send=True).app_success)
            workflow = PaymentWorkflow(client, journal=PaymentJournal(Path(directory).resolve()/'payments'))
            review = workflow.prepare(support.BILL, account_selector=lambda _: 1, send=True)
            self.assertEqual(review['amount'], 900000)
            self.assertNotIn('national.payment', self.server.steps)
            paid = workflow.pay(review['draft_id'], account_password_provider=lambda: '1234', send=True)
            self.assertEqual(paid['service_decision'], 'success', paid)
            self.assertEqual(self.server.steps.count('national.payment'), 1)
            with self.assertRaises(GiroError):
                workflow.pay(review['draft_id'], account_password_provider=lambda: '1234', send=True)
            self.assertEqual(len(self.server.keys), 3)  # authenticated datetime is ENCRYPT
            self.assertEqual(runtime.events.count('manager_token_listener'), 3)
            receipt = json.loads((store.root/'attempt.json').read_text())
            self.assertEqual(receipt['registration_service_decision'], 'success')
            self.assertTrue(receipt['authenticated_session_created'])

    def test_login_failure_cannot_erase_completed_registration_or_retry(self):
        self.protection.values.extend(['SYNTHETIC-DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        self.server.responses['auth.pin'] = (200, {'responseCode': '999'})
        with tempfile.TemporaryDirectory() as directory:
            store = EnrollmentStore(Path(directory).resolve())
            saved = store.finish
            snapshots = []
            def finish(path, report):
                snapshots.append(json.loads(json.dumps(report)))
                saved(path, report)
            store.finish = finish
            result = self.workflow(store, login_pin_provider=lambda: '234567', send=True)
        self.assertEqual(result.registration_service_decision, 'success')
        self.assertEqual(result.report()['login']['login_service_decision'], 'failure')
        self.assertIsNone(result.session)
        self.assertEqual(snapshots[0]['registration_service_decision'], 'success')
        self.assertIsNone(snapshots[0]['login'])
        self.assertEqual(self.registration.registration_response.code, '000')
        with self.assertRaises(GiroError): self.registration.login(pin_provider=lambda: '234567', send=True)
        self.assertEqual(self.server.steps.count('auth.pin'), 1)

    def test_existing_registration_continues_without_sms_or_second_initialization(self):
        self.server.responses['auth.device-status'][1]['deviceRegYn'] = 'Y'
        self.protection.values = ['SYNTHETIC-DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}']
        with tempfile.TemporaryDirectory() as directory:
            result = self.workflow(EnrollmentStore(Path(directory).resolve()),
                                   login_pin_provider=lambda: '234567', send=True)
        self.assertTrue(result.report()['login']['session_ready'])
        self.assertEqual(result.registration_service_decision, 'unobserved')
        self.assertEqual(self.server.steps, ['auth.server-cert', 'protection.initialize', 'auth.device-status',
            'auth.datetime', 'codeguard.token', 'codeguard.token', 'auth.pin'])

    def test_login_is_explicit_and_only_available_after_registration(self):
        provider = Mock(return_value='234567')
        with self.assertRaises(GiroError): self.registration.login(pin_provider=provider, send=True)
        self.check_pin(); self.register()
        with self.assertRaises(GiroError): self.registration.login(pin_provider=provider)
        provider.assert_not_called()
        self.assertNotIn('auth.pin', self.server.steps)

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

    def test_local_input_validation_preserves_the_screen_for_explicit_correction(self):
        self.send_sms()
        before = list(self.server.calls)
        result = self.registration.verify_sms(code_provider=lambda: '123', send=True)
        self.assertEqual(result.next_action, 'sms_code')
        self.assertEqual(result.processing_issues, ['local_input_invalid'])
        self.assertEqual(before, self.server.calls)
        self.registration.verify_sms(code_provider=lambda: '123456', send=True)
        before = list(self.server.calls)
        result = self.registration.check_existing_pin(pin_provider=lambda: '123', send=True)
        self.assertEqual(result.next_action, 'existing_pin')
        self.assertEqual(before, self.server.calls)
        self.registration.check_existing_pin(pin_provider=lambda: '012345', send=True)
        before = list(self.server.calls)
        result = self.registration.register_pin(pin_provider=lambda: '234567',
            confirmation_provider=lambda: 'abc123', send=True)
        self.assertEqual(result.next_action, 'new_pin')
        self.assertEqual(before, self.server.calls)
        self.assertEqual(self.register().report()['registration_service_decision'], 'success')

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
