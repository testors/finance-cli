from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from giro.auth_flow import authenticate, login_dependencies, CODEGUARD_USER_AGENT
from giro.client import AuthenticatedClient
from giro.registration_flow import EnrollmentStore
from giro.session_store import SessionStore
import test_registration as registration_support
import test_login as login_support


class DependencyHeaderTests(unittest.TestCase):
    def test_business_and_protection_headers_are_separate_before_any_requests(self):
        from giro.codeguard_app import giro_task_settings
        settings = giro_task_settings(etc_data=None)
        profile = SimpleNamespace(app_info=settings.app_info, version=settings.version,
            platform=SimpleNamespace(abi='arm64-v8a', service=object()),
            locale_language='ko', map_profile='aosp-8',
            business_user_agent=Mock(return_value='SYNTHETIC-BUSINESS-AGENT'))
        with patch('giro.auth_flow.ProtectionProfile.load', return_value=profile), \
             patch('giro.auth_flow.PublicCache'), patch('giro.auth_flow.RecipientContext'), \
             patch('giro.auth_flow.CodeGuardHTTP') as transport, \
             patch('giro.auth_flow.PythonProtectionRuntime') as runtime:
            with login_dependencies() as dependencies:
                self.assertEqual(dependencies.user_agent, 'SYNTHETIC-BUSINESS-AGENT')
                self.assertEqual(transport.call_args.kwargs['default_user_agent'], CODEGUARD_USER_AGENT)
                runtime.return_value.initialize.assert_not_called()
            profile.business_user_agent.assert_called_once_with()


class AuthFlowTests(unittest.TestCase):
    cert, crl, target = (login_support.LoginTests.cert, login_support.LoginTests.crl, login_support.LoginTests.target)
    setUpClass = classmethod(registration_support.RegistrationTests.setUpClass.__func__)
    tearDownClass = classmethod(registration_support.RegistrationTests.tearDownClass.__func__)
    setUp = registration_support.RegistrationTests.setUp

    @contextmanager
    def dependencies(self, **kwargs):
        yield SimpleNamespace(profile=object(), recipient=self.context,
                              runtime=self.protection, user_agent='SYNTHETIC-BUSINESS-AGENT', processing_issues=[])

    def providers(self, profile):
        return dict(consent_provider=lambda: True, identity_provider=lambda: self.person,
            sms_provider=lambda: '123456', existing_pin_provider=lambda: '012345',
            new_pin_provider=lambda: '234567', confirmation_provider=lambda: '234567')

    def invoke(self, *, register=True, session_store=None):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.sessions = session_store or SessionStore(root/'giro')
        with patch('giro.auth_flow.login_dependencies', self.dependencies):
            return authenticate(register=register, send=True, pin_provider=lambda: '234567',
                enrollment_providers=self.providers, enrollment_store=EnrollmentStore(root/'enrollment'),
                session_store=self.sessions)

    def test_plan_does_not_open_files_or_consume_providers(self):
        provider, store = Mock(), Mock()
        with patch('giro.auth_flow.login_dependencies') as dependencies:
            result = authenticate(register=True, pin_provider=provider,
                enrollment_providers=provider, enrollment_store=store, session_store=store)
        self.assertTrue(result['plan_only'])
        self.assertFalse(result['network_used'])
        dependencies.assert_not_called()
        provider.assert_not_called()
        self.assertEqual(store.mock_calls, [])

    def test_registration_login_and_reload_session(self):
        self.protection.values.extend(['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        result = self.invoke()
        self.assertEqual(result['registration_service_decision'], 'success', result)
        self.assertEqual(result['login_service_decision'], 'success', result)
        self.assertTrue(result['session_saved'], result)
        self.assertTrue(all({k.lower(): v for k, v in call[2].items()}['user-agent'] == 'SYNTHETIC-BUSINESS-AGENT'
                            for call in self.server.calls))
        before = list(self.server.steps)
        with self.sessions.use() as (session, _):
            self.assertTrue(AuthenticatedClient(session).query('national.list', {'page':'1'}, send=True).app_success)
        self.assertEqual(self.server.steps, before + ['national.list'])

    def test_normal_login_does_not_register_or_send_sms(self):
        self.server.responses['auth.device-status'] = (200, {'responseCode': '000', 'deviceRegYn': 'Y'})
        self.protection.values = ['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}']
        result = self.invoke(register=False)
        self.assertEqual(result['login_service_decision'], 'success', result)
        self.assertEqual(result['registration_service_decision'], 'unobserved')
        self.assertFalse(any(name.startswith('registration.') for name in self.server.steps))

    def test_explicit_retry_after_consent_exit_archives_record_before_registering(self):
        providers = self.providers
        with patch.object(self, 'providers', side_effect=lambda p: providers(p) | {'consent_provider': lambda: False}):
            first = self.invoke()
        self.assertEqual(first['next_action'], 'consent_not_given')
        self.assertEqual([c[0] for c in self.server.calls],
                         ['auth.server-cert', 'auth.device-status', 'auth.datetime'])
        root = Path(self.temp.name).resolve() / 'enrollment'
        identity, receipt = (root / 'identity.json').read_bytes(), (root / 'attempt.json').read_bytes()
        self.protection.values.extend(['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        with patch('giro.auth_flow.login_dependencies', self.dependencies):
            result = authenticate(register=True, retry=True, send=True,
                pin_provider=lambda: '234567', enrollment_providers=self.providers,
                enrollment_store=EnrollmentStore(root), session_store=self.sessions)
        self.assertEqual(result['registration_service_decision'], 'success', result)
        self.assertEqual(result['login_service_decision'], 'success', result)
        self.assertTrue(result['session_saved'])
        self.assertEqual((root / 'identity.json').read_bytes(), identity)
        self.assertEqual([p.read_bytes() for p in (root / 'attempts').glob('*.json')], [receipt])

    def test_explicit_retry_archives_initial_rejection_and_reuses_identity_through_login(self):
        accepted = self.server.responses['auth.device-status']
        self.server.responses['auth.device-status'] = (200, {'errorInfo': {'errorCode': '999'}})
        first = self.invoke()
        self.assertEqual(first['steps'][0]['service_decision'], 'failure')
        root = Path(self.temp.name).resolve() / 'enrollment'
        store = EnrollmentStore(root)
        identity, receipt = (root / 'identity.json').read_bytes(), (root / 'attempt.json').read_bytes()
        calls = list(self.server.calls)
        def invoke(retry):
            with patch('giro.auth_flow.login_dependencies', self.dependencies):
                return authenticate(register=True, retry=retry, send=True,
                    pin_provider=lambda: '234567', enrollment_providers=self.providers,
                    enrollment_store=store, session_store=self.sessions)
        blocked = invoke(False)
        self.assertIn('enrollment_processing_incomplete', blocked['processing_issues'])
        self.assertEqual(self.server.calls, calls)
        self.server.responses['auth.device-status'] = accepted
        self.protection.values.extend(['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        result = invoke(True)
        self.assertEqual(result['registration_service_decision'], 'success', result)
        self.assertEqual(result['login_service_decision'], 'success', result)
        self.assertTrue(result['session_saved'])
        self.assertEqual((root / 'identity.json').read_bytes(), identity)
        archives = list((root / 'attempts').glob('*.json'))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), receipt)
        self.assertEqual(archives[0].stat().st_mode & 0o777, 0o600)
        device_id = json.loads(identity)['device_id']
        self.assertTrue(all(c[1]['deviceId'] == [device_id] for c in self.server.calls))
        calls = list(self.server.calls)
        refused = invoke(True)
        self.assertIn('enrollment_retry_unavailable', refused['processing_issues'])
        self.assertEqual(self.server.calls, calls)

    def test_failed_login_keeps_registration_success_and_no_saved_session(self):
        self.protection.values.extend(['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        self.server.responses['auth.pin'] = (200, {'responseCode': '999'})
        result = self.invoke()
        self.assertEqual(result['registration_service_decision'], 'success')
        self.assertEqual(result['login_service_decision'], 'failure')
        self.assertFalse(result['session_saved'])
        self.assertEqual(self.server.steps.count('auth.pin'), 1)

    def test_explicit_retry_after_rejected_sms_keeps_identity_and_archives_before_login(self):
        accepted = self.server.responses['registration.sms-send']
        self.server.responses['registration.sms-send'] = (200, {'errorInfo': {'errorCode': '999'}})
        first = self.invoke()
        self.assertEqual(first['next_action'], 'identity_and_consent')
        self.assertEqual(first['steps'][-1]['service_decision'], 'failure')
        self.assertNotIn('registration.sms-verify', self.server.steps)
        root = Path(self.temp.name).resolve() / 'enrollment'
        identity, receipt = (root/'identity.json').read_bytes(), (root/'attempt.json').read_bytes()
        before = list(self.server.calls)
        with patch('giro.auth_flow.login_dependencies', self.dependencies):
            blocked = authenticate(register=True, send=True, pin_provider=lambda: '234567',
                enrollment_providers=self.providers, enrollment_store=EnrollmentStore(root), session_store=self.sessions)
        self.assertIn('enrollment_processing_incomplete', blocked['processing_issues'])
        self.assertEqual(self.server.calls, before)
        self.server.responses['registration.sms-send'] = accepted
        self.protection.values.extend(['{"CODE_RESPONSE":"SYNTHETIC-RETRY"}',
                                      'DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        with patch('giro.auth_flow.login_dependencies', self.dependencies):
            result = authenticate(register=True, retry=True, send=True, pin_provider=lambda: '234567',
                enrollment_providers=self.providers, enrollment_store=EnrollmentStore(root), session_store=self.sessions)
        self.assertEqual(result['registration_service_decision'], 'success', result)
        self.assertEqual(result['login_service_decision'], 'success', result)
        self.assertTrue(result['session_saved'])
        self.assertEqual((root/'identity.json').read_bytes(), identity)
        self.assertEqual([p.read_bytes() for p in (root/'attempts').glob('*.json')], [receipt])
        self.assertEqual(self.server.steps.count('registration.sms-send'), 2)

    def test_explicit_login_after_registered_attempt_reuses_identity_without_enrolling(self):
        self.protection.values.extend(['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        accepted_login = self.server.responses['auth.pin']
        self.server.responses['auth.pin'] = (200, {'responseCode': '999'})
        first = self.invoke()
        self.assertEqual(first['registration_service_decision'], 'success')
        self.assertEqual(first['login_service_decision'], 'failure')
        enrollment_root = Path(self.temp.name).resolve()/'enrollment'
        receipt = (enrollment_root/'attempt.json').read_bytes()
        self.assertEqual(json.loads(receipt)['registration_service_decision'], 'success')
        device_id = EnrollmentStore(enrollment_root).identity()
        old_calls = len(self.server.calls)
        self.server.responses['auth.device-status'] = (200, {'responseCode': '000', 'deviceRegYn': 'Y'})
        self.server.responses['auth.pin'] = accepted_login
        self.protection.values.extend(['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        with patch('giro.auth_flow.login_dependencies', self.dependencies):
            second = authenticate(register=False, send=True, pin_provider=lambda: '234567',
                enrollment_providers=Mock(side_effect=AssertionError('no enrollment')),
                enrollment_store=EnrollmentStore(enrollment_root), session_store=self.sessions)
        self.assertEqual(second['login_service_decision'], 'success', second)
        self.assertTrue(second['session_saved'], second)
        self.assertEqual((enrollment_root/'attempt.json').read_bytes(), receipt)
        calls = self.server.calls[old_calls:]
        self.assertEqual([call[0] for call in calls],
                         ['auth.server-cert', 'auth.device-status', 'auth.datetime', 'auth.pin'])
        self.assertTrue(all(call[1]['deviceId'] == [device_id] for call in calls))
        with self.sessions.use() as (session, _):
            self.assertEqual(session.device_id, device_id)

    def test_storage_failure_does_not_turn_registration_or_login_into_failure(self):
        self.protection.values.extend(['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        with patch.object(SessionStore, '_save', side_effect=OSError('SECRET')):
            result = self.invoke()
        self.assertEqual(result['registration_service_decision'], 'success')
        self.assertEqual(result['login_service_decision'], 'success')
        self.assertEqual(result['processing_issues'], ['session_save_incomplete'])

    def test_busy_session_stops_login_before_dependencies_identity_or_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            sessions = SessionStore(Path(directory).resolve()/'session')
            identity, pin = Mock(), Mock()
            with sessions.replacement(), patch('giro.auth_flow.login_dependencies') as dependencies:
                result = authenticate(send=True, pin_provider=pin, enrollment_store=identity,
                                      session_store=sessions)
            self.assertFalse(result['network_used'])
            self.assertEqual(result['login_service_decision'], 'unobserved')
            self.assertFalse(result['session_saved'])
            self.assertEqual(result['processing_issues'], ['session_in_use_or_unavailable'])
            self.assertEqual(self.server.calls, [])
            dependencies.assert_not_called()
            pin.assert_not_called()
            self.assertEqual(identity.mock_calls, [])

    def test_login_excludes_queries_and_other_logins_until_saved_and_released(self):
        from giro.errors import GiroError
        self.server.responses['auth.device-status'] = (200, {'responseCode': '000', 'deviceRegYn': 'Y'})
        self.protection.values = ['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sessions = SessionStore(root/'session')
            def pin():
                with self.assertRaises(GiroError):
                    with SessionStore(root/'session').use(): self.fail('query entered during login')
                with patch('giro.auth_flow.login_dependencies') as dependencies:
                    other = authenticate(send=True, pin_provider=Mock(),
                        enrollment_store=EnrollmentStore(root/'enrollment'), session_store=sessions)
                dependencies.assert_not_called()
                self.assertFalse(other['network_used'])
                return '234567'
            with patch('giro.auth_flow.login_dependencies', self.dependencies):
                result = authenticate(send=True, pin_provider=pin,
                    enrollment_store=EnrollmentStore(root/'enrollment'), session_store=sessions)
            self.assertEqual(result['login_service_decision'], 'success', result)
            self.assertTrue(result['session_saved'], result)
            with sessions.use() as (session, _):
                self.assertTrue(AuthenticatedClient(session).query('national.list', {'page':'1'}, send=True).app_success)
            self.assertEqual(self.server.steps.count('auth.pin'), 1)
