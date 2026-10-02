from contextlib import contextmanager
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from giro.auth_flow import authenticate
from giro.client import AuthenticatedClient
from giro.registration_flow import EnrollmentStore
from giro.session_store import SessionStore
import test_registration as registration_support
import test_login as login_support


class AuthFlowTests(unittest.TestCase):
    cert, crl, target = (login_support.LoginTests.cert, login_support.LoginTests.crl, login_support.LoginTests.target)
    setUpClass = classmethod(registration_support.RegistrationTests.setUpClass.__func__)
    tearDownClass = classmethod(registration_support.RegistrationTests.tearDownClass.__func__)
    setUp = registration_support.RegistrationTests.setUp

    @contextmanager
    def dependencies(self, **kwargs):
        yield SimpleNamespace(profile=object(), recipient=self.context,
                              runtime=self.protection, processing_issues=[])

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

    def test_failed_login_keeps_registration_success_and_no_saved_session(self):
        self.protection.values.extend(['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        self.server.responses['auth.pin'] = (200, {'responseCode': '999'})
        result = self.invoke()
        self.assertEqual(result['registration_service_decision'], 'success')
        self.assertEqual(result['login_service_decision'], 'failure')
        self.assertFalse(result['session_saved'])
        self.assertEqual(self.server.steps.count('auth.pin'), 1)

    def test_storage_failure_does_not_turn_registration_or_login_into_failure(self):
        self.protection.values.extend(['DISCARDED', '{"CODE_RESPONSE":"SYNTHETIC-LOGIN"}'])
        result = self.invoke(session_store=SimpleNamespace(save=Mock(side_effect=OSError('SECRET'))))
        self.assertEqual(result['registration_service_decision'], 'success')
        self.assertEqual(result['login_service_decision'], 'success')
        self.assertEqual(result['processing_issues'], ['session_save_incomplete'])
