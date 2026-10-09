"""Login dependency wiring with synthetic certificates, LDAP wire and loopback HTTP."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from giro.auth_flow import authenticate, login_dependencies
from giro.cert_acquisition import _ca_key
from giro.codeguard_app import giro_task_settings
from giro.login import PinLogin
from giro.public_material_io import PublicCache
from giro.recipient_trust import MATERIAL_LIMIT, PUBLIC_ENDPOINT
from giro.session_store import SessionStore
import test_login as login_support
import test_ldap_codec as wire
from test_public_material_io import FakeSocket


class RecipientRefreshTests(unittest.TestCase):
    cert = login_support.LoginTests.cert
    crl = login_support.LoginTests.crl
    target = login_support.LoginTests.target
    setUpClass = classmethod(login_support.LoginTests.setUpClass.__func__)
    tearDownClass = classmethod(login_support.LoginTests.tearDownClass.__func__)

    def setUp(self):
        login_support.LoginTests.setUp(self)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.cache_dir = self.root / 'public'
        self.cache_dir.mkdir()
        self.target_cert = self.target(aia='ldap://ds.yessign.or.kr:389/cn=issuer',
            dp='ldap://ds.yessign.or.kr:389/cn=list?certificateRevocationList')
        points = x509.CRLDistributionPoints([x509.DistributionPoint(
            [x509.UniformResourceIdentifier('ldap://ds.yessign.or.kr:389/cn=root-list')], None, None, None)])
        self.issuer = self.cert(1, extra=((points, False),))
        self.good_crl = self.crl(1).data
        self.server.responses['auth.server-cert'][1]['serverCert'] = x509.load_der_x509_certificate(
            self.target_cert.data).public_bytes(Encoding.PEM).decode('ascii')
        with PublicCache(self.cache_dir, max_bytes=MATERIAL_LIMIT) as cache:
            cache.write(_ca_key(self.target_cert), self.issuer.data)
            cache.write('cn=root-list.crl', self.crl(0).data)
            cache.write('cn=list.crl', self.good_crl)
        self.protection.close = Mock()

    @contextmanager
    def wiring(self):
        settings = giro_task_settings(etc_data=None)
        profile = SimpleNamespace(app_info=settings.app_info, version=settings.version,
            platform=SimpleNamespace(abi='arm64-v8a', service=object()), locale_language='ko',
            map_profile='aosp-8', business_user_agent=lambda: 'SYNTHETIC-BUSINESS-AGENT')
        with patch('giro.auth_flow.ProtectionProfile.load', return_value=profile), \
             patch('giro.recipient_trust.load_anchors', return_value=(self.cert(0),)), \
             patch('giro.auth_flow.CodeGuardHTTP'), \
             patch('giro.auth_flow.PythonProtectionRuntime', return_value=self.protection):
            yield

    def socket_reply(self, data=None, attribute=b'certificateRevocationList'):
        data = self.good_crl if data is None else data
        return FakeSocket(wire.result() + wire.entry([(attribute, [data])]) + wire.result(5, 0))

    def validate(self, dependencies):
        return dependencies.recipient.validate(self.server.responses['auth.server-cert'][1]['serverCert'])

    def test_valid_cache_uses_no_ldap_and_configuration_is_bounded(self):
        with self.wiring(), login_dependencies(public_cache=self.cache_dir) as deps, \
             patch('socket.create_connection', side_effect=AssertionError('cache must avoid network')):
            ldap = deps.recipient.ldap
            self.assertEqual(ldap.allowed, frozenset((PUBLIC_ENDPOINT,)))
            self.assertEqual((ldap.timeout_ms, ldap.max_bytes), (10000, MATERIAL_LIMIT))
            self.assertEqual(self.validate(deps), self.target_cert.data)
            self.assertFalse(ldap.network_attempted)

    def test_expired_crl_refreshes_once_then_login_succeeds_and_cache_is_reused(self):
        path = self.cache_dir / 'cn=list.crl'
        path.write_bytes(self.crl(1, valid=False).data)
        sock = self.socket_reply()
        # PinLogin's HTTP exchange is separately redirected to the loopback fixture.
        with self.wiring(), login_dependencies(public_cache=self.cache_dir) as deps:
            original = deps.recipient.ldap.fetch
            def fetch(location):
                with patch('socket.create_connection', return_value=sock) as connect:
                    result = original(location)
                connect.assert_called_once_with(PUBLIC_ENDPOINT, timeout=10)
                return result
            with patch.object(deps.recipient.ldap, 'fetch', side_effect=fetch) as lookup:
                login = PinLogin(device_id='SYNTHETIC', user_agent=deps.user_agent,
                                 recipient=deps.recipient, protection=deps.runtime)
                result = login.login(pin_provider=self.pin, send=True)
            self.assertEqual(result.report()['login_service_decision'], 'success', result.report())
            self.assertEqual(lookup.call_count, 1)
            self.assertEqual(self.server.steps.count('auth.pin'), 1)
            self.assertEqual(path.read_bytes(), self.good_crl)
            with patch('socket.create_connection', side_effect=AssertionError('refreshed cache')):
                self.validate(deps)
        self.assertTrue(sock.closed)

    def test_missing_issuer_and_crl_are_acquired_in_order(self):
        (self.cache_dir / _ca_key(self.target_cert)).unlink()
        (self.cache_dir / 'cn=list.crl').unlink()
        sockets = [self.socket_reply(self.issuer.data, b'cacertificate'), self.socket_reply()]
        with self.wiring(), login_dependencies(public_cache=self.cache_dir) as deps, \
             patch('socket.create_connection', side_effect=sockets) as connect:
            self.validate(deps)
        self.assertEqual(connect.call_count, 2)
        self.assertEqual((self.cache_dir / _ca_key(self.target_cert)).read_bytes(), self.issuer.data)
        self.assertEqual((self.cache_dir / 'cn=list.crl').read_bytes(), self.good_crl)
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_timeout_stops_before_pin_without_retry_and_keeps_old_session(self):
        (self.cache_dir / 'cn=list.crl').unlink()
        sessions = SessionStore(self.root / 'session')
        sessions.root.mkdir(mode=0o700)
        # The replacement contract must leave an existing session file untouched.
        old = sessions.root / 'session.json'
        old.write_bytes(b'SYNTHETIC-EXISTING-SESSION')
        from giro.public_material_io import PublicLdapClient
        original = PublicLdapClient.fetch
        def fetch(ldap, location):
            with patch('socket.create_connection', side_effect=TimeoutError('SYNTHETIC-PRIVATE-ERROR')) as connect:
                result = original(ldap, location)
            connect.assert_called_once()
            return result
        with self.wiring(), patch.object(PublicLdapClient, 'fetch', fetch):
            result = authenticate(send=True, pin_provider=self.pin, public_cache=self.cache_dir,
                enrollment_store=SimpleNamespace(identity=lambda: 'SYNTHETIC'), session_store=sessions)
        self.assertEqual(result['login_service_decision'], 'unobserved', result)
        self.assertIn('recipient_public_lookup_failed', result['processing_issues'])
        self.assertFalse(result['session_saved'])
        self.assertEqual(self.server.steps, ['auth.server-cert'])
        self.pin.assert_not_called()
        self.assertEqual(old.read_bytes(), b'SYNTHETIC-EXISTING-SESSION')
        self.assertNotIn('SYNTHETIC-PRIVATE-ERROR', str(result))

    def test_downloaded_crls_still_require_dates_signature_and_revocation_checks(self):
        from giro.cert_rules import CertificateRuleError
        for kwargs in ({'valid': False}, {'wrong_key': True}, {'revoked': True}):
            with self.subTest(kwargs=kwargs):
                (self.cache_dir / 'cn=list.crl').unlink(missing_ok=True)
                with self.wiring(), login_dependencies(public_cache=self.cache_dir) as deps, \
                     patch('socket.create_connection', return_value=self.socket_reply(self.crl(1, **kwargs).data)) as connect:
                    with self.assertRaises(CertificateRuleError):
                        self.validate(deps)
                connect.assert_called_once()
        self.pin.assert_not_called()

    def test_cache_write_failure_does_not_reverse_validation_success(self):
        (self.cache_dir / 'cn=list.crl').unlink()
        with self.wiring(), login_dependencies(public_cache=self.cache_dir) as deps, \
             patch('socket.create_connection', return_value=self.socket_reply()) as connect, \
             patch('giro.public_material_io.os.write', side_effect=OSError('SYNTHETIC-WRITE-ERROR')):
            self.assertEqual(self.validate(deps), self.target_cert.data)
        connect.assert_called_once()

    def test_unlisted_endpoint_is_refused_before_dns(self):
        from giro.public_material_io import MaterialAccessLimit
        from giro.ldap_codec import parse_uri
        with self.wiring(), login_dependencies(public_cache=self.cache_dir) as deps, \
             patch('socket.create_connection') as connect, patch('socket.getaddrinfo') as dns:
            with self.assertRaises(MaterialAccessLimit):
                deps.recipient.ldap.fetch(parse_uri('ldap://unlisted.invalid/cn=list'))
        connect.assert_not_called()
        dns.assert_not_called()

