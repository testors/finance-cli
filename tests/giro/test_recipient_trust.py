from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_cert_acquisition as certificates
from giro import recipient_trust as trust
from giro.__main__ import main
from giro.cert_selectors import MaterialStore
from giro.errors import GiroError
from giro.login import RecipientContext
from giro.public_material_io import PublicCache


class PublicTrustTests(unittest.TestCase):
    cert = certificates.AcquisitionTests.cert
    crl = certificates.AcquisitionTests.crl
    target = certificates.AcquisitionTests.target

    @classmethod
    def setUpClass(cls):
        certificates.AcquisitionTests.setUpClass.__func__(cls)
        cls.at = datetime.now(timezone.utc)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.materials = (self.cert(0).data, self.cert(0, valid=False).data)
        self.specs = tuple(trust.RootSpec('Synthetic Root ' + str(index), str(index) + '.der',
                          hashlib.sha256(data).hexdigest()) for index, data in enumerate(self.materials))
        patcher = patch.object(trust, 'ROOTS', self.specs)
        patcher.start()
        self.addCleanup(patcher.stop)
        guard = patch('socket.create_connection', side_effect=AssertionError('real network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)

    def seed_cache(self):
        for spec, data in zip(self.specs, self.materials):
            (self.directory / spec.filename).write_bytes(data)

    def reply(self, values, *, code=1):
        return SimpleNamespace(network_attempted=True, replay=SimpleNamespace(code=code, values=values))

    def ldap(self, replies):
        def fetch(client, location):
            self.assertEqual((location.host, location.port, location.attribute),
                             ('ds.yessign.or.kr', '389', 'cacertificate'))
            self.assertEqual(client.allowed, frozenset((trust.PUBLIC_ENDPOINT,)))
            client.network_attempted = True
            result = next(replies)
            if isinstance(result, Exception):
                raise result
            return result
        return patch.object(trust.PublicLdapClient, 'fetch', autospec=True, side_effect=fetch)

    def test_plan_never_reads_cache_or_connects(self):
        with patch.object(trust, 'PublicCache', side_effect=AssertionError('no file access')):
            report = trust.prepare_trust(self.directory)
        self.assertTrue(report['plan_only'])
        self.assertFalse(report['cache_accessed'])
        self.assertFalse(report['network_attempted'])

    def test_pinned_cache_is_reused_without_ldap(self):
        self.seed_cache()
        with self.ldap(iter(())) as fetch:
            report = trust.prepare_trust(self.directory, send=True)
        self.assertTrue(report['prepared'])
        self.assertEqual(report['ldap_requests'], 0)
        self.assertFalse(report['recipient_validated'])
        fetch.assert_not_called()

    def test_at_most_two_exchanges_and_only_exact_pinned_bytes_saved(self):
        replies = iter(self.reply((b'UNTRUSTED-DER', data)) for data in self.materials)
        with self.ldap(replies) as fetch:
            report = trust.prepare_trust(self.directory, send=True)
        self.assertTrue(report['prepared'])
        self.assertEqual(report['ldap_requests'], 2)
        self.assertEqual(fetch.call_count, 2)
        for spec, data in zip(self.specs, self.materials):
            path = self.directory / spec.filename
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('UNTRUSTED', json.dumps(report))

    def test_pin_mismatch_cannot_promote_or_save_a_different_root(self):
        with self.ldap(iter((self.reply((self.materials[1],)),))) as fetch:
            report = trust.prepare_trust(self.directory, send=True)
        self.assertFalse(report['prepared'])
        self.assertEqual(fetch.call_count, 1)
        self.assertIn('public_root_pin_not_found', report['processing_issues'])
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_transport_failure_is_not_retried_or_logged_raw(self):
        with self.ldap(iter((OSError('PRIVATE-REMOTE'),))) as fetch:
            report = trust.prepare_trust(self.directory, send=True)
        self.assertFalse(report['prepared'])
        self.assertEqual(fetch.call_count, 1)
        self.assertTrue(report['network_attempted'])
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_failed_ldap_wrapper_does_not_trust_its_values(self):
        with self.ldap(iter((self.reply(self.materials, code=0),))) as fetch:
            report = trust.prepare_trust(self.directory, send=True)
        self.assertEqual(fetch.call_count, 1)
        self.assertFalse(report['prepared'])
        self.assertFalse(report['roots'][0]['pinned_material_verified'])

    def test_write_failure_preserves_verified_material_result(self):
        with self.ldap(iter((self.reply((self.materials[0],)),))), \
             patch.object(PublicCache, 'write', return_value='io_error'):
            report = trust.prepare_trust(self.directory, send=True)
        self.assertFalse(report['prepared'])
        self.assertTrue(report['roots'][0]['pinned_material_verified'])
        self.assertIn('public_root_cache_write_failed', report['processing_issues'])

    def test_loader_never_downloads_or_accepts_missing_or_changed_roots(self):
        with PublicCache(self.directory, max_bytes=65536) as cache:
            with self.assertRaises(GiroError):
                trust.load_anchors(cache)
            self.seed_cache()
            anchors = trust.load_anchors(cache)
            self.assertEqual(tuple(cert.data for cert in anchors), self.materials)
            (self.directory / self.specs[1].filename).write_bytes(self.materials[0])
            with self.assertRaises(GiroError):
                trust.load_anchors(cache)

    def test_missing_relative_or_symlink_cache_is_not_created_or_followed(self):
        link = self.directory / 'link'
        link.symlink_to(self.directory, target_is_directory=True)
        for path in (None, Path('relative-cache'), self.directory / 'absent', link):
            with self.subTest(path=path):
                report = trust.prepare_trust(path, send=True)
                self.assertFalse(report['prepared'])
                self.assertFalse(report['network_attempted'])
        self.assertFalse((self.directory / 'absent').exists())

    def test_context_from_public_cache_keeps_mandatory_recipient_checks(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        from giro.cert_rules import CertificateRuleError
        self.seed_cache()
        target = self.target()
        pem = x509.load_der_x509_certificate(target.data).public_bytes(Encoding.PEM).decode('ascii')
        with PublicCache(self.directory, max_bytes=65536) as cache:
            context = RecipientContext.from_public_cache(cache, locale_language='ko',
                stores=(MaterialStore((self.cert(1),), (self.crl(0), self.crl(1))),))
            self.assertEqual(context.validate(pem), target.data)
            context.stores = (MaterialStore((self.cert(1),), (self.crl(0), self.crl(1, revoked=True))),)
            with self.assertRaises(CertificateRuleError):
                context.validate(pem)

    def test_cli_plan_and_missing_cache_report_without_secret_input(self):
        for arguments, expected in ((['auth', 'prepare-trust'], 0),
                                    (['auth', 'prepare-trust', '--send'], 2)):
            with redirect_stdout(io.StringIO()) as output:
                code = main(arguments)
            self.assertEqual(code, expected)
            report = json.loads(output.getvalue())
            self.assertFalse(report['network_attempted'])
            self.assertFalse(report['live_login_ready'])
