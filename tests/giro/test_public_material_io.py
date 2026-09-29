from io import BytesIO
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from giro.cert_acquisition import AcquisitionEffect, ObservedReadFailure
from giro.ldap_codec import parse_uri, bind_request, search_request, unbind_request
from giro.public_material_io import PublicCache, PublicLdapClient, PublicMaterialExecutor, MaterialAccessLimit
import test_ldap_codec as wire

class CacheTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = PublicCache(self.root, max_bytes=32)
        self.addCleanup(self.cache.close)

    def test_real_public_file_roundtrip_truncates_previous_contents(self):
        self.assertEqual(self.cache.write('public.der', b'PUBLIC-CERT'), 'written')
        self.assertEqual(self.cache.read('public.der'), b'PUBLIC-CERT')
        self.assertEqual(self.cache.write('public.der', b'X'), 'written')
        self.assertEqual(self.cache.read('public.der'), b'X')
        self.assertEqual((self.root / 'public.der').stat().st_mode & 511, 384)

    def test_actual_missing_file_is_observed_io_failure(self):
        self.assertIsInstance(self.cache.read('missing.crl'), ObservedReadFailure)

    def test_explicit_root_and_budget_are_required(self):
        for (root, budget) in ((Path('relative'), 32), (self.root, 0), (self.root, True), (self.root / 'absent', 32)):
            with self.assertRaises(MaterialAccessLimit):
                PublicCache(root, max_bytes=budget)

    def test_cache_keys_cannot_escape_root(self):
        for key in ('', '.', '..', '../outside', '/outside', 'a/b', 'nul\x00x'):
            for action in (lambda : self.cache.read(key), lambda : self.cache.write(key, b'X')):
                with self.assertRaises(MaterialAccessLimit):
                    action()

    def test_symlink_not_followed_or_truncated(self):
        victim = self.root / 'original'
        victim.write_bytes(b'UNTOUCHED')
        (self.root / 'link').symlink_to(victim)
        with self.assertRaises(MaterialAccessLimit):
            self.cache.read('link')
        with self.assertRaises(MaterialAccessLimit):
            self.cache.write('link', b'X')
        self.assertEqual(victim.read_bytes(), b'UNTOUCHED')

    def test_observed_shared_inode_not_truncated(self):
        victim = self.root / 'original'
        victim.write_bytes(b'UNTOUCHED')
        shared = SimpleNamespace(st_mode=victim.stat().st_mode, st_nlink=2)
        with patch('os.fstat', return_value=shared):
            with self.assertRaises(MaterialAccessLimit):
                self.cache.write('original', b'X')
            with self.assertRaises(MaterialAccessLimit):
                self.cache.read('original')
        self.assertEqual(victim.read_bytes(), b'UNTOUCHED')

    def test_fifo_read_does_not_block(self):
        os.mkfifo(self.root / 'fifo')
        with self.assertRaises(MaterialAccessLimit):
            self.cache.read('fifo')

    def test_budget_not_reported_as_read_or_write_failure(self):
        (self.root / 'large').write_bytes(b'A' * 33)
        with self.assertRaises(MaterialAccessLimit):
            self.cache.read('large')
        with self.assertRaises(MaterialAccessLimit):
            self.cache.write('large', b'B' * 33)
        self.assertEqual((self.root / 'large').read_bytes(), b'A' * 33)

    def test_fstat_failure_closes_open_descriptor(self):
        self.cache.write('public.der', b'X')
        with patch('os.fstat', side_effect=OSError('synthetic')), patch('os.close', wraps=os.close) as close:
            self.assertIsInstance(self.cache.read('public.der'), ObservedReadFailure)
        close.assert_called_once()

    def test_actual_write_failure_maps_only_to_nonfatal_io(self):
        with patch('os.write', side_effect=OSError('synthetic')):
            self.assertEqual(self.cache.write('public.der', b'X'), 'io_error')

    def test_closed_cache_is_not_a_cache_miss(self):
        self.cache.close()
        with self.assertRaises(MaterialAccessLimit):
            self.cache.read('missing')

class FakeSocket:

    def __init__(self, data, *, fail_write=None, fail_recv=False, chunk=3):
        self.input = BytesIO(data)
        self.sent = []
        self.closed = False
        self.timeout = None
        (self.fail_write, self.fail_recv, self.chunk) = (fail_write, fail_recv, chunk)

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        if self.fail_recv:
            raise TimeoutError('synthetic')
        return self.input.read(min(size, self.chunk))

    def sendall(self, data):
        self.sent.append(data)
        if self.fail_write == len(self.sent):
            raise OSError('synthetic')

    def close(self):
        self.closed = True

class LdapIOTests(unittest.TestCase):
    location = parse_uri('ldap://PUBLIC.invalid:389/cn=synthetic?cacertificate')

    def client(self, **kwargs):
        return PublicLdapClient(allowed_endpoints=(('public.invalid', 389),), timeout_ms=100, max_bytes=kwargs.pop('max_bytes', 65536), locale_language='ko', **kwargs)

    def response(self, tail=None):
        if tail is None:
            tail = wire.result(5, 49)
        return wire.result() + wire.entry([(b'CACERTIFICATE;binary', [b'PUBLIC'])]) + tail

    def fetch(self, sock, *, client=None, identifier=42):
        client = client or self.client()
        with patch('socket.socket', side_effect=AssertionError('no real network')), patch('socket.create_connection', return_value=sock) as connect, patch('secrets.randbelow', return_value=identifier) as random:
            result = client.fetch(self.location)
        connect.assert_called_once_with(('PUBLIC.invalid', 389), timeout=0.1)
        random.assert_called_once_with(2147483647)
        self.assertTrue(sock.closed)
        return result

    def test_exchange_uses_fresh_id_and_complete_actual_io_sequence(self):
        sock = FakeSocket(self.response())
        result = self.fetch(sock)
        self.assertEqual((result.replay.code, result.replay.values), (1, (b'PUBLIC',)))
        self.assertEqual(sock.sent, [bind_request(42), search_request(43, self.location), unbind_request(44)])
        self.assertEqual(sock.timeout, 0.1)
        self.assertTrue(result.network_attempted)
        self.assertFalse(result.transport_equivalence_verified)

    def test_zero_random_maps_to_one_like_original_constructor(self):
        sock = FakeSocket(self.response())
        self.fetch(sock, identifier=0)
        self.assertEqual(sock.sent[0], bind_request(1))

    def test_scheme_and_allowlist_checked_before_dns_or_random(self):
        client = self.client()
        with patch('socket.create_connection', side_effect=AssertionError('no DNS')), patch('secrets.randbelow', side_effect=AssertionError('no random')):
            for uri in ('ldaps://public.invalid/dn', 'ldap://other.invalid/dn', 'ldap://public.invalid:390/dn', 'ldap://public.invalid:invalid/dn'):
                with self.assertRaises(MaterialAccessLimit):
                    client.fetch(parse_uri(uri))
                self.assertFalse(client.network_attempted)

    def test_connect_failure_is_observed_not_fabricated_policy_error(self):
        client = self.client()
        with patch('socket.create_connection', side_effect=OSError('private diagnostic')):
            result = client.fetch(self.location)
        self.assertEqual((result.replay.code, result.replay.failure_stage), (0, 'connect'))
        self.assertTrue(client.network_attempted)
        self.assertNotIn('private', repr(result))

    def test_bind_send_failure_does_not_unbind(self):
        sock = FakeSocket(b'', fail_write=1)
        result = self.fetch(sock)
        self.assertEqual(result.replay.failure_stage, 'send_bind')
        self.assertEqual(len(sock.sent), 1)

    def test_search_send_failure_attempts_unbind(self):
        sock = FakeSocket(self.response(), fail_write=2)
        result = self.fetch(sock)
        self.assertEqual(result.replay.failure_stage, 'send_search')
        self.assertEqual(sock.sent[-1], unbind_request(44))

    def test_read_timeout_fails_and_attempts_unbind(self):
        sock = FakeSocket(b'', fail_recv=True)
        result = self.fetch(sock)
        self.assertEqual(result.replay.failure_stage, 'receive_bind')
        self.assertEqual(sock.sent[-1], unbind_request(43))

    def test_completion_eof_and_unbind_failure_preserve_success(self):
        sock = FakeSocket(self.response(tail=b''), fail_write=3)
        result = self.fetch(sock)
        self.assertEqual(result.replay.code, 1)
        self.assertTrue(result.replay.completion_io_ignored)

    def test_backend_limit_closes_socket_without_claiming_wrapper_failure(self):
        from giro.cert_factory import CertificateBackendLimit
        sock = FakeSocket(b'0\x01X')
        with self.assertRaises(CertificateBackendLimit):
            self.fetch(sock)
        self.assertTrue(sock.closed)

    def test_byte_budget_is_not_swallowed_as_completion_io(self):
        data = self.response()
        client = self.client(max_bytes=len(data) - 1)
        sock = FakeSocket(data)
        with self.assertRaises(MaterialAccessLimit):
            self.fetch(sock, client=client)
        self.assertTrue(sock.closed)
        self.assertTrue(client.network_attempted)

    def test_oversized_frame_refused_before_receiving_declared_body(self):
        sock = FakeSocket(bytes.fromhex('30847fffffff') + b'UNREAD')
        with self.assertRaises(MaterialAccessLimit):
            self.fetch(sock, client=self.client(max_bytes=100))
        self.assertEqual(sock.input.read(), b'UNREAD')

    def test_executor_records_network_attempt_even_on_backend_limit(self):
        sock = FakeSocket(self.response())
        executor = PublicMaterialExecutor(stores=(), ldap=self.client(max_bytes=2))

        def operation():
            yield AcquisitionEffect('ldap_certificate', location=self.location)
        with patch('socket.create_connection', return_value=sock), self.assertRaises(MaterialAccessLimit):
            executor.run(operation())
        self.assertTrue(executor.network_attempted)
        self.assertTrue(sock.closed)

    def test_executor_never_invents_missing_cache_or_ldap(self):
        executor = PublicMaterialExecutor(stores=())
        for kind in ('read_certificate_cache', 'ldap_crl', 'set_trust_anchors'):

            def operation():
                yield AcquisitionEffect(kind, location=self.location, cache_key='x')
            with self.assertRaises(MaterialAccessLimit):
                executor.run(operation())
        self.assertFalse(executor.network_attempted)
