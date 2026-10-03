"""One encrypted query on a stored session, with no assertion of server TTL."""
import contextlib
from http.cookiejar import CookieJar
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from finance_cli.cli.main import main
from finance_cli.core import storage
from giro import client, session
from giro.crypto import decrypt_text, encrypt_text
from giro.errors import GiroError
from giro.session_store import SessionStore


class SessionExtensionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name).resolve()
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(self.home)}))
        self.enterContext(patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden')))
        self.store = SessionStore()
        self.saved = client.AuthenticatedSession('SYNTHETIC-DEVICE', b'S'*16, CookieJar(), 'SYNTHETIC/1', 'PIN', {})
        self.store.save(self.saved)
        self.calls = []
        self.response = {'responseCode': '000'}

    def post(self, path, body, headers):
        self.calls.append(path)
        self.assertEqual(path, '/service/common/mQryDateTime.m')
        values = parse_qs(body.decode())
        self.assertEqual(set(values), {'encryptedData'})
        self.assertIn('SYNTHETIC-DEVICE', decrypt_text(values['encryptedData'][0], self.saved.key))
        self.assertEqual(headers['User-agent'], self.saved.user_agent)
        with self.assertRaises(GiroError):
            with self.store.replacement():
                self.fail('login entered during extension')
        raw = encrypt_text(json.dumps(self.response), self.saved.key).hex().encode()
        return client.WireResponse(200, [('Mgiro-App-Encrypt', '1')], raw)

    def test_success_single_query_no_pin_token_or_server_expiry_claim(self):
        with patch.object(client, '_post', side_effect=self.post):
            result = session.extend(send=True, store=self.store)
        self.assertTrue(result['app_success'])
        self.assertTrue(result['request_accepted'])
        self.assertIsNone(result['login_extension_accepted'])
        self.assertEqual(result['extension_effect'], 'unverified')
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn('SYNTHETIC', json.dumps(result))
        self.assertIsNone(result['server_expires_at'])
        directory = self.store.root / 'session-operations' / result['operation_id']
        self.assertTrue((directory / 'attempt.json').exists())
        self.assertTrue(storage.read_json(directory / 'outcome.json')['app_success'])
        for file in directory.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_disconnect_persists_and_later_extension_does_not_send(self):
        for code in ('300', '301', '302'):
            self.store.save(self.saved)
            self.response = {'responseCode': code}
            with patch.object(client, '_post', side_effect=self.post):
                result = session.extend(send=True, store=self.store)
                before = len(self.calls)
                later = session.extend(send=True, store=self.store)
            self.assertEqual(result['callback'], 'disconnected_session')
            self.assertTrue(result['session_ended'])
            self.assertEqual(len(self.calls), before)
            self.assertFalse(later['network_used'])
            with self.store.use() as (saved, _):
                self.assertFalse(saved.active)

    def test_other_business_failure_does_not_invent_session_end(self):
        self.response = {'responseCode': '311'}
        with patch.object(client, '_post', side_effect=self.post):
            result = session.extend(send=True, store=self.store)
        self.assertFalse(result['app_success'])
        self.assertFalse(result['session_ended'])
        with self.store.use() as (saved, _):
            self.assertTrue(saved.active)

    def test_transport_failure_does_not_claim_server_rejection_or_retry(self):
        with patch.object(client, '_post', side_effect=TimeoutError('SYNTHETIC-SECRET')) as post:
            result = session.extend(send=True, store=self.store)
        self.assertEqual(post.call_count, 1)
        self.assertFalse(result['app_success'])
        self.assertIsNone(result['request_accepted'])
        self.assertEqual(result['service_decision'], 'unobserved')
        self.assertNotIn('SYNTHETIC-SECRET', json.dumps(result))

    def test_success_survives_session_and_outcome_storage_failures(self):
        with patch.object(client, '_post', side_effect=self.post), patch.object(self.store, '_save', side_effect=OSError('SYNTHETIC-SECRET')):
            result = session.extend(send=True, store=self.store)
        self.assertTrue(result['app_success'])
        self.assertEqual(result['session_processing_issues'], ['session_save_incomplete'])
        original = storage.atomic_json
        def write(path, value):
            if path.name == 'outcome.json':
                raise OSError('SYNTHETIC-SECRET')
            return original(path, value)
        with patch.object(client, '_post', side_effect=self.post), patch.object(storage, 'atomic_json', side_effect=write):
            result = session.extend(send=True, store=self.store)
        self.assertTrue(result['app_success'])
        self.assertIn('outcome_storage_failed', result['processing_issues'])

    def test_reservation_failure_prevents_request(self):
        with patch.object(storage, 'write_new', side_effect=OSError('SYNTHETIC')), patch.object(client, '_post') as post:
            result = session.extend(send=True, store=self.store)
        self.assertFalse(result['network_used'])
        post.assert_not_called()

    def test_plan_cli_alias_and_both_json_formats(self):
        for versioned in (False, True):
            prefix = ['--format', 'json-v1'] if versioned else []
            with patch.object(SessionStore, 'use', side_effect=AssertionError('opened')), contextlib.redirect_stdout(io.StringIO()) as output:
                code = main(prefix + ['giro', 'session', 'extend'])
            self.assertEqual(code, 0)
            self.assertIn('plan_only', output.getvalue())
            with patch.object(client, '_post', side_effect=self.post), contextlib.redirect_stdout(io.StringIO()) as output:
                code = main(prefix + ['giro', 'session', 'keepalive', '--send'])
            result = json.loads(output.getvalue())
            if versioned:
                self.assertEqual(result['exit_code'], code)
                result = result['result']
            self.assertEqual(code, 0)
            self.assertTrue(result['app_success'])
