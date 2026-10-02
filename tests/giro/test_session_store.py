from http.cookiejar import Cookie, CookieJar
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from giro.client import AuthenticatedSession
from giro.errors import GiroError
from giro.session_store import SessionStore


class SessionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = SessionStore(Path(self.temp.name).resolve()/'giro')
        cookies = CookieJar()
        cookies.set_cookie(Cookie(0, 'session', 'SYNTHETIC-COOKIE', None, False,
            'm.giro.or.kr', False, False, '/', True, True, None, True, None, None,
            {'HttpOnly': None, 'SameSite': 'Lax'}))
        self.session = AuthenticatedSession('synthetic-device', b'S'*16, cookies, 'Test/1',
            'PIN', {'payer': 'SYNTHETIC-PAYER'})

    def test_sealed_roundtrip_preserves_cookie_scope_and_persists_session_expiry(self):
        self.store.save(self.session)
        saved = (self.store.root/'session.json').read_bytes()
        for secret in (b'SYNTHETIC-COOKIE', b'synthetic-device', b'SYNTHETIC-PAYER', b'S'*16):
            self.assertNotIn(secret, saved)
        for path in self.store.root.iterdir(): self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.store.use() as (session, issues):
            self.assertEqual(session.info, self.session.info)
            self.assertEqual(session.key, self.session.key)
            self.assertEqual(vars(next(iter(session.cookies))), vars(next(iter(self.session.cookies))))
            session.active, session.info = False, {}
        self.assertEqual(issues, [])
        with self.store.use() as (session, _):
            self.assertFalse(session.active)
            self.assertEqual(session.info, {})

    def test_lost_key_does_not_replace_existing_key_or_session(self):
        self.store.save(self.session)
        saved = (self.store.root/'session.json').read_bytes()
        (self.store.root/'session.key').unlink()
        with self.assertRaises(GiroError): self.store.save(self.session)
        with self.assertRaises(GiroError):
            with self.store.use(): self.fail('missing key accepted')
        self.assertEqual((self.store.root/'session.json').read_bytes(), saved)
        self.assertFalse((self.store.root/'session.key').exists())

    def test_tampered_ciphertext_and_public_permissions_are_rejected(self):
        self.store.save(self.session)
        path = self.store.root/'session.json'
        document = json.loads(path.read_text())
        document['sealed'] = 'AAAA'
        path.write_text(json.dumps(document))
        with self.assertRaises(GiroError):
            with self.store.use(): self.fail('tamper accepted')
        self.store.save(self.session)
        path.chmod(0o644)
        with self.assertRaises(GiroError):
            with self.store.use(): self.fail('public session accepted')

    def test_save_failure_is_separate_from_observed_work_result(self):
        self.store.save(self.session)
        with self.store.use() as (session, issues):
            result = {'service_decision': 'success', 'processing_issues': issues}
            patcher = patch.object(self.store, '_save', side_effect=OSError('synthetic'))
            patcher.start()
        patcher.stop()
        self.assertEqual(result, {'service_decision': 'success', 'processing_issues': ['session_save_incomplete']})
