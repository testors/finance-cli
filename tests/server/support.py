"""Shared synthetic setup for server tests: temp data home, no network, test client."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests' / 'hometax'))

from fastapi.testclient import TestClient  # noqa: E402

from finance_cli.server import access, config as settings  # noqa: E402
from finance_cli.server.app import create_app  # noqa: E402
from finance_cli.server.db import Database  # noqa: E402

ORIGIN = 'http://127.0.0.1:8740'
# Timestamps and random identifiers the server generates. The digits of a short secret can occur
# in them by chance, so they are blanked before a text is searched for one.
GENERATED = re.compile(r'(?<![\w.])\d+\.\d+(?![\w.])|[0-9a-f]{16,}')


class ServerCase(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(directory).resolve()
        self.home = self.root / 'home'
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(self.home)}))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.config = settings.Config()
        self.db = Database()
        self.app = create_app(self.config, db=self.db, dispatcher=False)
        self.client = self.enterContext(TestClient(self.app, base_url=ORIGIN))

    def enroll(self, client=None):
        client = client or self.client
        with self.db.write() as con:
            code = access.create_code(con, self.config)['code']
        response = client.post('/api/v1/auth/enroll', json={'code': code, 'device_name': '테스트 브라우저'},
                               headers={'Origin': ORIGIN})
        self.assertEqual(response.status_code, 200, response.text)
        self.csrf = response.json()['csrf_token']
        return response

    def headers(self, **extra):
        return {'Origin': ORIGIN, 'X-CSRF-Token': self.csrf, **extra}

    def post(self, path, value=None, **kwargs):
        return self.client.post('/api/v1' + path, content=json.dumps(value or {}),
                                headers=self.headers(**{'Content-Type': 'application/json'}), **kwargs)

    def patch_(self, path, value):
        return self.client.patch('/api/v1' + path, content=json.dumps(value),
                                 headers=self.headers(**{'Content-Type': 'application/json'}))

    def get(self, path, **kwargs):
        return self.client.get('/api/v1' + path, **kwargs)

    def assertAbsent(self, text, *needles):
        """No needle occurs in the text outside the values the server generates."""
        searched = GENERATED.sub(' ', text)
        for needle in needles:
            # A needle that reads as a generated value itself is searched in the text as it stands.
            self.assertNotIn(needle, text if GENERATED.search(needle) else searched)


def synthetic_certificate(alias='synthetic', password=b'Synthetic-Password!'):
    """Import a synthetic joint certificate into the temp vault."""
    from test_certificate import synthetic_material
    from finance_cli.credentials.joint import crypto
    from finance_cli.credentials.registry import Registry
    cert, private, _ = synthetic_material()
    Registry().import_npki(alias, cert, crypto.encrypt(private, password.decode()), password)
    return alias
