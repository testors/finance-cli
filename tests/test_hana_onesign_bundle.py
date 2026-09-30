"""OneSign vault bundle: an independent sealer proves the layout; no network, no real vault."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unicodedata
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from finance_cli.cli.main import main
from finance_cli.services.hana import onesign_bundle as bundle
from finance_cli.services.hana.hana_protocol import device_uuid

PASSPHRASE = 'Synthetic-Bundle-Pass-01'
FIXTURE = Path(__file__).parent / 'fixtures' / 'onesign-bundle-v1.json'
SALT, NONCE = bytes(range(16)), bytes(range(100, 112))


def plaintext():
    android = '0123456789abcdef'
    device = device_uuid(android)
    app_key = b'synthetic-app-key'
    certificate = b'synthetic certificate bytes'
    record = {'alias': 'SYNTH-ALIAS', 'device_id': device, 'fingerprint': hashlib.sha256(certificate).hexdigest(),
              'certificate': bundle.b64url(certificate), 'pinSalt': 'c2FsdA', 'pinVersion': '', 'pinSpecVersion': 2,
              'authType': 9, 'key': 'c2VhbGVk'}
    return {'version': 1, 'created_at': '2026-01-01T00:00:00+00:00', 'device_id': device,
            'profile': {'device_id': device, 'customer_number': '0000000001', 'agent': 'synthetic',
                        'app_identity': {'android_id': android, 'key_sha256': hashlib.sha256(app_key).hexdigest(),
                                         'provenance': 'synthetic', 'user_agent': 'synthetic'},
                        'app_key': bundle.b64url(app_key), 'enrollment': {'state': 'ready', 'alias': 'SYNTH-ALIAS'}},
            'cloud': {'device_id': device, 'private_key': bundle.b64url(b'synthetic-cloud-key')},
            'records': {'SYNTH-ALIAS': record}}


def seal(plain, passphrase=PASSPHRASE, salt=SALT, nonce=NONCE):
    """Written against the format document with the standard library, not with the product's helpers."""
    header = {'format': 'finance-onesign-bundle-v1',
              'kdf': {'name': 'scrypt', 'n': 131072, 'r': 8, 'p': 1, 'salt': bundle.b64url(salt)},
              'cipher': {'name': 'aes-256-gcm', 'nonce': bundle.b64url(nonce)}}
    aad = json.dumps(header, sort_keys=True, separators=(',', ':')).encode()
    derived = hashlib.scrypt(passphrase.encode(), salt=salt, n=131072, r=8, p=1, maxmem=256 * 1024 * 1024, dklen=32)
    sealed = AESGCM(derived).encrypt(nonce, json.dumps(plain, sort_keys=True, separators=(',', ':')).encode(), aad)
    return json.dumps({**header, 'sealed': bundle.b64url(sealed)}).encode()


class Bundle(unittest.TestCase):
    def test_four_character_passphrases_roundtrip(self):
        for password in ('1234', 'aaaa', '가나다라', '!!!!', '    '):
            with self.subTest(password=password):
                self.assertEqual(bundle.opened(bundle.sealed(plaintext(), password), password), plaintext())
        with self.assertRaisesRegex(ValueError, 'passphrase_minimum_4_characters'):
            bundle.sealed(plaintext(), '123')

    def test_fixture_is_stable_and_opens(self):
        self.assertEqual(FIXTURE.read_bytes(), seal(plaintext()))
        self.assertEqual(bundle.opened(FIXTURE.read_bytes(), PASSPHRASE), plaintext())

    def test_wrong_passphrase_and_tampering(self):
        data = json.loads(seal(plaintext()))
        with self.assertRaisesRegex(ValueError, 'incorrect_passphrase_or_damaged_bundle'):
            bundle.opened(json.dumps(data).encode(), 'Another-Passphrase-1')
        salt = bytearray(bundle.unb64url(data['kdf']['salt']))
        salt[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'incorrect_passphrase_or_damaged_bundle'):
            bundle.opened(json.dumps({**data, 'kdf': {**data['kdf'], 'salt': bundle.b64url(bytes(salt))}}).encode(), PASSPHRASE)
        sealed = bytearray(bundle.unb64url(data['sealed']))
        sealed[3] ^= 1
        with self.assertRaisesRegex(ValueError, 'incorrect_passphrase_or_damaged_bundle'):
            bundle.opened(json.dumps({**data, 'sealed': bundle.b64url(bytes(sealed))}).encode(), PASSPHRASE)

    def test_layout_is_strict(self):
        data = json.loads(seal(plaintext()))
        for broken in ({**data, 'format': 'x'}, {**data, 'extra': 1}, {**data, 'kdf': {**data['kdf'], 'n': 1024}},
                       {**data, 'cipher': {**data['cipher'], 'name': 'aes-128-gcm'}}, {k: v for k, v in data.items() if k != 'sealed'}):
            with self.assertRaisesRegex(ValueError, 'unsupported_bundle_format|invalid_bundle_file'):
                bundle.opened(json.dumps(broken).encode(), PASSPHRASE)
        with self.assertRaisesRegex(ValueError, 'invalid_bundle_file'):
            bundle.opened(b'not json', PASSPHRASE)
        with self.assertRaisesRegex(ValueError, 'bundle_too_large'):
            bundle.opened(b'x' * (bundle.LIMIT + 1), PASSPHRASE)

    def test_bindings_are_checked_after_decryption(self):
        def mutate(change):
            plain = plaintext()
            change(plain)
            return seal(plain)
        cases = {
            'bundle_device_binding_failed': lambda p: p.update(device_id='00000000-0000-3000-8000-000000000000'),
            'bundle_app_key_mismatch': lambda p: p['profile'].update(app_key=bundle.b64url(b'another key')),
            'bundle_enrollment_not_ready': lambda p: p['profile']['enrollment'].update(state='pending'),
            'bundle_cloud_binding_failed': lambda p: p['cloud'].update(device_id='other'),
            'bundle_record_binding_failed': lambda p: p['records']['SYNTH-ALIAS'].update(fingerprint='0' * 64),
            'invalid_bundle_content': lambda p: p.update(records={}),
        }
        for code, change in cases.items():
            with self.subTest(code), self.assertRaisesRegex(ValueError, code):
                bundle.opened(mutate(change), PASSPHRASE)
        with self.assertRaisesRegex(ValueError, 'invalid_bundle_content'):
            bundle.opened(mutate(lambda p: p.update(ledger={'halted': False})), PASSPHRASE)

    def test_decrypted_content_uses_nfc_passphrase(self):
        decomposed = 'Passé-Synthetic-1'
        data = seal(plaintext(), unicodedata.normalize('NFC', decomposed))
        self.assertEqual(bundle.opened(data, decomposed), plaintext())


class Store(unittest.TestCase):
    def test_four_character_state_password(self):
        from finance_cli.services.hana.onesign_state import State
        for index, password in enumerate(('1234', 'aaaa', '가나다라', '!!!!', '    ')):
            name = 'short-' + str(index)
            with State(name, password, initial={'synthetic': True}) as state:
                self.assertEqual(state.snapshot(), {'synthetic': True})
            with State(name, password) as state:
                self.assertEqual(state.snapshot(), {'synthetic': True})
        with self.assertRaisesRegex(ValueError, 'passphrase_minimum_4_characters'):
            with State('too-short', '123', initial={'synthetic': True}):
                self.fail('three-character password accepted')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        for start in (patch.dict(os.environ, {'FINANCE_HOME': str(self.root / 'state')}),
                      patch('socket.socket', side_effect=AssertionError('No real network'))):
            start.start()
            self.addCleanup(start.stop)
        self.addCleanup(self.temp.cleanup)
        self.source = self.root / 'incoming.json'
        self.source.write_bytes(seal(plaintext()))

    def run_cli(self, *argv, passphrase=PASSPHRASE):
        output = io.StringIO()
        stdin = type('Stdin', (), {'buffer': io.BytesIO((passphrase + '\n').encode())})()
        with contextlib.redirect_stdout(output), patch('sys.stdin', stdin):
            code = main(['hana', 'onesign', *argv])
        return code, json.loads(output.getvalue())

    def refused(self, message, *argv, **options):
        code, result = self.run_cli(*argv, **options)
        self.assertEqual(code, 2)
        self.assertRegex(result['message'], message)

    def test_import_keeps_sealed_bytes_and_private_modes(self):
        code, result = self.run_cli('import', '--name', 'main', '--bundle', str(self.source), '--password-stdin')
        self.assertEqual((code, result['imported'], result['certificates'], result['network_used']), (0, True, 1, False))
        stored = self.root / 'state/hana/onesign/main/bundle.json'
        self.assertEqual(stored.read_bytes(), self.source.read_bytes())
        self.assertEqual(stat.S_IMODE(stored.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(stored.parent.stat().st_mode), 0o700)
        for secret in (b'0123456789abcdef', b'0000000001', b'SYNTH-ALIAS'):
            self.assertNotIn(secret, stored.read_bytes())
        self.assertEqual(self.run_cli('list')[1]['bundles'], ['main'])

    def test_show_needs_the_passphrase_and_hides_customer_and_alias(self):
        self.run_cli('import', '--name', 'main', '--bundle', str(self.source), '--password-stdin')
        code, result = self.run_cli('show', '--name', 'main', '--password-stdin')
        self.assertEqual(result['certificate_ids'], [hashlib.sha256(b'synthetic certificate bytes').hexdigest()])
        self.assertEqual(result['enrollment_state'], 'ready')
        self.assertNotIn('0000000001', json.dumps(result))
        self.refused('incorrect_passphrase_or_damaged_bundle', 'show', '--name', 'main', '--password-stdin',
                     passphrase='Another-Passphrase-1')

    def test_import_rejects_bad_input_without_storing(self):
        self.refused('incorrect_passphrase_or_damaged_bundle', 'import', '--name', 'main', '--bundle', str(self.source),
                     '--password-stdin', passphrase='Another-Passphrase-1')
        self.assertFalse((self.root / 'state/hana/onesign/main').exists())
        (self.root / 'link.json').symlink_to(self.source)
        self.refused('symlink_not_allowed', 'import', '--name', 'main', '--bundle', str(self.root / 'link.json'), '--password-stdin')
        self.refused('invalid_name', 'import', '--name', '../x', '--bundle', str(self.source), '--password-stdin')

    def test_import_never_overwrites_and_export_copies_bytes(self):
        self.run_cli('import', '--name', 'main', '--bundle', str(self.source), '--password-stdin')
        self.refused('onesign_bundle_exists', 'import', '--name', 'main', '--bundle', str(self.source), '--password-stdin')
        out = self.root / 'exported.json'
        code, result = self.run_cli('export', '--name', 'main', '--output', str(out))
        self.assertEqual((code, result['bytes_preserved']), (0, True))
        self.assertEqual(out.read_bytes(), self.source.read_bytes())
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        self.refused('exists', 'export', '--name', 'main', '--output', str(out))
        self.refused('onesign_bundle_not_found', 'export', '--name', 'missing', '--output', str(self.root / 'other.json'))


if __name__ == '__main__':
    unittest.main()
