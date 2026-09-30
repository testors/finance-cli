"""Synthetic credentials only; shared selection never performs a login."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from asn1crypto import cms as asn_cms
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from finance_cli.cli.main import main
from finance_cli.core import profiles, storage
from finance_cli.credentials.registry import Registry, decode
from finance_cli.credentials.joint import crypto, cms
from finance_cli.services.hana.hana_protocol import joint_cert_tbs

sys.path.insert(0, str(Path(__file__).parent / 'hometax'))
from test_certificate import synthetic_material, encrypt_test_key
from test_pfx import synthetic_pfx


class SharedCredentials(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.private, cls.random = synthetic_material()
        cls.password = b'Synthetic-Password!'
        cls.encrypted = crypto.encrypt(cls.private, cls.password.decode())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name).resolve() / 'state'
        self.environment = patch.dict(os.environ, {'FINANCE_HOME': str(self.home)})
        self.environment.start()
        self.network = patch('socket.socket', side_effect=AssertionError('No institution requests'))
        self.network.start()
        self.registry = Registry()

    def tearDown(self):
        self.network.stop()
        self.environment.stop()
        self.temp.cleanup()

    def imported(self):
        return self.registry.import_npki('personal', self.cert, self.encrypted, self.password)

    def command(self, argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch('getpass.getpass', return_value=self.password.decode()):
            code = main(argv)
        return code, json.loads(output.getvalue())

    def test_empty_listing_has_no_side_effect(self):
        self.assertEqual(self.registry.list(), [])
        self.assertFalse(self.home.exists())

    def test_npki_roundtrip_preserves_original_bytes_and_vid(self):
        self.imported()
        value = self.registry.load('personal', self.password)
        self.assertEqual(decode(value['certificate']), self.cert)
        self.assertEqual(decode(value['encrypted_key']), self.encrypted)
        private = crypto.check_pair(self.cert, decode(value['encrypted_key']), self.password.decode())
        self.assertEqual(private, self.private)
        self.assertEqual(cms.extract_vid_random(private), self.random)

    def test_no_clear_key_or_password_or_certificate_in_store(self):
        self.imported()
        for path in self.home.rglob('*'):
            if path.is_file():
                data = path.read_bytes()
                for forbidden in (self.password, self.private, self.cert, base64.b64encode(self.private), base64.b64encode(self.cert)):
                    self.assertNotIn(forbidden, data)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_wrong_password_and_ciphertext_tamper_are_rejected(self):
        self.imported()
        with self.assertRaisesRegex(ValueError, 'incorrect_password'):
            self.registry.load('personal', b'wrong')
        path = self.registry.root / 'blobs' / self.registry.entry('personal')['blob']
        value = storage.read_json(path)
        data = bytearray(base64.b64decode(value['sealed'])); data[0] ^= 1
        value['sealed'] = base64.b64encode(data).decode()
        storage.atomic_json(path, value)
        with self.assertRaisesRegex(ValueError, 'damaged_credential'):
            self.registry.load('personal', self.password)

    def test_blob_swap_does_not_select_another_identity(self):
        self.imported()
        other_cert, other_private, _ = synthetic_material()
        other_key = crypto.encrypt(other_private, self.password.decode())
        self.registry.import_npki('second', other_cert, other_key, self.password)
        state = self.registry.index()
        state['entries']['personal']['blob'] = state['entries']['second']['blob']
        storage.atomic_json(self.registry.root / 'index.json', state)
        with self.assertRaises(ValueError):
            self.registry.load('personal', self.password)

    def test_duplicate_alias_and_certificate_do_not_overwrite(self):
        self.imported()
        before = (self.registry.root / 'index.json').read_bytes()
        for alias in ('personal', 'second'):
            with self.assertRaises(ValueError):
                self.registry.import_npki(alias, self.cert, self.encrypted, self.password)
        self.assertEqual(before, (self.registry.root / 'index.json').read_bytes())

    def test_alias_traversal_is_rejected(self):
        for alias in ('../outside', '', '/absolute', 'a/b'):
            with self.assertRaises(ValueError):
                self.registry.entry(alias)

    def test_symlink_home_is_rejected(self):
        target = self.home.parent / 'target'; target.mkdir(mode=0o700)
        self.home.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.imported()

    def test_pfx_roundtrip_retains_pkcs8_attributes(self):
        pfx = synthetic_pfx([self.cert], [self.private], self.password)
        self.registry.import_pfx('pfx', pfx, self.password)
        value = self.registry.load('pfx', self.password)
        self.assertEqual(decode(value['pfx']), pfx)
        from hometax_cli.pfx import read_pfx
        pairs, _ = read_pfx(decode(value['pfx']), self.password)
        self.assertEqual(pairs[0][1], self.private)

    def test_export_is_exact_and_never_overwrites(self):
        self.imported()
        destination = self.home.parent / 'export'
        self.registry.export('personal', self.password, destination)
        self.assertEqual((destination / 'signPri.key').read_bytes(), self.encrypted)
        with self.assertRaises(FileExistsError):
            self.registry.export('personal', self.password, destination)

    def test_hometax_native_npki_compatibility(self):
        encrypted = encrypt_test_key(self.private, self.password)
        self.registry.import_npki('native', self.cert, encrypted, self.password, compatibility='hometax')
        self.assertEqual(self.registry.load('native', self.password)['compatibility'], 'hometax')

    def test_rename_keeps_identity_and_remove_deletes_blob(self):
        self.imported()
        blob = self.home / 'credentials' / 'blobs' / self.registry.entry('personal')['blob']
        renamed = self.registry.rename('personal', 'personal2')
        self.assertEqual((renamed['renamed'], renamed['previous_name'], renamed['network_used']), (True, 'personal', False))
        self.assertEqual([row['name'] for row in self.registry.list()], ['personal2'])
        self.assertEqual(self.registry.load('personal2', self.password)['certificate'], self.registry.load('personal2', self.password)['certificate'])
        self.assertTrue(blob.is_file())
        with self.assertRaisesRegex(ValueError, 'not_found'):
            self.registry.rename('personal', 'x')
        with self.assertRaisesRegex(ValueError, 'name_unchanged'):
            self.registry.rename('personal2', 'personal2')
        removed = self.registry.remove('personal2')
        self.assertEqual((removed['removed'], removed['blob_removed']), (True, True))
        self.assertEqual(self.registry.list(), [])
        self.assertFalse(blob.exists())
        with self.assertRaisesRegex(ValueError, 'not_found'):
            self.registry.remove('personal2')

    def test_remove_and_rename_are_refused_while_a_profile_references_the_alias(self):
        self.imported()
        profiles.set_certificate('personal', 'hometax', 'personal')
        for argv in (['cert', 'joint', 'remove', 'personal'], ['cert', 'joint', 'rename', 'personal', 'other']):
            code, result = self.command(argv)
            self.assertEqual(code, 2, result)
            self.assertEqual(result['error'], 'credential_in_use')
            self.assertEqual(result['references'], [{'source': 'profile', 'profile': 'personal', 'service': 'hometax'}])
        self.assertEqual([row['name'] for row in self.registry.list()], ['personal'])
        self.assertEqual(profiles.resolve('personal', 'hometax'), 'personal')

    def test_remove_and_rename_commands_without_references(self):
        self.imported()
        code, result = self.command(['cert', 'joint', 'rename', 'personal', 'renamed'])
        self.assertEqual((code, result['renamed'], result['name']), (0, True, 'renamed'))
        code, result = self.command(['cert', 'joint', 'remove', 'renamed'])
        self.assertEqual((code, result['removed']), (0, True))
        self.assertEqual(self.registry.list(), [])

    def test_profile_scopes_selection_by_institution(self):
        self.imported()
        profiles.set_certificate('personal', 'hometax', 'personal')
        self.assertEqual(profiles.resolve('personal', 'hometax'), 'personal')
        with self.assertRaisesRegex(ValueError, 'not_configured'):
            profiles.resolve('personal', 'hana')

    def test_profile_pins_certificate_identity(self):
        self.imported()
        profiles.set_certificate('personal', 'hometax', 'personal')
        state = profiles.load(); state['personal']['hometax']['certificate_id'] = '0'*64
        storage.atomic_json(self.home / 'profiles.json', state)
        with self.assertRaisesRegex(ValueError, 'changed'):
            profiles.resolve('personal', 'hometax')

    def test_same_shared_npki_prepares_hometax_and_hana(self):
        self.imported()
        profiles.set_certificate('personal', 'hometax', 'personal')
        prepared = self.home.parent / 'hometax.json'
        code, result = self.command(['hometax', 'auth', 'prepare-cert', '--profile', 'personal', '--output', str(prepared)])
        self.assertEqual(code, 0)
        self.assertTrue(result['prepared'])
        signed = self.home.parent / 'hana.der'
        code, result = self.command(['hana', 'sign-login', '--credential', 'personal', '--nonce', 'SYNTHETIC-NONCE', '--output', str(signed)])
        self.assertEqual(code, 0)
        self.assertFalse(result['network_used'])
        value = asn_cms.ContentInfo.load(signed.read_bytes())['content']
        self.assertEqual(value['encap_content_info']['content'].native, joint_cert_tbs('SYNTHETIC-NONCE').encode())

    def test_hometax_missing_send_does_not_read_credentials(self):
        code, result = self.command(['hometax', 'login', '--credential', 'absent', '--output', 'unused'])
        self.assertEqual(code, 2)
        self.assertEqual(result['error'], 'send_required')
        self.assertFalse(self.home.exists())

    def test_hometax_profile_equals_selects_shared_certificate(self):
        self.imported()
        profiles.set_certificate('personal', 'hometax', 'personal')
        destination = self.home.parent / 'profile-equals.json'
        code, result = self.command(['hometax', 'auth', 'prepare-cert', '--profile=personal', '--output', str(destination)])
        self.assertEqual(code, 0)
        self.assertTrue(result['prepared'])
        self.assertTrue(destination.exists())

    def test_hometax_pfx_shared_prepare(self):
        pfx = synthetic_pfx([self.cert], [self.private], self.password)
        self.registry.import_pfx('personal', pfx, self.password)
        code, result = self.command(['hometax', 'auth', 'prepare-cert', '--credential', 'personal', '--output', str(self.home.parent / 'pfx.json')])
        self.assertEqual(code, 0)
        self.assertTrue(result['prepared'])

    def test_shared_hana_password_encoding_is_preserved_for_hometax(self):
        password = '합성암호!2026'.encode()
        encrypted = crypto.encrypt(self.private, password.decode())
        self.registry.import_npki('unicode', self.cert, encrypted, password)
        with patch('getpass.getpass', return_value=password.decode()), contextlib.redirect_stdout(io.StringIO()):
            code = main(['hometax', 'auth', 'prepare-cert', '--credential', 'unicode',
                         '--output', str(self.home.parent / 'unicode.json')])
        self.assertEqual(code, 0)

    def test_invoice_worker_uses_shared_identity_without_export(self):
        self.imported()
        payload = {'credential': 'personal', 'password': base64.b64encode(self.password).decode(),
            'xml': '<TaxInvoice><TaxInvoiceDocument><ID>SYNTHETIC</ID></TaxInvoiceDocument></TaxInvoice>'}
        result = subprocess.run([sys.executable, '-m', 'hometax_cli.invoice_certificate'],
            input=json.dumps(payload), text=True, capture_output=True, check=True)
        report = json.loads(result.stdout)
        self.assertTrue(report['selection']['selectable'])
        self.assertTrue(report['callback']['xmlSigniture'])
        self.assertNotIn(self.password.decode(), result.stdout)

    def test_show_does_not_claim_revocation_or_bank_validity(self):
        self.imported()
        info = self.registry.inspect('personal', self.password)
        self.assertFalse(info['revocation_checked'])
        self.assertNotIn('bank_accepted', info)


if __name__ == '__main__':
    unittest.main()
