"""Password-encrypted originals. No login, trust verdict or key reserialization.

The index contains aliases, certificate fingerprints and format only. Subject,
certificate, encrypted NPKI key or complete PFX stay in a scrypt/AES-GCM envelope.
Decoded PKCS#8 (including VID attributes) is validated only in memory.
"""
import base64
import hashlib
import json
import re
import secrets

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from finance_cli.core.paths import data_home
from finance_cli.core import storage

FORMAT = 'finance-credential-v1'


def name(value):
    if not isinstance(value, str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value) is None:
        raise ValueError('invalid_name')
    return value


def encode(value):
    return base64.b64encode(value).decode('ascii')


def decode(value):
    return base64.b64decode(value, validate=True)


def key(password, salt):
    if not isinstance(password, bytes) or not password:
        raise ValueError('nonempty_password_required')
    if len(salt) != 16:
        raise ValueError('invalid_salt')
    return Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password)


def matched(cert, private):
    encoding, form = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    a = x509.load_der_x509_certificate(cert).public_key().public_bytes(encoding, form)
    b = serialization.load_der_private_key(private, None).public_key().public_bytes(encoding, form)
    if a != b:
        raise ValueError('certificate_key_mismatch')


class Registry:
    def __init__(self, home=None):
        self.home = (home or data_home()).absolute()
        self.root = self.home / 'credentials'

    def index(self):
        path = self.root / 'index.json'
        storage.no_symlinks(path)
        if not path.exists():
            return {'format': FORMAT, 'entries': {}}
        state = storage.read_json(path)
        if state.get('format') != FORMAT or not isinstance(state.get('entries'), dict):
            raise ValueError('invalid_registry')
        for alias, row in state['entries'].items():
            name(alias)
            if (re.fullmatch('[0-9a-f]{64}', row.get('certificate_id', '')) is None
                    or re.fullmatch('[0-9a-f]{32}', row.get('blob', '')) is None
                    or row.get('format') not in ('npki', 'pfx')):
                raise ValueError('invalid_registry_entry')
        return state

    def list(self):
        return [{'name': alias, 'type': 'joint', 'certificate_id': row['certificate_id'],
                 'format': row['format']} for alias, row in sorted(self.index()['entries'].items())]

    def entry(self, alias):
        name(alias)
        row = self.index()['entries'].get(alias)
        if row is None:
            raise ValueError('credential_not_found')
        return row

    def import_npki(self, alias, cert, encrypted, password, *, compatibility='hana'):
        if compatibility == 'hana':
            from .joint.crypto import check_pair
            private = check_pair(cert, encrypted, password.decode('utf-8'))
        elif compatibility == 'hometax':
            from hometax_cli.certificate import decrypt_key
            private, _ = decrypt_key(encrypted, password)
            matched(cert, private)
        else:
            raise ValueError('unsupported_key_compatibility')
        del private
        return self._store(alias, cert, {'format': 'npki', 'certificate': encode(cert),
            'encrypted_key': encode(encrypted), 'compatibility': compatibility}, password)

    def import_pfx(self, alias, pfx, password, *, index=None):
        from hometax_cli.pfx import read_pfx, select_signing_pair
        pairs, warnings = read_pfx(pfx, password)
        cert, private = select_signing_pair(pairs, index)
        matched(cert, private)
        del private, pairs
        result = self._store(alias, cert, {'format': 'pfx', 'certificate': encode(cert),
            'pfx': encode(pfx), 'pfx_index': index}, password)
        return {**result, 'warnings': warnings}

    def _store(self, alias, cert, value, password):
        name(alias)
        identity = hashlib.sha256(cert).hexdigest()
        storage.directory(self.home)
        storage.directory(self.root)
        storage.directory(self.root / 'blobs')
        with storage.lock(self.root / 'lock'):
            state = self.index()
            if alias in state['entries']:
                raise ValueError('credential_name_exists')
            if any(row['certificate_id'] == identity for row in state['entries'].values()):
                raise ValueError('certificate_already_imported')
            blob, salt, nonce = secrets.token_hex(16), secrets.token_bytes(16), secrets.token_bytes(12)
            aad = f'{FORMAT}/{identity}/{blob}'.encode()
            ciphertext = AESGCM(key(password, salt)).encrypt(nonce, json.dumps(value).encode(), aad)
            envelope = {'format': FORMAT, 'salt': encode(salt), 'nonce': encode(nonce), 'sealed': encode(ciphertext)}
            storage.write_new(self.root / 'blobs' / blob, json.dumps(envelope).encode())
            state['entries'][alias] = {'certificate_id': identity, 'blob': blob, 'format': value['format']}
            storage.atomic_json(self.root / 'index.json', state)
        return {'name': alias, 'certificate_id': identity, 'imported': True, 'network_used': False}

    def load(self, alias, password):
        row = self.entry(alias)
        envelope = storage.read_json(self.root / 'blobs' / row['blob'])
        if envelope.get('format') != FORMAT:
            raise ValueError('invalid_credential_envelope')
        aad = f"{FORMAT}/{row['certificate_id']}/{row['blob']}".encode()
        try:
            plain = AESGCM(key(password, decode(envelope['salt']))).decrypt(
                decode(envelope['nonce']), decode(envelope['sealed']), aad)
        except InvalidTag:
            raise ValueError('incorrect_password_or_damaged_credential') from None
        value = json.loads(plain)
        if (hashlib.sha256(decode(value['certificate'])).hexdigest() != row['certificate_id']
                or value['format'] != row['format']):
            raise ValueError('credential_identity_mismatch')
        return value

    def inspect(self, alias, password):
        from .joint.crypto import metadata
        value = self.load(alias, password)
        return {'name': alias, 'format': value['format'], 'type': 'joint',
                **metadata(decode(value['certificate']))}

    def material(self, alias, password):
        """Unlock in memory using the imported key's recorded encoding profile."""
        value = self.load(alias, password)
        cert = decode(value['certificate'])
        if value['format'] == 'pfx':
            from hometax_cli.pfx import read_pfx, select_signing_pair
            pairs, warnings = read_pfx(decode(value['pfx']), password)
            selected, private = select_signing_pair(pairs, value['pfx_index'])
            if selected != cert:
                raise ValueError('credential_identity_mismatch')
        elif value['compatibility'] == 'hometax':
            from hometax_cli.certificate import decrypt_key
            private, warnings = decrypt_key(decode(value['encrypted_key']), password)
        elif value['compatibility'] == 'hana':
            from .joint.crypto import check_pair
            private = check_pair(cert, decode(value['encrypted_key']), password.decode('utf-8'))
            warnings = []
        else:
            raise ValueError('unsupported_key_compatibility')
        matched(cert, private)
        return cert, private, warnings

    def export(self, alias, password, destination):
        from pathlib import Path
        destination = storage.no_symlinks(Path(destination))
        value = self.load(alias, password)
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        if value['format'] == 'npki':
            storage.write_new(destination / 'signCert.der', decode(value['certificate']))
            storage.write_new(destination / 'signPri.key', decode(value['encrypted_key']))
        else:
            storage.write_new(destination / 'certificate.pfx', decode(value['pfx']))
        return {'exported': True, 'original_bytes_preserved': True, 'output': str(destination), 'network_used': False}
