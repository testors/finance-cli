"""Shared encrypted Shinhan certificate material; bank sessions hold references."""
import hashlib
import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from finance_cli.core import storage
from finance_cli.core.paths import data_home
from .registry import name, key, encode, decode, matched

FORMAT = 'finance-shinhan-credential-v1'


class SelectionRequired(ValueError):
    def __init__(self, count):
        self.count = count
        super().__init__('credential_selection_required')


class Registry:
    def __init__(self, home=None):
        self.home = (home or data_home()).absolute()
        self.root = self.home / 'credentials' / 'shinhan'

    def path(self, reference):
        return storage.no_symlinks(self.root / (name(reference)+'.json'))

    def list(self):
        storage.no_symlinks(self.root)
        if not self.root.exists():
            return []
        return [{'name': name(path.stem), 'type': 'shinhan'} for path in sorted(self.root.glob('*.json'))]

    def select(self, reference=None):
        if reference is not None:
            if not self.path(reference).is_file():
                raise ValueError('credential_not_found')
            return reference
        entries = self.list()
        if len(entries) != 1:
            raise SelectionRequired(len(entries))
        return entries[0]['name']

    def load(self, reference, password):
        envelope = storage.read_json(self.path(reference))
        if envelope.get('format') != FORMAT:
            raise ValueError('invalid_credential_format')
        try:
            plain = AESGCM(key(password, decode(envelope['salt']))).decrypt(
                decode(envelope['nonce']), decode(envelope['sealed']), (FORMAT+'/'+reference).encode())
        except InvalidTag:
            raise ValueError('incorrect_password_or_damaged_credential') from None
        value = json.loads(plain)
        if value.get('certificate'):
            matched(decode(value['certificate']), decode(value['private_key']))
        return value

    def save(self, reference, password, value, *, create=False):
        name(reference)
        storage.directory(self.home)
        storage.directory(self.home / 'credentials')
        storage.directory(self.root)
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        sealed = AESGCM(key(password, salt)).encrypt(nonce, json.dumps(value).encode(), (FORMAT+'/'+reference).encode())
        envelope = {'format': FORMAT, 'salt': encode(salt), 'nonce': encode(nonce), 'sealed': encode(sealed)}
        with storage.lock(self.root / '.lock'):
            if create:
                storage.write_new(self.path(reference), json.dumps(envelope).encode())
            else:
                # Verify the password and existing identity before replacing a credential.
                self.load(reference, password)
                storage.atomic_json(self.path(reference), envelope)

    def prepare(self, reference, password, unique_value, salt, device_id):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        encoded = private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
        value = {'state': 'prepared', 'private_key': encode(encoded), 'certificate': '',
                 'pin_salt': encode(salt), 'vid_random': encode(secrets.token_bytes(32)),
                 'access_key_digest': hashlib.sha256(unique_value.encode()).hexdigest(),
                 'device_id': device_id, 'alias': '', 'msb_version': ''}
        self.save(reference, password, value, create=True)
        return value
