"""Portable OneSign vault bundle: one passphrase-sealed file. No login, no network.

The bundle carries the imported OneSign vault (app identity and key, cloud key,
stored certificate records) but never a run ledger or a PIN. The format is fixed
in docs/onesign-bundle.md; the private Hana research tool writes and reads the
same layout. Bytes are kept sealed at rest; a passphrase is needed to open them.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from finance_cli.core import storage
from . import store
from .hana_protocol import device_uuid

FORMAT = 'finance-onesign-bundle-v1'
KDF = {'name': 'scrypt', 'n': 131072, 'r': 8, 'p': 1}
LIMIT = 1024 * 1024
TOP = {'version', 'created_at', 'device_id', 'profile', 'cloud', 'records'}


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64url(value):
    if not isinstance(value, str) or re.fullmatch(r'[A-Za-z0-9_-]+', value) is None:
        raise ValueError('invalid_bundle_encoding')
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def key(passphrase, salt):
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError('nonempty_passphrase_required')
    raw = unicodedata.normalize('NFC', passphrase).encode('utf-8')
    return Scrypt(salt=salt, length=32, n=KDF['n'], r=KDF['r'], p=KDF['p']).derive(raw)


def opened(data, passphrase):
    """Decrypt and validate a bundle file's bytes; returns the plaintext record."""
    if len(data) > LIMIT:
        raise ValueError('bundle_too_large')
    try:
        outer = json.loads(data)
        header = {name: outer[name] for name in ('format', 'kdf', 'cipher')}
        salt, nonce, sealed = unb64url(outer['kdf']['salt']), unb64url(outer['cipher']['nonce']), unb64url(outer['sealed'])
    except (ValueError, KeyError, TypeError):
        raise ValueError('invalid_bundle_file') from None
    if (set(outer) != {'format', 'kdf', 'cipher', 'sealed'} or outer['format'] != FORMAT
            or outer['kdf'] != {**KDF, 'salt': outer['kdf'].get('salt')} or len(salt) != 16
            or outer['cipher'] != {'name': 'aes-256-gcm', 'nonce': outer['cipher'].get('nonce')} or len(nonce) != 12):
        raise ValueError('unsupported_bundle_format')
    try:
        plain = AESGCM(key(passphrase, salt)).decrypt(nonce, sealed, canonical(header))
    except InvalidTag:
        raise ValueError('incorrect_passphrase_or_damaged_bundle') from None
    return validated(json.loads(plain))


def validated(plain):
    """The binding checks; certificate and key material stay opaque."""
    if not isinstance(plain, dict) or set(plain) != TOP or plain['version'] != 1 or not isinstance(plain['created_at'], str):
        raise ValueError('invalid_bundle_content')
    profile, cloud, records, device = plain['profile'], plain['cloud'], plain['records'], plain['device_id']
    if not all(isinstance(v, dict) for v in (profile, cloud, records)) or not records:
        raise ValueError('invalid_bundle_content')
    identity = profile.get('app_identity')
    if (not isinstance(identity, dict) or re.fullmatch('[0-9a-f]{16}', str(identity.get('android_id', ''))) is None
            or device != device_uuid(identity['android_id']) or profile.get('device_id') != device):
        raise ValueError('bundle_device_binding_failed')
    if hashlib.sha256(unb64url(profile.get('app_key'))).hexdigest() != identity.get('key_sha256'):
        raise ValueError('bundle_app_key_mismatch')
    enrollment = profile.get('enrollment')
    if not isinstance(enrollment, dict) or enrollment.get('state') != 'ready':
        raise ValueError('bundle_enrollment_not_ready')
    if cloud.get('device_id') != device or not unb64url(cloud.get('private_key')):
        raise ValueError('bundle_cloud_binding_failed')
    for alias, record in records.items():
        if (not isinstance(record, dict) or record.get('alias') != alias or record.get('device_id') != device
                or hashlib.sha256(unb64url(record.get('certificate'))).hexdigest() != record.get('fingerprint')):
            raise ValueError('bundle_record_binding_failed')
    return plain


def directory(name, *, create=False):
    path = store.root('onesign') / store.name(name)
    storage.no_symlinks(path)
    if create:
        if path.exists():
            raise ValueError('onesign_bundle_exists')
        for part in (store.root('onesign').parent.parent, store.root('onesign').parent, store.root('onesign')):
            storage.directory(part)
        path.mkdir(mode=0o700)
    elif not path.is_dir():
        raise ValueError('onesign_bundle_not_found')
    return path


def read_file(path):
    path = storage.no_symlinks(Path(path).expanduser())
    if not path.is_file():
        raise ValueError('bundle_file_required')
    if path.stat().st_size > LIMIT:
        raise ValueError('bundle_too_large')
    return path.read_bytes()


def import_bundle(name, source, passphrase):
    """Validate a bundle with its passphrase, then keep its sealed bytes unchanged."""
    data = read_file(source)
    plain = opened(data, passphrase)
    path = directory(name, create=True)
    storage.write_new(path / 'bundle.json', data)
    return {'name': name, 'imported': True, 'sealed_at_rest': True, 'certificates': len(plain['records']),
            'network_used': False}


def export_bundle(name, output):
    """Copy the sealed bytes; the file keeps the passphrase it was created with."""
    data = storage.read(directory(name) / 'bundle.json', LIMIT)
    storage.write_new(Path(output).expanduser(), data)
    return {'name': name, 'exported': True, 'output': str(Path(output).expanduser()), 'bytes_preserved': True,
            'network_used': False}


def list_bundles():
    base = store.root('onesign')
    names = sorted(p.name for p in base.iterdir() if p.is_dir() and not p.is_symlink()) if base.is_dir() else []
    return {'bundles': names, 'network_used': False}


def show(name, passphrase):
    plain = opened(storage.read(directory(name) / 'bundle.json', LIMIT), passphrase)
    return {'name': name, 'created_at': plain['created_at'], 'enrollment_state': plain['profile']['enrollment']['state'],
            'certificate_ids': sorted(r['fingerprint'] for r in plain['records'].values()), 'network_used': False}
