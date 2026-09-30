"""Portable, passphrase-sealed OneSign identities; no sessions or plaintext PINs.

v1 retains the cloud key requirement. v2 also supports direct issuance without
a cloud key. Archive operations preserve bytes; activation creates fresh state.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from finance_cli.core import storage
from . import store
from .hana_protocol import device_uuid

FORMAT = 'finance-onesign-bundle-v1'
FORMAT_V2 = 'finance-onesign-bundle-v2'
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
    if (set(outer) != {'format', 'kdf', 'cipher', 'sealed'} or outer['format'] not in (FORMAT, FORMAT_V2)
            or outer['kdf'] != {**KDF, 'salt': outer['kdf'].get('salt')} or len(salt) != 16
            or outer['cipher'] != {'name': 'aes-256-gcm', 'nonce': outer['cipher'].get('nonce')} or len(nonce) != 12):
        raise ValueError('unsupported_bundle_format')
    try:
        plain = AESGCM(key(passphrase, salt)).decrypt(nonce, sealed, canonical(header))
    except InvalidTag:
        raise ValueError('incorrect_passphrase_or_damaged_bundle') from None
    value = json.loads(plain)
    expected_version = 1 if outer['format'] == FORMAT else 2
    if not isinstance(value,dict) or type(value.get('version')) is not int or value['version'] != expected_version:
        raise ValueError('unsupported_bundle_format')
    return validated(value)


def validated(plain):
    """The binding checks; certificate and key material stay opaque."""
    if not isinstance(plain, dict) or set(plain) != TOP or type(plain['version']) is not int or plain['version'] not in (1, 2) or not isinstance(plain['created_at'], str):
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
    if (plain['version'] == 1 or cloud) and (cloud.get('device_id') != device or not unb64url(cloud.get('private_key'))):
        raise ValueError('bundle_cloud_binding_failed')
    for alias, record in records.items():
        if (not isinstance(record, dict) or record.get('alias') != alias or record.get('device_id') != device
                or hashlib.sha256(unb64url(record.get('certificate'))).hexdigest() != record.get('fingerprint')):
            raise ValueError('bundle_record_binding_failed')
    return plain


def sealed(plain, passphrase):
    validated(plain)
    if len(passphrase) < 4:
        raise ValueError('passphrase_minimum_4_characters')
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = {'format': FORMAT if plain['version']==1 else FORMAT_V2,
              'kdf': {**KDF, 'salt':b64url(salt)}, 'cipher':{'name':'aes-256-gcm','nonce':b64url(nonce)}}
    encrypted = AESGCM(key(passphrase,salt)).encrypt(nonce,canonical(plain),canonical(header))
    result = canonical({**header,'sealed':b64url(encrypted)})
    if len(result) > LIMIT:
        raise ValueError('bundle_too_large')
    return result


def export_identity(state, output, passphrase):
    from datetime import datetime, timezone
    import copy
    from .onesign import record
    record(state)
    value = state.snapshot()
    profile = copy.deepcopy(value['profile'])
    for field in list(profile):
        if field.startswith('customer_source'):
            del profile[field]
    profile['enrollment'].pop('run',None)
    plain = {'version':2,'created_at':datetime.now(timezone.utc).isoformat(),'device_id':profile['device_id'],
             'profile':profile,'cloud':value.get('cloud',{}),'records':value['records']}
    storage.write_new(Path(output).expanduser(),sealed(plain,passphrase))
    return {'exported':True,'format':FORMAT_V2,'network_used':False}


def activate(name, source, passphrase, settings_name):
    import copy
    from .onesign import initial, record
    from .onesign_state import State
    from . import onesign_setup
    from Crypto.PublicKey import RSA
    from types import SimpleNamespace
    from .onesign_keys import certificate_alias, PIN_ITEM, EXTERNAL_ITEM
    from .onesign_crypto import certificate_parts
    plain = opened(read_file(source),passphrase)
    settings = onesign_setup.load(settings_name)
    state = initial(settings)
    state.update(profile=copy.deepcopy(plain['profile']),records=plain['records'],cloud=plain['cloud'])
    state['profile']['service_profile'] = settings['service_profile']
    # Import is usable only when the material is a real compatible record.
    app_key = RSA.import_key(unb64url(state['profile']['app_key']))
    if not app_key.has_private() or app_key.size_in_bits()<2048:
        raise ValueError('unsupported_app_private_key')
    state['signup']['state']='imported'
    state['issuance'].update(state='imported',certificate_issued=False)
    for entry in state['records'].values():
        if (type(entry.get('pinSpecVersion')) is not int or entry['pinSpecVersion'] != 2
                or type(entry.get('authType')) is not int or not entry['authType'] & 1
                or not isinstance(entry.get('pinSalt'),str) or not isinstance(entry.get('pinVersion'),str)):
            raise ValueError('unsupported_signing_record')
        certificate = unb64url(entry['certificate'])
        certificate_parts(certificate)
        if entry['alias'] != certificate_alias(certificate):
            raise ValueError('certificate_alias_mismatch')
        if len(unb64url(entry.get('key'))) < 28 or len(unb64url(entry.get(PIN_ITEM)))%16:
            raise ValueError('invalid_signing_record_envelope')
        if entry['authType'] & 8 and len(unb64url(entry.get(EXTERNAL_ITEM)))%16:
            raise ValueError('invalid_external_auth_envelope')
    record(SimpleNamespace(snapshot=lambda:state))
    with State(name,passphrase,state):
        pass
    return {'imported':True,'identity':name,'network_used':False,'next':'new-session'}


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
