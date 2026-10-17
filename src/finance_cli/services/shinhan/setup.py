"""Install versioned settings from a user-supplied package, without executing it."""
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import struct
import zipfile

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from finance_cli.core import storage
from finance_cli.core.paths import data_home

VERSION = '20.0.40'
PACKAGE_SHA256 = '78c1f7e87f11b2493e3ec843a6c244b5f74f9f2bb49f0fa5030dbae21d19b733'
DATA_SHA256 = '7beaf1bd59de5cd754cfc1be1726c0287e01546d5a8cc01c53ff40dde5a10748'
MENU_SHA256 = '80b30a1348696d09fbf978728928b541ba8f0cc30a1933d6d02e3a8f64195dd0'
KEY_OFFSET = 16388928
PARAMETER_OFFSETS = (16388846, 16388852, 16388858, 16388840)
E2E_DATA_SHA256 = 'afed8b2a314d3e4f8672c27bafafb893b0727269003ab2bb468a07a7cccb0d9c'
E2E_ARRAY_OFFSETS = (7021452, 7022484, 7023516)
E2E_CIPHER_OFFSET, E2E_CIPHER_LENGTH = 2729082, 20192
PIN_DATA_SHA256 = '74130cbd7c46195a85228f93a14db47b255c76bed1e683f89512fd2b5c29414f'
PIN_PARAMETER_OFFSETS = (3138544, 3138550, 3138556, 3138534)
PIN_CIPHER_OFFSET, PIN_CIPHER_LENGTH = 3139108, 16


def root():
    return data_home() / 'shinhan'


def prepare_directory():
    storage.directory(data_home())
    return storage.directory(root())


def rotate(value, count):
    value &= 0xffffffff
    return ((value << count) | (value >> (32-count))) & 0xffffffff


def decode_key(data):
    if hashlib.sha256(data).hexdigest() != DATA_SHA256:
        raise ValueError('unsupported_service_data')
    a, b, c, d = (struct.unpack_from('<i', data, offset)[0] for offset in PARAMETER_OFFSETS)
    value = (-660212165-d) ^ a
    value = ((rotate(value, 8)-c) ^ d) ^ c
    value = rotate(value, 5)-a
    value = rotate(value, 8)+c
    value = (rotate(value, 30)+d) ^ a
    value = rotate(value, 4)-b+2*d
    value = (rotate(value, 7) ^ c)-c
    value = rotate(rotate(rotate(value, 7), 7), 20)
    value = (a ^ ((value+2*b) ^ c)) ^ d
    mask = rotate(value, 9).to_bytes(4, 'little')
    encoded = data[KEY_OFFSET:KEY_OFFSET+64]
    decoded = bytes(byte ^ mask[i % 4] for i, byte in enumerate(encoded)).decode('ascii')
    if not re.fullmatch('[0-9a-fA-F]{64}', decoded):
        raise ValueError('invalid_service_data')
    return decoded


def extract(package):
    with Path(package).expanduser().open('rb') as stream:
        data = stream.read(512*1024*1024+1)
    if len(data) > 512*1024*1024 or hashlib.sha256(data).hexdigest() != PACKAGE_SHA256:
        raise ValueError('unsupported_package')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in ('classes9.dex', 'classes5.dex', 'classes7.dex', 'assets/menu_program_nss_default.json'):
            if archive.getinfo(name).file_size > 64*1024*1024:
                raise ValueError('service_data_too_large')
        key = decode_key(archive.read('classes9.dex'))
        keypad_data = archive.read('classes5.dex')
        e2e_key = decode_e2e_key(keypad_data)
        keypad_alphabet = decode_keypad_alphabet(keypad_data)
        pin_check_key = decode_pin_check_key(archive.read('classes7.dex'))
        menu = archive.read('assets/menu_program_nss_default.json')
    if hashlib.sha256(menu).hexdigest() != MENU_SHA256:
        raise ValueError('unsupported_menu_data')
    return {'version': VERSION, 'bank_key': key, 'menu_version': json.loads(menu)['G1'],
            'e2e_key': e2e_key, 'keypad_alphabet': keypad_alphabet, 'pin_check_key': pin_check_key}


def decode_pin_check_key(data):
    if hashlib.sha256(data).hexdigest() != PIN_DATA_SHA256:
        raise ValueError('unsupported_pin_check_data')
    a, b, c, d = (struct.unpack_from('<i', data, offset)[0] for offset in PIN_PARAMETER_OFFSETS)
    value = (((rotate(-2019316365+c, 23)-a) ^ b) ^ b)+a
    value = rotate(value, 30)-2*d
    value = rotate(rotate(value, 8), 9)
    value = ((d ^ value)-c) ^ a
    value = rotate(rotate(value, 29), 12)-2*c+a-b
    mask = rotate(value, 23).to_bytes(4, 'little')
    encoded = data[PIN_CIPHER_OFFSET:PIN_CIPHER_OFFSET+PIN_CIPHER_LENGTH]
    return hashlib.md5(bytes(value ^ mask[index % 4] for index, value in enumerate(encoded))).hexdigest()


def _e2e_profile(data):
    if hashlib.sha256(data).hexdigest() != E2E_DATA_SHA256:
        raise ValueError('unsupported_e2e_data')
    arrays = [struct.pack('>256i', *struct.unpack_from('<256i', data, offset)) for offset in E2E_ARRAY_OFFSETS]
    left, middle, right = arrays
    def xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))
    for _ in range(16):
        left, middle, right = xor(left, middle), xor(middle, right), xor(xor(left, middle), right)
    encrypted = bytes.fromhex(data[E2E_CIPHER_OFFSET:E2E_CIPHER_OFFSET+E2E_CIPHER_LENGTH].decode('ascii'))
    plain = unpad(AES.new(hashlib.sha256(left).digest(), AES.MODE_CBC,
                         hashlib.sha256(middle).digest()[:16]).decrypt(encrypted), 16)
    profile = json.loads(plain)
    if 'com.shinhan.sbanking' not in json.loads(profile['ffff']) or not isinstance(profile['b'], str):
        raise ValueError('invalid_e2e_profile')
    return profile


def decode_e2e_key(data):
    return _e2e_profile(data)['b']


def decode_keypad_alphabet(data):
    alphabet = bytes.fromhex(_e2e_profile(data)['mmmm'])
    if len(alphabet) != 109 or alphabet[:10] != b'0123456789':
        raise ValueError('invalid_keypad_alphabet')
    return alphabet.hex()


def refresh(package):
    replacement = extract(package)
    folder = prepare_directory()
    with storage.lock(folder / '.lock'):
        existing = load()
        existing.update(replacement)
        storage.atomic_json(folder / 'settings.json', existing)
    return {'installed': True, 'version': VERSION, 'network_used': False}


def device(android_id, model, os_version):
    if not all(isinstance(value, str) for value in (android_id, model, os_version)):
        raise ValueError('invalid_device_input')
    # A new-format identity. This does not import an existing app's stored ID.
    identity = hashlib.sha256((android_id+model).encode('utf-8')).hexdigest()
    return {'device_id': identity, 'uuid1': identity[:32], 'uuid2': identity,
            'model': model, 'os_version': os_version}


def install(package, device_input=None):
    settings = extract(package)
    # One local CLI identity, persisted for issuance and subsequent logins.
    settings['device'] = (device(**device_input) if device_input is not None else
                          device(secrets.token_hex(8), 'SM-S921N', '14'))
    folder = prepare_directory()
    with storage.lock(folder / '.lock'):
        # Changing identity would invalidate the session/certificate association.
        storage.write_new(folder / 'settings.json', (json.dumps(settings)+'\n').encode())
    return {'installed': True, 'version': VERSION, 'network_used': False}


def load():
    settings = storage.read_json(root() / 'settings.json')
    if settings.get('version') != VERSION or not re.fullmatch('[0-9a-fA-F]{64}', settings.get('bank_key', '')):
        raise ValueError('invalid_settings')
    for field in ('device_id', 'uuid1', 'uuid2', 'model', 'os_version'):
        if not isinstance(settings['device'][field], str):
            raise ValueError('invalid_settings')
    if not isinstance(settings.get('menu_version'), str):
        raise ValueError('invalid_settings')
    return settings
