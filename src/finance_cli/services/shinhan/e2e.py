"""Cloud PIN ECDH handshake. Keys remain in the calling process only."""
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def message(**fields):
    return json.dumps({'SeProtocolMessage': fields}, separators=(',', ':'))


def initial(profile_key, package_name='com.shinhan.sbanking'):
    return message(op='7E01', data=hmac.new(profile_key.encode(), package_name.encode(), hashlib.sha256).hexdigest().upper())


def unpad(data):
    if not data:
        raise ValueError('empty_ciphertext')
    count = data[-1]
    if count > len(data):
        raise ValueError('invalid_padding_length')
    if count == 0:
        return data
    if data[-count:] != bytes([count])*count:
        return None
    return data[:-count]


def health_error(text):
    if not text:
        return True
    try:
        value = json.loads(text).get('DSErrProtocolMessage', {}).get('result')
        return isinstance(value, str) and bool(value)
    except (ValueError, TypeError, AttributeError):
        return False


@dataclass(repr=False)
class Handshake:
    key: bytes
    iv: bytes
    request: str
    kr1: bytes | None = None
    accepted: bool = False

    @classmethod
    def challenge(cls, text, *, private_key=None, random=None):
        fields = json.loads(text)['SeProtocolMessage']
        server = serialization.load_der_public_key(bytes.fromhex(fields['sp']))
        challenge, server_iv = bytes.fromhex(fields['sc']), bytes.fromhex(fields['si'])
        if not challenge or len(server_iv) < 16:
            raise ValueError('invalid_challenge_material')
        private_key = private_key or ec.generate_private_key(ec.SECP256R1())
        shared = private_key.exchange(ec.ECDH(), server)
        keys = hashlib.pbkdf2_hmac('sha512', shared, challenge, 1024, 64)
        random = secrets.token_bytes(16) if random is None else random
        iv = bytes(a ^ b for a, b in zip(server_iv[:16], random))
        encrypted = AES.new(keys[:32], AES.MODE_CBC, iv).encrypt(pad(challenge, 16))
        public = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        mac = hmac.new(keys[32:], encrypted+iv+public, hashlib.sha256).digest()
        return cls(keys[:32], iv, message(op='7E03', ced=encrypted.hex().upper(),
                   cfi=iv.hex().upper(), cp=public.hex().upper(), cfm=mac.hex().upper()))

    def finish(self, text):
        fields = json.loads(text)['SeProtocolMessage']
        if fields.get('result') != '0000':
            return False
        plain = AES.new(self.key, AES.MODE_CBC, self.iv).decrypt(bytes.fromhex(fields['data']))
        self.kr1 = unpad(plain)
        self.accepted = True
        return True

    @property
    def ready(self):
        return bool(self.key and self.iv and self.kr1)

    def encrypt(self, value):
        if not self.accepted:
            # No cached state produces an empty successful value in this branch.
            return ''
        if not value:
            raise ValueError('empty_keypad_value')
        encrypted = AES.new(self.key, AES.MODE_CBC, self.iv).encrypt(pad(value.encode('utf-8'), 16))
        return message(op='7E05', data=encrypted.hex().upper())

    def health_request(self):
        return message(op='7E06', data=hmac.new(self.iv, self.key, hashlib.sha256).hexdigest().upper())
