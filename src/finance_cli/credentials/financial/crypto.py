"""Python FinCert issuance primitives, verified against the pinned SDK. No I/O."""
import base64
import hashlib
import hmac
import json
import re
import secrets
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from finance_cli.core.errors import require

CLOUD_KEY_ID = 'ba14f338-7e37-409f-93d2-423f37111ada'
CLOUD_KEY_N = ('mEaWH-l05N3b8fZIdEu4cg2MTQWTnETWzjjcDiDFEtUCorHcumF3SgtjfzwdQYxv2-dUBUjXdq9Byu6J0pWU9ePdv0rP9uZBBdHfJC5NFvJzlkVck4NpnVD-1bidMob4EwDxRyExDpCujFzWbWWqYeLZ_gX2P5o2LaYYLwAgFBKnHAF5QZ01uagDUsUrMKwUMQShZKAodSsrv2_BqK37xkbCw1lHUzs18xTa-gYR8mKkg5fTBMiTymeYBpIxn1M3HuDjXaTR8ooefdhMwkZD4ydVcK-yDBP1sCyyQsedBEx9dV0kJJpK0TDhZEhlg1lTVZjDpVd2ziFtI8n_szSlqQ')


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def unb64(value):
    require(isinstance(value, str), 'base64_string_required')
    return base64.b64decode(value+'='*(-len(value) % 4), altchars=b'-_', validate=True)


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def keypair(bits=2048):
    require(type(bits) is int and bits in (2048, 3072, 4096), 'unsupported_ca_key_size')
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def private_bytes(key):
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def load_key(value):
    key = serialization.load_der_private_key(unb64(value), password=None)
    require(isinstance(key, rsa.RSAPrivateKey), 'rsa_registration_key_required')
    return key


def public_jwk(key):
    numbers = key.public_key().public_numbers()
    integer = lambda n: b64(n.to_bytes((n.bit_length()+7)//8, 'big'))
    # WebCrypto RSA export property order, included in the signed PoP payload.
    return {'key_ops': ['verify'], 'ext': True, 'kty': 'RSA', 'n': integer(numbers.n),
            'e': integer(numbers.e), 'alg': 'RS256'}


def sign(payload, key, *, algorithm='RS256'):
    head = b64(compact({'alg': algorithm, 'typ': 'JOSE'}))
    body = b64(compact(payload))
    signed = (head+'.'+body).encode()
    if algorithm == 'HS256': signature = hmac.digest(key, signed, 'sha256')
    else:
        require(algorithm == 'RS256', 'unsupported_signature_algorithm')
        signature = key.sign(signed, rsa_padding.PKCS1v15(), hashes.SHA256())
    return signed.decode()+'.'+b64(signature)


def protect(payload, auth_code):
    return sign(payload, hashlib.sha256((auth_code+'aaaaabbbbb').encode()).digest(), algorithm='HS256')


def cbc(key, iv, value):
    pad = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(pad.update(value)+pad.finalize())+enc.finalize()


def encrypt(payload, cek, *, recipient=None, algorithm='dir', encryption='A256GCM', thumb=None, iv=None):
    require(len(cek) == 32, 'jwe_key_length')
    header = {'alg': algorithm, 'enc': encryption}
    if thumb is not None: header['x5t'] = thumb
    head = b64(compact(header))
    plain = payload.encode() if isinstance(payload, str) else compact(payload)
    wrapped = b''
    if algorithm != 'dir':
        require(algorithm in ('RSA-OAEP', 'RSA-OAEP-256') and isinstance(recipient, rsa.RSAPublicKey), 'unsupported_jwe_recipient')
        digest = hashes.SHA1() if algorithm == 'RSA-OAEP' else hashes.SHA256()
        wrapped = recipient.encrypt(cek, rsa_padding.OAEP(rsa_padding.MGF1(digest), digest, None))
    if encryption == 'A256GCM':
        iv = iv if iv is not None else secrets.token_bytes(12)
        data = AESGCM(cek).encrypt(iv, plain, head.encode())
        encrypted, tag = data[:-16], data[-16:]
    else:
        require(encryption == 'A128CBC-HS256', 'unsupported_jwe_encryption')
        iv = iv if iv is not None else secrets.token_bytes(16)
        encrypted = cbc(cek[16:], iv, plain)
        tag = hmac.digest(cek[:16], head.encode()+iv+encrypted+struct.pack('>Q', len(head)*8), 'sha256')[:16]
    return '.'.join((head, b64(wrapped), b64(iv), b64(encrypted), b64(tag)))


def decrypt(value, cek):
    head, wrapped, iv, data, tag = value.split('.')
    header = json.loads(unb64(head))
    require(header.get('alg') == 'dir' and wrapped == '' and len(cek) == 32, 'unsupported_response_jwe')
    if header.get('enc') == 'A256GCM':
        raw = AESGCM(cek).decrypt(unb64(iv), unb64(data)+unb64(tag), head.encode())
    else:
        require(header.get('enc') == 'A128CBC-HS256', 'unsupported_response_jwe')
        actual = hmac.digest(cek[:16], head.encode()+unb64(iv)+unb64(data)+struct.pack('>Q', len(head)*8), 'sha256')[:16]
        require(hmac.compare_digest(actual, unb64(tag)), 'response_jwe_tag_mismatch')
        dec = Cipher(algorithms.AES(cek[16:]), modes.CBC(unb64(iv))).decryptor()
        pad = padding.PKCS7(128).unpadder()
        raw = pad.update(dec.update(unb64(data))+dec.finalize())+pad.finalize()
    return json.loads(raw)


def init_jwe(payload, cek):
    public = rsa.RSAPublicNumbers(65537, int.from_bytes(unb64(CLOUD_KEY_N), 'big')).public_key()
    return encrypt(payload, cek, recipient=public, algorithm='RSA-OAEP-256')


def derive(pin, salt):
    value = salt[2:-3] if len(salt) > 20 else salt
    for _ in range(10): value = hashlib.sha256(value).digest()
    return hashlib.pbkdf2_hmac('sha256', pin, value, 2032, 32)


def pin_hash(pin, salt):
    return b64(hashlib.sha256(pin+unb64(salt)).digest())


def wrap_key(pin, salt, key, random_value):
    require(len(random_value) == 20, 'certificate_random_length')
    derived = derive(pin, unb64(salt))
    return b64(struct.pack('>HHIB', 1, 0, 2032 >> 3, 255)+
               cbc(derived[:16], derived[16:], b'\x01'+random_value+private_bytes(key)))


def valid_pin(pin, phone, birthday):
    if not re.fullmatch(rb'[0-9]{6}', pin) or len(phone) < 8 or len(birthday) < 8: return False
    for i in range(4):
        a, b, c = pin[i:i+3]
        if a == b == c or a+1 == b and b+1 == c or a-1 == b and b-1 == c: return False
    return not any(value.encode() in pin for value in (phone[-8:-4], phone[-4:], birthday[-4:]))


def issue_message(reference, auth_code, ca, key, random_value, *, device_info=''):
    certificate = x509.load_der_x509_certificate(unb64(ca['enc_server_cert']))
    additional = encrypt({'r': b64(random_value), 'device_info': device_info}, secrets.token_bytes(32),
        recipient=certificate.public_key(), algorithm='RSA-OAEP', encryption='A128CBC-HS256', thumb=ca['enc_server_cert_thumbprint'])
    pop = sign({'reference_number': reference, 'public_key': public_jwk(key)}, key)
    protected = protect({'reference_number': reference, 'enc_additional_info': additional, 'proof_of_possession': pop}, auth_code)
    return {'reference_number': reference, 'enc_additional_info': additional, 'protected_pub_key_info': protected}
