"""Hana resident keypad wrapping, separated from shared financial-certificate crypto."""
import hashlib
import re
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from finance_cli.core.errors import require
from finance_cli.credentials.financial.crypto import cbc, b64

def resident_aes_key(server):
    xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
    both = lambda a, b: bytes(x & y for x, y in zip(a, b))
    either = lambda a, b: bytes(x | y for x, y in zip(a, b))
    md5 = lambda a: hashlib.md5(a).hexdigest().encode()
    encoded = '\x0e\x7f\x03x\x0f,\x0e/\x00|U)\x00)\x02z\x02y\x05)\x02r\x05.\x07s\x00(\x05yU}'
    constant = bytes(ord(c) ^ (74 if (len(encoded)-i) % 2 else 55) for i, c in enumerate(encoded))
    require(isinstance(server, str) and len(server) >= 72 and server.isascii(), 'resident_key_envelope_required')
    blocks = [server[i:i+8].encode() for i in range(0, 72, 8)]
    folded = xor(both(both(blocks[0], blocks[1]), both(blocks[2], blocks[3])),
                 either(either(blocks[4], blocks[5]), either(blocks[6], blocks[7])))
    return md5(xor(xor(xor(md5(server.encode()), server.encode()), md5(folded)), constant))


def resident_dummy(server, digits, seed):
    from .nfilter_number import numeric_random
    require(re.fullmatch('[0-9]{1,7}', digits) is not None, 'resident_digits_required')
    pad = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(resident_aes_key(server)), modes.ECB()).encryptor()
    data = (enc.update(pad.update(digits.encode())+pad.finalize())+enc.finalize()).hex()
    digest = hashlib.sha256(data.encode()).hexdigest()
    remain = list(range(7)); permutation = [remain.pop(v % len(remain)) for v in numeric_random(seed, 7)]
    return ''.join(digest[i] for i in permutation[:len(digits)])
