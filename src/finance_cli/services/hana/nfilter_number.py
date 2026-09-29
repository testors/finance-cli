"""Numeric NFilter input packing recovered from db/wc/jk and ARM64 NSafer.

This is the NUM/FULL EncData profile, not the AES result consumed by PIN
signing. It models fresh input without deletion, layout changes or reuse.
"""
import hashlib
import struct

# FIPS_PRNG context modulus: five little-endian limbs at native RVA 0x15d20
# (the final limb 0xc468245b is loaded as an immediate in N_GenRandFromSeed).
_Q = 0xc468245bb6795c7ffff96962c642e5165f51a6f9
_MASK = (1 << 32) - 1


def _rotate(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & _MASK


def _sha1_compress(block):
    """One raw SHA1 compression, without SHA message padding or bit length."""
    words = list(struct.unpack('>16I', block))
    for i in range(16, 80):
        words.append(_rotate(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1))
    initial = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)
    a, b, c, d, e = initial
    for i, word in enumerate(words):
        if i < 20:
            f, k = (b & c) | (~b & d), 0x5a827999
        elif i < 40:
            f, k = b ^ c ^ d, 0x6ed9eba1
        elif i < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8f1bbcdc
        else:
            f, k = b ^ c ^ d, 0xca62c1d6
        a, b, c, d, e = (_rotate(a, 5) + f + e + k + word) & _MASK, a, _rotate(b, 30), c, d
    return struct.pack('>5I', *((x + y) & _MASK for x, y in zip(initial, (a, b, c, d, e))))


def _minimal_big_endian(value):
    return value.to_bytes((value.bit_length() + 7) // 8, 'big')


def numeric_random(seed, length):
    """SDK N_GenRandFromSeed subset used by the ten-digit keypad (1..10).

    The SDK imports SHA1(seed) directly into little-endian ZZ limbs, adds
    XSEED and XKEY, exports minimally, right-pads to 64 bytes, then performs
    one raw SHA1 compression and reduces modulo Q. Each call restarts state.
    Deliberately excludes the unused multi-block PRNG API.
    """
    if not isinstance(seed, bytes) or len(seed) != 21 or not 1 <= length <= 10:
        raise ValueError('Expected a 21-byte numeric seed and length 1..10')
    seed_integer = int.from_bytes(hashlib.sha1(seed).digest(), 'little')
    value = (seed_integer * 2) & ((1 << 160) - 1)
    block = _minimal_big_endian(value).ljust(64, b'\0')
    output = _minimal_big_endian(int.from_bytes(_sha1_compress(block), 'big') % _Q)
    # The native implementation copies a 20-byte stack buffer even when its
    # integer export is shorter. Only use the fully initialized prefix.
    if len(output) < length:
        raise ValueError('Numeric PRNG output requires undefined native bytes')
    return output[:length]


def numeric_permutation(shared):
    remaining = list(range(10))
    return [remaining.pop(value % len(remaining)) for value in numeric_random(shared, 10)]


def pack_numeric_input(shared, digits):
    """Serialize key-position segments before SEED encryption (db.f(View))."""
    if not isinstance(digits, str) or not 1 <= len(digits) <= 16 or any(c not in '0123456789' for c in digits):
        raise ValueError('Expected 1 to 16 ASCII digits')
    permutation = numeric_permutation(shared)
    mutable_seed = bytearray(shared)
    output = bytearray()
    for digit in digits:
        # jk.j(1,10) calls j(17): increment M[17 % 7] BEFORE generating.
        mutable_seed[3] = (mutable_seed[3] + 1) & 255
        seed = bytes(mutable_seed)
        descriptor = numeric_random(seed, 2)
        length = descriptor[0] % 10 or 10
        position = descriptor[1] % length
        segment = bytearray(48 + byte % 10 for byte in numeric_random(seed, length))
        segment[position] = 48 + permutation.index(int(digit))
        output.extend(segment)
    return bytes(output)
