"""Offline arithmetic recovered from ImageDecoder; no JNI, SDK or network.

Legacy algorithms here are protocol compatibility, not a recommendation for
new cryptography. Callers must supply actual inputs, never fabricated hashes.
"""
import hashlib
import struct
from functools import reduce
from operator import xor

from .codeguard_tables import SBOXES

# hshdyq... at 0x25820: each row is the input-byte XOR set.
DIFFUSION = (
    (3, 4, 6, 8, 9, 13, 14), (2, 5, 7, 8, 9, 12, 15),
    (1, 4, 6, 10, 11, 12, 15), (0, 5, 7, 10, 11, 13, 14),
    (0, 2, 5, 8, 11, 14, 15), (1, 3, 4, 9, 10, 14, 15),
    (0, 2, 7, 9, 10, 12, 13), (1, 3, 6, 8, 11, 12, 13),
    (0, 1, 4, 7, 10, 13, 15), (0, 1, 5, 6, 11, 12, 14),
    (2, 3, 5, 6, 8, 13, 15), (2, 3, 4, 7, 9, 12, 14),
    (1, 2, 6, 7, 9, 11, 12), (0, 3, 6, 7, 8, 10, 13),
    (0, 3, 4, 5, 9, 11, 14), (1, 2, 4, 5, 8, 10, 15),
)
CONSTANTS = tuple(bytes.fromhex(s) for s in (
    'db92371d2126e9700324977504e8c90e',
    '517cc1b727220a94fe13abe8fa9a6ee0',
    '6db14acc9e21c820ff28b1d5ef5de2b0',
))


def xor_bytes(a, b):
    if len(a) != len(b):
        raise ValueError('internal XOR operand sizes differ')
    return bytes(x ^ y for x, y in zip(a, b))


def diffuse(block):
    if len(block) != 16:
        raise ValueError('diffusion needs 16 bytes')
    return bytes(reduce(xor, (block[j] for j in row)) for row in DIFFUSION)


def substitute(block, even=False):
    return bytes(SBOXES[(i + (2 if even else 0)) % 4][b] for i, b in enumerate(block))


def aria256_schedule(key):
    """17 round keys for 0x23eb4; NOT the distinct 0x219f8 schedule."""
    if len(key) != 32:
        raise ValueError('ARIA-256 needs 32 key bytes')
    words = [key[:16]]
    words.append(xor_bytes(diffuse(substitute(xor_bytes(words[0], CONSTANTS[0]))), key[16:]))
    words.append(xor_bytes(diffuse(substitute(xor_bytes(words[1], CONSTANTS[1]), True)), words[0]))
    words.append(xor_bytes(diffuse(substitute(xor_bytes(words[2], CONSTANTS[2]))), words[1]))
    integers = [int.from_bytes(w, 'big') for w in words]
    mask = (1 << 128) - 1
    result = []
    for shift in (19, 31, 67, 97, 109):
        for i in range(4):
            value = integers[(i + 1) % 4]
            rotated = ((value >> shift) | (value << (128-shift))) & mask
            result.append((integers[i] ^ rotated).to_bytes(16, 'big'))
    return b''.join(result[:17])


def aria_block(block, schedule):
    """0x22f68, 16 rounds, including caller-modified schedules."""
    if len(block) != 16 or len(schedule) != 272:
        raise ValueError('ARIA block/schedule sizes must be 16/272')
    state = block
    for i in range(15):
        state = diffuse(substitute(xor_bytes(state, schedule[16*i:16*i+16]), bool(i % 2)))
    return xor_bytes(substitute(xor_bytes(state, schedule[240:256]), True), schedule[256:272])


def aria256_encrypt(block, key):
    return aria_block(block, aria256_schedule(key))


def md4(data):
    """MD4 compression reconstructed from 0x268d4..0x26ea8.

    The native wrapper hashes exactly 20 bytes, including embedded zero bytes;
    this general helper also permits independent standard-vector checks.
    """
    bit_length = len(data) * 8
    data += b'\x80' + bytes((55 - len(data)) % 64) + struct.pack('<Q', bit_length)
    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    mask = 0xffffffff
    for offset in range(0, len(data), 64):
        words = struct.unpack('<16I', data[offset:offset+64])
        a, b, c, d = state
        for round_index, order in enumerate((range(16),
                (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15),
                (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15))):
            shifts = ((3, 7, 11, 19), (3, 5, 9, 13), (3, 9, 11, 15))[round_index]
            for j, index in enumerate(order):
                f = ((b & c) | (~b & d)) if round_index == 0 else (
                    (b & c) | (b & d) | (c & d)) if round_index == 1 else b ^ c ^ d
                value = (a + f + words[index] + (0, 0x5a827999, 0x6ed9eba1)[round_index]) & mask
                shift = shifts[j % 4]
                value = ((value << shift) | (value >> (32-shift))) & mask
                a, b, c, d = d, value, b, c
        state = [(x+y) & mask for x, y in zip(state, (a, b, c, d))]
    return struct.pack('<4I', *state)


def native_md4_20(data):
    if len(data) < 20:
        raise ValueError('native fixed-length MD4 reads 20 bytes')
    return md4(data[:20])


def native_md5_hex(data):
    """0x25fe0: hashes 64 uppercase ASCII hex characters, writes 16 bytes."""
    if len(data) != 32:
        raise ValueError('native MD5 input needs 32 bytes')
    return hashlib.md5(data.hex().upper().encode('ascii')).digest()
