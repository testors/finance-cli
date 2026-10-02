from finance_cli.core.native import crypto_library
import ctypes
import ctypes.util
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
import unittest
from unittest.mock import patch
from giro import codeguard_nonce as cg
from giro import codeguard_primitives as prim
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_tables import SBOXES
ROOT = Path(__file__).resolve().parents[1]

class PrimitiveTests(unittest.TestCase):

    def test_aria_known_answer(self):
        self.assertEqual(prim.aria256_encrypt(bytes.fromhex('00112233445566778899aabbccddeeff'), bytes(range(32))).hex(), 'f92bd7c79fb72e2f2b8f80c1972d24fc')
        self.assertEqual(prim.aria256_encrypt(bytes(16), bytes(32)).hex(), 'c20857dd9106ddde286ec59fa98d77cc')

    def test_md4_known_answers(self):
        for (data, expected) in ((b'', '31d6cfe0d16ae931b73c59d7e0c089c0'), (b'a', 'bde52cb31de33e46245e05fbdbd6fb24'), (b'abc', 'a448017aaf21d8525fc10ae87aa6729d')):
            self.assertEqual(prim.md4(data).hex(), expected)

    def test_diffusion_involution(self):
        for i in range(16):
            block = bytes([0] * i + [128] + [0] * (15 - i))
            self.assertEqual(prim.diffuse(prim.diffuse(block)), block)

    def test_sbox_inverse_pairs(self):
        for (a, b) in ((0, 2), (1, 3)):
            self.assertEqual(bytes((SBOXES[b][v] for v in SBOXES[a])), bytes(range(256)))

    def test_md4_fixed_twenty_bytes_including_nul(self):
        self.assertEqual(prim.native_md4_20(bytes(20) + b'ignored'), prim.md4(bytes(20)))
        self.assertNotEqual(prim.native_md4_20(bytes(20)), prim.md4(b''))
        with self.assertRaises(ValueError):
            prim.native_md4_20(bytes(19))

    def test_md5_uses_uppercase_ascii_hex(self):
        data = bytes(range(32))
        self.assertEqual(prim.native_md5_hex(data), hashlib.md5(data.hex().upper().encode()).digest())
        self.assertNotEqual(prim.native_md5_hex(data), hashlib.md5(data).digest())

    def test_primitive_sizes(self):
        for (callback, args) in ((prim.aria256_schedule, (bytes(31),)), (prim.aria_block, (bytes(15), bytes(272))), (prim.diffuse, (bytes(15),)), (prim.xor_bytes, (bytes(2), bytes(3)))):
            with self.assertRaises(ValueError):
                callback(*args)

class NonceTests(unittest.TestCase):

    def test_hex_normal_and_nul(self):
        self.assertEqual(cg.native_hex32(b'aA01\x00ignored'), bytes.fromhex('aa01') + bytes(30))

    def test_hex_odd_null_and_empty(self):
        for data in (None, b'', b'0', b'ABC'):
            self.assertEqual(cg.native_hex32(data), bytes(32))

    def test_hex_invalid_keeps_partial_nibble_not_strict_rejection(self):
        self.assertEqual(cg.native_hex32(b'12AzFFFF'), bytes.fromhex('12a0') + bytes(30))
        self.assertEqual(cg.native_hex32(b'12 3'), b'\x12' + bytes(31))

    def test_hex_fortify_even_overflow_and_odd_skip(self):
        with self.assertRaises(AnalysisLimit):
            cg.native_hex32(b'0' * 66)
        self.assertEqual(cg.native_hex32(b'0' * 67), bytes(32))

    def test_native_key_allocation_boundaries(self):
        for value in (None, b'', b'0' * 62, b'0' * 63):
            with self.assertRaises(AnalysisLimit):
                cg.key_code_array(value)
        self.assertEqual(cg.key_code_array(b'0' * 65), cg.key_code_array(b'0' * 64))

    def test_key_schedule_is_not_substituted_with_standard_aria(self):
        key = bytes(range(32))
        self.assertNotEqual(cg.native_schedule(key), prim.aria256_schedule(key))
        old = bytes((i % 256 for i in range(272)))
        self.assertEqual(cg.native_schedule(key, old), prim.xor_bytes(cg.native_schedule(key), old))

    def test_modified_schedule_independent_instruction_vectors(self):
        # Synthetic vectors obtained independently from arithmetic instructions.
        # Catch missing D/Q alias writes as well as dependence on prior output.
        vectors = (
            (bytes(32), (
                '03aed1fadc9151692e336d3dabf5ddb9f72f212642b9d81261c85b0fd4abcfee',
                'bf004bf70ee13723cf4608afbb74bc4b52e4f14cf62eca064386c2bfb867b5f3')),
            (bytes([255]) * 32, (
                '85c0c5dde6567c72bc792f8b9b2d3c50e2528651e7c4f986c5567340e18bc195',
                '8c00820a3c69a1124b545eb2a00d606f1570d3fba83cdd78b7169fb15ef774f9')),
            (bytes(range(32)), (
                '6fc6a45a28f9de256fa23ec5873d78c3e919afa15ff0d4039aad0e07a34ff852',
                '5b99b40659440a6d732e7fd3c1c2dd6c0794fa6987bae632d33e6b8539637e7c')),
        )
        for key, expected in vectors:
            for old, digest in zip((bytes(272), bytes(i % 256 for i in range(272))), expected):
                with self.subTest(key=key.hex(), old_nonzero=any(old)):
                    self.assertEqual(hashlib.sha256(cg.native_schedule(key, old)).hexdigest(), digest)

    def test_six_selectors_use_cumulative_cursor(self):
        self.assertEqual(cg.selected_functions(bytes(range(32))), (2, 3, 5, 6, 8, 9))
        self.assertEqual(cg.selected_functions(bytes([255]) * 32), (55,) * 6)

    def test_work_key_uses_modified_schedule_and_chained_blocks(self):
        key = bytes(range(32))
        schedule = cg.native_schedule(key)
        first = prim.aria_block(key[:16], schedule)
        self.assertEqual(cg.key_code_array(key.hex().encode()), first + prim.aria_block(first, schedule))

    def test_programs_cover_all_one_hundred_indices(self):
        data = cg.load_programs()
        self.assertEqual([x['index'] for x in data['functions']], list(range(100)))

    def test_manual_transform_2(self):
        (work, code, old) = (bytes(range(32)), bytes(range(32, 64)), bytes([165]) * 32)
        schedule = prim.aria256_schedule(work)
        independent = prim.aria_block(code[:16], schedule) + prim.aria_block(code[16:][::-1], schedule)[::-1]
        self.assertEqual(cg.transform(2, work, code, old), prim.xor_bytes(independent, old))

    def test_manual_transform_9(self):
        (code, old) = (bytes(range(32)), bytes([165]) * 32)
        expected = prim.xor_bytes(hashlib.md5(code.hex().upper().encode()).digest() + bytes(16), old)
        self.assertEqual(cg.transform(9, bytes(32), code, old), expected)

    def test_all_functions_keep_previous_output_xor(self):
        (work, code, old) = (bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96)))
        for index in range(100):
            with self.subTest(index=index):
                zero = cg.transform(index, work, code, bytes(32))
                self.assertEqual(len(zero), 32)
                self.assertEqual(cg.transform(index, work, code, old), prim.xor_bytes(zero, old))

    def test_native_buffer_persists_across_six_calls(self):
        key = bytes(range(32)).hex().encode()
        codes = [bytes([i]) * 32 for i in range(6)]
        work = cg.key_code_array(key)
        indices = cg.selected_functions(work)
        expected = bytes(32)
        for i in (1, 3, 5):
            expected = prim.xor_bytes(expected, cg.transform(indices[i], work, codes[i], bytes(32)))
        result = cg.cg_auth_code(key, [x.hex().encode() for x in codes])
        self.assertEqual(result, expected.hex().upper())
        self.assertEqual(result, 'F8A5FE289232BC07333BA4EA63A3444CE4432CEA0ECE16F128C9BB8D79B08C4F')

    def test_extra_array_entries_ignored_short_array_unmodeled(self):
        key = b'0' * 64
        self.assertEqual(cg.cg_auth_code(key, [None] * 6), cg.cg_auth_code(key, [None] * 6 + [b'BAD']))
        with self.assertRaises(AnalysisLimit):
            cg.cg_auth_code(key, [None] * 5)

    def test_arithmetic_has_no_socket_or_sdk_load(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), patch('ctypes.CDLL', side_effect=AssertionError('native load forbidden')):
            self.assertEqual(len(cg.cg_auth_code(b'0' * 64, [None] * 6)), 64)

@unittest.skipUnless(crypto_library(), 'independent OpenSSL unavailable')
class OpenSSLDifferentialTests(unittest.TestCase):

    def test_aria_against_independent_system_crypto_not_sdk(self):
        lib = ctypes.CDLL(crypto_library())
        (ptr, integer) = (ctypes.c_void_p, ctypes.c_int)
        for (name, args, restype) in (('EVP_get_cipherbyname', [ctypes.c_char_p], ptr), ('EVP_CIPHER_CTX_new', [], ptr), ('EVP_EncryptInit_ex', [ptr, ptr, ptr, ptr, ptr], integer), ('EVP_CIPHER_CTX_set_padding', [ptr, integer], integer), ('EVP_EncryptUpdate', [ptr, ptr, ctypes.POINTER(integer), ptr, integer], integer), ('EVP_CIPHER_CTX_free', [ptr], None)):
            fn = getattr(lib, name)
            fn.argtypes = args
            fn.restype = restype
        cipher = lib.EVP_get_cipherbyname(b'ARIA-256-ECB')
        if not cipher:
            self.skipTest('OpenSSL ARIA unavailable')
        rng = random.Random(1024)
        for _ in range(32):
            (key, block) = (rng.randbytes(32), rng.randbytes(16))
            ctx = lib.EVP_CIPHER_CTX_new()
            self.assertTrue(ctx)
            try:
                (out, n) = (ctypes.create_string_buffer(32), integer())
                self.assertEqual(lib.EVP_EncryptInit_ex(ctx, cipher, None, key, None), 1)
                self.assertEqual(lib.EVP_CIPHER_CTX_set_padding(ctx, 0), 1)
                self.assertEqual(lib.EVP_EncryptUpdate(ctx, out, ctypes.byref(n), block, 16), 1)
                self.assertEqual(prim.aria256_encrypt(block, key), out.raw[:n.value])
            finally:
                lib.EVP_CIPHER_CTX_free(ctx)
