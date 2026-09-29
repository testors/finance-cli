import importlib.util
import unittest
from giro.crypto import API_IV, NUMERIC_KEYPAD, PIN_IV, _cbc, decrypt_body, encode_pin, encrypt_body
from giro.errors import GiroError

@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional cryptography package unavailable')
class CryptoTests(unittest.TestCase):
    KEY = bytes(range(16))

    def test_numeric_mapping(self):
        self.assertEqual(NUMERIC_KEYPAD, '1234567890')

    def test_body_padding_boundaries(self):
        for count in (1, 15, 16, 17, 31, 32, 300):
            with self.subTest(count=count):
                plain = b'x' * count
                cipher = encrypt_body(plain, self.KEY)
                self.assertEqual(len(cipher), (count // 16 + 1) * 16)
                self.assertEqual(decrypt_body(cipher, self.KEY), plain)

    def test_body_korean_bytes_preserved(self):
        for charset in ('utf-8', 'euc-kr'):
            plain = '작업구분=로그인'.encode(charset)
            self.assertEqual(decrypt_body(encrypt_body(plain, self.KEY), self.KEY), plain)

    def test_invalid_padding_rejected(self):
        invalid = _cbc(self.KEY, API_IV, bytes(16))
        with self.assertRaises(GiroError):
            decrypt_body(invalid, self.KEY)

    def test_pin_block_layout(self):
        pin = '012345'
        raw = bytes.fromhex(encode_pin(pin, self.KEY))
        self.assertEqual(len(raw), 96)
        for (index, keypad_index) in enumerate((10, 1, 2, 3, 4, 5)):
            plain = _cbc(self.KEY, PIN_IV, raw[index * 16:(index + 1) * 16], decrypt=True)
            self.assertEqual(plain, bytes((5, keypad_index)) + bytes(14))

    def test_pin_resets_iv_for_each_digit(self):
        result = encode_pin('111111', self.KEY)
        self.assertEqual(result[:32] * 6, result)

    def test_zeroes_are_valid_digits(self):
        self.assertEqual(len(encode_pin('000000', self.KEY)), 192)

    def test_pin_validation(self):
        for pin in ('12345', '1234567', '１２３４５６', 'abcdef', '12345\n', 123456):
            with self.subTest(pin=pin), self.assertRaises(GiroError):
                encode_pin(pin, self.KEY)

    def test_bad_keys_and_empty_body(self):
        for key in (b'', bytes(15), bytes(17), '0' * 16):
            with self.subTest(length=len(key)), self.assertRaises(GiroError):
                encrypt_body(b'test', key)
        with self.assertRaises(GiroError):
            encrypt_body(b'', self.KEY)
