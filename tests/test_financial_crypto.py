"""Independent crypto checks on synthetic data; no financial cloud requests."""
import json
import unittest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from finance_cli.credentials.financial import crypto as c


class FinancialCrypto(unittest.TestCase):
    def test_jwe_roundtrip_and_tamper(self):
        for algorithm in ('A256GCM', 'A128CBC-HS256'):
            message = c.encrypt({'synthetic': '한글'}, b'A'*32, encryption=algorithm)
            self.assertEqual(c.decrypt(message, b'A'*32), {'synthetic': '한글'})
            with self.assertRaises((ValueError, InvalidTag)):
                c.decrypt(message, b'B'*32)
            parts = message.split('.'); parts[-1] = c.b64(b'0'*16)
            with self.assertRaises((ValueError, InvalidTag)):
                c.decrypt('.'.join(parts), b'A'*32)

    def test_rs256_signature_independently_verifies(self):
        key = c.keypair()
        head, payload, signature = c.sign({'scope': 'synthetic'}, key).split('.')
        key.public_key().verify(c.unb64(signature), (head+'.'+payload).encode(), padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(json.loads(c.unb64(payload)), {'scope': 'synthetic'})

    def test_unsupported_formats_are_rejected(self):
        for bits in (True, 1024, '2048'):
            with self.assertRaises(ValueError): c.keypair(bits)
        with self.assertRaises(ValueError): c.unb64('!!')

    def test_pin_policy_and_key_restore(self):
        self.assertTrue(c.valid_pin(b'258047', '01092837465', '19870923'))
        self.assertFalse(c.valid_pin(b'123456', '01092837465', '19870923'))
        key = c.keypair()
        self.assertEqual(c.public_jwk(c.load_key(c.b64(c.private_bytes(key)))), c.public_jwk(key))
