"""Certificate tests using generated keys and certificates."""
import base64
from datetime import datetime, timezone
import hashlib
import unittest

from asn1crypto import algos, cms, core, keys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import SEED
from cryptography.x509.oid import NameOID

from hometax_cli import certificate as c


def synthetic_material(policies=None):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OFFLINE TEST ONLY")])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(private.public_key()).serial_number(0x8001)
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2049, 12, 31, tzinfo=timezone.utc)))
    if policies is not None:
        builder = builder.add_extension(x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier(oid), None) for oid in policies]), critical=False)
    cert = builder.sign(private, hashes.SHA256())
    info = keys.PrivateKeyInfo.load(private.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    random = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    info["attributes"] = [{"type": c.VID_RANDOM_OID,
                           "values": [core.OctetBitString(random)]}]
    return cert.public_bytes(serialization.Encoding.DER), info.dump(), random


def encrypt_test_key(private, password, oid=c.SEED_SHA1, *, prf="sha1", iterations=2048,
                     iv=b"0123456789abcdef", key_length=None):
    salt = bytes.fromhex("f0e1d2c3b4a59687")
    if oid in (c.SEED_SHA1, c.SEED_CBC):
        # Independent iterative SHA1 using the digest primitive's copy/update API.
        d = password + salt
        for _ in range(max(1, iterations)):
            h = hashes.Hash(hashes.SHA1())
            h.update(d)
            d = h.finalize()
        key = d[:16]
        iv = b"0123456789012345" if oid == c.SEED_CBC else hashlib.sha1(d[16:]).digest()[:16]
        algorithm = {"oid": oid, "parameters": c.PBEParameters({"salt": salt, "iterations": iterations})}
        cipher = SEED(key)
    else:
        # Native ignores explicit PRF/keyLength; fixtures exercise that behavior.
        material = hashlib.pbkdf2_hmac("sha1", password, salt, iterations, 32)
        key = material[:16]
        kdf = {"salt": {"specified": salt}, "iteration_count": iterations,
               "prf": {"algorithm": prf}}
        if key_length is not None:
            kdf["key_length"] = key_length
        params = c.PBES2Parameters({
            "kdf": {"oid": "1.2.840.113549.1.5.12", "parameters": algos.Pbkdf2Params(kdf)},
            "cipher": {"oid": oid, "parameters": core.OctetString(iv)},
        })
        algorithm = {"oid": c.PBES2, "parameters": params}
        iv = iv or material[16:32]
        cipher = algorithms.AES(key) if oid == c.AES128_CBC else SEED(key)
    n = 16 - len(private) % 16
    enc = Cipher(cipher, modes.CBC(iv)).encryptor()
    encrypted = enc.update(private + bytes([n]) * n) + enc.finalize()
    return c.EncryptedKey({"algorithm": algorithm, "encrypted": encrypted}).dump()


class CertificateContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.private, cls.random = synthetic_material()
        cls.password = "synthetic 한글 암호 +  ".encode()

    def test_legacy_and_pbes2_decryption(self):
        for oid in (c.SEED_SHA1, c.SEED_CBC, c.AES128_CBC, c.SEED_CBC + ".2"):
            with self.subTest(oid=oid):
                encrypted = encrypt_test_key(self.private, self.password, oid)
                plain, warnings = c.decrypt_key(encrypted, self.password)
                self.assertEqual(plain, self.private)
                self.assertFalse(warnings)

    def test_native_pbkdf2_ignores_prf_and_key_length(self):
        encrypted = encrypt_test_key(self.private, self.password, c.AES128_CBC,
                                     prf="sha256", key_length=32, iv=b"")
        plain, warnings = c.decrypt_key(encrypted, self.password)
        self.assertEqual(plain, self.private)
        self.assertEqual(len(warnings), 2)

    def test_legacy_zero_iterations_still_hashes_once(self):
        encrypted = encrypt_test_key(self.private, self.password, iterations=0)
        self.assertEqual(c.decrypt_key(encrypted, self.password)[0], self.private)

    def test_wrong_password_and_absent_vid(self):
        encrypted = encrypt_test_key(self.private, self.password)
        with self.assertRaises(ValueError):
            c.decrypt_key(encrypted, b"wrong")
        info = keys.PrivateKeyInfo.load(self.private)
        del info["attributes"]
        with self.assertRaises(c.CertificateError):
            c.vid_random(info.dump())

    def test_native_padding_zero_and_invalid_padding(self):
        self.assertEqual(c.native_unpad(b"A" * 15 + b"\0"), b"A" * 15 + b"\0")
        self.assertEqual(c.native_unpad(b"A" * 14 + b"\x02\x02"), b"A" * 14)
        self.assertEqual(c.native_unpad(b"\x10" * 16), b"")
        for data in (b"", b"A" * 14 + b"\x03\x02", b"\x11" * 16):
            with self.subTest(data=data), self.assertRaises(c.CertificateError):
                c.native_unpad(data)

    def test_signer_contract_and_signature(self):
        when = datetime(2026, 9, 28, 12, 34, 56, tzinfo=timezone.utc)
        signed = c.sign_empty(self.cert, self.private, when)
        sd = cms.SignedData.load(signed)
        self.assertEqual(sd["version"].native, "v1")
        self.assertEqual(sd["encap_content_info"].dump().hex(), "300f06092a864886f70d010701a0020400")
        self.assertEqual(sd["digest_algorithms"][0].dump().hex(), "300b0609608648016503040201")
        signer = sd["signer_infos"][0]
        self.assertEqual(signer["signature_algorithm"].dump().hex(), "300d06092a864886f70d01010b0500")
        attrs = signer["signed_attrs"]
        self.assertEqual([a["type"].native for a in attrs], ["content_type", "signing_time", "message_digest"])
        self.assertEqual(attrs[2]["values"][0].native, hashlib.sha256(b"").digest())
        # Parse the encoded output, then verify, independent of builder internals.
        x509.load_der_x509_certificate(self.cert).public_key().verify(
            signer["signature"].native, b"\x31" + attrs.dump()[1:], padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(c.vid_random(self.private), self.random)

    def test_full_prepare_and_mismatched_key(self):
        encrypted = encrypt_test_key(self.private, self.password)
        prepared = c.prepare_certificate(self.cert, encrypted, self.password)
        self.assertTrue(base64.b64encode(prepared.signed_data))
        self.assertEqual(prepared.callback()["payload"]["certResult"], "SUCC")
        other_cert, _, _ = synthetic_material()
        with self.assertRaises(c.CertificateError):
            c.sign_empty(other_cert, self.private)


if __name__ == "__main__":
    unittest.main()
