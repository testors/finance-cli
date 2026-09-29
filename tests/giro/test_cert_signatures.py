from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
from pathlib import Path
import unittest
from giro.cert_signatures import verify_rsa, verify_signed_material, algorithm_identifier, _require_stable_der
from giro.cert_factory import _node
from giro.cert_rules import CertificateRuleError
from giro.cert_factory import CertificateBackendLimit
from giro.cms import _tlv

@unittest.skipUnless(importlib.util.find_spec('cryptography') and importlib.util.find_spec('asn1crypto'), 'optional crypto/ASN.1 unavailable')
class SignatureTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        cls.pub = cls.key.public_key().public_numbers()
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'synthetic offline')])
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        cls.cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(cls.key.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(cls.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        cls.crl = x509.CertificateRevocationListBuilder().issuer_name(name).last_update(now).next_update(now + timedelta(days=1)).sign(cls.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def verify(self, sig, msg, oid='1.2.840.113549.1.1.11'):
        return verify_rsa(sig, msg, modulus=self.pub.n, exponent=self.pub.e, signature_oid=oid)

    def test_standard_signatures_independent_crypto(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        for (algorithm, oid) in ((hashes.SHA1(), '1.2.840.113549.1.1.5'), (hashes.SHA256(), '1.2.840.113549.1.1.11'), (hashes.SHA512(), '1.2.840.113549.1.1.13'), (hashes.MD5(), '1.2.840.113549.1.1.4')):
            msg = b'synthetic signed content'
            sig = self.key.sign(msg, padding.PKCS1v15(), algorithm)
            self.assertIsNone(self.verify(sig, msg, oid))
            with self.assertRaises(CertificateRuleError):
                self.verify(sig, msg + b'changed', oid)

    def test_certificate_and_crl_signatures_not_trust_or_time_checks(self):
        for (kind, data) in (('certificate', self.cert), ('crl', self.crl)):
            for explicit in (False, True):
                self.assertIsNone(verify_signed_material(data, self.key.public_key(), kind=kind, provider_explicit=explicit))

    def test_certificate_overload_uses_inner_algorithm_without_outer_equality(self):
        from asn1crypto import x509
        parsed = x509.Certificate.load(self.cert)
        parsed['signature_algorithm']['algorithm'] = 'sha1_rsa'
        modified = parsed.dump()
        self.assertIsNone(verify_signed_material(modified, self.key.public_key(), kind='certificate', provider_explicit=True))
        with self.assertRaisesRegex(CertificateRuleError, 'outer_tbs'):
            verify_signed_material(modified, self.key.public_key(), kind='certificate', provider_explicit=False)

    def test_crl_always_compares_outer_algorithm(self):
        from asn1crypto import crl
        parsed = crl.CertificateList.load(self.crl)
        parsed['signature_algorithm']['algorithm'] = 'sha1_rsa'
        with self.assertRaisesRegex(CertificateRuleError, 'outer_tbs'):
            verify_signed_material(parsed.dump(), self.key.public_key(), kind='crl', provider_explicit=True)

    def synthetic_signature(self, *, block_type=1, pad=255, trailing=b'', null_params=True):
        from asn1crypto.core import ObjectIdentifier
        alg = _tlv(48, ObjectIdentifier('2.16.840.1.101.3.4.2.1').dump() + (b'\x05\x00' if null_params else b''))
        info = _tlv(48, alg + _tlv(4, hashlib.sha256(b'synthetic').digest())) + trailing
        raw = bytes([block_type]) + bytes([pad]) * (126 - len(info)) + b'\x00' + info
        sig = pow(int.from_bytes(raw, 'big'), self.key.private_numbers().d, self.pub.n)
        return sig.to_bytes(128, 'big')

    def test_original_padding_acceptance_not_silently_strengthened(self):
        for (block_type, pad) in ((1, 255), (1, 7), (2, 9)):
            self.assertIsNone(self.verify(self.synthetic_signature(block_type=block_type, pad=pad), b'synthetic'))

    def test_original_first_digestinfo_object_trailing_data_ignored(self):
        self.assertIsNone(self.verify(self.synthetic_signature(trailing=b'trailer'), b'synthetic'))

    def test_digest_algorithm_null_and_absent_differ(self):
        with self.assertRaisesRegex(CertificateRuleError, 'algorithm_mismatch'):
            self.verify(self.synthetic_signature(null_params=False), b'synthetic')

    def test_unknown_algorithm_is_unmodeled_not_validation_success(self):
        with self.assertRaises(CertificateBackendLimit):
            self.verify(b'bad', b'x', '1.2.3')

    def test_algorithm_identifier_more_than_two_members_means_absent_params(self):
        from asn1crypto.core import ObjectIdentifier
        oid = ObjectIdentifier('1.2.3').dump()
        self.assertEqual(algorithm_identifier(_tlv(48, oid + b'\x05\x00\x05\x00')), ('1.2.3', None))

    def test_input_size_and_bad_block_are_original_failures(self):
        with self.assertRaises(CertificateRuleError):
            self.verify(b'\x80' + bytes(128), b'x')
        with self.assertRaises(CertificateRuleError):
            self.verify(bytes(128), b'x')

    def test_primitive_reencoding_gaps_are_not_false_signature_failures(self):
        for encoded in (_tlv(1, b'\xff\x00'), _tlv(5, b'x'), _tlv(30, b'\x00A\x00'), _tlv(20, b'\xff')):
            with self.assertRaises(CertificateBackendLimit):
                _require_stable_der(_node(encoded))
        self.assertIsNone(_require_stable_der(_node(_tlv(12, b'\xff'))))
