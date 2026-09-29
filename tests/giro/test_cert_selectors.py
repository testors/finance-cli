import importlib.util
from pathlib import Path
import unittest
import shutil
import subprocess
from giro.cms import _tlv
from giro.cert_factory import CertificateBackendLimit
from giro.cert_selectors import principal_canonical, principal_equal, unique_selection, MaterialStore
import test_cert_path as support

def name(*rdns):
    from asn1crypto.core import ObjectIdentifier
    return _tlv(48, b''.join((_tlv(49, b''.join((_tlv(48, ObjectIdentifier(oid).dump() + _tlv(tag, raw)) for (oid, tag, raw) in rdn))) for rdn in rdns)))

@unittest.skipUnless(importlib.util.find_spec('asn1crypto'), 'ASN.1 unavailable')
class PrincipalTests(unittest.TestCase):

    def test_canonical_reverse_rdn_order_and_space_case(self):
        value = name([('2.5.4.10', 12, b'  SYNTHETIC   ORG  ')], [('2.5.4.3', 19, b' ExAmPlE ')])
        self.assertEqual(principal_canonical(value), 'cn=example,o=synthetic org')

    def test_recognized_string_tags_equal_but_ia5_is_hex(self):

        def tagged(tag):
            return name([('2.5.4.3', tag, b'Example')])
        for tag in (12, 19, 20):
            self.assertTrue(principal_equal(tagged(tag), tagged(12)))
        self.assertEqual(principal_canonical(tagged(22)), 'cn=#16074578616d706c65')
        self.assertFalse(principal_equal(tagged(22), tagged(12)))

    def test_unknown_oid_and_noncanonical_keyword_use_full_der_hex(self):
        for oid in ('1.2.3.4', '2.5.4.5', '1.2.840.113549.1.9.1'):
            self.assertEqual(principal_canonical(name([(oid, 12, b'ABC')])), oid + '=#0c03414243')
            self.assertFalse(principal_equal(name([(oid, 12, b'ABC')]), name([(oid, 12, b'abc')])))

    def test_escapes_and_leading_hash(self):
        self.assertEqual(principal_canonical(name([('2.5.4.3', 12, b'#A,+<>;"\\')])), 'cn=\\#a\\,\\+\\<\\>\\;\\"\\\\')

    def test_rdn_order_is_not_sdk_unordered_name_equality(self):
        a = [('2.5.4.3', 12, b'X')]
        b = [('2.5.4.10', 12, b'Y')]
        self.assertFalse(principal_equal(name(a, b), name(b, a)))

    def test_multi_ava_and_unicode_not_silently_nonmatch(self):
        values = (name([('2.5.4.3', 12, '한국'.encode())]), name([('2.5.4.3', 12, b'X'), ('2.5.4.10', 12, b'Y')]))
        for value in values:
            self.assertTrue(principal_equal(value, value))
            with self.assertRaises(CertificateBackendLimit):
                principal_canonical(value)

    def test_unmodeled_nonprintable_is_not_trimmed(self):
        for raw in (b'\tX', b'A#B', b'A\x00B'):
            with self.assertRaises(CertificateBackendLimit):
                principal_canonical(name([('2.5.4.3', 12, raw)]))

    def test_synthetic_canonical_vectors_match_independent_standard_jdk(self):
        java = shutil.which('java')
        if java is None:
            self.skipTest('JDK unavailable')
        source = Path(__file__).parent / 'java/PrincipalVectors.java'
        values = [name([('2.5.4.3', tag, b'  SyNtHeTiC   CA  ')]) for tag in (12, 19, 22, 30)]
        values += [name([(oid, 12, b'ABC')]) for oid in ('1.2.3.4', '2.5.4.5', '2.5.4.9', '2.5.4.11', '0.9.2342.19200300.100.1.1', '0.9.2342.19200300.100.1.25', '1.2.840.113549.1.9.1')]
        values += [name([('2.5.4.3', 12, b'#A,+<>;"\\')]), name([('2.5.4.10', 12, b'ORG')], [('2.5.4.3', 12, b'CA')])]
        output = subprocess.run([java, str(source), *(v.hex() for v in values)], capture_output=True, text=True, check=True, timeout=30).stdout.splitlines()
        self.assertEqual(output, [principal_canonical(v) for v in values])

@unittest.skipUnless(importlib.util.find_spec('asn1crypto') and importlib.util.find_spec('cryptography'), 'crypto unavailable')
class StoreTests(unittest.TestCase):
    cert = support.SuppliedPathTests.cert
    crl = support.SuppliedPathTests.crl

    @classmethod
    def setUpClass(cls):
        support.SuppliedPathTests.setUpClass()
        for attr in ('keys', 'at', 'names', 'policy'):
            setattr(cls, attr, getattr(support.SuppliedPathTests, attr))

    def test_certificate_subject_selector_ignores_crls_and_other_subjects(self):
        (target, issuer) = (self.cert(2), self.cert(1))
        store = MaterialStore((target, issuer, issuer, None, self.crl(1)))
        self.assertEqual(store.certificates_for_subject(target.issuer_der), (issuer,))

    def test_selector_does_not_prematurely_check_validity(self):
        issuer = self.cert(1, valid=False)
        self.assertEqual(MaterialStore((issuer,)).certificates_for_subject(issuer.subject_der), (issuer,))

    def test_crl_selector_uses_issuer_not_target_subject(self):
        (first, second) = (self.crl(0), self.crl(1))
        store = MaterialStore(crls=(first, second, second, self.cert(1), None))
        self.assertEqual(store.crls_for_issuer(self.cert(1).subject_der), (second,))

    def test_crl_number_range_is_inclusive(self):
        from cryptography import x509
        for (number, expected) in ((4, False), (5, True), (6, True), (7, False)):
            crl = self.crl(1, extra=(x509.CRLNumber(number),))
            result = MaterialStore(crls=(crl,)).crls_for_issuer(crl.issuer_der, bounds=(5, 6))
            self.assertEqual(bool(result), expected)

    def test_missing_number_does_not_become_false_or_zero(self):
        crl = self.crl(1)
        with self.assertRaisesRegex(CertificateBackendLimit, 'null extension'):
            MaterialStore(crls=(crl,)).crls_for_issuer(crl.issuer_der, bounds=(0, 9))

    def test_subject_nonmatch_shortcircuits_missing_crl_number(self):
        self.assertEqual(MaterialStore(crls=(self.crl(0),)).crls_for_issuer(self.cert(1).subject_der, bounds=(0, 9)), ())

    def test_duplicates_dedup_but_distinct_material_order_unresolved(self):
        (good, bad) = (self.cert(1), self.cert(1, valid=False))
        self.assertEqual(unique_selection((good, good)), (good,))
        with self.assertRaisesRegex(CertificateBackendLimit, 'HashSet'):
            MaterialStore((bad, good)).certificates_for_subject(good.subject_der)

    def test_store_repr_does_not_leak_contents(self):
        self.assertNotIn('PRIVATE', repr(MaterialStore(('PRIVATE',), ('PRIVATE',))))
