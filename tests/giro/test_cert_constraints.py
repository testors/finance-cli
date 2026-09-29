import importlib.util
from pathlib import Path
import unittest
from giro.cert_constraints import NameConstraints, within_domain, sdk_split, uri_host, email_matches, ip_matches, _ip_pick, _ip_intersection, dn_value
from giro.cert_factory import _node, CertificateBackendLimit
from giro.cert_rules import CertificateRuleError
from giro.cms import _tlv

class NameConstraintTests(unittest.TestCase):

    def test_dns_split_stops_at_leading_separator(self):
        self.assertEqual(sdk_split('a..b.c'), ['a', '.b.c'])
        self.assertEqual(sdk_split('.a.b'), ['.a.b'])
        self.assertEqual(sdk_split('a.'), ['a', ''])

    def test_domain_strict_descendant_and_case(self):
        self.assertTrue(within_domain('a.Example.test', '.example.TEST'))
        self.assertFalse(within_domain('example.test', '.example.test'))
        self.assertFalse(within_domain('.example.test', 'example.test'))
        self.assertFalse(within_domain('example.test.attacker', 'example.test'))

    def test_dns_intersection_identical_constraint_becomes_empty(self):
        state = NameConstraints()
        state.intersect(2, 'example.test')
        state.check(2, 'example.test')
        state.intersect(2, 'example.test')
        self.assertEqual(state.permitted[2], set())
        with self.assertRaisesRegex(CertificateRuleError, 'not_permitted_2'):
            state.check(2, 'example.test')

    def test_dns_subtrees_sequential_not_siblings_union(self):
        state = NameConstraints()
        state.intersect(2, 'a.example.test')
        state.intersect(2, 'b.example.test')
        with self.assertRaises(CertificateRuleError):
            state.check(2, 'a.example.test')

    def test_dns_narrowing_and_exclusion(self):
        state = NameConstraints()
        state.intersect(2, 'example.test')
        state.intersect(2, 'a.example.test')
        state.check(2, 'x.a.example.test')
        state.exclude(2, 'a.example.test')
        state.exclude(2, 'example.test')
        self.assertEqual(state.excluded[2], {'example.test'})
        with self.assertRaisesRegex(CertificateRuleError, 'excluded_2'):
            state.check(2, 'x.a.example.test')

    def test_empty_permitted_and_empty_subject_exception_except_dn(self):
        for (tag, value) in ((1, ''), (2, ''), (6, ''), (7, b'')):
            state = NameConstraints()
            state.permitted[tag] = set()
            state.check(tag, value)
        state = NameConstraints()
        state.permitted[4] = set()
        with self.assertRaises(CertificateRuleError):
            state.check(4, ())

    def test_mailbox_host_and_descendants(self):
        self.assertTrue(email_matches('Person@EXAMPLE.test', 'person@example.test'))
        self.assertTrue(email_matches('person@example.test', 'example.test'))
        self.assertFalse(email_matches('person@example.test', '.example.test'))
        self.assertTrue(email_matches('person@a.example.test', '.example.test'))
        with self.assertRaisesRegex(CertificateRuleError, 'empty_email_base'):
            email_matches('a@b', '')

    def test_mail_intersection_outer_index_quirk(self):
        state = NameConstraints()
        state.intersect(1, 'x@example.test')
        state.intersect(1, '.example.test')
        self.assertEqual(state.permitted[1], set())
        state = NameConstraints()
        state.intersect(1, 'x@a.example.test')
        state.intersect(1, '.example.test')
        state.check(1, 'x@a.example.test')

    def test_excluded_mail_union_retains_mailbox_due_to_index_bug(self):
        state = NameConstraints()
        state.exclude(1, 'example.test')
        state.exclude(1, 'x@example.test')
        self.assertEqual(state.excluded[1], {'example.test', 'x@example.test'})

    def test_uri_host_original_substring_not_urlparse(self):
        self.assertEqual(uri_host('https://user:password@example.test/path'), 'user')
        self.assertEqual(uri_host('https://example.test:443/path'), 'example.test')
        self.assertEqual(uri_host('mailto:x@example.test'), 'example.test')
        self.assertEqual(uri_host('https://example.test/path:odd'), 'example.test')

    def test_uri_host_exact_and_dot_descendant(self):
        state = NameConstraints()
        state.intersect(6, 'example.test')
        state.check(6, 'https://example.test/a')
        with self.assertRaises(CertificateRuleError):
            state.check(6, 'https://a.example.test')
        state = NameConstraints()
        state.intersect(6, '.example.test')
        state.check(6, 'https://a.example.test')
        with self.assertRaises(CertificateRuleError):
            state.check(6, 'https://example.test')

    def test_ip_supports_arbitrary_masks_not_only_cidr(self):
        base = bytes([10, 0, 3, 0, 255, 0, 255, 0])
        self.assertTrue(ip_matches(bytes([10, 99, 3, 98]), base))
        self.assertFalse(ip_matches(bytes([10, 99, 4, 98]), base))
        self.assertFalse(ip_matches(bytes(16), base))

    def test_ip_picker_is_not_lexical_and_right_operand_signed_mask_differs(self):
        self.assertEqual(_ip_pick(b'\x01\t', b'\x02\x03', maximum=True), b'\x01\t')
        self.assertEqual(_ip_pick(b'\xff', b'\x80', maximum=True), b'\x80')
        self.assertEqual(_ip_pick(b'\xff', b'\x80', maximum=False), b'\xff')

    def test_ip_intersection_and_exclusion(self):
        broad = bytes([10, 0, 0, 0, 255, 0, 0, 0])
        narrow = bytes([10, 1, 0, 0, 255, 255, 0, 0])
        self.assertEqual(_ip_intersection(broad, narrow), {narrow})
        self.assertEqual(_ip_intersection(broad, bytes(32)), set())
        state = NameConstraints()
        state.intersect(7, broad)
        state.intersect(7, narrow)
        state.check(7, bytes([10, 1, 5, 6]))
        state.exclude(7, narrow)
        with self.assertRaisesRegex(CertificateRuleError, 'excluded_7'):
            state.check(7, bytes([10, 1, 5, 6]))

    def test_other_legal_name_types_unconstrained(self):
        state = NameConstraints()
        for tag in (0, 5, 8):
            state.intersect(tag, None)
            state.exclude(tag, None)
            state.check(tag, None)

    def test_unknown_unicode_case_mapping_is_analysis_limit(self):
        state = NameConstraints()
        state.intersect(2, 'é.test')
        with self.assertRaises(CertificateBackendLimit):
            state.check(2, 'É.test')

    def test_raw_state_does_not_render_names(self):
        state = NameConstraints()
        state.intersect(2, 'private.example.test')
        self.assertNotIn('private', repr(state))

@unittest.skipUnless(importlib.util.find_spec('asn1crypto'), 'optional ASN.1 unavailable')
class ConstraintDERTests(unittest.TestCase):

    def extension(self, *names):
        return _node(_tlv(48, _tlv(160, b''.join((_tlv(48, _tlv(130, name.encode())) for name in names)))))

    def test_der_subtrees_sequential(self):
        state = NameConstraints()
        state.add_extension(self.extension('example.test', 'example.test'))
        with self.assertRaises(CertificateRuleError):
            state.check(2, 'x.example.test')

    def test_empty_group_not_same_as_empty_allow_set(self):
        state = NameConstraints()
        state.add_extension(_node(_tlv(48, _tlv(160, b''))))
        self.assertIsNone(state.permitted[2])
        state.check(2, 'anything')

    def test_duplicate_group_last_wins(self):
        first = _tlv(160, _tlv(48, _tlv(130, b'one.test')))
        last = _tlv(160, _tlv(48, _tlv(130, b'two.test')))
        state = NameConstraints()
        state.add_extension(_node(_tlv(48, first + last)))
        self.assertEqual(state.permitted[2], {'two.test'})

    def test_subtree_minimum_and_maximum_not_added_as_new_gates(self):
        subtree = _tlv(48, _tlv(130, b'example.test') + _tlv(135, b'\x05') + _tlv(137, b'\x01'))
        state = NameConstraints()
        state.add_extension(_node(_tlv(48, _tlv(160, subtree))))
        state.check(2, 'example.test')

    def test_unknown_general_name_tag_original_failure(self):
        with self.assertRaisesRegex(CertificateRuleError, 'unknown_tag'):
            NameConstraints().check_der_name(_tlv(131, b'bad'))

    def test_dn_exact_der_prefix_not_sdk_unordered_name(self):

        def rdn(value):
            return _tlv(49, _tlv(48, b'\x06\x03U\x04\x03' + _tlv(19, value)))
        (a, b) = (rdn(b'AAA'), rdn(b'BBB'))
        state = NameConstraints()
        state.intersect(4, dn_value(_tlv(48, a)))
        state.check(4, dn_value(_tlv(48, a + b)))
        with self.assertRaises(CertificateRuleError):
            state.check(4, dn_value(_tlv(48, b + a)))
        with self.assertRaises(CertificateRuleError):
            state.check(4, dn_value(_tlv(48, rdn(b'aaa'))))
