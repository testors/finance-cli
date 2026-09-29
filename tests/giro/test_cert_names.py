import importlib.util
from pathlib import Path
import unittest
from giro.cert_names import SDKName, sdk_lower
from giro.cert_factory import CertificateBackendLimit
from giro.cms import _tlv
(CN, O) = ('2.5.4.3', '2.5.4.10')

class NameComparisonTests(unittest.TestCase):

    def name(self, text, tag=19, oid=CN):
        return SDKName(((oid, text, tag),))

    def test_printable_case_trim_spaces_but_utf8_exact(self):
        self.assertTrue(self.name(' \tA  B\r').equals(self.name('a b'), locale_language='ko'))
        self.assertFalse(self.name('A', 12).equals(self.name('a', 12), locale_language='ko'))
        self.assertFalse(self.name(' A ', 12).equals(self.name('A', 12), locale_language='ko'))

    def test_type_difference_is_significant(self):
        self.assertFalse(self.name('same', 12).equals(self.name('same', 19), locale_language='ko'))

    def test_order_independent_and_duplicate_entries_consumed_once(self):
        a = SDKName(((CN, 'A', 19), (O, 'B', 19)))
        b = SDKName(tuple(reversed(a.entries)))
        self.assertTrue(a.equals(b, locale_language='ko'))
        self.assertFalse(SDKName(((CN, 'A', 19), (CN, 'A', 19))).equals(SDKName(((CN, 'A', 19), (CN, 'B', 19))), locale_language='ko'))

    def test_original_other_type_uses_outer_index_not_matching_index(self):
        a = SDKName(((CN, 'A', 19), (O, 'B', 12)))
        b = SDKName(tuple(reversed(a.entries)))
        self.assertFalse(a.equals(b, locale_language='ko'))
        c = SDKName(((O, 'B', 19), (CN, 'A', 12)))
        self.assertTrue(a.equals(c, locale_language='ko'))

    def test_render_reverse_aliases_and_escape_set(self):
        name = SDKName((('2.5.4.8', 'Seoul', 19), ('2.5.4.9', ' a, b+\\"<>; ', 19), (CN, ' #X= ', 12)))
        self.assertEqual(name.render(locale_language='ko'), 'cn= #X= ,st=a\\, b\\+\\\\\\"\\<\\>\\;,s=Seoul')

    def test_java_trim_not_unicode_strip_and_only_ascii_spaces_collapse(self):
        self.assertEqual(self.name('\tA\t B\n').render(locale_language='ko'), 'cn=A\t B')
        self.assertEqual(self.name('\xa0A\xa0').render(locale_language='ko'), 'cn=\xa0A\xa0')

    def test_locale_must_not_be_silently_assumed(self):
        self.assertEqual(sdk_lower('KISA', 'tr'), 'kısa')
        with self.assertRaises(CertificateBackendLimit):
            sdk_lower('KISA', None)
        with self.assertRaises(CertificateBackendLimit):
            sdk_lower('Ä', 'ko')

    def test_repr_does_not_include_identity(self):
        self.assertNotIn('sensitive', repr(self.name('sensitive')))

@unittest.skipUnless(importlib.util.find_spec('asn1crypto'), 'optional asn1crypto unavailable')
class NameParsingTests(unittest.TestCase):

    def ava(self, value, tag=19, oid=CN):
        from asn1crypto.core import ObjectIdentifier
        return _tlv(48, ObjectIdentifier(oid).dump() + _tlv(tag, value))

    def test_only_first_ava_of_each_rdn_is_read(self):
        raw = _tlv(48, _tlv(49, self.ava(b'first') + self.ava(b'ignored', oid=O)))
        name = SDKName.from_der(raw)
        self.assertEqual(name.entries, ((CN, 'first', 19),))

    def test_t61_uses_java_default_utf8_not_standard_t61_decoder(self):
        raw = _tlv(48, _tlv(49, self.ava('한'.encode(), 20)))
        self.assertEqual(SDKName.from_der(raw).entries[0][1], '한')

    def test_universal_string_original_hex_and_bmp_odd_tail(self):
        universal = _tlv(48, _tlv(49, self.ava(b'\xff', 28)))
        self.assertEqual(SDKName.from_der(universal).entries[0][1], '0f')
        bmp = _tlv(48, _tlv(49, self.ava(b'\x00A\xff', 30)))
        self.assertEqual(SDKName.from_der(bmp).entries[0][1], 'A')
