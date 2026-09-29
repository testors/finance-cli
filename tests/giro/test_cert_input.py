import base64
from pathlib import Path
import unittest
from giro.cert_input import CertificateInputError, base64_decode_string, certificate_payload

class YessignBase64Tests(unittest.TestCase):

    def test_standard_data_all_padding_lengths(self):
        for length in range(260):
            data = bytes((i % 256 for i in range(length)))
            self.assertEqual(base64_decode_string(base64.b64encode(data).decode()), data)

    def test_original_empty_and_null(self):
        self.assertEqual(base64_decode_string(None), b'')
        self.assertEqual(base64_decode_string(''), b'')
        with self.assertRaises(CertificateInputError):
            base64_decode_string(' \t\r\n')

    def test_unknown_ascii_entries_are_zero_not_skipped(self):
        self.assertEqual(base64_decode_string('!!!!'), bytes(3))
        self.assertEqual(base64_decode_string('!Q=='), b'\x01')
        self.assertEqual(base64_decode_string('T Q\r\n=\t='), b'M')
        self.assertEqual(base64_decode_string('AA=Z'), b'\x00')

    def test_non_ascii_is_only_checked_when_looked_up(self):
        with self.assertRaises(CertificateInputError):
            base64_decode_string('AA\xa0A')
        self.assertEqual(base64_decode_string('AA=\xa0'), b'\x00')

    def test_java_bounds_not_python_negative_index(self):
        for text in ('A', 'AA', 'AAA', '=====', 'AA😀'):
            with self.subTest(text=text), self.assertRaises(CertificateInputError):
                base64_decode_string(text)

    def test_odd_length_overwrites_final_output_like_original(self):
        self.assertEqual(base64_decode_string('QUJDZ'), base64.b64decode('UJDZ'))

class CertificateFramingTests(unittest.TestCase):
    DATA = b'0\x03\x02\x01\x01'

    def pem(self, name='CERTIFICATE', footer=True, crlf=False):
        text = '-----BEGIN ' + name + '-----\n' + base64.b64encode(self.DATA).decode() + '\n'
        if footer:
            text += '-----END ' + name + '-----\n'
        return (text.replace('\n', '\r\n') if crlf else text).encode()

    def test_binary_payload_and_trailing_data_preserved(self):
        self.assertEqual(certificate_payload(self.DATA + b'trailer'), self.DATA + b'trailer')

    def test_pem_variants_and_preamble(self):
        for name in ('CERTIFICATE', 'X509 CERTIFICATE'):
            for crlf in (False, True):
                self.assertEqual(certificate_payload(b'preamble\n' + self.pem(name, crlf=crlf)), self.DATA)

    def test_line_body_does_not_require_footer(self):
        self.assertEqual(certificate_payload(self.pem(footer=False)), self.DATA)

    def test_unterminated_last_line_is_discarded(self):
        with self.assertRaises(CertificateInputError):
            certificate_payload(self.pem(footer=False).rstrip(b'\n'))

    def test_mismatched_footer_is_still_a_terminator(self):
        data = self.pem().replace(b'-----END CERTIFICATE-----', b'-----END X509 CERTIFICATE-----')
        self.assertEqual(certificate_payload(data), self.DATA)

    def test_inline_fallback_uses_exact_header_lengths(self):
        for name in ('CERTIFICATE', 'X509 CERTIFICATE'):
            encoded = base64.b64encode(self.DATA)
            start = ('-----BEGIN ' + name + '-----').encode()
            end = ('-----END ' + name + '-----').encode()
            self.assertEqual(certificate_payload(start + b' ' + encoded + end), self.DATA)
            self.assertEqual(certificate_payload(start + encoded + end), self.DATA)
ROOT = Path(__file__).resolve().parents[1]
