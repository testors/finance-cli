import gzip
import importlib.util
from pathlib import Path
import unittest
import zlib
from giro.http_body import BOMS, BodyAnalysisLimit, BodySizeLimit, GzipRuntimeError, decode_body, gunzip_app, media_charset
from giro.response import receive_bytes
SUCCESS = b'{"responseCode":"000","paymentList":[]}'

class MediaTypeTests(unittest.TestCase):

    def test_token_quoted_and_single_quoted_charset(self):
        for value in ('utf-8', '"utf-8"', "'utf-8'"):
            self.assertEqual(media_charset('application/json; CHARSET=' + value), 'utf-8')

    def test_invalid_whitespace_and_malformed_parameter_fall_back(self):
        for text in (' application/json;charset=ascii', 'application/json ;charset=ascii', 'application/json;charset =ascii', 'application/json; charset=ascii;broken', 'application/json; charset=ascii\xa0'):
            with self.subTest(text=text):
                self.assertIsNone(media_charset(text))
                self.assertEqual(decode_body(b'\xc3\xa9', [('Content-Type', text)]).text, 'é')

    def test_duplicate_names_compare_spelling_not_codec_aliases(self):
        self.assertEqual(media_charset('text/plain;charset=UTF-8;charset=utf-8'), 'utf-8')
        self.assertIsNone(media_charset('text/plain;charset=UTF8;charset=utf-8'))
        self.assertEqual(media_charset('text/plain;;charset=ascii;'), 'ascii')

    def test_last_header_wins_and_no_charset_defaults_utf8(self):
        result = decode_body(b'\xc3\xa9', [('Content-Type', 'text/plain;charset=ascii'), ('content-type', 'application/json')])
        self.assertEqual(result.text, 'é')

    def test_illegal_charset_falls_back_but_unmodeled_is_not_server_rejection(self):
        self.assertEqual(decode_body(b'abc', [('Content-Type', 'text/plain;charset="!"')]).text, 'abc')
        with self.assertRaises(BodyAnalysisLimit):
            receive_bytes('national.list', 200, [('Content-Type', 'text/plain;charset=x-unmodeled')], SUCCESS)
        result = decode_body(b'abc', [('Content-Type', 'text/plain;charset=x-known-unsupported')], charset_resolver=lambda _: None)
        self.assertEqual(result.charset, 'utf-8')

class BodyCharsetTests(unittest.TestCase):

    def test_bom_overrides_content_type_including_unknown_label(self):
        for (marker, codec) in BOMS:
            text = '{"responseCode":"000"}'
            result = decode_body(marker + text.encode(codec), [('Content-Type', 'text/plain;charset=x-unknown')])
            self.assertEqual(result.text, text)
            self.assertEqual(result.bom_length, len(marker))
            self.assertEqual(result.charset, codec)

    def test_preserve_nonstandard_utf32_constants_and_utf16_precedence(self):
        self.assertEqual(BOMS[3][0].hex(), '0000ffff')
        self.assertEqual(BOMS[4][0].hex(), 'ffff0000')
        little = decode_body(bytes.fromhex('fffe0000') + SUCCESS.decode().encode('utf-32-le'))
        self.assertEqual(little.charset, 'utf-16-le')
        self.assertEqual(little.bom_length, 2)
        self.assertIn('\x00', little.text)
        big = decode_body(bytes.fromhex('0000feff') + b'\x00\x00\x00A')
        self.assertEqual(big.bom_length, 0)

    def test_utf16_without_bom_is_big_endian(self):
        self.assertEqual(decode_body(b'\x00A', [('Content-Type', 'text/plain;charset=utf-16')]).text, 'A')

    def test_content_length_not_checked_by_string_method(self):
        result = receive_bytes('national.list', 200, [('Content-Length', '1')], SUCCESS)
        self.assertTrue(result.app_success)

    def test_malformed_replacement_diagnostic_does_not_flip_success(self):
        result = receive_bytes('national.list', 200, [], b'{responseCode:"000",unused:"\xff"}')
        self.assertTrue(result.app_success)
        self.assertIn('android_malformed_replacement_boundary_unverified', result.issues)

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto unavailable')
    def test_encrypted_body_uses_http_charset_before_seed_plaintext_charset(self):
        from giro.crypto import encrypt_text
        key = bytes(range(16))
        encrypted = encrypt_text('{responseCode:"000",paymentList:[]}', key).hex()
        body = b'\xff\xfe' + encrypted.encode('utf-16-le')
        result = receive_bytes('national.list', 200, [('Mgiro-App-Encrypt', '1')], gzip.compress(body), key=key, request_headers=[('Accept-Encoding', 'gzip')])
        self.assertFalse(result.app_success)
        result = receive_bytes('national.list', 200, [('Mgiro-App-Encrypt', '1'), ('Content-Encoding', 'gzip')], gzip.compress(body), key=key)
        self.assertTrue(result.app_success)

class GzipTests(unittest.TestCase):

    def test_optional_budget_exact_boundary_and_original_unbounded_default(self):
        body = gzip.compress(SUCCESS)
        self.assertEqual(gunzip_app(body, max_output=len(SUCCESS)), SUCCESS)
        with self.assertRaises(BodySizeLimit):
            gunzip_app(body, max_output=len(SUCCESS) - 1)
        self.assertEqual(gunzip_app(body), SUCCESS)
        self.assertEqual(gunzip_app(gzip.compress(b''), max_output=0), b'')

    def test_optional_plain_body_budget_propagates_as_analysis_not_605(self):
        with self.assertRaises(BodySizeLimit):
            receive_bytes('national.list', 200, [], SUCCESS, max_decoded_bytes=1)

    def test_single_member_crc_and_length(self):
        self.assertEqual(gunzip_app(gzip.compress(SUCCESS)), SUCCESS)
        bad = bytearray(gzip.compress(SUCCESS))
        for offset in (-8, -4):
            altered = bad.copy()
            altered[offset] ^= 1
            with self.assertRaises(OSError):
                gunzip_app(bytes(altered))

    def test_header_optional_fields_and_crc(self):
        ordinary = gzip.compress(SUCCESS)
        header = b'\x1f\x8b\x08\x1e' + bytes(6) + b'\x03\x00abcfile\x00comment\x00'
        encoded = header + (zlib.crc32(header) & 65535).to_bytes(2, 'little') + ordinary[10:]
        self.assertEqual(gunzip_app(encoded), SUCCESS)
        with self.assertRaises(OSError):
            gunzip_app(encoded[:len(header)] + b'\x00\x00' + ordinary[10:])

    def test_reserved_flags_and_compression_method_not_additional_gates(self):
        body = bytearray(gzip.compress(SUCCESS))
        (body[2], body[3]) = (0, 224)
        self.assertEqual(gunzip_app(bytes(body)), SUCCESS)

    def test_extra_length_is_signed_in_original(self):
        with self.assertRaises(GzipRuntimeError):
            gunzip_app(b'\x1f\x8b\x08\x04' + bytes(6) + b'\x00\x80')
        result = receive_bytes('national.list', 200, [('Content-Encoding', 'gzip')], b'\x1f\x8b\x08\x04' + bytes(6) + b'\x00\x80')
        self.assertEqual(result.code, '605')

    def test_rejects_concatenated_members_and_trailing_padding_like_app(self):
        valid = gzip.compress(SUCCESS)
        for data in (valid + valid, valid + b'\x00', valid[:-1], b'not-gzip'):
            with self.subTest(length=len(data)):
                result = receive_bytes('national.list', 200, [('Content-Encoding', 'gzip')], data)
                self.assertEqual(result.code, '603')
                self.assertEqual(result.origin, 'body_io')

    def test_transparency_requires_no_accept_encoding_or_range(self):
        data = gzip.compress(SUCCESS)
        for request in ([('Accept-Encoding', 'gzip')], [('Range', 'bytes=0-')]):
            self.assertFalse(decode_body(data, [('Content-Encoding', 'gzip')], request_headers=request).gzip_decoded)
        result = decode_body(data, [('content-encoding', 'GZIP'), ('Content-Length', '99')])
        self.assertEqual(result.text, SUCCESS.decode())
        self.assertEqual(result.headers, ())

    def test_unsuccessful_http_does_not_consume_bad_body(self):
        result = receive_bytes('national.list', 500, [('Content-Encoding', 'gzip')], b'invalid')
        self.assertEqual(result.code, '500')

    def test_has_body_for_head_204_and_declared_length(self):
        data = gzip.compress(SUCCESS)
        headers = [('Content-Encoding', 'gzip')]
        self.assertFalse(decode_body(data, headers, method='HEAD').gzip_decoded)
        self.assertFalse(decode_body(data, headers, status=204).gzip_decoded)
        for declaration in (('Content-Length', '0'), ('Content-Length', '٠'), ('Transfer-Encoding', 'chunked')):
            self.assertTrue(decode_body(data, headers + [declaration], status=204).gzip_decoded)
ROOT = Path(__file__).resolve().parents[1]
