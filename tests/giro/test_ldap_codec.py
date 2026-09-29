from io import BytesIO
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from giro.cms import _tlv
from giro.cert_factory import _node, CertificateBackendLimit
from giro.ldap_codec import LdapLocation, LdapIOError, LdapRuntimeError, parse_uri, bind_request, search_request, unbind_request, message, read_frame, replay_responses, _number

def result(tag=1, code=0, identifier=99):
    return message(identifier, tag, _number(code, 10) + _tlv(4, b'') + _tlv(4, b''))

def entry(attributes, identifier=888):
    items = b''.join((_tlv(48, _tlv(4, name) + _tlv(49, b''.join((_tlv(4, v) for v in values)))) for (name, values) in attributes))
    return message(identifier, 4, _tlv(4, b'cn=synthetic') + _tlv(48, items))

class URITests(unittest.TestCase):

    def test_normal_port_and_literal_percent_encoding(self):
        location = parse_uri('ldap://example.invalid:123/cn=a%20b?caCertificate;binary?sub?ignored')
        self.assertEqual((location.scheme, location.host, location.port, location.dn, location.attribute), ('ldap', 'example.invalid', '123', 'cn=a%20b', 'caCertificate;binary'))

    def test_no_port_default_and_scheme_not_validated(self):
        for scheme in ('ldap', 'ldaps', 'https', 'custom'):
            location = parse_uri(scheme + '://example.invalid/cn=x')
            self.assertEqual((location.port, location.attribute), ('389', None))

    def test_delimiters_are_sets_not_separator_strings(self):
        self.assertEqual(parse_uri('ldap:::example.invalid/cn=x').host, 'example.invalid')
        self.assertIsNone(parse_uri('ldap://example.invalid/'))
        self.assertIsNone(parse_uri('ldap://example.invalid:389/'))
        self.assertIsNone(parse_uri(None))
        self.assertIsNone(parse_uri(''))
        self.assertIsNone(parse_uri('not-a-uri'))

    def test_empty_question_tokens_shift_fields(self):
        location = parse_uri('ldap://h/??attr??sub')
        self.assertEqual((location.dn, location.attribute), ('attr', 'sub'))
        location = parse_uri('ldap://h/???')
        self.assertEqual((location.dn, location.attribute), (None, None))

    def test_port_is_not_validated_or_trimmed_by_parser(self):
        self.assertEqual(parse_uri('ldap://h:no-number/dn').port, 'no-number')
        self.assertEqual(parse_uri('ldap://h:+389/dn').port, '+389')

    def test_short_remainder_throws_not_caught_no_such_element(self):
        with self.assertRaises(LdapRuntimeError):
            parse_uri('x:a')

    def test_colon_inside_dn_not_normalized_to_correct_host(self):
        self.assertIsNone(parse_uri('ldap://h/cn=a:b'))

    def test_locations_hide_identities(self):
        self.assertNotIn('PRIVATE', repr(parse_uri('ldap://PRIVATE/dn')))

class FrameTests(unittest.TestCase):

    def test_bind_and_unbind_literal_bytes(self):
        self.assertEqual(bind_request(1).hex(), '300c020101600702010304008000')
        self.assertEqual(unbind_request(3).hex(), '30050201034200')

    def test_search_literal_baseobject_no_aliases_limits_or_typesonly(self):
        location = LdapLocation('ldap', 'h', '389', 'cn=x', None)
        fields = bytes.fromhex('0404636e3d780a01000a0100020100020100010100870b6f626a656374636c6173733000')
        self.assertEqual(search_request(2, location), _tlv(48, b'\x02\x01\x02' + _tlv(99, fields)))
        self.assertEqual(search_request(2, location), search_request(2, LdapLocation('other', 'different', '0', 'cn=x', '')))

    def test_message_zero_rejected_but_negative_and_wrap_allowed(self):
        with self.assertRaises(LdapIOError):
            bind_request(0)
        self.assertIn(b'\x02\x01\xff', bind_request(-1))
        self.assertEqual(unbind_request(2147483648), unbind_request(-2147483648))

    def test_null_dn_runtime_before_message_creation(self):
        with self.assertRaises(LdapRuntimeError):
            search_request(0, LdapLocation('ldap', 'h', '389', None, 'a'))

    def test_frame_accepts_noncanonical_length_and_does_not_check_tag(self):
        raw = b'w\x84\x00\x00\x00\x01X'
        stream = BytesIO(raw + b'remaining')
        self.assertEqual(read_frame(stream), raw)
        self.assertEqual(stream.read(), b'remaining')

    def test_frame_original_length_failures(self):
        for (raw, failure) in ((b'', 'frame_eof'), (b'0\x80', 'indefinite'), (b'0\x85', 'over_four'), (b'0\x84\x80\x00\x00\x00', 'negative'), (b'0\x03ab', 'eof')):
            with self.subTest(raw=raw), self.assertRaisesRegex(LdapIOError, failure):
                read_frame(BytesIO(raw))

    def test_frame_readfully_handles_partial_reads(self):

        class Partial(BytesIO):

            def read(self, size=-1):
                return super().read(min(size, 1))
        self.assertEqual(read_frame(Partial(b'0\x03abc')), b'0\x03abc')

@unittest.skipUnless(importlib.util.find_spec('asn1crypto'), 'optional ASN.1 unavailable')
class ReplayTests(unittest.TestCase):
    location = LdapLocation('ldap', 'synthetic.invalid', '389', 'cn=synthetic', 'cacertificate')

    def replay(self, data, **kwargs):
        return replay_responses(data, self.location, locale_language='ko', message_id=kwargs.get('message_id', 1))

    def test_offline_success_ignores_response_ids_and_completion_code(self):
        data = result() + entry([(b'CACERTIFICATE;binary', [b'z', b'a', b'z'])]) + result(5, 49)
        with patch('socket.socket', side_effect=AssertionError('offline')):
            replay = self.replay(data)
        self.assertEqual((replay.code, replay.values), (1, (b'z', b'a', b'z')))
        self.assertEqual(replay.requests, (bind_request(1), search_request(2, self.location), unbind_request(3)))

    def test_substring_attribute_matching_and_empty_null_value_filter(self):
        data = result() + entry([(b'prefixcacertificateSUFFIX', [b'', b'NuLl', b' null', b'\xff\xfe', b'certificate']), (b'other', [b'ignored'])]) + result(5)
        self.assertEqual(self.replay(data).values, (b' null', b'\xff\xfe', b'certificate'))

    def test_no_matching_attribute_is_successful_empty_vector_not_missing_attribute_error(self):
        self.assertEqual(self.replay(result() + entry([(b'other', [b'x'])]) + result(5)).code, 1)
        self.assertEqual(self.replay(result() + entry([(b'other', [b'x'])]) + result(5)).values, ())
        failed = self.replay(result() + entry([]))
        self.assertEqual((failed.code, failed.io_error), (0, 'search_no_attributes'))

    def test_completion_eof_and_length_error_swallowed(self):
        for tail in (b'', b'0\x80'):
            replay = self.replay(result() + entry([(b'cacertificate', [b'X'])]) + tail)
            self.assertEqual(replay.code, 1)
            self.assertTrue(replay.completion_io_ignored)

    def test_completion_protocol_tag_not_checked_and_extra_frames_unused(self):
        replay = self.replay(result() + entry([(b'cacertificate', [b'X'])]) + result(12, 100) + b'malformed ignored')
        self.assertEqual(replay.values, (b'X',))

    def test_completion_runtime_exception_not_swallowed_as_io(self):
        with self.assertRaisesRegex(LdapRuntimeError, 'sequence_index'):
            self.replay(result() + entry([(b'cacertificate', [b'X'])]) + message(5, 5, b''))

    def test_referral_is_error_not_followed_or_looped(self):
        replay = self.replay(result() + message(7, 19, _tlv(4, b'ldap://other.invalid/dn')) + result(5))
        self.assertEqual((replay.code, replay.io_error), (0, 'search_referral'))
        self.assertEqual(len(replay.requests), 3)

    def test_search_done_before_entry_fails_even_result_zero(self):
        replay = self.replay(result() + result(5, 0))
        self.assertEqual((replay.code, replay.io_error), (0, 'search_done_without_entry'))

    def test_bind_result_big_integer_intvalue_wrap(self):
        data = result(code=2 ** 32) + entry([(b'cacertificate', [b'x'])]) + result(5)
        self.assertEqual(self.replay(data).code, 1)
        replay = self.replay(result(code=49))
        self.assertEqual((replay.code, replay.failure_stage), (0, 'process_bind'))
        self.assertEqual(replay.requests[-1], unbind_request(2))

    def test_search_id_zero_increment_still_occurs_before_failed_constructor(self):
        replay = self.replay(result(), message_id=-1)
        self.assertEqual((replay.code, replay.failure_stage), (0, 'generate_search'))
        self.assertEqual(replay.requests[-1], unbind_request(1))

    def test_backend_gap_not_reported_as_wrapper_failure(self):
        with self.assertRaises(CertificateBackendLimit):
            self.replay(b'0\x01X')

    def test_no_values_requests_or_location_in_repr(self):
        replay = self.replay(result() + entry([(b'cacertificate', [b'PRIVATE'])]) + result(5))
        self.assertNotIn('PRIVATE', repr(replay))

    def test_cli_no_socket_no_pin_and_no_raw_values_or_uri(self):
        from giro.__main__ import parser, run
        data = result() + entry([(b'cacertificate', [b'PRIVATE'])]) + result(5)
        with patch.object(Path, 'read_bytes', return_value=data), patch('socket.socket', side_effect=AssertionError('offline')), patch('getpass.getpass', side_effect=AssertionError('no PIN')):
            (output, status) = run(parser().parse_args(['auth', 'inspect-ldap', '--input', 'response.bin', '--uri', 'ldap://PRIVATE/dn?cacertificate', '--message-id', '1', '--locale', 'ko']))
        self.assertEqual((status, output['ldap_wrapper_code'], output['value_count']), (0, 1, 1))
        self.assertNotIn('PRIVATE', json.dumps(output))
        self.assertNotIn('app_success', output)
        self.assertFalse(output['certificate_validation_performed'])

    def test_cli_report_keeps_original_io_runtime_and_local_gap_separate(self):
        from giro.ldap_codec import inspect_responses

        def report(data, uri='ldap://h/dn'):
            return inspect_responses(data, uri, message_id=1, locale_language='ko')
        self.assertEqual(report(b'')['ldap_wrapper_code'], 0)
        self.assertEqual(report(b'0\x00')['analysis_status'], 'original_runtime_exception')
        self.assertEqual(report(b'0\x01X')['analysis_status'], 'unmodeled')
        self.assertEqual(report(b'', 'invalid')['analysis_status'], 'uri_parse_returned_null')
