import base64
from pathlib import Path
import shutil
import struct
import subprocess
import unittest
from unittest.mock import patch
from giro.android_json import parse_object, string_field, java_text, double_text
from giro.android_cookie import parse_cookies
from giro.codeguard_effects import Effect, JavaFault, LinkFault
from giro.codeguard_flow import ChallengeState
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_http_values import MemoryReader, decode_default_utf8, decode_value, decode_values_steps
from giro.codeguard_updater import challenge_steps, token_steps
from giro.codeguard_service import generate_token_http_values_steps
from cg_exchange_fixture import Transcript, drive, fault
from test_codeguard_service import service

class JSONTests(unittest.TestCase):

    def field(self, text, name='x', default='DEFAULT'):
        return string_field(parse_object(text), name, default)

    def test_missing_null_and_literal_null_are_distinct(self):
        for text in ('{}', '{x:null}', '{x:NULL}'):
            self.assertEqual(self.field(text), 'DEFAULT')
            self.assertIsNone(self.field(text, default=None))
        self.assertEqual(self.field('{x:"null"}'), 'null')

    def test_comments_quotes_bom_and_nonstandard_separators(self):
        self.assertEqual(self.field("\ufeff/*one*/{#two\n'x'=>'v'; //three\n y:>TRUE}"), 'v')
        self.assertEqual(self.field('{x:true}'), 'true')
        self.assertEqual(self.field('{x:falſe}'), 'false')

    def test_constructor_ignores_trailing_input_even_invalid_comment(self):
        self.assertEqual(self.field('{x:"ok"} bad /*'), 'ok')

    def test_duplicate_keeps_last_value_and_first_insertion_order(self):
        self.assertEqual(self.field('{x:{b:1,a:2,b:3}}'), '{"b":3,"a":2}')
        self.assertEqual(self.field('{x:1,x:null}'), 'DEFAULT')

    def test_earlier_invalid_duplicate_still_fails(self):
        with self.assertRaises(JavaFault) as caught:
            self.field('{x:NaN,x:"later"}')
        self.assertEqual(caught.exception.message, 'Forbidden numeric value: NaN')

    def test_objects_arrays_stringified_not_python_repr(self):
        self.assertEqual(self.field('{x:[true,null,3,"a/b",{z:false}]}'), '[true,null,3,"a\\/b",{"z":false}]')

    def test_array_holes_and_trailing_separator(self):
        for (raw, expected) in (('[]', '[]'), ('[;]', '[null,null]'), ('[1,]', '[1,null]'), ('[,1,,]', '[null,1,null,null]')):
            self.assertEqual(self.field('{x:' + raw + '}'), expected)

    def test_trailing_object_separator_is_not_accepted(self):
        for text in ('{x:1,}', '{x:1;}'):
            with self.assertRaises(JavaFault) as caught:
                parse_object(text)
            self.assertEqual(caught.exception.kind, 'JSONException')

    def test_unquoted_names_are_values_and_must_be_strings(self):
        self.assertEqual(self.field('{x:plain}'), 'plain')
        for name in ('true', 'null', '123', '0x10', '[]', '{}'):
            with self.assertRaises(JavaFault):
                parse_object('{' + name + ':1}')

    def test_unknown_escape_control_and_utf16_surrogates(self):
        self.assertEqual(self.field('{x:"a\\qb\\u+001\\uD83D\\uDE00"}'), 'aqb\x01😀')
        self.assertEqual(self.field('{x:"line\nline"}'), 'line\nline')
        self.assertEqual(self.field('{x:"\\uD800"}'), '\ud800')

    def test_unescaped_slash_control_and_unicode_string_serialization(self):
        self.assertEqual(self.field('{x:["한/😀\x01\t"]}'), '["한\\/😀\\u0001\\t"]')

    def test_integer_octal_hex_signed_and_long_limits(self):
        for (raw, expected) in (('010', '8'), ('0x10', '16'), ('-010', '-10'), ('+010', '10'), ('-0', '0'), ('0x-1', '-1'), ('2147483648', '2147483648'), ('9223372036854775807', '9223372036854775807')):
            self.assertEqual(self.field('{x:' + raw + '}'), expected)

    def test_double_storage_and_direct_vs_nested_rendering(self):
        for (raw, value) in (('08', '8.0'), ('1e3', '1000.0'), ('1.25', '1.25'), ('0x1.8p1', '3.0'), ('-0.0', '-0.0'), ('2f', '2.0')):
            self.assertEqual(self.field('{x:' + raw + '}'), value)
        self.assertEqual(self.field('{x:[1.0,-0.0,1e3,1.25]}'), '[1,-0,1000,1.25]')

    def test_nonfinite_object_field_fails_even_if_unused(self):
        for raw in ('NaN', 'Infinity', '-Infinity', '1e9999'):
            with self.assertRaises(JavaFault):
                self.field('{unused:' + raw + ',x:"ok"}')

    def test_array_nonfinite_is_allowed_until_string_conversion(self):
        self.assertEqual(self.field('{unused:[NaN],x:"ok"}'), 'ok')
        with self.assertRaises(JavaFault) as caught:
            self.field('{x:[NaN]}')
        self.assertEqual(caught.exception.message, 'Value null at x of type org.json.JSONArray cannot be converted to String')
        with self.assertRaises(JavaFault):
            self.field('{x:{z:[Infinity]}}')

    def test_float_render_boundary_does_not_block_unknown_fields(self):
        self.assertEqual(self.field('{unused:1.2345678901234567,x:"ok"}'), 'ok')
        with self.assertRaises(AnalysisLimit):
            self.field('{x:1.2345678901234567}')

    def test_numeric_looking_strings_and_double_trim(self):
        for raw in ('nan', 'infinity', '1_0', '1e', 'not-a-number'):
            self.assertEqual(self.field('{x:' + raw + '}'), raw)
        self.assertEqual(self.field('{x:1\x00}'), '1.0')

    def test_top_level_type_errors(self):
        for (raw, name, text) in (('[]', 'org.json.JSONArray', '[]'), ('null', 'org.json.JSONObject$1', 'null'), ('true', 'java.lang.Boolean', 'true'), ('"a"', 'java.lang.String', 'a')):
            with self.assertRaises(JavaFault) as caught:
                parse_object(raw)
            self.assertEqual(caught.exception.message, f'Value {text} of type {name} cannot be converted to JSONObject')

    def test_error_positions_are_utf16_and_bom_is_removed(self):
        source = '\ufeff{"😀" 1}'
        with self.assertRaises(JavaFault) as caught:
            parse_object(source)
        self.assertEqual(caught.exception.message, 'Expected \':\' after 😀 at character 7 of {"😀" 1}')

    def test_fault_repr_str_and_value_repr_do_not_leak(self):
        secret = 'SYNTHETIC-PRIVATE-TEXT'
        with self.assertRaises(JavaFault) as caught:
            parse_object('{"' + secret + '":}')
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, repr(caught.exception))
        self.assertIn(secret, caught.exception.message)
        self.assertNotIn(secret, repr(parse_object('{x:"' + secret + '"}')))

    def test_all_primary_syntax_errors_are_typed_not_python_errors(self):
        for text in ('', '/*', '{', '[', '{x:"', '{x:"\\', '{x:"\\u12"}', '{x:"\\uZZZZ"}', '{x:1 z:2}'):
            with self.assertRaises(JavaFault) as caught:
                parse_object(text)
            self.assertEqual(caught.exception.kind, 'JSONException')

    def test_unmodeled_resource_or_unicode_digits_not_java_failure(self):
        with self.assertRaises(AnalysisLimit):
            self.field('{x:１２３}')
        with self.assertRaises(AnalysisLimit):
            parse_object('{x:' + '[' * 2000 + ']' * 2000 + '}')

    def test_short_exact_double_text_agrees_with_independent_jdk(self):
        java = shutil.which('java')
        if java is None:
            self.skipTest('optional reference JDK unavailable on PATH')
        values = [-0.0, 0.0, 0.0625, 0.125, 1.25, -1.5, 4.75, 1000.0, 9999999.5]
        result = subprocess.run([java, str(Path(__file__).parent / 'java/HttpValueVectors.java'), 'double', *(str(v) for v in values)], capture_output=True, text=True, timeout=30, check=True)
        self.assertEqual(result.stdout.splitlines(), [double_text(v) for v in values])

    def test_decimal_hex_binary64_parse_bits_match_independent_jdk(self):
        java = shutil.which('java')
        if java is None:
            self.skipTest('optional reference JDK unavailable on PATH')
        numbers = ['1.2345678901234567', '0.1', '1e7', '1e-324', '-1e-4000', '4.9e-324', '2.2250738585072012e-308', '1.7976931348623157e308', '1e9999', '-1e9999', '9223372036854775808.0', '0x1.0000000000001p0', '0x1.fffffffffffffp1023', '0x1p-1074', '0x0p9999999999', '1.25f', '-0.0']
        result = subprocess.run([java, str(Path(__file__).parent / 'java/HttpValueVectors.java'), 'bits', *numbers], capture_output=True, text=True, timeout=30, check=True)
        values = [parse_object('{x:[' + n + ']}').values['x'].values[0] for n in numbers]
        expected = [str(struct.unpack('>Q', struct.pack('>d', v))[0]) for v in values]
        self.assertEqual(result.stdout.splitlines(), expected)

class CookieTests(unittest.TestCase):

    def text(self, header, locale='ko'):
        return tuple((c.wire_text() for c in parse_cookies(header, locale_language=locale)))

    def test_version_zero_omits_attributes(self):
        self.assertEqual(self.text('SID=synthetic; Path=/a; Domain=EXAMPLE.INVALID; Secure; HttpOnly'), ('SID=synthetic',))

    def test_version_one_attribute_order_and_domain_lowercase(self):
        self.assertEqual(self.text('SID=synthetic; Domain=EXAMPLE.INVALID; Port="443,8443"; Path=/a; Version=1'), ('SID="synthetic";$Path="/a";$Domain="example.invalid";$Port="443,8443"',))

    def test_version_guess_overrides_parsed_version_and_searches_whole_header(self):
        self.assertEqual(self.text('x=v; Version=0'), ('x="v"',))
        self.assertEqual(self.text('x=max-age'), ('x="max-age"',))
        self.assertEqual(self.text('x=expires=; Version=1'), ('x=expires=',))

    def test_version_guess_expires_precedes_max_age(self):
        self.assertEqual(self.text('x=v; Max-Age=0; Expires=ignored'), ('x=v',))

    def test_prefixes_and_multi_cookie_split(self):
        self.assertEqual(self.text('Set-Cookie: a=1'), ('a=1',))
        self.assertEqual(self.text('Set-Cookie2: a=1,b=2'), ('a="1"', 'b="2"'))
        self.assertEqual(self.text('a=1,b=2'), ('a=1,b=2',))

    def test_double_quotes_protect_comma_but_single_quotes_do_not(self):
        self.assertEqual(self.text('a="1,2",b=3;Version=1'), ('a="1,2"', 'b="3"'))
        with self.assertRaises(JavaFault):
            self.text("a='1,2';Version=1")

    def test_quotes_empty_quotes_and_semicolon_tokenization(self):
        self.assertEqual(self.text("x='ab'"), ('x=ab',))
        self.assertEqual(self.text('x=""'), ('x=""',))
        self.assertEqual(self.text('x="";Version=1'), ('x=""""',))
        self.assertEqual(self.text('x="a;b"'), ('x="a',))

    def test_duplicate_first_nonnull_attributes_and_port_empty(self):
        self.assertEqual(self.text('x=v;Version=1;Path;Path=/a;Path=/b;Domain=ONE;Domain=TWO;Port;Port=443'), ('x="v";$Path="/a";$Domain="one";$Port=""',))

    def test_invalid_duplicate_maxage_fails_even_when_previous_was_set(self):
        for raw in ('x=v;Max-Age=no', 'x=v;Max-Age=0;Max-Age=no', 'x=v;Max-Age=9223372036854775808'):
            with self.assertRaises(JavaFault) as caught:
                self.text(raw)
            self.assertEqual(caught.exception.message, 'Illegal cookie max-age attribute')

    def test_expired_maxage_cookie_not_filtered(self):
        for age in ('0', '-2', '+10'):
            self.assertEqual(self.text('x=v;Max-Age=' + age), ('x="v"',))

    def test_bad_version_number_ignored_but_two_is_error(self):
        for ver in ('invalid', '2147483648', ''):
            self.assertEqual(self.text('x=v;Version=' + ver), ('x="v"',))
        for ver in ('2', '-1'):
            with self.assertRaises(JavaFault):
                self.text('x=v;Version=' + ver)

    def test_expires_canonical_empty_and_duplicate_assignment(self):
        for date in ('Mon, 28 Sep 2026 12:00:00 GMT', ''):
            self.assertEqual(self.text('x=v;Expires=' + date), ('x=v',))
        self.assertEqual(self.text('x=v;Expires=;Expires=not-modeled'), ('x=v',))
        self.assertEqual(self.text('x=v;Max-Age=-2;Expires'), ('x="v"',))

    def test_minus_one_maxage_still_requires_expires_parse(self):
        with self.assertRaises(AnalysisLimit):
            self.text('x=v;Max-Age=-1;Expires=not-modeled')
        with self.assertRaises(AnalysisLimit):
            self.text('x=v;Expires')

    def test_illegal_name_reserved_ascii_and_empty_header(self):
        for raw in ('', ';;;', 'a', 'Path=x', '$x=v', 'é=v', 'x y=v', 'x\x01y=v'):
            expected = AnalysisLimit if 'é' in raw else JavaFault
            with self.assertRaises(expected):
                self.text(raw)
        self.assertEqual(self.text(';; x = v ;;'), ('x=v',))

    def test_java_trim_does_not_use_python_unicode_whitespace(self):
        self.assertEqual(self.text('\x00 x=v\x00'), ('x=v',))
        with self.assertRaises(AnalysisLimit):
            self.text('x=\xa0v')

    def test_entire_header_is_atomic_not_cookie_by_cookie(self):
        with self.assertRaises(JavaFault):
            self.text('a=1,broken;Version=1')

    def test_turkish_locale_header_guess_and_domain_assignment(self):
        self.assertEqual(self.text('x=v; VERSION=1; DOMAIN=I.INVALID', 'tr'), ('x=v',))
        self.assertEqual(self.text('x=v; version=1; domain=I.INVALID', 'tr'), ('x="v";$Domain="ı.ınvalıd"',))

    def test_unknown_attribute_and_cookie_repr_do_not_expose_value(self):
        (cookie,) = parse_cookies('x=SYNTHETIC-SECRET; Unknown=ignored', locale_language='ko')
        self.assertNotIn('SYNTHETIC-SECRET', repr(cookie))
        self.assertTrue(cookie.projection_only)

    def test_common_cookie_vectors_agree_with_independent_jdk(self):
        java = shutil.which('java')
        if java is None:
            self.skipTest('optional reference JDK unavailable on PATH')
        headers = ['x=v', 'x=v;Version=1;Path=/a;Domain=EXAMPLE.INVALID;Port=443', 'x=v;Version=0', 'x="";Version=1', 'a=1,b=2;Version=1', 'x=v;Max-Age=0']
        encoded = [base64.b64encode(h.encode()).decode() for h in headers]
        result = subprocess.run([java, str(Path(__file__).parent / 'java/HttpValueVectors.java'), 'cookie', *encoded], capture_output=True, text=True, timeout=30, check=True)
        expected = [base64.b64encode('\n'.join(self.text(h)).encode()).decode() for h in headers]
        self.assertEqual(result.stdout.splitlines(), expected)

class ValuePipelineTests(unittest.TestCase):

    def transcript(self, documents, **kwargs):
        """Actual parser/reader; HTTP/native/file observations stay SYNTHETIC."""
        t = Transcript(documents, **kwargs)
        t.overrides['input_stream_reader'] = lambda e: MemoryReader.from_bytes(t.responses[e.args[0]])
        t.overrides['read_line'] = lambda e: e.args[0].read_line()
        for name in ('json_object', 'json_string_field', 'http_cookie_parse', 'http_cookie_string', 'java_decode_default_charset'):
            t.overrides[name] = AssertionError('opaque value fixture must not be used')
        return t

    def run_values(self, t, generator):
        return t.run(decode_values_steps(generator, locale_language='ko'))

    def test_readline_cr_lf_crlf_empty_last_and_unicode_separators(self):
        for (data, lines) in ((b'', []), (b'\r\n', ['']), (b'a\r\nb\rc\n', ['a', 'b', 'c']), ('한\u2028글\x0b\x0c'.encode(), ['한\u2028글\x0b\x0c'])):
            reader = MemoryReader.from_bytes(data)
            self.assertEqual(list(iter(reader.read_line, None)), lines)

    def test_utf8_default_preserves_bom_and_bad_bytes_are_unknown(self):
        self.assertEqual(decode_default_utf8(b'\xef\xbb\xbf{}'), '\ufeff{}')
        with self.assertRaises(AnalysisLimit):
            decode_default_utf8(b'\xff')

    def test_raw_cmd200_json_and_cookies_reach_updater_state(self):
        t = self.transcript([(200, b"\xef\xbb\xbf{CODE_CHALLENGE:123,CODE_RCL:'bmV3',CODE_RESPONSE2_VER:'isMix'} ignored")])
        t.overrides['set_cookie_header_values'] = ['a=synthetic;Path=/a', 'b=synthetic;Version=1;Path=/b']
        self.assertEqual(self.run_values(t, challenge_steps(t.runtime, t.agent, t.main, 'APP11')), '123')
        self.assertEqual(t.runtime.data.cookie, 'a=synthetic; b="synthetic";$Path="/b"')
        self.assertEqual(t.runtime.data.rcl, 'new')
        self.assertTrue(t.runtime.data.is_mix)

    def test_bad_later_cookie_discards_whole_header_but_not_prior_headers(self):
        t = self.transcript([(200, b'{CODE_CHALLENGE:ok}')])
        t.overrides['set_cookie_header_values'] = ['prior=1', 'a=1,broken;Version=1', 'after=2']
        self.assertEqual(self.run_values(t, challenge_steps(t.runtime, t.agent, t.main, 'APP11')), 'ok')
        self.assertEqual(t.runtime.data.cookie, 'prior=1; after=2')

    def test_json_syntax_exception_enters_original_003_catch_after_cookies(self):
        t = self.transcript([(200, b'{x:}')])
        t.overrides['set_cookie_header_values'] = ['a=synthetic']
        result = self.run_values(t, challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        self.assertTrue(result.startswith('E101_NET_ERROR_003'))
        self.assertIn('org.json.JSONException: Expected literal value', result)
        self.assertEqual(t.runtime.data.cookie, 'a=synthetic')
        self.assertIn('close_reader', t.kinds())

    def test_version_field_stringification_error_precedes_rcl_write(self):
        t = self.transcript([(200, b'{CODE_RCL:"bmV3",CODE_RESPONSE2_VER:[NaN]}')])
        t.runtime.data.rcl = 'old'
        result = self.run_values(t, challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        self.assertTrue(result.startswith('E101_NET_ERROR_003'))
        self.assertEqual(t.runtime.data.rcl, 'old')

    def test_cmd300_object_token_is_serialized_and_set_cookie_not_consumed(self):
        t = self.transcript([(300, b'{CODE_TOKEN:{z:1,active:true}}')])
        result = self.run_values(t, token_steps(t.runtime, t.agent, t.main, 'r', 'n'))
        self.assertEqual(result, '{"z":1,"active":true}')
        self.assertNotIn('set_cookie_header_values', t.kinds())

    def test_full_generate_token_routes_raw_101_200_300_values(self):
        t = self.transcript([(101, b"{CERT:'c3ludGhldGlj',ENGINE_VERSION:2,ENGINE_MD:''}"), (200, b"{CODE_CHALLENGE:'challenge::rule'}"), (300, b'{CODE_TOKEN:synthetic}')], cert='')
        t.overrides['set_cookie_header_values'] = ['sid=value;Max-Age=10;Path=/']
        self.assertEqual(t.run(generate_token_http_values_steps(t.main, t.runtime, t.agent, locale_language='ko', server_url='https://synthetic.invalid/', timeout=500, root_check=True, rooting_info=False, encrypted_token=False)), 'synthetic')
        self.assertEqual([r[0] for r in t.requests], [101, 200, 300])
        self.assertEqual(t.agent.engine_version, '2')
        sent = [e.args[2] for e in t.calls('setRequestProperty') if e.args[2][0] == 'Cookie']
        self.assertEqual(sent, [('Cookie', 'sid="value";$Path="/"')])

    def test_nested_challenge_refresh_also_uses_real_values(self):
        t = self.transcript([(200, b'{CODE_CHALLENGE:one}'), (200, b"{CODE_CHALLENGE:'next::rule'}"), (300, b'{CODE_TOKEN:synthetic}')])
        t.main.challenge = ChallengeState()
        self.assertEqual(self.run_values(t, service(t)), 'synthetic')
        self.assertEqual([r[0] for r in t.requests], [200, 200, 300])

    def test_external_link_fault_forwarded_to_original_catch(self):
        t = self.transcript([(200, b"{CODE_CHALLENGE:'next::rule'}"), (300, b'{CODE_TOKEN:synthetic}')])
        t.overrides['native_get_nonce'] = LinkFault(message='SYNTHETIC link')
        self.assertEqual(self.run_values(t, service(t)), 'synthetic')

    def test_unmodeled_values_never_become_java_failure_or_cookie_skip(self):
        for location in ('json', 'cookie'):
            t = self.transcript([(200, b'{CODE_CHALLENGE:0.123456789}' if location == 'json' else b'{}')])
            if location == 'cookie':
                t.overrides['set_cookie_header_values'] = ['x=v;Expires=unknown-format']
            with self.assertRaises(AnalysisLimit):
                self.run_values(t, challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
            self.assertNotIn('E30.5:', t.main.status_log)

    def test_adapter_does_not_perform_io_or_invent_unknown_effects(self):
        with patch('socket.socket', side_effect=AssertionError('no network')), patch('getpass.getpass', side_effect=AssertionError('no PIN')):
            self.assertEqual(string_field(decode_value(Effect('json_object', ('{x:1}',)), locale_language='ko'), 'x', ''), '1')
            with self.assertRaises(AnalysisLimit):
                decode_value(Effect('native_start'), locale_language='ko')

            def source():
                result = (yield Effect('genuine_external_observation'))
                return result
            wrapped = decode_values_steps(source(), locale_language='ko')
            self.assertEqual(next(wrapped).kind, 'genuine_external_observation')
            with self.assertRaises(StopIteration) as caught:
                wrapped.send('EXPLICIT')
            self.assertEqual(caught.exception.value, 'EXPLICIT')
if __name__ == '__main__':
    unittest.main()
