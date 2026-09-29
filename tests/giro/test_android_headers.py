import base64
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch
from giro.android_headers import HeaderFields, read_header_lines, cookie_header_values_steps, project_header_values_steps
from giro.codeguard_effects import Effect, JavaFault, LinkFault
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_http_values import decode_values_steps
from giro.codeguard_updater import challenge_steps
from giro.codeguard_service import generate_token_http_values_steps
import test_android_http_values as value_support
from test_codeguard_response import drive, fault

class HeaderTests(unittest.TestCase):

    def test_case_insensitive_duplicates_keep_value_order_not_first_or_last_only(self):
        fields = read_header_lines(['set-cookie:a=1', 'X:ignored', 'Set-Cookie:b=2', 'SET-COOKIE:a=3', ''])
        self.assertEqual(fields.get('Set-Cookie'), ('a=1', 'b=2', 'a=3'))
        self.assertEqual(fields.last('SET-cookie'), 'a=3')
        self.assertIsNone(fields.get('absent'))

    def test_tree_order_first_key_spelling_and_null_status(self):
        fields = HeaderFields((('z', 'v'), ('B', 'one'), ('a', 'v'), ('b', 'two')), 'HTTP/1.1 200 OK')
        self.assertEqual(fields.entries(), ((None, ('HTTP/1.1 200 OK',)), ('a', ('v',)), ('B', ('one', 'two')), ('z', ('v',))))
        self.assertEqual(fields.last(None), 'HTTP/1.1 200 OK')

    def test_colonless_and_folded_lines_are_empty_name_not_continuations(self):
        fields = read_header_lines(['Set-Cookie:a=1', ' ; Path=/wrong', 'colonless', ':statuslike', ''])
        self.assertEqual(fields.get('Set-Cookie'), ('a=1',))
        self.assertEqual(fields.get(''), ('; Path=/wrong', 'colonless', 'statuslike'))
        self.assertIsNone(fields.get(None))

    def test_lenient_colon_search_starts_at_one(self):
        fields = read_header_lines(['::value', ':only', ':a:b', ''])
        self.assertEqual(fields.pairs, ((':', 'value'), ('', 'only'), (':a', 'b')))

    def test_name_not_trimmed_but_value_java_trimmed(self):
        fields = read_header_lines([' Set-Cookie : \x00 a=1\x1f', 'Set-Cookie:\t b=2\t', ''])
        self.assertEqual(fields.get('Set-Cookie'), ('b=2',))
        self.assertEqual(fields.get(' Set-Cookie '), ('a=1',))

    def test_unicode_value_whitespace_not_python_strip(self):
        fields = read_header_lines(['X:\xa0v\xa0', ''])
        self.assertEqual(fields.get('X'), ('\xa0v\xa0',))

    def test_empty_line_only_terminates_and_does_not_consume_body(self):
        lines = iter(['   ', '', 'BODY'])
        fields = read_header_lines(lines)
        self.assertEqual(fields.get(''), ('',))
        self.assertEqual(next(lines), 'BODY')

    def test_name_validation_from_strict_builder_not_added(self):
        fields = read_header_lines(['bad name: value', 'a\x00b: next', ''])
        self.assertEqual(fields.get('bad name'), ('value',))
        self.assertEqual(fields.get('a\x00b'), ('next',))

    def test_missing_terminator_or_unobserved_decode_is_not_fabricated_eof(self):
        for lines in (['X:1'], [None], ['X:1\nY:2', '']):
            with self.assertRaises(AnalysisLimit):
                read_header_lines(lines)

    def test_nonascii_comparator_not_guessed_from_python_casefold(self):
        fields = read_header_lines(['ſet-Cookie:a=1', ''])
        with self.assertRaises(AnalysisLimit):
            fields.get('Set-Cookie')

    def test_no_values_in_repr(self):
        fields = HeaderFields((('private', 'PRIVATE-VALUE'),), 'PRIVATE-STATUS')
        self.assertNotIn('PRIVATE', repr(fields))

    def test_tree_map_order_and_first_spelling_match_independent_jdk(self):
        java = shutil.which('java')
        if java is None:
            self.skipTest('optional reference JDK unavailable on PATH')
        pairs = (('z', 'last'), ('set-cookie', 'one'), ('B', '1'), ('Set-Cookie', 'two'), ('b', '2'), ('', 'empty'))
        b64 = lambda s: base64.b64encode(s.encode()).decode()
        args = [b64(n) + '.' + b64(v) for (n, v) in pairs]
        result = subprocess.run([java, str(Path(__file__).parent / 'java/HeaderVectors.java'), *args], capture_output=True, text=True, timeout=30, check=True)
        entries = HeaderFields(pairs, 'HTTP/1.1 200 synthetic').entries()
        expected = [b64('<status>' if n is None else n) + ':' + b64('\x00'.join(v)) for (n, v) in entries]
        self.assertEqual(result.stdout.splitlines(), expected)

class HeaderEffectTests(unittest.TestCase):

    def test_ioexception_returns_absent_cookie_like_empty_header_map(self):
        for problem in (fault('IOException'), JavaFault('SocketTimeoutException', message='synthetic', java_string='synthetic', bases=('IOException',))):
            self.assertIsNone(drive(cookie_header_values_steps('conn', 'Set-Cookie'), lambda _: problem))

    def test_non_io_java_and_python_unknown_are_not_empty_map(self):
        for problem in (fault('IllegalStateException'), AnalysisLimit('unknown'), OSError('synthetic'), LinkFault()):
            with self.assertRaises(type(problem)):
                drive(cookie_header_values_steps('conn', 'Set-Cookie'), lambda _: problem)

    def test_opaque_list_or_unobserved_response_not_substituted(self):
        with self.assertRaises(AnalysisLimit):
            drive(cookie_header_values_steps('conn', 'Set-Cookie'), lambda _: ['cookie=value'])

    def test_real_header_cookie_and_body_values_connect_to_updater(self):
        t = value_support.ValuePipelineTests().transcript([(200, b'{CODE_CHALLENGE:ok}')])
        t.overrides['urlconnection_response_headers'] = read_header_lines(['set-cookie: first=1', 'Set-Cookie: bad=1,broken;Version=1', 'SET-COOKIE: last=2', ''])
        source = project_header_values_steps(challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        result = t.run(decode_values_steps(source, locale_language='ko'))
        self.assertEqual(result, 'ok')
        self.assertEqual(t.runtime.data.cookie, 'first=1; last=2')
        self.assertNotIn('set_cookie_header_values', t.kinds())

    def test_header_io_failure_still_reaches_original_body_read(self):
        t = value_support.ValuePipelineTests().transcript([(200, b'{CODE_CHALLENGE:ok}')])
        t.overrides['urlconnection_response_headers'] = fault('IOException')
        source = project_header_values_steps(challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        self.assertEqual(t.run(decode_values_steps(source, locale_language='ko')), 'ok')
        self.assertEqual(t.runtime.data.cookie, '')
        self.assertIn('read_line', t.kinds())

    def test_unknown_header_projection_does_not_skip_cookie_or_read_body(self):
        t = value_support.ValuePipelineTests().transcript([(200, b'{}')])
        t.overrides['urlconnection_response_headers'] = HeaderFields((('ſet-cookie', 'x=1'),))
        source = project_header_values_steps(challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        with self.assertRaises(AnalysisLimit):
            t.run(decode_values_steps(source, locale_language='ko'))
        self.assertNotIn('read_line', t.kinds())

    def test_full_pipeline_reuses_ordered_cookies_in_synthetic_cmd300(self):
        t = value_support.ValuePipelineTests().transcript([(200, b'{CODE_CHALLENGE:"c::r"}'), (300, b'{CODE_TOKEN:synthetic}')])
        t.overrides['urlconnection_response_headers'] = HeaderFields((('set-cookie', 'a=1'), ('Set-Cookie', 'a=2')))
        with patch('socket.socket', side_effect=AssertionError('no real network')):
            result = t.run(generate_token_http_values_steps(t.main, t.runtime, t.agent, locale_language='ko', project_headers=True, server_url='https://synthetic.invalid/', timeout=500, root_check=True, rooting_info=False, encrypted_token=False))
        self.assertEqual(result, 'synthetic')
        sent = [e.args[2] for e in t.calls('setRequestProperty') if e.args[2][0] == 'Cookie']
        self.assertEqual(sent, [('Cookie', 'a=1; a=2')])
        self.assertEqual(t.kinds().count('urlconnection_response_headers'), 1)

    def test_other_effects_are_forwarded_without_default_success(self):

        def source():
            return (yield Effect('actual_observation'))
        wrapped = project_header_values_steps(source())
        self.assertEqual(next(wrapped).kind, 'actual_observation')
        with self.assertRaises(StopIteration) as done:
            wrapped.send('observed')
        self.assertEqual(done.exception.value, 'observed')
