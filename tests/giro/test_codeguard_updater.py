import base64
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from giro.codeguard_codec import java_seed_encrypt
from giro.codeguard_effects import JavaFault, LinkFault
from giro.codeguard_exchange import cmd101_request
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_platform import engine_exists_steps
from giro.codeguard_updater import wrapped_key_steps, check_update_steps, challenge_steps, token_steps, agent_certificate_steps
from cg_exchange_fixture import Transcript, fault

class KeySetupTests(unittest.TestCase):

    def test_random_clock_keys_before_certificate_and_cipher(self):
        t = Transcript()
        value = t.run(wrapped_key_steps(t.runtime, t.agent))
        self.assertEqual(t.kinds(), ['new_java_random', 'clock_ms', 'java_random_seed_and_bytes', 'android_parse_x509', 'rsa_cipher_instance', 'certificate_public_key', 'rsa_cipher_init', 'rsa_cipher_final'])
        self.assertEqual(t.runtime.data.key, b'\x01' * 16)
        self.assertEqual(t.agent.key, t.runtime.data.key)
        self.assertEqual(base64.b64decode(value), b'SYNTHETIC-wrapped-' + b'\x01' * 16)

    def test_each_call_replaces_key_even_when_rsa_fails(self):
        t = Transcript(overrides={'rsa_cipher_final': fault('InvalidKeyException')})
        for n in (1, 2):
            self.assertEqual(t.run(wrapped_key_steps(t.runtime, t.agent)), '')
            self.assertEqual((t.runtime.data.key, t.agent.key), (bytes([n]) * 16, bytes([n]) * 16))

    def test_random_failure_keeps_old_key_but_parse_failure_keeps_new(self):
        for (site, new) in (('new_java_random', False), ('java_random_seed_and_bytes', False), ('android_parse_x509', True)):
            t = Transcript(overrides={site: fault()})
            (t.runtime.data.key, t.agent.key) = (b'old-updater', b'old-agent')
            self.assertEqual(t.run(wrapped_key_steps(t.runtime, t.agent)), '')
            self.assertEqual(t.agent.key, b'\x01' * 16 if new else b'old-agent')

    def test_invalid_base64_null_result_returns_empty_after_key_assignment(self):
        for cert in ('', 'a', None):
            t = Transcript(cert=cert)
            self.assertEqual(t.run(wrapped_key_steps(t.runtime, t.agent)), '')
            self.assertEqual(t.agent.key, b'\x01' * 16)
            self.assertNotIn('android_parse_x509', t.kinds())

    def test_null_context_only_fails_when_certificate_preference_needed(self):
        t = Transcript(context=None, cert='c3ludGhldGlj')
        self.assertTrue(t.run(wrapped_key_steps(t.runtime, t.agent)))
        t.agent.certificate_text = ''
        self.assertEqual(t.run(wrapped_key_steps(t.runtime, t.agent)), '')

    def test_nonempty_agent_cert_avoids_preference_and_empty_uses_it(self):
        t = Transcript()
        self.assertEqual(t.run(agent_certificate_steps(t.runtime, t.agent)), 'c3ludGhldGlj')
        self.assertEqual(t.effects, [])
        t.agent.certificate_text = ''
        t.preferences['CERT'] = 'cached cert'
        self.assertEqual(t.run(agent_certificate_steps(t.runtime, t.agent)), 'cached cert')

    def test_analysis_limit_and_link_error_not_caught_as_java_exception(self):
        for error in (AnalysisLimit('unknown'), LinkFault(), ValueError('Python bug')):
            t = Transcript(overrides={'android_parse_x509': error})
            with self.assertRaises(type(error)):
                t.run(wrapped_key_steps(t.runtime, t.agent))

    def test_key_size_is_observation_shape_not_server_input_gate(self):
        t = Transcript(overrides={'java_random_seed_and_bytes': b'incomplete'})
        with self.assertRaises(AnalysisLimit):
            t.run(wrapped_key_steps(t.runtime, t.agent))
        self.assertIsNone(t.agent.key)

class UpdateTests(unittest.TestCase):

    def run_update(self, fields=None, **kwargs):
        t = Transcript([(101, fields or {})], **kwargs)
        result = t.run(check_update_steps(t.runtime, t.agent, t.main))
        return (t, result)

    def test_null_context_returns_false_status_zero_no_io(self):
        t = Transcript(context=None)
        t.runtime.status = 9
        self.assertIs(t.run(check_update_steps(t.runtime, t.agent, t.main)), False)
        self.assertEqual(t.runtime.status, 0)
        self.assertEqual(t.main.status_log, 'E0,E11.1')
        self.assertEqual(t.effects, [])

    def test_exact_request_and_user_agent_key(self):
        (t, result) = self.run_update()
        expected = cmd101_request(t.runtime.url, abi='arm64-v8a', native_library_dir=None, app_info='APP', version='1', user_agent='synthetic-UA')
        self.assertEqual(t.requests[0][1], expected.url)
        self.assertIs(result, True)
        self.assertIn(('User-Agent', 'synthetic-UA'), [e.args[2] for e in t.calls('setRequestProperty')])

    def test_engine_false_still_true_and_metadata_persisted_before_check(self):
        fields = dict(ENGINE_VERSION='new', ENGINE_MD='m' * 26, CERT='new cert')
        (t, result) = self.run_update(fields, overrides={'file_exists': False})
        self.assertTrue(result)
        self.assertEqual(t.runtime.status, 3)
        self.assertEqual(t.agent.certificate_text, 'new cert')
        self.assertEqual(t.agent.engine_version, 'new')
        self.assertEqual(t.preferences['CERT'], 'new cert')
        self.assertEqual(t.main.status_log, 'E0,E11.1,E19.1')
        self.assertEqual(t.effects[-1].args, ('/synthetic/lib/libCodeGuard.so',))
        self.assertLess(t.kinds().index('preference_write'), t.kinds().index('application_info'))

    def test_digest_length_md5_branch_counts_utf16(self):
        for (value, expected) in (('a' * 25, True), ('a' * 26, False), ('😀' * 13, False)):
            with patch('giro.codeguard_updater.engine_exists_steps', wraps=engine_exists_steps) as engine:
                self.run_update({'ENGINE_MD': value})
            self.assertIs(engine.call_args.args[-1], expected)

    def test_cert_write_failure_does_not_rollback_agent_writes(self):

        def write(e):
            return fault() if e.args[1] == 'CERT' else None
        (t, result) = self.run_update({'ENGINE_VERSION': 'new', 'CERT': 'new cert'}, overrides={'preference_write': write})
        self.assertFalse(result)
        self.assertEqual(t.runtime.status, 3)
        self.assertEqual((t.agent.engine_version, t.agent.certificate_text), ('new', 'new cert'))
        self.assertNotIn('application_info', t.kinds())
        self.assertIn(',E11:java.synthetic.', t.main.status_log)

    def test_first_version_write_failure_prevents_agent_changes(self):
        (t, result) = self.run_update({'ENGINE_VERSION': 'new', 'CERT': 'new'}, overrides={'preference_write': fault()})
        self.assertFalse(result)
        self.assertEqual(t.agent.engine_version, 'synthetic-engine')
        self.assertEqual(t.agent.certificate_text, 'c3ludGhldGlj')

    def test_cpu_abi_exception_uses_dir_fallback(self):
        (t, result) = self.run_update(overrides={'cpu_abi': fault(), 'native_library_dir': '/synthetic/armeabi'})
        self.assertTrue(result)
        self.assertIn('&ABI=armeabi&', t.requests[0][1])

    def test_response_code_exception_is_not_body_failure(self):
        t = Transcript([(101, {})])

        def http(e):
            return fault() if e.args[1] == 'getResponseCode' else t.default(e)
        t.overrides['http_call'] = http
        self.assertTrue(t.run(check_update_steps(t.runtime, t.agent, t.main)))
        self.assertIn('json_object', t.kinds())

    def test_engine_link_error_not_changed_into_false_update(self):
        t = Transcript([(101, {})], overrides={'file_exists': LinkFault()})
        with self.assertRaises(LinkFault):
            t.run(check_update_steps(t.runtime, t.agent, t.main))
        self.assertEqual(t.runtime.status, 0)

    def test_application_info_exception_is_update_failure_before_engine_log(self):
        (t, result) = self.run_update({'CERT': 'new cert'}, overrides={'application_info': fault('SecurityException')})
        self.assertFalse(result)
        self.assertEqual(t.runtime.status, 3)
        self.assertEqual(t.agent.certificate_text, 'new cert')
        self.assertNotIn(',E19.1', t.main.status_log)
        self.assertNotIn('application_native_library_dir', t.kinds())

    def test_engine_file_exception_is_not_update_failure(self):
        (t, result) = self.run_update(overrides={'open_file_input': fault('IOException')})
        self.assertTrue(result)
        self.assertEqual(t.main.status_log, 'E0,E11.1,E19.1,E19.6')
        self.assertNotIn('close_file_input', t.kinds())

    def test_engine_digest_connected_not_an_opaque_true_observation(self):
        for hashfun in (hashlib.md5, hashlib.sha256):
            digest = base64.b64encode(hashfun(b'abc').digest()).decode()
            (t, result) = self.run_update({'ENGINE_MD': digest})
            self.assertTrue(result)
            self.assertEqual(t.main.status_log, 'E0,E11.1,E19.1,E19.6,E19.7,E11')
            self.assertNotIn('engine_exists', t.kinds())

    def test_engine_null_application_info_fault_stays_inside_engine_catch(self):
        (t, result) = self.run_update(overrides={'application_info': None, 'application_native_library_dir': fault('NullPointerException')})
        self.assertTrue(result)
        self.assertEqual(t.main.status_log, 'E0,E11.1,E19.1')

class ChallengeTests(unittest.TestCase):

    def run_challenge(self, fields=None, **kwargs):
        t = Transcript([(200, fields or {})], **kwargs)
        value = t.run(challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        return (t, value)

    def test_null_context_resets_cookie_only_and_returns_empty(self):
        t = Transcript(context=None)
        (t.runtime.data.cookie, t.runtime.data.hash_key, t.runtime.data.rcl) = ('old cookie', 'old hash', 'old rcl')
        t.runtime.data.is_mix = True
        self.assertEqual(t.run(challenge_steps(t.runtime, t.agent, t.main, None)), '')
        self.assertEqual((t.runtime.data.cookie, t.runtime.data.hash_key, t.runtime.data.rcl), ('', 'old hash', 'old rcl'))
        self.assertTrue(t.runtime.data.is_mix)
        self.assertEqual(t.effects, [])

    def test_abi_encoding_precedes_key_and_app_encoding_follows_key(self):
        t = Transcript(overrides={'cpu_abi': None})
        result = t.run(challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        self.assertTrue(result.startswith('E101_NET_ERROR_005'))
        self.assertIsNone(t.agent.key)
        t = Transcript()
        result = t.run(challenge_steps(t.runtime, t.agent, t.main, None))
        self.assertTrue(result.startswith('E101_NET_ERROR_005'))
        self.assertEqual(t.agent.key, b'\x01' * 16)
        self.assertEqual(t.requests, [])

    def test_key_wrap_failure_still_sends_empty_key_without_extra_gate(self):
        (t, result) = self.run_challenge({'CODE_CHALLENGE': 'value'}, overrides={'rsa_cipher_final': fault()})
        self.assertEqual(result, 'value')
        query = parse_qs(urlsplit(t.requests[0][1]).query, keep_blank_values=True)
        self.assertEqual(query['KEY'], [''])
        self.assertEqual(t.agent.key, b'\x01' * 16)

    def test_empty_abi_does_not_use_directory_fallback(self):
        (t, _) = self.run_challenge(overrides={'cpu_abi': fault()})
        self.assertIn('&ABI=&', t.requests[0][1])
        self.assertNotIn('native_library_dir', t.kinds())

    def test_error_type_prefix_and_old_vs_new_status_log(self):
        for (kind, suffix, includes) in (('IOException', 1, False), ('ParseException', 2, False), ('JSONException', 3, True), ('IllegalArgumentException', 4, True), ('NullPointerException', 5, True), ('Exception', 6, True)):
            (t, result) = self.run_challenge(overrides={'http_open': fault(kind, 'FAULT')})
            self.assertTrue(result.startswith('E101_NET_ERROR_%03d&&' % suffix))
            self.assertEqual('FAULT' in result, includes)
            self.assertIn('FAULT', t.main.status_log)
            self.assertEqual(t.runtime.data.cookie, '')

    def test_socket_timeout_uses_explicit_java_ancestry(self):
        error = JavaFault('SocketTimeoutException', bases=('IOException',), message='timeout', java_string='observed timeout')
        (_, result) = self.run_challenge(overrides={'http_open': error})
        self.assertTrue(result.startswith('E101_NET_ERROR_001&&'))

    def test_response_code_exception_is_swallowed_before_cookie_and_body(self):
        t = Transcript([(200, {'CODE_CHALLENGE': 'value'})])
        t.overrides['http_call'] = lambda e: fault('IOException') if e.args[1] == 'getResponseCode' else t.default(e)
        self.assertEqual(t.run(challenge_steps(t.runtime, t.agent, t.main, 'APP11')), 'value')
        self.assertIn('set_cookie_header_values', t.kinds())

    def test_cookie_parse_per_header_exception_and_partial_append(self):
        t = Transcript([(200, {})])
        t.overrides.update(set_cookie_header_values=['h1', 'h2', 'h3'])

        def parse(e):
            return fault() if e.args[0] == 'h2' else ('a', 'b') if e.args[0] == 'h1' else ('c',)

        def string(e):
            return e.args[0] + '=synthetic'
        t.overrides.update(http_cookie_parse=parse, http_cookie_string=string)
        t.run(challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        self.assertEqual(t.runtime.data.cookie, 'a=synthetic; b=synthetic; c=synthetic')
        self.assertEqual(t.kinds().count('http_cookie_string'), 6)

    def test_cookie_string_exception_is_not_in_parse_catch(self):
        t = Transcript([(200, {})], overrides={'set_cookie_header_values': ['h1', 'h2'], 'http_cookie_parse': ['a', 'b']})
        t.overrides['http_cookie_string'] = lambda e: fault() if e.args[0] == 'b' else 'a=synthetic'
        result = t.run(challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        self.assertEqual(t.runtime.data.cookie, 'a=synthetic')
        self.assertTrue(result.startswith('E101_NET_ERROR_006'))
        self.assertEqual(t.kinds().count('http_cookie_parse'), 1)
        self.assertNotIn('json_object', t.kinds())

    def test_body_error_after_cookie_preserves_cookie_and_skips_reader_close(self):
        t = Transcript([(200, {})], overrides={'set_cookie_header_values': ['h'], 'http_cookie_parse': ['c'], 'http_cookie_string': 'cookie=synthetic', 'read_line': fault('IOException')})
        value = t.run(challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        self.assertTrue(value.startswith('E101_NET_ERROR_001'))
        self.assertEqual(t.runtime.data.cookie, 'cookie=synthetic')
        self.assertNotIn('close_reader', t.kinds())

    def test_fields_are_read_before_rcl_update_and_flags(self):
        t = Transcript([(200, {'CODE_CHALLENGE': 'c', 'CODE_RCL': base64.b64encode(b'r').decode()})])
        t.runtime.data.rcl = 'old'
        t.overrides['json_string_field'] = lambda e: fault('JSONException') if e.args[1] == 'CODE_RESPONSE2_VER' else t.default(e)
        result = t.run(challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        self.assertTrue(result.startswith('E101_NET_ERROR_003'))
        self.assertEqual(t.runtime.data.rcl, 'old')

    def test_hash_parse_error_keeps_rcl_mix_split_and_old_hash(self):
        fields = {'CODE_RCL': base64.b64encode(b'new').decode(), 'CODE_RESPONSE2_VER': 'isMix,isSplit', 'HASH_KEY': 'no separator'}
        t = Transcript([(200, fields)])
        t.runtime.data.hash_key = 'old'
        result = t.run(challenge_steps(t.runtime, t.agent, t.main, 'APP11'))
        self.assertTrue(result.startswith('E101_NET_ERROR_006'))
        self.assertEqual((t.runtime.data.rcl, t.runtime.data.is_mix, t.runtime.data.is_split, t.runtime.data.hash_key), ('new', True, True, 'old'))
        self.assertIn(',E30.5,E30.5:', t.main.status_log)

    def test_hash_key_uses_new_key_and_decrypt_error_is_empty_not_outer_error(self):
        iv = bytes(16)
        encoded = base64.b64encode(java_seed_encrypt(b'synthetic nonce key', b'\x01' * 16, iv)).decode() + '::' + base64.b64encode(iv).decode()
        (t, result) = self.run_challenge({'CODE_CHALLENGE': 'c', 'HASH_KEY': encoded})
        self.assertEqual(result, 'c')
        self.assertEqual(t.runtime.data.hash_key, b'synthetic nonce key'.hex().upper())
        (t, result) = self.run_challenge({'CODE_CHALLENGE': 'c', 'HASH_KEY': 'a::a'})
        self.assertEqual((result, t.runtime.data.hash_key), ('c', ''))

    def test_missing_hash_flags_rcl_preserve_previous_values_across_requests(self):
        t = Transcript([(200, {'CODE_CHALLENGE': 'c'})])
        (t.runtime.data.hash_key, t.runtime.data.rcl, t.runtime.data.is_split) = ('hash', 'rcl', True)
        self.assertEqual(t.run(challenge_steps(t.runtime, t.agent, t.main, 'APP11')), 'c')
        self.assertEqual((t.runtime.data.hash_key, t.runtime.data.rcl, t.runtime.data.is_split), ('hash', 'rcl', True))

    def test_invalid_rcl_null_decode_uses_npe_not_generic_base64_rejection(self):
        (t, result) = self.run_challenge({'CODE_RCL': 'a', 'CODE_RESPONSE2_VER': 'isMix'})
        self.assertTrue(result.startswith('E101_NET_ERROR_005'))
        self.assertFalse(t.runtime.data.is_mix)
        self.assertNotIn('java_decode_default_charset', t.kinds())

    def test_link_backend_or_python_error_not_converted_to_network_code(self):
        for error in (LinkFault(), AnalysisLimit('unknown'), TypeError('bug')):
            with self.assertRaises(type(error)):
                self.run_challenge(overrides={'http_open': error})

class TokenTests(unittest.TestCase):

    def run_token(self, fields=None, *, get_mode=False, cookie='', overrides=None):
        t = Transcript([(300, fields or {})], overrides=overrides)
        t.preferences['GETMODE'] = get_mode
        t.runtime.data.cookie = cookie
        result = t.run(token_steps(t.runtime, t.agent, t.main, 'first +', 'second&'))
        return (t, result)

    def test_post_leading_ampersand_output_order_cookie_fallback(self):
        (t, result) = self.run_token({'CODE_TOKEN': 'synthetic server fixture'})
        self.assertEqual(result, 'synthetic server fixture')
        self.assertEqual(t.writes[0][1], b'&CODE_RESPONSE=first+%2B&CODE_RESPONSE2=second%26&FIXED=true')
        self.assertEqual(t.runtime.data.cookie, 'synthetic-agent-cookie')
        kinds = t.kinds()
        connect = next((i for (i, e) in enumerate(t.effects) if e.kind == 'http_call' and e.args[1] == 'connect'))
        self.assertLess(kinds.index('close_output'), connect)
        self.assertNotIn('set_cookie_header_values', kinds)

    def test_get_never_takes_agent_cookie_or_writes_body(self):
        (t, _) = self.run_token(get_mode=True)
        self.assertEqual(t.runtime.data.cookie, '')
        self.assertIn('&CODE_RESPONSE=first+%2B', t.requests[0][1])
        self.assertEqual(t.writes, [])
        self.assertNotIn('setDoOutput', [e.args[1] for e in t.effects if e.kind == 'http_call'])

    def test_null_context_returns_null_without_cookie_mutation(self):
        t = Transcript(context=None)
        t.runtime.data.cookie = 'old'
        self.assertIsNone(t.run(token_steps(t.runtime, t.agent, t.main, None, None)))
        self.assertEqual(t.runtime.data.cookie, 'old')
        self.assertEqual(t.effects, [])

    def test_null_response_is_error7_before_clock_getmode_or_io(self):
        t = Transcript()
        value = t.run(token_steps(t.runtime, t.agent, t.main, 'first', None))
        self.assertTrue(value.startswith('E101_NET_ERROR_007&&'))
        self.assertNotIn('clock_ms', t.kinds())
        self.assertEqual(t.requests, [])

    def test_http_code_metadata_not_an_extra_2xx_gate(self):
        t = Transcript([(300, {'CODE_TOKEN': 'synthetic available body'})])
        t.overrides['http_call'] = lambda e: 503 if e.args[1] == 'getResponseCode' else t.default(e)
        self.assertEqual(t.run(token_steps(t.runtime, t.agent, t.main, 'a', 'b')), 'synthetic available body')

    def test_token_missing_null_empty_preserved(self):
        for (fields, expected) in (({}, None), ({'CODE_TOKEN': None}, None), ({'CODE_TOKEN': ''}, '')):
            (_, result) = self.run_token(fields)
            self.assertEqual(result, expected)

    def test_body_io_failure_is_error7_and_no_finally_close(self):
        (t, result) = self.run_token(overrides={'read_line': fault('IOException')})
        self.assertTrue(result.startswith('E101_NET_ERROR_007&&'))
        self.assertIn(',E33.99:', result)
        self.assertNotIn('close_reader', t.kinds())

    def test_open_failure_keeps_old_connection_and_pre_fallback_cookie(self):
        t = Transcript(overrides={'http_open': fault('IOException')})
        t.runtime.connection = 'old connection'
        t.runtime.data.cookie = ''
        t.run(token_steps(t.runtime, t.agent, t.main, 'a', 'b'))
        self.assertEqual(t.runtime.connection, 'old connection')
        self.assertEqual(t.runtime.data.cookie, '')

    def test_no_sdk_socket_file_or_sensitive_repr(self):
        t = Transcript([(300, {'CODE_TOKEN': 'PRIVATE'})])
        with patch('socket.socket', side_effect=AssertionError('no socket')), patch('ctypes.CDLL', side_effect=AssertionError('no SDK')), patch('builtins.open', side_effect=AssertionError('no files')):
            self.assertEqual(t.run(token_steps(t.runtime, t.agent, t.main, 'PRIVATE', 'PRIVATE')), 'PRIVATE')
        self.assertNotIn('PRIVATE', repr(t.runtime) + repr(t.agent) + repr(t.effects))
