import base64
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from giro import codeguard_exchange as cg
from giro.codeguard_codec import java_seed_encrypt, CodeGuardCodecError
from giro.codeguard_rule import AnalysisLimit

class RequestTests(unittest.TestCase):
    base = 'https://example.invalid/'

    def test_cmd101_exact_abi_raw_app_encoding(self):
        req = cg.cmd101_request(self.base, abi='arm +64', native_library_dir=None, app_info='APP ', version='4.9.5_209', user_agent='ua')
        self.assertEqual(req.url, self.base + 'CodeGuard/check.jsp?CODEGUARD_CMD=101&OS=CG1&ABI=arm +64&CODE_APP_INFO=APP+4.9.5_2091&CERT=yes')
        self.assertEqual(req.headers, (('User-Agent', 'ua'),))
        self.assertIsNone(req.body)

    def test_cmd101_abi_fallback_and_optional_app_info(self):
        for (folder, expected) in (('/lib/arm64', 'arm64-v8a'), ('/lib/arm', 'armeabi')):
            req = cg.cmd101_request(self.base, abi='', native_library_dir=folder, app_info='a', version='', user_agent='')
            self.assertIn('&ABI=' + expected + '&CERT=yes', req.url)
            self.assertNotIn('CODE_APP_INFO', req.url)
            self.assertFalse(req.headers)
        with self.assertRaises(AnalysisLimit):
            cg.cmd101_request(self.base, abi='', native_library_dir=None, app_info='a', version='v', user_agent='')

    def test_cmd200_resets_only_cookie_and_encodes_all_three_values(self):
        state = cg.UpdaterState(cookie='old', rcl='old-rcl', hash_key='old-key', is_mix=True, is_split=True)
        req = state.cmd200_request(self.base, app_info='a b', abi='x+y', wrapped_key='k/+=', mix_setting=False, user_agent='')
        self.assertEqual(req.url, self.base + 'CodeGuard/check.jsp?CODEGUARD_CMD=200&CODE_APP_INFO=a+b&ABI=x%2By&KEY=k%2F%2B%3D&isMix=false')
        self.assertEqual(state.cookie, '')
        self.assertEqual((state.rcl, state.hash_key, state.is_mix, state.is_split), ('old-rcl', 'old-key', True, True))
        self.assertNotIn('Cookie', dict(req.headers))

    def test_cmd200_cookie_cleared_even_when_encoding_fails(self):
        state = cg.UpdaterState(cookie='old')
        with self.assertRaises(CodeGuardCodecError):
            state.cmd200_request(self.base, app_info=None, abi='arm', wrapped_key='k', mix_setting=True, user_agent='')
        self.assertEqual(state.cookie, '')

    def test_cmd300_post_leading_ampersand_and_agent_cookie_fallback(self):
        state = cg.UpdaterState(is_mix=True)
        req = state.cmd300_request(self.base, response='a +/~*', response2='', get_mode=False, agent_cookie='fallback=1', user_agent='')
        self.assertEqual(req.body, b'&CODE_RESPONSE=a+%2B%2F%7E*&CODE_RESPONSE2=&CODE_RESPONSE2_VER=isMix&FIXED=true')
        self.assertEqual(req.url, self.base + 'CodeGuard/check.jsp?CODEGUARD_CMD=300')
        self.assertEqual(dict(req.headers)['Cookie'], 'fallback=1')
        self.assertEqual(state.cookie, 'fallback=1')

    def test_cmd300_get_does_not_fallback_cookie(self):
        state = cg.UpdaterState()
        req = state.cmd300_request(self.base, response='r', response2='s', get_mode=True, agent_cookie='ignored', user_agent='ua')
        self.assertTrue(req.url.endswith('300&CODE_RESPONSE=r&CODE_RESPONSE2=s&FIXED=true'))
        self.assertEqual(dict(req.headers)['Cookie'], '')
        self.assertEqual(state.cookie, '')
        self.assertIsNone(req.body)

    def test_cmd300_keeps_existing_cookie_and_error_response_text(self):
        state = cg.UpdaterState(cookie='original')
        req = state.cmd300_request(self.base, response='E101_ENGINE_LOAD_ERROR', response2='err', get_mode=False, agent_cookie='ignored', user_agent=None)
        self.assertEqual(dict(req.headers)['Cookie'], 'original')
        self.assertIn(b'E101_ENGINE_LOAD_ERROR', req.body)

    def test_base_url_is_concatenated_not_normalized(self):
        req = cg.cmd101_request('base', abi='arm', native_library_dir=None, app_info=None, version=None, user_agent=None)
        self.assertTrue(req.url.startswith('baseCodeGuard/'))

    def test_sensitive_values_hidden_in_repr_and_diagnostics(self):
        state = cg.UpdaterState(cookie='secret-cookie', hash_key='secret-key', key=b'secret', certificate_text='secret-cert')
        req = state.cmd300_request(self.base, response='secret-response', response2='secret-nonce', get_mode=False, agent_cookie=None, user_agent='')
        for rendered in (repr(state), repr(req), str(req.diagnostic())):
            self.assertNotIn('secret', rendered)

    def test_cookies_preserve_order_duplicates_and_version_one_strings(self):
        state = cg.UpdaterState()
        state.append_parsed_cookies(['sid=a', 'sid=b', 'v="c";$Path="/"'])
        self.assertEqual(state.cookie, 'sid=a; sid=b; v="c";$Path="/"')

class ResponseFieldTests(unittest.TestCase):

    def test_cmd101_fields_no_fake_engineexist_success(self):
        state = cg.UpdaterState()
        self.assertIsNone(state.consume_cmd101_fields({'ENGINE_VERSION': 'v', 'ENGINE_MD': 'm', 'CERT': 'c'}))
        self.assertEqual((state.engine_version, state.engine_md, state.certificate_text), ('v', 'm', 'c'))
        state.consume_cmd101_fields({})
        self.assertEqual((state.engine_version, state.engine_md, state.certificate_text), ('', '', ''))

    def test_mix_split_are_substrings_and_sticky(self):
        state = cg.UpdaterState()
        self.assertEqual(state.consume_cmd200_fields({'CODE_CHALLENGE': 'g::h', 'CODE_RESPONSE2_VER': 'prefixisMix-isSplit'}), 'g::h')
        state.consume_cmd200_fields({'CODE_RESPONSE2_VER': ''})
        self.assertTrue(state.is_mix)
        self.assertTrue(state.is_split)

    def test_missing_rcl_hash_key_retain_prior_values(self):
        state = cg.UpdaterState(rcl='old-rcl', hash_key='old-key')
        self.assertEqual(state.consume_cmd200_fields({}), '')
        self.assertEqual((state.rcl, state.hash_key), ('old-rcl', 'old-key'))

    def test_rcl_uses_original_lenient_base64_not_strict_standard(self):
        state = cg.UpdaterState()
        state.consume_cmd200_fields({'CODE_RCL': '!!!!'})
        self.assertEqual(state.rcl, '\x00\x00\x00')

    def test_rcl_null_decode_fails_before_flags_are_changed(self):
        state = cg.UpdaterState(rcl='old')
        with self.assertRaises(cg.ExchangeStageError) as exc:
            state.consume_cmd200_fields({'CODE_RCL': 'A', 'CODE_RESPONSE2_VER': 'isMix'})
        self.assertEqual(exc.exception.sdk_error_prefix, 'E101_NET_ERROR_005')
        self.assertEqual(state.rcl, 'old')
        self.assertFalse(state.is_mix)

    def test_hash_key_substring_failure_is_not_swallowed_as_empty_key(self):
        state = cg.UpdaterState(hash_key='old')
        with self.assertRaises(cg.ExchangeStageError) as exc:
            state.consume_cmd200_fields({'HASH_KEY': 'bad', 'CODE_RESPONSE2_VER': 'isMix'})
        self.assertEqual(exc.exception.sdk_error_prefix, 'E101_NET_ERROR_006')
        self.assertTrue(state.is_mix)
        self.assertEqual(state.hash_key, 'old')

    def test_hash_key_internal_failure_sets_empty_without_challenge_failure(self):
        state = cg.UpdaterState(hash_key='old')
        self.assertEqual(state.consume_cmd200_fields({'CODE_CHALLENGE': 'g::h', 'HASH_KEY': 'AAAA::AAAA'}, agent_key=b'k' * 16), 'g::h')
        self.assertEqual(state.hash_key, '')
        self.assertEqual(state.key, b'k' * 16)
        self.assertEqual(len(state.nonce_key('g')), 64)

    def test_android_json_unresolved_types_are_analysis_not_server_failure(self):
        with self.assertRaises(AnalysisLimit):
            cg.token_field({'CODE_TOKEN': 123})

    def test_token_null_empty_and_error_are_returned_without_new_success_gate(self):
        for (fields, expected) in (({}, None), ({'CODE_TOKEN': None}, None), ({'CODE_TOKEN': ''}, ''), ({'CODE_TOKEN': 'E101_error'}, 'E101_error'), ({'CODE_TOKEN': 'token', 'responseCode': '999'}, 'token')):
            self.assertEqual(cg.token_field(fields), expected)

    def test_readline_only_cr_lf_and_appends_final_newline(self):
        for (text, expected) in (('', ''), ('a\r\nb\rc\n', 'a\nb\nc\n'), ('x\u2028y', 'x\u2028y\n'), ('\n', '\n')):
            self.assertEqual(cg.read_line_join(text), expected)

    def test_java_split_trailing_empty_semantics(self):
        for (text, parts) in (('', ('',)), ('::', ()), ('g::h::', ('g', 'h')), ('g::::cert::x', ('g', '', 'cert', 'x'))):
            self.assertEqual(cg.challenge_parts(text), parts)

    def test_rcl_substring_counts_utf16_not_python_codepoints(self):
        self.assertEqual(cg.rcl_after_challenge('XYrest', '😀'), 'rest')
        self.assertEqual(cg.rcl_after_challenge('😀rest', 'X'), '\ude00rest')
        self.assertIsNone(cg.rcl_after_challenge('', 'g'))
        with self.assertRaises(CodeGuardCodecError):
            cg.rcl_after_challenge('X', '😀')

    def test_no_network_or_sdk_execution(self):
        with patch('socket.socket', side_effect=AssertionError('no network')), patch('ctypes.CDLL', side_effect=AssertionError('no SDK')):
            state = cg.UpdaterState()
            self.assertEqual(state.consume_cmd200_fields({'CODE_CHALLENGE': 'g::h'}), 'g::h')
            self.assertEqual(cg.token_field({'CODE_TOKEN': 'synthetic'}), 'synthetic')

@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto unavailable')
class ExchangeCryptoTests(unittest.TestCase):

    def test_hash_key_decryption_uses_codeguard_key_and_first_separator(self):
        (key, iv) = (bytes(range(16)), bytes(range(16, 32)))
        plain = bytes(range(32))
        value = base64.b64encode(java_seed_encrypt(plain, key, iv)).decode() + '::' + base64.b64encode(iv).decode()
        state = cg.UpdaterState(key=key)
        state.consume_cmd200_fields({'HASH_KEY': value}, agent_key=b'ignored-key.....')
        self.assertEqual(state.hash_key, plain.hex().upper())
        self.assertEqual(state.nonce_key('ignored-challenge'), plain.hex().upper())

    def test_rsa_key_wrap_independent_decryption(self):
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        key = bytes(range(16))
        wrapped = cg.rsa_wrap_key(private.public_key(), key)
        self.assertEqual(private.decrypt(base64.b64decode(wrapped), padding.PKCS1v15()), key)

class ExchangeStaticTests(unittest.TestCase):
    pass
