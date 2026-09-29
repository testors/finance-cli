import importlib.util
import json
import unittest
from giro.crypto import encrypt_text, hex_decode_app
from giro.response import receive

class ResponseTests(unittest.TestCase):

    def test_success_keeps_warning_conditions(self):
        response = receive('national.list', 200, [], '{"responseCode":"000","paymentList":null}')
        self.assertTrue(response.app_success)
        self.assertIsNone(response.query['paymentList'])

    def test_header_last_value_and_exact_marker(self):
        response = receive('national.list', 200, [('Mgiro-App-Encrypt', '1'), ('mgiro-app-encrypt', '01')], '{"responseCode":"000"}')
        self.assertTrue(response.app_success)

    def test_http_and_parse_failures(self):
        for (status, body, code) in ((500, '{"responseCode":"000"}', '500'), (204, None, '204'), (200, '', '605'), (200, 'null', '605'), (200, '[]', '605')):
            with self.subTest(status=status, body=body):
                result = receive('national.list', status, [], body)
                self.assertFalse(result.app_success)
                self.assertEqual(result.callback_code, code)

    def test_disconnect_is_not_normal_error_callback(self):
        for code in ('300', '301', '302'):
            response = receive('national.list', 200, [], json.dumps({'responseCode': code}))
            self.assertTrue(response.clear_session)
            self.assertEqual(response.callback, 'disconnected_session')
            self.assertIsNone(response.callback_code)

    def test_session_update_on_unsuccessful_response(self):
        response = receive('national.list', 200, [], json.dumps({'responseCode': '999', 'sessionInfo': {}, 'errorInfo': {'errorCode': '', 'errorName': 'name', 'errorMessage': 'message'}}))
        self.assertFalse(response.app_success)
        self.assertEqual(response.callback_code, '')
        self.assertIsNotNone(response.session_update)
        self.assertEqual(response.error_html, '<b>name</b><br/><br/>message')
        self.assertNotIn('message', repr(response))

    def test_hex_decoder_is_app_arithmetic_not_strict_validation(self):
        self.assertEqual(hex_decode_app('ABC'), b'\n\xbc')
        self.assertEqual(hex_decode_app(''), b'')
        self.assertEqual(hex_decode_app('gg'), b'\x10')
        self.assertEqual(hex_decode_app('  '), b'\xf0')

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto unavailable')
    def test_encrypted_response_roundtrip_and_bad_padding(self):
        key = bytes(range(16))
        plain = '{"responseCode":"000","paymentList":[]}'
        result = receive('national.list', 200, [('Mgiro-App-Encrypt', '1')], encrypt_text(plain, key).hex().upper(), key=key)
        self.assertTrue(result.app_success)
        self.assertEqual(receive('national.list', 200, [('Mgiro-App-Encrypt', '1')], '00', key=key).code, '605')
