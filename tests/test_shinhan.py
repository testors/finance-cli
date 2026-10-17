"""Synthetic settings, bank replies and loopback HTTP; no institution traffic."""
import base64
import contextlib
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.cli.main import main
from finance_cli.core import storage
from finance_cli.services.shinhan import session, setup, transport


def settings():
    return {'version': setup.VERSION, 'bank_key': bytes(range(32)).hex(), 'menu_version': 'SYN-MENU', 'e2e_key': 'SYN-E2E',
            'keypad_alphabet': b'0123456789'.hex(), 'pin_check_key': bytes(range(16)).hex(),
            'device': setup.device('SYN-ANDROID', 'SYN-MODEL', 'SYN-OS')}


def response(result='SUCCESS', body=None, **header):
    return json.dumps({'dataHeader': {'result': result, **header}, 'dataBody': body}).encode()


class PrivateHome(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(tempfile.TemporaryDirectory())
        self.home = Path(self.temp).resolve() / 'home'
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(self.home)}))

    def install(self):
        folder = setup.prepare_directory()
        storage.write_new(folder / 'settings.json', json.dumps(settings()).encode())

    def call(self, args, versioned=True):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main((['--format', 'json-v1'] if versioned else []) + ['shinhan', *args])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()


class SetupTests(PrivateHome):
    def test_new_device_identity_preserves_empty_unicode_and_input_order(self):
        actual = setup.device('가', '나', '')
        self.assertEqual(actual['device_id'], hashlib.sha256('가나'.encode()).hexdigest())
        self.assertEqual(actual['uuid1'], actual['uuid2'][:32])
        self.assertEqual(setup.device('', '', '')['device_id'], hashlib.sha256(b'').hexdigest())
        with self.assertRaises(ValueError):
            setup.device(None, '', '')

    def test_settings_install_from_synthetic_package_never_overwrites(self):
        target = Path(self.temp) / 'synthetic.zip'
        menu = b'{"G1":"SYN-MENU"}'
        with zipfile.ZipFile(target, 'w') as archive:
            archive.writestr('classes9.dex', b'SYNTHETIC-DATA')
            archive.writestr('classes5.dex', b'SYNTHETIC-E2E')
            archive.writestr('classes7.dex', b'SYNTHETIC-PIN-CHECK')
            archive.writestr('assets/menu_program_nss_default.json', menu)
        with patch.object(setup, 'PACKAGE_SHA256', hashlib.sha256(target.read_bytes()).hexdigest()), \
             patch.object(setup, 'MENU_SHA256', hashlib.sha256(menu).hexdigest()), \
             patch.object(setup, 'decode_key', return_value=bytes(range(32)).hex()), \
             patch.object(setup, 'decode_e2e_key', return_value='SYN-E2E'), \
             patch.object(setup, 'decode_keypad_alphabet', return_value=b'0123456789'.hex()), \
             patch.object(setup, 'decode_pin_check_key', return_value=bytes(range(16)).hex()):
            result = setup.install(target, {'android_id': 'SYN-ANDROID', 'model': 'SYN-MODEL', 'os_version': 'SYN-OS'})
            self.assertFalse(result['network_used'])
            self.assertEqual(setup.load(), settings())
            with self.assertRaises(FileExistsError):
                setup.install(target, {'android_id': 'DIFFERENT', 'model': '', 'os_version': ''})
            self.assertEqual(setup.load(), settings())
        self.assertEqual((setup.root() / 'settings.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(setup.root().stat().st_mode & 0o777, 0o700)

    def test_unknown_package_rejected_before_settings_written(self):
        target = Path(self.temp) / 'synthetic.zip'
        target.write_bytes(b'SYNTHETIC')
        with self.assertRaises(ValueError):
            setup.install(target, {'android_id': '', 'model': '', 'os_version': ''})
        self.assertFalse(self.home.exists())

    def test_refresh_changes_service_settings_without_replacing_identity_or_session(self):
        self.install()
        storage.atomic_json(setup.root() / 'session.json', {'cookie': 'SYN-COOKIE'})
        before = setup.load()
        with patch.object(setup, 'extract', return_value={'version': setup.VERSION, 'bank_key': before['bank_key'],
                                                         'menu_version': 'SYN-MENU', 'e2e_key': 'SYN-REFRESH'}):
            setup.refresh('synthetic.zip')
        self.assertEqual(setup.load()['device'], before['device'])
        self.assertEqual(setup.load()['e2e_key'], 'SYN-REFRESH')
        self.assertEqual(storage.read_json(setup.root() / 'session.json'), {'cookie': 'SYN-COOKIE'})


class TransportTests(unittest.TestCase):
    def test_body_is_encrypted_header_defaults_and_unicode_preserved(self):
        value = settings()
        wire = transport.encode('SYN-TRANSACTION', {'hello': '한글', 'count': 0}, value)
        envelope = json.loads(wire)
        self.assertEqual(envelope['dataHeader'], {
            'trxCd': 'SYN-TRANSACTION', 'language': '1', 'subChannel': '03',
            'uuid': value['device']['device_id'], 'encG': '1', 'appG': 'supersol'})
        key = bytes.fromhex(value['bank_key'])
        plaintext = unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(envelope['dataBody'])), 16)
        self.assertEqual(plaintext.decode(), '{"hello":"한글","count":0}')
        self.assertNotIn('한글', wire.decode())

    def test_bank_judgement_is_not_http_status_or_result_code(self):
        cases = [
            (200, response(body=None, resultCode='FAIL'), 'success'),
            (200, response('FAIL', {}, resultCode='SUCCESS'), 'failure'),
            (200, response('success', {}), 'unknown'),
            (200, response(' SUCCESS', {}), 'unknown'),
            (200, response(None, {}), 'unknown'),
            (200, b'{}', 'unknown'), (200, b'not-json', 'unknown'),
            (200, b'{"dataHeader":null}', 'unknown'),
            (204, response(body={}), 'unknown'), (205, response(body={}), 'unknown'),
            (302, response(body={}), 'unknown'), (500, response('FAIL', {}), 'unknown'),
        ]
        for status, body, verdict in cases:
            with self.subTest(status=status, body=body):
                result, _ = transport.parse(transport.Reply(status, [], body))
                self.assertEqual(result['bank_result'], verdict)

    def test_challenges_update_as_pair_without_requiring_bank_success(self):
        state = {'challenges': ['old1', 'old2']}
        transport.update_challenges(state, json.loads(response('FAIL', secChal1='', secChal2=None)))
        self.assertEqual(state['challenges'], ['old1', 'old2'])
        transport.update_challenges(state, json.loads(response('FAIL', secChal1=' ', secChal2=None)))
        self.assertEqual(state['challenges'], [' ', ''])
        transport.update_challenges(state, json.loads(response(secChal1=123, secChal2=True)))
        self.assertEqual(state['challenges'], ['123', 'true'])
        with self.assertRaises(ValueError):
            transport.update_challenges(state, json.loads(response(secChal1='new', secChal2={})))
        self.assertEqual(state['challenges'], ['123', 'true'])

    def test_cookie_uses_first_matching_name_and_rejects_unrelated_domain(self):
        state = {}
        transport.update_cookie(state, [('Set-Cookie', 'jsessionid=wrong'),
            ('Set-Cookie', 'JSESSIONID=wrong; Domain=other.invalid'),
            ('Set-Cookie', 'JSESSIONID=first; Path=/; HttpOnly; Secure'),
            ('Set-Cookie', 'JSESSIONID=second')])
        self.assertEqual(state, {'cookie': 'JSESSIONID=first'})
        transport.update_cookie(state, [('Set-Cookie', 'other=ignored')])
        self.assertEqual(state, {'cookie': 'JSESSIONID=first'})

    def test_transport_uses_one_post_no_redirect_and_decodes_gzip(self):
        received = []
        bodies = [response(body={}), response(body=None)]
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((self.path, dict(self.headers), self.rfile.read(int(self.headers['Content-Length']))))
                body = gzip.compress(bodies[len(received)-1])
                self.send_response(302 if len(received) == 1 else 200)
                self.send_header('Location', '/must-not-follow')
                self.send_header('Content-Encoding', 'gzip')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(transport.http.client, 'HTTPSConnection', side_effect=lambda *a, **kw: http.client.HTTPConnection(*server.server_address)):
                first = transport.post(b'{}', 'JSESSIONID=SYN-COOKIE')
                second = transport.post(b'{}')
            self.assertEqual(first.status, 302)
            self.assertEqual(first.body, bodies[0])
            self.assertEqual(second.body, bodies[1])
            self.assertEqual(len(received), 2)
            self.assertEqual(received[0][0], '/serviceEndpoint/httpDigital')
            self.assertEqual(received[0][1]['Cookie'], 'JSESSIONID=SYN-COOKIE')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_timeout_is_unknown_and_never_retried(self):
        with patch.object(transport.http.client, 'HTTPSConnection') as connection:
            connection.return_value.getresponse.side_effect = TimeoutError('SYN-SECRET')
            reply = transport.post(b'{}')
            self.assertEqual(connection.return_value.request.call_count, 1)
            result, _ = transport.parse(reply)
            self.assertEqual(result['bank_result'], 'unknown')
            self.assertNotIn('SYN-SECRET', json.dumps(result))


class SessionTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('External network forbidden')))

    def test_missing_send_help_and_status_never_read_settings_or_prompt(self):
        with patch.object(setup, 'load', side_effect=AssertionError('Settings read')), \
             patch('getpass.getpass', side_effect=AssertionError('Secret input')):
            for action in ('start', 'extend'):
                code, text, _ = self.call(['session', action])
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(text)['result']['error'], 'send_required')
            self.assertEqual(self.call(['--help'])[0], 0)
            self.assertEqual(self.call(['session', 'status'])[0], 0)
        self.assertFalse(self.home.exists())

    def test_arguments_and_local_errors_never_echo_private_values(self):
        for framed in (True, False):
            code, text, error = self.call(['SYN-PRIVATE-ARG'], framed)
            self.assertEqual(code, 2)
            self.assertNotIn('SYN-PRIVATE-ARG', text+error)
            with patch.object(session, 'status', side_effect=ValueError('SYN-PRIVATE-EXCEPTION')):
                code, text, error = self.call(['session', 'status'], framed)
                self.assertEqual(code, 2)
                self.assertNotIn('SYN-PRIVATE-EXCEPTION', text+error)

    def test_shortest_start_path_installs_once_then_reuses_default(self):
        def install(package, device):
            self.assertEqual(package, 'synthetic.zip')
            self.install()
        reply = transport.Reply(200, [], response(body={}))
        with patch('finance_cli.services.shinhan.cli.device_input', return_value={}) as inputs, \
             patch.object(setup, 'install', side_effect=install) as installer, \
             patch.object(transport, 'post', return_value=reply) as sender:
            self.assertEqual(self.call(['session', 'start', '--apk', 'synthetic.zip', '--send'])[0], 0)
            self.assertEqual(self.call(['session', 'start', '--send'])[0], 0)
            self.assertEqual(installer.call_count, 1)
            self.assertEqual(inputs.call_count, 1)
            self.assertEqual(sender.call_count, 2)

    def test_start_preserves_private_state_and_report_excludes_sensitive_values(self):
        self.install()
        reply = transport.Reply(200, [('Set-Cookie', 'JSESSIONID=SYN-PRIVATE-COOKIE')], response(
            body={'appNotiYnS1': 'Y', 'appNotiS1000': 'SYN-PRIVATE-TEXT'},
            secChal1='SYN-PRIVATE-CHALLENGE', secChal2='SECOND-PRIVATE-CHALLENGE'))
        with patch.object(transport, 'post', return_value=reply) as sender:
            code, text, errors = self.call(['session', 'start', '--send'])
        self.assertEqual(code, 0)
        value = json.loads(text)
        self.assertEqual(value['service'], 'shinhan')
        result = value['result']
        self.assertEqual(result['bank_result'], 'success')
        self.assertEqual(result['authentication'], 'unverified')
        self.assertTrue(result['intro']['notice'])
        self.assertEqual(sender.call_count, 1)
        private = storage.read_json(setup.root() / 'session.json')
        self.assertEqual(private['cookie'], 'JSESSIONID=SYN-PRIVATE-COOKIE')
        self.assertEqual(private['challenges'], ['SYN-PRIVATE-CHALLENGE', 'SECOND-PRIVATE-CHALLENGE'])
        report = storage.read_json(setup.root() / 'runs' / result['attempt'] / 'report.json')
        self.assertEqual(report, result)
        self.assertNotIn('PRIVATE', text+errors+json.dumps(report))
        self.assertEqual((setup.root() / 'session.json').stat().st_mode & 0o777, 0o600)

    def test_null_body_requires_start_body_but_extension_succeeds(self):
        self.install()
        reply = transport.Reply(200, [('Set-Cookie', 'JSESSIONID=SYN')], response())
        with patch.object(transport, 'post', return_value=reply) as sender:
            start = session.execute('start')
            self.assertEqual(start['bank_result'], 'success')
            self.assertEqual(start['processing_status'], 'incomplete')
            extend = session.execute('extend')
            self.assertEqual(extend['bank_result'], 'success')
            self.assertEqual(extend['processing_status'], 'complete')
        envelope = json.loads(sender.call_args.args[0])
        self.assertEqual(envelope['dataHeader']['trxCd'], 'RSMCM9000E03')
        key = bytes(range(32))
        decoded = unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(envelope['dataBody'])), 16)
        self.assertEqual(json.loads(decoded), {'osGS10': '03', 'appVersion': setup.VERSION, 'osVer': 'SYN-OS'})

    def test_success_survives_each_post_response_storage_failure(self):
        self.install()
        atomic, write = storage.atomic_json, storage.write_new
        for target in ('session.json', 'response.json', 'report.json'):
            with self.subTest(target=target):
                def save(path, value):
                    # Initial reservation must succeed; only fail after the response.
                    if Path(path).name == target and value.get('bank_result') == 'success':
                        raise OSError('SYN-PRIVATE-ERROR')
                    if Path(path).name == target == 'session.json':
                        raise OSError('SYN-PRIVATE-ERROR')
                    return atomic(path, value)
                def new(path, value):
                    if Path(path).name == target == 'response.json':
                        raise OSError('SYN-PRIVATE-ERROR')
                    return write(path, value)
                with patch.object(transport, 'post', return_value=transport.Reply(200, [], response(body={}))) as sender, \
                     patch.object(storage, 'atomic_json', side_effect=save), \
                     patch.object(storage, 'write_new', side_effect=new):
                    code, text, errors = self.call(['session', 'start', '--send'])
                result = json.loads(text)['result']
                self.assertEqual(code, 2)
                self.assertEqual(result['bank_result'], 'success')
                self.assertEqual(result['local_status'], 'incomplete')
                self.assertEqual(sender.call_count, 1)
                self.assertNotIn('SYN-PRIVATE-ERROR', text+errors)

    def test_failed_reservation_never_sends(self):
        self.install()
        with patch.object(storage, 'write_new', side_effect=OSError('SYN')), \
             patch.object(transport, 'post') as sender:
            with self.assertRaises(OSError):
                session.execute('start')
        sender.assert_not_called()


if __name__ == '__main__':
    unittest.main()
