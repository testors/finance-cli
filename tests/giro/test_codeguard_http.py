"""Verified loopback TLS and synthetic exchanges; never institution requests."""
import base64
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import ssl
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from giro.codeguard_effects import Effect
from giro.codeguard_http import CodeGuardHTTP, HTTPBoundary, project_http_steps
from giro.codeguard_http_values import decode_values_steps
from giro.android_headers import project_header_values_steps
from giro.codeguard_updater import challenge_steps, token_steps
from giro.codeguard_service import generate_token_http_values_steps
from giro.codeguard_codec import java_seed_encrypt
from giro.codeguard_crypto import CodeGuardCrypto, CRYPTO_EFFECTS, project_crypto_steps
from giro.codeguard_certificate_values import NativeByteArrayValue
from giro.codeguard_fingerprint_values import KnownCertificateStream
from giro.codeguard_package import project_package_steps
from giro.codeguard_string_values import project_native_value_steps
from giro.codeguard_inputs import NonceArtifacts, nonce_artifact_codes, fallback_nonce_key
from giro.codeguard_nonce import cg_auth_code
from cg_exchange_fixture import Transcript, drive
from test_codeguard_native_start import NativeObservations, rule
from test_codeguard_native_nonce import NonceObservations
from test_codeguard_package import PackageObservations, Entry
from test_codeguard_fingerprint_values import bag
from test_codeguard_string_values import path_values


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args): pass
    def do_GET(self): self.respond()
    def do_POST(self): self.respond()

    def respond(self):
        command = int(parse_qs(urlsplit(self.path).query)['CODEGUARD_CMD'][0])
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.server.calls.append((command, self.command, self.path, tuple(self.headers.items()), body))
        status, headers, payload = self.server.reply(command, body, self)
        self.send_response(status)
        for name, value in headers: self.send_header(name, value)
        chunked = any(k.lower() == 'transfer-encoding' and v.lower() == 'chunked' for k,v in headers)
        if not chunked and not any(k.lower() == 'content-length' for k,v in headers):
            self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        if chunked:
            for chunk in (payload[:3], payload[3:]):
                if chunk: self.wfile.write(('%x\r\n' % len(chunk)).encode()+chunk+b'\r\n')
            self.wfile.write(b'0\r\n\r\n')
        else: self.wfile.write(payload)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        at = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'SYNTHETIC LOOPBACK')])
        cls.certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(cls.private.public_key()).serial_number(1)
            .not_valid_before(at-timedelta(days=1)).not_valid_after(at+timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
            .sign(cls.private, hashes.SHA256()))
        cert, key = Path(cls.temp.name)/'cert.pem', Path(cls.temp.name)/'key.pem'
        cert.write_bytes(cls.certificate.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(cls.private.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.base = 'https://127.0.0.1:%d/CodeGuard/' % cls.server.server_port
        cls.endpoint = cls.base+'CodeGuard/check.jsp'
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def setUp(self):
        self.server.calls = []
        self.server.reply = lambda command, body, handler: (200, [], b'{"CODE_TOKEN":"SYNTHETIC TOKEN"}')
        self.obs = Transcript()
        self.obs.runtime.url = self.base
        self.transports = []

    def tearDown(self):
        for transport in self.transports: transport.close()

    def transport(self, **changes):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=self.certificate.public_bytes(serialization.Encoding.PEM).decode())
        options = dict(endpoint=self.endpoint, send=True, default_user_agent='synthetic-default-UA',
                       max_requests=5, tls_context=context)
        options.update(changes)
        transport = CodeGuardHTTP(**options)
        self.transports.append(transport)
        return transport

    def run_steps(self, generator, transport):
        generator = decode_values_steps(project_header_values_steps(generator), locale_language='ko')
        return drive(project_http_steps(generator, transport=transport), self.obs.reply)

    def token(self, transport):
        return self.run_steps(token_steps(self.obs.runtime, self.obs.agent, self.obs.main, 'first', 'second'), transport)

    def test_tls_cmd200_cookie_order_cmd300_post_and_raw_json_conversion(self):
        def reply(command, body, handler):
            if command == 200:
                return 200, [('Set-Cookie', 'one=1'), ('set-cookie', 'two=2')], b'{CODE_CHALLENGE:"c::r"}'
            return 200, [('Set-Cookie', 'ignored=3')], b'{CODE_TOKEN:7}'
        self.server.reply = reply
        transport = self.transport()
        value = self.run_steps(challenge_steps(self.obs.runtime, self.obs.agent, self.obs.main, 'APP1'), transport)
        self.assertEqual(value, 'c::r')
        self.assertEqual(self.obs.runtime.data.cookie, 'one=1; two=2')
        self.assertEqual(self.token(transport), '7')
        first, second = self.server.calls
        self.assertEqual([first[0], second[0]], [200, 300])
        headers = dict(second[3])
        self.assertEqual(headers['Cookie'], 'one=1; two=2')
        self.assertEqual(headers['Accept-Encoding'], 'gzip')
        self.assertEqual(headers['User-Agent'], 'synthetic-UA')
        self.assertEqual(second[4], b'&CODE_RESPONSE=first&CODE_RESPONSE2=second&FIXED=true')
        self.assertEqual(transport.attempts, 2)
        self.assertEqual(self.obs.runtime.data.cookie, 'one=1; two=2')
        self.assertEqual(self.obs.requests, [])  # no mock HTTP fallback
        self.assertNotIn('SYNTHETIC TOKEN', repr(transport.connections))
        self.assertNotIn('one=1', json.dumps(transport.events))

    def test_buffered_post_opens_tls_but_flush_close_connect_do_not_send(self):
        transport = self.transport()
        connection = transport.resolve(Effect('http_open', (self.endpoint+'?CODEGUARD_CMD=300',)))
        call = lambda method, *args: transport.resolve(Effect('http_call', (connection, method, args)))
        call('setRequestMethod', 'POST')
        call('setDoOutput', True)
        call('getOutputStream')
        for kind, extra in (('write_bytes', (b'body',)), ('flush_output', ()), ('close_output', ())):
            transport.resolve(Effect(kind, (connection, *extra)))
        call('connect')
        self.assertEqual(self.server.calls, [])
        self.assertEqual(call('getResponseCode'), 200)
        self.assertEqual(call('getResponseCode'), 200)
        self.assertEqual(len(self.server.calls), 1)
        self.assertEqual(self.server.calls[0][4], b'body')

    def test_gzip_chunked_utf8_cr_lines_and_exposed_header_removal(self):
        raw = '{\rCODE_TOKEN:"한글"\r}\r'.encode()
        self.server.reply = lambda *_: (200, [('Content-Encoding','GZip'), ('Transfer-Encoding','Chunked')], gzip.compress(raw))
        transport = self.transport()
        self.assertEqual(self.token(transport), '한글')
        fields = transport.connections[0].header_fields
        self.assertIsNone(fields.get('Content-Encoding'))
        self.assertIsNone(fields.get('Content-Length'))

    def test_cmd101_real_der_rsa_key_wrap_hash_key_then_token_exchange(self):
        der = self.certificate.public_bytes(serialization.Encoding.DER)
        state = {}
        def reply(command, body, handler):
            if command == 101:
                document = {'CERT':base64.b64encode(der).decode(), 'ENGINE_VERSION':'test', 'ENGINE_MD':''}
            elif command == 200:
                query = parse_qs(urlsplit(handler.path).query)
                key = self.private.decrypt(base64.b64decode(query['KEY'][0]), padding.PKCS1v15())
                state['key'] = key
                iv = b'I'*16
                document = {'CODE_CHALLENGE':'c::r', 'HASH_KEY':base64.b64encode(java_seed_encrypt(b'known', key, iv)).decode()+'::'+base64.b64encode(iv).decode()}
            else: document = {'CODE_TOKEN':'loopback-issued'}
            return 200, [], json.dumps(document).encode()
        self.server.reply = reply
        self.obs.preferences['CERT'] = ''
        self.obs.agent.certificate_text = ''
        transport = self.transport()
        generator = generate_token_http_values_steps(self.obs.main, self.obs.runtime, self.obs.agent,
            locale_language='ko', project_headers=True, server_url=self.base,
            timeout=1000, root_check=True, rooting_info=False, encrypted_token=False)
        generator = project_crypto_steps(generator, crypto=CodeGuardCrypto())
        self.assertEqual(drive(project_http_steps(generator, transport=transport), self.obs.reply), 'loopback-issued')
        self.assertEqual([call[0] for call in self.server.calls], [101, 200, 300])
        self.assertEqual(state['key'], self.obs.agent.key)
        self.assertEqual(self.obs.runtime.data.hash_key, b'known'.hex().upper())
        self.assertTrue(CRYPTO_EFFECTS.isdisjoint(self.obs.kinds()))

    def test_get_mode_uses_query_and_keeps_empty_cookie_without_agent_fallback(self):
        self.obs.preferences['GETMODE'] = True
        transport = self.transport()
        self.assertEqual(self.token(transport), 'SYNTHETIC TOKEN')
        call, = self.server.calls
        self.assertEqual(call[1], 'GET')
        self.assertEqual(call[4], b'')
        self.assertEqual(dict(call[3])['Cookie'], '')
        self.assertIn('CODE_RESPONSE=first', call[2])

    def test_native_package_and_certificate_calculations_reach_actual_tls_post(self):
        self.server.reply = lambda command, *_: (200, [], json.dumps(
            {'CODE_CHALLENGE':'TQ==::'+rule()} if command == 200 else {'CODE_TOKEN':'calculated-loopback'}).encode())
        self.obs.main.pid = '123'
        first, second, package = NativeObservations(), NonceObservations(), PackageObservations()
        second.der = self.certificate.public_bytes(serialization.Encoding.DER)
        self.obs.agent.certificate_text = base64.b64encode(second.der).decode()
        second.digest = hashlib.sha256(second.der).digest()
        second.override = lambda e: (True, NativeByteArrayValue(second.der)) if (
            e.kind == 'native_jni' and e.args[:3] == ('CallObjectMethod', 'signature', 'toByteArray')) else (False, None)
        package.archives[package.source] = [Entry(e.name, bag([second.der]) if e.name.endswith('.RSA') else e.data)
                                            for e in package.archives[package.source]]
        stage = 'first'
        def reply(e):
            nonlocal stage
            if e.kind == 'package_java':
                stage = 'second'
                result = (KnownCertificateStream(e.args[2].data) if e.args[0] == 'zip.getInputStream'
                          and e.args[2].name.endswith('.RSA') else package.reply(e))
                second.files = {key.encode():value for key,value in package.files.items()}
                return result
            if e.kind.startswith('native_'): return path_values(first if stage == 'first' else second, e)
            return self.obs.reply(e)
        generator = generate_token_http_values_steps(self.obs.main, self.obs.runtime, self.obs.agent,
            locale_language='ko', project_headers=True, server_url=self.base,
            timeout=1000, root_check=True, rooting_info=False, encrypted_token=False)
        generator = project_package_steps(project_native_value_steps(generator, service='service',
            certificate_values=True), certificate_values=True)
        generator = project_crypto_steps(generator, crypto=CodeGuardCrypto())
        result = drive(project_http_steps(generator, transport=self.transport()), reply)
        self.assertEqual(result, 'calculated-loopback')
        materials = NonceArtifacts(*(package.files[package.destination+suffix] for suffix in (
            '/lib/libCodeGuard.so','/lib/libImageDecoder.so','/classes.dex','/META-INF/MANIFEST.MF','/META-INF/CERT.SF')), second.der)
        expected = cg_auth_code(fallback_nonce_key('TQ=='), nonce_artifact_codes(materials, 'TQ==', is_mix=False, is_split=False))
        form = parse_qs(self.server.calls[-1][4].decode())
        self.assertEqual(form['CODE_RESPONSE2'], [expected])
        self.assertEqual(package.calls('certificateFactory.generateCertificate'), [])
        for coarse in ('native_start', 'native_get_nonce', 'check_fingerprint', 'check_zip_os14'):
            self.assertNotIn(coarse, self.obs.kinds())
        self.assertEqual(self.obs.requests, [])
        self.assertTrue(CRYPTO_EFFECTS.isdisjoint(self.obs.kinds()))

    def test_no_send_and_endpoint_scope_stop_before_socket_or_body(self):
        transport = self.transport(send=False)
        with patch('socket.create_connection', side_effect=AssertionError('no network')):
            with self.assertRaises(HTTPBoundary) as error: self.token(transport)
            self.assertEqual(error.exception.stage, 'send_not_enabled')
            for url in (self.endpoint.replace('https:', 'http:')+'?CODEGUARD_CMD=300',
                        self.endpoint+'?CODEGUARD_CMD=999', self.endpoint+'?CODEGUARD_CMD=300#secret'):
                with self.assertRaises(HTTPBoundary): transport.resolve(Effect('http_open', (url,)))
        self.assertEqual(self.server.calls, [])
        self.assertEqual(transport.attempts, 0)

    def test_request_budget_stops_second_exchange_without_retry(self):
        transport = self.transport(max_requests=1)
        self.assertEqual(self.token(transport), 'SYNTHETIC TOKEN')
        with self.assertRaises(HTTPBoundary) as error: self.token(transport)
        self.assertEqual(error.exception.stage, 'request_budget')
        self.assertEqual(len(self.server.calls), 1)

    def test_token_empty_missing_and_json_null_keep_value_semantics(self):
        for payload, expected in ((b'{"CODE_TOKEN":""}', ''), (b'{}', None),
                                  (b'{"CODE_TOKEN":null}', None)):
            with self.subTest(payload=payload):
                self.server.reply = lambda *_, p=payload: (200, [], p)
                self.assertEqual(self.token(self.transport()), expected)

    def test_truncated_and_invalid_compressed_bodies_stay_unresolved_and_do_not_retry(self):
        for headers, payload in (([('Content-Length','99'), ('Connection','close')], b'{}'),
                                 ([('Content-Encoding','gzip')], gzip.compress(b'{}')[:-5]),
                                 ([('Content-Encoding','gzip')], bytes.fromhex('1f8b0800000000000000ff'))):
            with self.subTest(headers=headers):
                self.server.reply = lambda *_, h=headers, p=payload: (200, h, p)
                transport = self.transport()
                before = len(self.server.calls)
                with self.assertRaises(HTTPBoundary) as error: self.token(transport)
                self.assertEqual(error.exception.stage, 'transport_or_stream')
                connection = transport.connections[0]
                with self.assertRaises(HTTPBoundary) as again:
                    transport.resolve(Effect('http_call', (connection, 'getResponseCode', ())))
                self.assertEqual(again.exception.stage, 'failed_connection_not_retried')
                self.assertEqual(len(self.server.calls), before+1)
                self.assertEqual(transport.attempts, 1)

    def test_tls_trust_failure_stays_processing_boundary_without_http_or_retry(self):
        transport = self.transport(tls_context=ssl.create_default_context())
        with self.assertRaises(HTTPBoundary) as error: self.token(transport)
        self.assertEqual(error.exception.stage, 'transport_or_stream')
        self.assertEqual(transport.attempts, 1)
        self.assertEqual(self.server.calls, [])
        self.assertNotIn('E101_NET_ERROR', str(error.exception))

    def test_unverified_tls_context_is_rejected(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with self.assertRaises(HTTPBoundary): self.transport(tls_context=context)

    def test_redirect_is_unresolved_and_never_followed(self):
        self.server.reply = lambda *_: (302, [('Location', self.endpoint+'?CODEGUARD_CMD=300')], b'')
        transport = self.transport()
        with self.assertRaises(HTTPBoundary) as error: self.token(transport)
        self.assertEqual(error.exception.stage, 'redirect_or_interim_response')
        self.assertEqual(len(self.server.calls), 1)

    def test_http_error_headers_precede_known_input_stream_exception(self):
        self.server.reply = lambda *_: (403, [('Set-Cookie', 'before-error=1')], b'not JSON')
        transport = self.transport()
        value = self.run_steps(challenge_steps(self.obs.runtime, self.obs.agent, self.obs.main, 'APP'), transport)
        self.assertTrue(value.startswith('E101_NET_ERROR_001'))
        self.assertEqual(self.obs.runtime.data.cookie, 'before-error=1')
        self.assertEqual(len(self.server.calls), 1)
        self.assertNotIn('before-error=1', repr(transport.connections))

    def test_folded_headers_and_body_limits_do_not_turn_into_java_network_errors(self):
        for headers, body, limit, stage in (([('Set-Cookie','a=1\r\n b=2')], b'{}', 50, 'header_framing'),
                                          ([], b'12345', 4, 'body_budget')):
            self.server.reply = lambda *_, h=headers, b=body: (200, h, b)
            transport = self.transport(max_body_bytes=limit)
            with self.assertRaises(HTTPBoundary) as error: self.token(transport)
            self.assertEqual(error.exception.stage, stage)

    def test_final_cleanup_failure_cannot_erase_returned_token(self):
        transport = self.transport()
        token = self.token(transport)
        client = transport.connections[0].client
        client.close()
        with patch.object(client, 'close', side_effect=OSError('sensitive cleanup detail')):
            transport.close()
        self.assertEqual(token, 'SYNTHETIC TOKEN')
        self.assertEqual(transport.events[-1]['phase'], 'cleanup_error')
        self.assertNotIn('sensitive', json.dumps(transport.events))

    def test_explicit_command_sequence_rejects_refresh_before_connect(self):
        transport = self.transport(request_sequence=((101, 'GET'), (200, 'GET'), (300, 'POST')))
        def request(command, method='GET'):
            connection = transport.resolve(Effect('http_open', (self.endpoint+'?CODEGUARD_CMD='+str(command),)))
            transport.resolve(Effect('http_call', (connection, 'setRequestMethod', (method,))))
            return transport.resolve(Effect('http_call', (connection, 'getResponseCode', ())))
        self.assertEqual(request(101), 200)
        self.assertEqual(request(200), 200)
        with self.assertRaises(HTTPBoundary) as error: request(200)
        self.assertEqual(error.exception.stage, 'request_sequence')
        self.assertEqual(transport.attempts, 2)
        self.assertEqual([row[0] for row in self.server.calls], [101, 200])

    def test_explicit_sequence_requires_post_and_allows_only_one_token_exchange(self):
        transport = self.transport(request_sequence=((200, 'GET'), (300, 'POST')))
        self.run_steps(challenge_steps(self.obs.runtime, self.obs.agent, self.obs.main, 'APP'), transport)
        self.obs.preferences['GETMODE'] = True
        with self.assertRaises(HTTPBoundary) as error: self.token(transport)
        self.assertEqual(error.exception.stage, 'request_sequence')
        self.assertEqual(transport.attempts, 1)
        self.obs.preferences['GETMODE'] = False
        self.assertEqual(self.token(transport), 'SYNTHETIC TOKEN')
        with self.assertRaises(HTTPBoundary) as error: self.token(transport)
        self.assertEqual(error.exception.stage, 'request_sequence')
        self.assertEqual([row[:2] for row in self.server.calls], [(200, 'GET'), (300, 'POST')])

    def test_sequence_configuration_is_explicit_and_does_not_enable_send(self):
        for sequence in ((), [ (101, 'GET') ], ((101, 'POST'),), ((999, 'GET'),), ((True, 'GET'),)):
            with self.subTest(sequence=sequence), self.assertRaises(HTTPBoundary):
                self.transport(request_sequence=sequence)
        transport = self.transport(send=False, request_sequence=((300, 'POST'),))
        with self.assertRaises(HTTPBoundary) as error: self.token(transport)
        self.assertEqual(error.exception.stage, 'send_not_enabled')
        self.assertEqual(transport.attempts, 0)
        self.assertEqual(self.server.calls, [])


if __name__ == '__main__': unittest.main()
