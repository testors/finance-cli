"""Queue protocol and loopback HTTP, without any institution traffic."""
from dataclasses import asdict
from email.message import Message
import gzip
from http.client import RemoteDisconnected
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import math
import socket
import ssl
import struct
import threading
import unittest
from unittest.mock import Mock, patch

from finance_cli.services.shinhan import netfunnel_http as http, netfunnel_protocol as protocol, netfunnel_state as state


class StateTests(unittest.TestCase):
    def engine(self, replies, **options):
        self.calls, self.events, self.sleeps = [], [], []
        self.now = 1000.0
        replies = iter(replies)
        def send(url, params, timeout):
            self.calls.append(params)
            reply = next(replies)
            if isinstance(reply, Exception): raise reply
            return reply
        def sleep(seconds):
            self.sleeps.append(seconds); self.now += seconds
        client = protocol.Client(protocol.Property('service_4', 'sol_login_1', **options), send)
        return state.Engine(client, [lambda engine, event: self.events.append((event.code, event.error))],
                            sleep=sleep, clock=lambda: self.now)

    def test_native_retry_sleeps_after_last_failure_and_error_bypass_is_not_bank_success(self):
        engine = self.engine([OSError('synthetic')]*3)
        engine.begin()
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.sleeps, [1, 1, 1])
        self.assertEqual(self.events, [(980, 909)])
        self.assertEqual(engine.client.response.code, 0)

    def test_continue_ttl_interval_and_terminal_events(self):
        engine = self.engine(['201:key=SYN&ttl=2&nwait=10', '200:key=SYN'])
        engine.begin()
        self.assertEqual(self.events, [(201, 201), (211, 201), (200, 200)])
        self.assertEqual(self.sleeps, [2, .5, .5])
        self.assertEqual(self.calls[-1], [('opcode', '5002'), ('key', 'SYN')])
        self.assertEqual(engine.progress.current.nwait, 10)

    def test_wait_stop_and_wait_exception_are_distinct(self):
        for stop in (True, False):
            engine = self.engine(['201:key=SYN&ttl=2'])
            def sleep(seconds):
                if stop: engine.stop_continue = True
                else: raise InterruptedError('synthetic')
            engine.sleep = sleep
            engine.begin()
            self.assertEqual(self.events, [(201, 201), (203, 111) if stop else (980, 909)])
            self.assertEqual(len(self.calls), 1)

    def test_stale_queue_check_precedes_new_success_event(self):
        engine = self.engine(['201:key=SYN&ttl=2', '200:key=SYN'], stale_seconds=1)
        engine.begin()
        self.assertEqual(self.events[-1], (980, 908))
        self.assertEqual(engine.client.response.code, 200)

    def test_load_failure_never_uses_error_bypass_and_listener_exception_is_isolated(self):
        engine = self.engine([])
        engine.load = lambda: False
        engine.listeners.insert(0, Mock(side_effect=ValueError('synthetic')))
        engine.begin()
        self.assertEqual(self.events, [(981, 928)])
        self.assertEqual(self.calls, [])

    def test_completion_failure_is_once_only_and_does_not_change_previous_event(self):
        engine = self.engine(['200:key=SYN', OSError('synthetic')])
        engine.begin(); engine.end()
        self.assertEqual(self.events, [(200, 200)])
        self.assertEqual(engine.client.response.key, 'SYN')
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.sleeps, [])

    def test_local_error_is_not_retried_or_error_bypassed(self):
        engine = self.engine([protocol.LocalError('local')])
        with self.assertRaises(protocol.LocalError): engine.begin()
        self.assertEqual(self.events, [])
        self.assertEqual(self.sleeps, [])
        self.assertEqual(len(self.calls), 1)

    def test_progress_is_copied_and_caps_against_first_nonzero_estimate(self):
        progress = state.Progress()
        response = protocol.Response(nwait=10, tps=3)
        progress.update(response)
        self.assertEqual(progress.wait_time(), protocol.float32('3.333333333333333333333'))
        response.nwait = 3
        self.assertEqual(progress.current.nwait, 10)
        progress.update(response)
        self.assertEqual(progress.wait_time(), 1)
        response.nwait = 6; progress.update(response)
        self.assertEqual(progress.wait_time(), 2)
        response.tps = math.inf; progress.update(response)
        self.assertEqual(progress.wait_time(), 0)


class ProtocolTests(unittest.TestCase):
    def test_parser_keeps_native_split_and_integer_rules(self):
        value = protocol.parse('+201:key=first&key=&key=last=ignored&ttl=٢&nwait=-1&unknown=x')
        self.assertEqual((value.code, value.key, value.ttl, value.nwait), (201, 'last', 2, -1))
        self.assertEqual(protocol.parse('200:key=first&key==last').key, '')
        self.assertEqual(protocol.parse('777:key=x').code, 0)
        for text in ['200', ' 200:', '200:ttl=bad&ttl=1', '200:nwait=2147483648', '200:port=𝟙']:
            with self.assertRaises(protocol.CodeError) as error: protocol.parse(text)
            self.assertEqual(error.exception.code, 905)
        with self.assertRaises(AttributeError): protocol.parse(None)

    def test_float_rounds_directly_and_preserves_native_special_values(self):
        bits = lambda s: int.from_bytes(struct.pack('!f', protocol.float32(s)), 'big')
        self.assertEqual(bits('1.000000059604644775390625'), 0x3f800000)
        self.assertEqual(bits('1.000000059604644775390626'), 0x3f800001)
        self.assertEqual(bits('0x1p-149'), 1)
        self.assertEqual(bits('-0'), 0x80000000)
        self.assertTrue(math.isnan(protocol.float32('NaN')))
        self.assertEqual(protocol.float32('1e999999999999999999999'), math.inf)
        self.assertEqual(protocol.float32('-1e-99999999999999999999'), -0.0)
        for value in ['nan', '1_0', 'NaNf']:
            with self.assertRaises(ValueError): protocol.float32(value)

    def test_failed_initial_clears_key_but_later_failure_preserves_response(self):
        send = Mock(side_effect=OSError('synthetic'))
        client = protocol.Client(protocol.Property('service_4', 'sol_login_1'), send)
        for opcode in (5002, 5003, 5004, 5101):
            client.response = protocol.parse('201:key=old-synthetic&ttl=2')
            with self.assertRaises(protocol.CodeError) as error: client.execute(opcode)
            self.assertEqual(error.exception.code, 920)
            self.assertEqual(client.response.key, '' if opcode == 5101 else 'old-synthetic')
        self.assertEqual(len(send.call_args_list), 4)

    def test_complete_ignores_body_and_empty_key_commands_do_not_send(self):
        send = Mock(return_value='not a queue response')
        client = protocol.Client(protocol.Property('service_1', 'SYN'), send)
        client.response = protocol.parse('201:key=old-synthetic&ttl=2')
        client.execute(5004)
        self.assertEqual(asdict(client.response), asdict(protocol.Response()))
        for opcode in (5002, 5003, 5004): client.execute(opcode)
        send.assert_called_once()
        self.assertEqual(send.call_args.args[1], [('opcode', '5004'), ('key', 'old-synthetic')])

    def test_inflight_complete_clears_current_response_after_a_poll_replaces_it(self):
        def send(url, params, timeout):
            self.assertEqual(params[-1], ('key', 'old-synthetic'))
            client.response = protocol.parse('200:key=new-synthetic')
            return 'ignored'
        client = protocol.Client(protocol.Property('service_1', 'SYN'), send)
        old = client.response = protocol.parse('201:key=old-synthetic')
        client.execute(5004)
        self.assertEqual(old.key, 'old-synthetic')
        self.assertEqual(client.response.key, '')

    def test_command_url_user_data_and_response_host_follow_native_policy(self):
        send = Mock(return_value='201:key=synthetic&ip=other.invalid&port=81')
        client = protocol.Client(protocol.Property('service_4', 'sol_login_1', user_data='a b\u00a0c\td'), send)
        client.execute(5101)
        self.assertEqual(send.call_args.args, ('http://apc.shinhan.com/ts.wseq',
            [('opcode', '5101'), ('sid', 'service_4'), ('aid', 'sol_login_1'), ('user_data', 'abc\td')], 3))
        client.execute(5002)
        self.assertEqual(send.call_args.args[0], 'http://apc.shinhan.com/ts.wseq')
        client.properties.host_fixed = False; client.execute(5002)
        self.assertEqual(send.call_args.args[0], 'http://other.invalid:81/ts.wseq')

    def test_local_limit_remains_distinct_from_sdk_error(self):
        client = protocol.Client(protocol.Property('service_1', 'SYN'), Mock(side_effect=protocol.LocalError('local limit')))
        with self.assertRaises(protocol.LocalError): client.execute(5101)
        self.assertEqual(client.response.key, '')


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        requests = self.requests
        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args): pass
            def do_GET(self):
                requests.append((self.path, dict(self.headers)))
                path = self.path.partition('?')[0]
                if path == '/dropped' and len([p for p,h in requests if p == '/dropped']) < 4:
                    self.close_connection = True; return
                body = '200:key=합성'.encode()
                code, headers = 503, {'Content-Type': 'text/plain; charset=UTF-8'}
                if path == '/redirect':
                    code = 302; headers.update(Location='/value', **{'Set-Cookie': 'QUEUE=SYN; Path=/'})
                elif path == '/redirectdrop':
                    code = 302; headers['Location'] = '/dropped'
                elif path in ('/a', '/b'):
                    code = 301; headers['Location'] = '/a' if path == '/b' else '/b'
                elif path == '/missing':
                    code = 302
                elif path == '/308':
                    code = 308; headers['Location'] = '/value'
                elif path == '/latin':
                    body = b'200:key=\xe9'; headers.clear()
                elif path == '/gzip':
                    body = gzip.compress(b'200:key=SYN'); headers = {'Content-Encoding': 'gzip'}
                elif path == '/204':
                    body = b''; code = 204
                self.send_response(code)
                for key, value in headers.items(): self.send_header(key, value)
                self.send_header('Connection', 'close'); self.close_connection = True
                self.send_header('Content-Length', str(len(body))); self.end_headers()
                self.wfile.write(body)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.close)
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()

    def test_java_query_encoding_and_existing_query_separator(self):
        self.assertEqual(http.form('a b*~+가'), 'a+b*%7E%2B%EA%B0%80')
        self.assertEqual(http.form('\ud83d\ude00\ud800'), '%F0%9F%98%80%3F')
        self.assertEqual(http.request_url('/x?', [('key', None)]), '/x?&key=')
        self.assertEqual(http.request_url('/x?q=1', [('key', 'value')]), '/x?q=1?key=value')
        self.assertEqual(http.request_url('/x', [('', None)]), '/x')
        http.get(self.base+'/value', [('key', 'a b*~')])
        self.assertEqual(self.requests[0][0], '/value?key=a+b*%7E')
        self.assertNotIn('Accept-Encoding', self.requests[0][1])
        self.assertEqual(self.requests[0][1]['User-Agent'], 'Apache-HttpClient/UNAVAILABLE (java 1.4)')
        http.get(self.base+'/합성?q=값')
        self.assertEqual(self.requests[1][0], '/%ED%95%A9%EC%84%B1?q=%EA%B0%92')

    def test_http_status_body_charset_and_cookie_scope(self):
        events = []
        self.assertEqual(http.get(self.base+'/redirect', observe=events.append), '200:key=합성')
        self.assertEqual(self.requests[-1][1].get('Cookie'), 'QUEUE=SYN')
        http.get(self.base+'/value')
        self.assertNotIn('Cookie', self.requests[-1][1])
        self.assertEqual(http.get(self.base+'/latin'), '200:key=é')
        self.assertNotIn('SYN', str(events))
        self.assertEqual([e['http_status'] for e in events if 'http_status' in e], [302, 503])

    def test_redirect_cycle_missing_location_and_non_redirect_308(self):
        with self.assertRaisesRegex(ValueError, 'cycle'): http.get(self.base+'/a')
        self.assertEqual([p for p,h in self.requests], ['/a', '/b', '/a'])
        with self.assertRaisesRegex(ValueError, 'location'): http.get(self.base+'/missing')
        self.requests.clear()
        self.assertEqual(http.get(self.base+'/308'), '200:key=합성')
        self.assertEqual(len(self.requests), 1)

    def test_no_response_is_retried_three_times_by_http_layer(self):
        events = []
        self.assertEqual(http.get(self.base+'/dropped', observe=events.append), '200:key=합성')
        self.assertEqual(len(self.requests), 4)
        self.assertEqual([e['retry'] for e in events if 'retry' in e], [True]*3)
        self.assertFalse(http.may_retry(RemoteDisconnected(), 4, True))
        for error in [TimeoutError(), InterruptedError(), socket.gaierror(), ssl.SSLError(), ConnectionResetError()]:
            self.assertFalse(http.may_retry(error, 1, True))
        self.assertTrue(http.may_retry(ConnectionResetError(), 1, False))

    def test_redirect_attempts_count_toward_http_retry_limit(self):
        with self.assertRaises(RemoteDisconnected): http.get(self.base+'/redirectdrop')
        self.assertEqual([p for p,h in self.requests], ['/redirectdrop']+['/dropped']*3)

    def test_charset_uses_first_element_and_preserves_invalid_empty_charset(self):
        self.assertEqual(http.charset({'Content-Type': 'text/plain; charset=UTF-8, text/plain; charset=ISO-8859-1'}), 'UTF-8')
        self.assertEqual(http.charset({'Content-Type': 'text/plain; x="a,b"; charset="UTF-8"'}), 'UTF-8')
        self.assertEqual(http.charset({'Content-Type': 'text/plain; charset=""'}), '')

    def test_no_automatic_gzip_decode_or_status_based_rejection(self):
        raw = http.get(self.base+'/gzip')
        self.assertEqual(gzip.decompress(raw.encode('iso-8859-1')), b'200:key=SYN')
        with self.assertRaisesRegex(ValueError, 'entity_missing'): http.get(self.base+'/204')

    def test_diagnostics_cannot_change_http_result_or_request_count(self):
        self.assertEqual(http.get(self.base+'/value', observe=Mock(side_effect=OSError('diagnostic'))), '200:key=합성')
        self.assertEqual(len(self.requests), 1)

    def test_entity_read_error_is_not_an_http_retry_and_close_error_is_consumed(self):
        headers = Message(); headers['Content-Type'] = 'text/plain'
        response = Mock(status=200, headers=headers)
        response.info.return_value = headers; response.getheader.return_value = None
        response.read.side_effect = OSError('body read')
        connection = Mock(); connection.getresponse.return_value = response
        connection.close.side_effect = OSError('close')
        with patch.object(http.http.client, 'HTTPConnection', return_value=connection):
            with self.assertRaisesRegex(OSError, 'body read'): http.get(self.base)
            self.assertEqual(connection.endheaders.call_count, 1)
            response.read.side_effect = None; response.read.return_value = b'200:key=SYN'
            self.assertEqual(http.get(self.base), '200:key=SYN')

    def test_local_size_limit_is_not_turned_into_native_bypass_error(self):
        with patch.object(http, 'LIMIT', 1):
            with self.assertRaises(protocol.LocalError): http.get(self.base+'/value')
