"""MO SMS and SSE use only synthetic bank responses and in-memory streams."""
import base64
import io
import json
import threading
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.core import storage
from finance_cli.services.shinhan import device_phone as phone, issuance_input, setup, transport
from finance_cli.services.shinhan.enrollment import Pending
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, response, settings


def reply(body, result='SUCCESS'):
    return transport.Reply(200, [], response(result, body))


class FakeStream:
    def __init__(self, query, callback):
        self.query, self.callback = query, callback
        self.status, self.error, self.events = 200, None, []
        self.closed = threading.Event()

    def start(self):
        pass

    def trigger(self, status='TRIGGER_SENT'):
        event = {'data': {'status': status}}
        self.events.append(event)
        self.callback(event)

    def close(self):
        self.closed.set()


class PhoneTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.install()
        self.state = {'cookie': 'JSESSIONID=SYN-COOKIE'}
        self.exchange = Exchange(settings(), self.state, 'synthetic-device-phone')
        self.calls = []
        self.replies = []
        def send(payload, cookie):
            envelope = json.loads(payload)
            key = bytes.fromhex(settings()['bank_key'])
            body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(envelope['dataBody'])), 16))
            self.calls.append((envelope['dataHeader'], body))
            return self.replies.pop(0)
        self.enterContext(patch.object(transport, 'post_web', side_effect=send))

    def prepare(self, events='N', result='SUCCESS', message='A9b2-Cd'):
        self.replies = [reply({'respTelnoS20': 'SYN-DESTINATION', 'authCS100': message}, result),
                        reply({'cvalS30': events})]

    def test_sms_request_configuration_then_seven_second_fallback_and_private_phone(self):
        self.prepare()
        self.replies.append(reply({'rstCS5': '000', 'respTelnoS20': 'SYN-VERIFIED-PHONE'}))
        def send(destination, message):
            self.assertEqual((destination, message), ('SYN-DESTINATION', 'A9b2-Cd'))
            self.assertEqual(len(self.calls), 2)
            return True
        self.assertEqual(phone.verify(self.exchange, send, fallback_seconds=0), 'SYN-VERIFIED-PHONE')
        self.assertEqual([body for _, body in self.calls], [
            {'procStepGS1': '1', 'macAdrS64': settings()['device']['device_id'], 'nspAppYnS1': 'Y'},
            {'cvalTblNmS20': 'HARDCODING_DATA', 'cvalNmS30': 'SOL_SMSMO_SSE_YN'},
            {'procStepGS1': '2', 'macAdrS64': settings()['device']['device_id']}])
        self.assertTrue(all(header['programId'] == phone.PROGRAM and 'language' not in header for header, _ in self.calls))
        self.assertTrue(self.state['device_phone']['verified'])
        self.assertEqual(self.exchange.report['device_phone_verification'], 'success')
        for secret in ('SYN-VERIFIED', 'SYN-DESTINATION', 'A9b2-Cd', 'SYN-COOKIE'):
            self.assertNotIn(secret, json.dumps(self.exchange.report))

    def test_successful_event_suppresses_timer_query_and_keeps_message_case_rule(self):
        self.prepare('Y')
        self.replies.append(reply({'rstCS5': '000', 'respTelnoS20': 'SYN-PHONE'}))
        streams = []
        def factory(query, callback):
            stream = FakeStream(query, callback)
            streams.append(stream)
            return stream
        def send(*args):
            streams[0].trigger()
            streams[0].trigger('TRIGGER_BROADCAST')
            return True
        number = phone.verify(self.exchange, send, stream_factory=factory, fallback_seconds=0)
        self.assertEqual(number, 'SYN-PHONE')
        self.assertEqual(len(self.calls), 3)
        self.assertIn('serviceValue=9b2d', streams[0].query)
        self.assertIn('preSvcCd=CO0607H0011P01', streams[0].query)
        self.assertTrue(streams[0].closed.is_set())

    def test_configuration_failure_uses_fallback_without_inventing_auth_failure(self):
        self.prepare()
        self.replies[1] = reply({}, 'FAIL')
        self.replies.append(reply({'rstCS5': '000', 'respTelnoS20': 'SYN-PHONE'}))
        number = phone.verify(self.exchange, lambda *args: True, fallback_seconds=0)
        self.assertEqual(number, 'SYN-PHONE')
        self.assertEqual(self.exchange.report['stages'][1]['result'], 'failure')
        self.assertEqual(self.exchange.report['device_phone_verification'], 'success')

    def test_rejected_request_never_sends_sms_or_verification(self):
        self.prepare(result='FAIL')
        with self.assertRaises(Pending), patch('builtins.input', side_effect=AssertionError('No input')):
            phone.verify(self.exchange, lambda *args: self.fail('SMS sent'), fallback_seconds=0)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.exchange.report['bank_result'], 'failure')

    def test_cancelled_sms_stops_late_events_without_erasing_earlier_bank_success(self):
        self.prepare('Y')
        streams = []
        def factory(query, callback):
            stream = FakeStream(query, callback); streams.append(stream); return stream
        with self.assertRaises(Pending):
            phone.verify(self.exchange, lambda *args: False, stream_factory=factory, fallback_seconds=0)
        streams[0].trigger()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.exchange.report['bank_result'], 'success')
        self.assertEqual(self.exchange.report['device_phone_verification'], 'unknown')

    def test_missing_phone_keeps_bank_auth_success_and_wrong_code_is_not_verified(self):
        self.prepare()
        self.replies.append(reply({'rstCS5': '000'}))
        with self.assertRaises(Pending) as caught:
            phone.verify(self.exchange, lambda *args: True, fallback_seconds=0)
        self.assertEqual(caught.exception.action, 'device_phone_number_unavailable')
        self.assertEqual(self.exchange.report['device_phone_verification'], 'success')
        self.prepare()
        self.replies.append(reply({'rstCS5': '001', 'respTelnoS20': 'SYN-PHONE'}))
        with self.assertRaises(Pending):
            phone.verify(self.exchange, lambda *args: True, fallback_seconds=0)
        self.assertEqual(self.exchange.report['bank_result'], 'success')
        self.assertEqual(self.exchange.report['device_phone_verification'], 'failure')

    def test_failed_event_then_timer_success_follows_original_fallback(self):
        self.prepare('Y')
        self.replies += [reply({'rstCS5': '001'}), reply({'rstCS5': '000', 'respTelnoS20': 'SYN-PHONE'})]
        streams = []
        def factory(query, callback):
            stream = FakeStream(query, callback); streams.append(stream); return stream
        def send(*args):
            streams[0].trigger()
            return True
        self.assertEqual(phone.verify(self.exchange, send, stream_factory=factory, fallback_seconds=0), 'SYN-PHONE')
        self.assertEqual(len(self.calls), 4)

    def test_late_event_after_fallback_failure_can_still_complete(self):
        self.prepare('Y')
        self.replies += [reply({'rstCS5': '001'}), reply({'rstCS5': '000', 'respTelnoS20': 'SYN-PHONE'})]
        streams = []
        class Late(FakeStream):
            def start(self):
                def arrive():
                    while len(self.calls) < 3:
                        threading.Event().wait(0.001)
                    self.trigger()
                self.calls = self_outer.calls
                self.worker = threading.Thread(target=arrive)
                self.worker.start()
        self_outer = self
        def factory(query, callback):
            stream = Late(query, callback);streams.append(stream);return stream
        self.assertEqual(phone.verify(self.exchange, lambda *args: True, stream_factory=factory, fallback_seconds=0), 'SYN-PHONE')
        streams[0].worker.join(1)
        self.assertFalse(streams[0].worker.is_alive())

    def test_parse_distinguishes_business_success_unknown_and_pending(self):
        result, _ = phone.parse(reply({}, 'UNRECOGNIZED'))
        self.assertFalse(result['bridge_success'])
        self.assertEqual(result['bank_result'], 'unknown')
        result, _ = phone.parse(transport.Reply(200, [], response('FAIL', {}, resultCode='RIB80306')))
        self.assertFalse(result['callback_ready'])
        result, _ = phone.parse(reply({'blklstG': 4}))
        self.assertEqual(result['bank_result'], 'success')
        self.assertFalse(result['callback_ready'])

    def test_cli_send_gate_before_settings_or_network(self):
        with patch.object(setup, 'load', side_effect=AssertionError('Settings read')):
            self.assertEqual(json.loads(self.call(['phone', 'verify'])[1])['result']['error'], 'send_required')
        self.assertEqual(self.call(['phone', 'verify', '--help'])[0], 0)

    def test_interactive_cli_displays_sms_values_on_prompt_and_keeps_json_private(self):
        storage.atomic_json(setup.root()/'session.json', self.state)
        message = '[합성 인증 안내]\nA9b2-Cd'
        self.prepare(message=message)
        self.replies.append(reply({'rstCS5': '000', 'respTelnoS20': 'SYN-PHONE'}))
        original = phone.verify
        with patch('sys.stdin.isatty', return_value=True), patch('builtins.input', return_value='') as prompt, \
             patch.object(phone, 'verify', side_effect=lambda exchange, send: original(exchange, send, fallback_seconds=0)):
            code, output, error = self.call(['phone', 'verify', '--send'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['result']['device_phone_verification'], 'success')
        files = list((setup.root()/'runs').glob('*/sms-instructions.json'))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(storage.read_json(files[0]), {'destination': 'SYN-DESTINATION', 'message': message})
        prompt.assert_called_once()
        displayed = error
        self.assertIn('받는 번호: SYN-DESTINATION\n', displayed)
        self.assertIn('아래 본문 전체를 보내세요):\n'+message+'\n\n문자 발송', displayed)
        self.assertNotIn('파일', displayed)
        self.assertNotIn('SYN-PHONE', output+error)
        for secret in ('SYN-DESTINATION', 'A9b2-Cd'):
            self.assertNotIn(secret, output)

    def test_issuance_prompt_uses_same_sms_display_without_file_dependency(self):
        message = 'SYN-HEADER\r\nSYN-MESSAGE'
        with patch.object(storage, 'write_new', side_effect=OSError('Synthetic write failure')), \
             patch('builtins.input', return_value='') as prompt, patch('sys.stderr', new_callable=io.StringIO) as stderr:
            answer = issuance_input.factory(self.exchange)('send_phone_sms',
                {'destination': 'SYN-DESTINATION', 'message': message})
        self.assertTrue(answer)
        displayed = stderr.getvalue()
        self.assertIn('받는 번호: SYN-DESTINATION\n', displayed)
        self.assertIn('\n'+message+'\n\n', displayed)
        self.assertIn('phone_sms_instructions_save_error', self.exchange.report['warnings'])
        self.assertNotIn('SYN-MESSAGE', json.dumps(self.exchange.report))

    def test_sms_instruction_save_failure_does_not_change_bank_verification_success(self):
        self.prepare()
        self.replies.append(reply({'rstCS5': '000', 'respTelnoS20': 'SYN-PHONE'}))
        write = storage.write_new
        def save(path, *args, **kwargs):
            if path.name == 'sms-instructions.json':
                raise OSError('Synthetic write failure')
            return write(path, *args, **kwargs)
        with patch.object(storage, 'write_new', side_effect=save), patch('getpass.getpass', return_value=''):
            number = phone.verify(self.exchange, lambda destination, message:
                issuance_input.send_phone_sms(self.exchange, destination, message), fallback_seconds=0)
        self.assertEqual(number, 'SYN-PHONE')
        self.assertEqual(self.exchange.report['device_phone_verification'], 'success')
        self.assertEqual(self.exchange.report['bank_result'], 'success')
        self.assertEqual(len(self.calls), 3)


class StreamTests(PrivateHome):
    def test_sse_multiline_bom_comments_event_names_and_cookie_free_request(self):
        class Response(io.BytesIO):
            status = 200
            def getheader(self, name):
                return 'text/event-stream; charset=utf-8'
        body = Response(b'\xef\xbb\xbf: hello\r\nevent: ignored\ndata: bad\n\nevent: KTMO\ndata: {"data":\ndata: {"status":"TRIGGER_SENT"}}\n\n')
        events = []
        with patch.object(http := phone.http.client, 'HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value = body
            stream = phone.EventStream('SYN-QUERY', events.append)
            stream.receive()
        self.assertEqual(events, [{'data': {'status': 'TRIGGER_SENT'}}])
        connection.return_value.request.assert_called_once_with('GET', '/api/ktmo/subscribe?SYN-QUERY', headers={'Accept': 'text/event-stream'})
        self.assertTrue(stream.closed.is_set())
        self.assertIsNone(stream.error)

    def test_stream_http_error_never_reconnects_or_invokes_authentication(self):
        with patch.object(phone.http.client, 'HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value.status = 503
            stream = phone.EventStream('SYN-QUERY', lambda event: self.fail('Unexpected callback'))
            stream.receive()
        self.assertEqual(connection.call_count, 1)
        self.assertEqual(stream.error, 'event_stream_response_unavailable')

    def test_bad_event_does_not_hide_later_verification_and_timeout_coerces_strings(self):
        class Response(io.BytesIO):
            status = 200
            def getheader(self, name):
                return 'text/event-stream'
        response = Response(b'event: KTMO\ndata: bad\n\nevent: KTMO\ndata: {"data":{"status":"TRIGGER_SENT"}}\n\n')
        events = []
        with patch.object(phone.http.client, 'HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value = response
            stream = phone.EventStream('SYN', events.append)
            stream.receive()
        self.assertEqual(len(events), 1)
        self.assertEqual(stream.error, 'event_listener_processing_error')
        self.assertEqual(phone.timer_seconds('55000'), 55)
        self.assertEqual(phone.timer_seconds(None), 0)
