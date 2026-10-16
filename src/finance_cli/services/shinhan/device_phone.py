"""MO phone verification: user sends SMS; only the bank supplies the phone."""
import http.client
import json
import math
import re
import threading
import time
from urllib.parse import urlencode

from finance_cli.core import storage
from . import setup, transport, web
from .enrollment import Pending
from .exchange import Exchange
from .session import SessionRequired

PROGRAM = 'CO0607H0011P01'
TRANSACTION = 'RSMCM1200A02'


def parse(reply):
    result, document = transport.parse(reply)
    result['bridge_success'] = result['bank_result'] == 'success'
    result['callback_ready'] = True
    header = document.get('dataHeader', {}) if isinstance(document, dict) else {}
    code = header.get('resultCode') if isinstance(header, dict) else None
    if code in ('RIB80306', 'RIB80307', 'MDE00016', 'RIB96472'):
        result.update(callback_ready=False, required_action='additional_authentication', processing_status='incomplete')
    elif code in ('RIB00011', 'RIB00060', 'MCM00005', 'RIB00057'):
        result.update(callback_ready=False, required_action='session_notice', processing_status='incomplete')
    body = document.get('dataBody') if isinstance(document, dict) else None
    if result['bridge_success'] and isinstance(body, dict) and str(body.get('blklstG')) in ('4', '5'):
        result.update(callback_ready=False, required_action='service_precheck', processing_status='incomplete')
    return result, document


def request(exchange, stage, transaction, body):
    step, document = exchange.web(stage, transaction, body, program=PROGRAM, response_parser=parse)
    if not step['callback_ready']:
        raise Pending(step['required_action'])
    return step, document.get('dataBody') if isinstance(document, dict) else None


def start(exchange):
    identity = exchange.settings['device']['device_id']
    step, body = request(exchange, 'device_phone_request', TRANSACTION,
                        {'procStepGS1': '1', 'macAdrS64': identity, 'nspAppYnS1': 'Y'})
    exchange.report['bank_result'] = step['bank_result']
    if step['bank_result'] != 'success':
        raise Pending('device_phone_request_unavailable')
    # A null body is a local consumer error, not an invented empty challenge.
    context = {'destination': body.get('respTelnoS20', ''), 'message': body.get('authCS100', '')}
    exchange.state['device_phone'] = context
    step, body = request(exchange, 'device_phone_event_configuration', 'RSMCM9009A06',
                        {'cvalTblNmS20': 'HARDCODING_DATA', 'cvalNmS30': 'SOL_SMSMO_SSE_YN'})
    context['events_enabled'] = step['bank_result'] == 'success' and body.get('cvalS30') == 'Y'
    exchange.save()
    return context


def check(exchange):
    step, body = request(exchange, 'device_phone_verify', TRANSACTION,
                        {'procStepGS1': '2', 'macAdrS64': exchange.settings['device']['device_id']})
    exchange.report['bank_result'] = step['bank_result']
    accepted = step['bank_result'] == 'success' and isinstance(body, dict) and body.get('rstCS5') == '000'
    exchange.report['device_phone_verification'] = ('success' if accepted else
        'failure' if step['bank_result'] in ('success', 'failure') else 'unknown')
    if accepted:
        exchange.state['device_phone'].update(verified=True, phone_number=body.get('respTelnoS20'))
    exchange.save()
    return accepted


def event_query(message, identity):
    # JavaScript's /[^a-z0-9]/g removes uppercase letters instead of lowercasing.
    return urlencode({'serviceValue': re.sub('[^a-z0-9]', '', message), 'deviceInfo': identity,
                      'channel': 'SOL', 'preSvcCd': PROGRAM})


def timer_seconds(value):
    try:
        milliseconds = float(value or 0)
    except (TypeError, ValueError):
        milliseconds = 0
    return max(0, milliseconds)/1000 if math.isfinite(milliseconds) else 0


class EventStream:
    """One cookie-free SSE connection; no automatic HTTP reconnect or retry."""
    def __init__(self, query, callback):
        self.callback, self.query = callback, query
        self.closed, self.stopped = threading.Event(), threading.Event()
        self.connection = None
        self.status, self.error = None, None
        self.events = []
        self.thread = threading.Thread(target=self.receive, daemon=True)

    def start(self):
        self.thread.start()

    def receive(self):
        try:
            self.connection = http.client.HTTPSConnection('sse.shinhan.com', timeout=60)
            self.connection.request('GET', '/api/ktmo/subscribe?'+self.query, headers={'Accept': 'text/event-stream'})
            response = self.connection.getresponse()
            self.status = response.status
            if response.status != 200 or (response.getheader('Content-Type') or '').split(';')[0].strip() != 'text/event-stream':
                self.error = 'event_stream_response_unavailable'
                return
            name, data = '', []
            deadline = time.monotonic()+60
            first = True
            while not self.stopped.is_set() and time.monotonic() < deadline:
                if self.connection.sock is not None:
                    self.connection.sock.settimeout(max(0.01, deadline-time.monotonic()))
                raw = response.readline(1024*1024+1)
                if not raw or self.stopped.is_set():
                    break
                if len(raw) > 1024*1024:
                    raise ValueError('event_too_large')
                line = raw.decode('utf-8', errors='replace').rstrip('\r\n')
                if first:
                    line, first = line.removeprefix('\ufeff'), False
                if not line:
                    if name == 'KTMO' and data:
                        try:
                            event = json.loads('\n'.join(data))
                            self.events.append(event)
                            value = event.get('data', {}) if isinstance(event, dict) else {}
                            if isinstance(value, dict) and value.get('status') == 'SUBSCRIBE_SUCCESS':
                                deadline = time.monotonic()+timer_seconds(value.get('clientTimeout'))
                            if not self.stopped.is_set():
                                self.callback(event)
                        except Exception:
                            # An EventSource listener exception does not close
                            # the connection or erase a prior authentication.
                            self.error = 'event_listener_processing_error'
                    name, data = '', []
                elif not line.startswith(':'):
                    field, _, value = line.partition(':')
                    value = value[1:] if value.startswith(' ') else value
                    if field == 'event':
                        name = value
                    elif field == 'data':
                        data.append(value)
        except Exception:
            self.error = 'event_stream_interrupted'
        finally:
            self.close()
            self.closed.set()

    def close(self):
        self.stopped.set()
        if self.connection:
            try:
                self.connection.close()
            except OSError:
                pass


def verify(exchange, send_sms, *, stream_factory=EventStream, fallback_seconds=7):
    """Reusable issuance step. send_sms confirms a user-performed SMS action."""
    context = start(exchange)
    report = exchange.report
    report['device_phone_verification'] = 'unknown'
    accepted, active, lock = threading.Event(), threading.Event(), threading.RLock()
    active.set()
    stream, stream_step = None, None
    deferred = []
    def verify_once():
        with lock:
            if active.is_set() and not accepted.is_set() and check(exchange):
                accepted.set()
    def event(value):
        if isinstance(value, dict) and isinstance(value.get('data'), dict) and value['data'].get('status') in ('TRIGGER_SENT', 'TRIGGER_BROADCAST'):
            try:
                verify_once()
            except Exception as error:
                # Background processing cannot replace a previously observed result.
                deferred.append(error)
    try:
        if context['events_enabled']:
            stream_step = exchange.reserve('device_phone_events')
            stream = stream_factory(event_query(context['message'], exchange.settings['device']['device_id']), event)
            stream.start()
        if not send_sms(context['destination'], context['message']):
            raise Pending('device_phone_sms_cancelled')
        # This is the screen's fallback after SMS return, not a retry caused by
        # a failed bank request. A successful SSE-triggered check suppresses it.
        if not accepted.wait(fallback_seconds):
            verify_once()
        if stream:
            # Keep late triggers available until the server's stream timeout.
            while not accepted.is_set() and not stream.closed.wait(0.1):
                pass
        if not accepted.is_set():
            if deferred:
                raise deferred[0]
            raise Pending('device_phone_unverified')
        number = context.get('phone_number')
        if web.nullish(number):
            raise Pending('device_phone_number_unavailable')
        return number
    finally:
        with lock:
            active.clear()
            if stream:
                stream.close()
                stream_step.update(http_status=stream.status, result='observed' if stream.status == 200 else 'unknown', processing_status='complete')
                if stream.error:
                    stream_step['error'] = stream.error
                stream_step['event_count'] = len(stream.events)
                try:
                    storage.write_new(exchange.run/'device-phone-events.json', json.dumps(stream.events).encode())
                except Exception:
                    exchange.warning('device_phone_events_save_error')
        exchange.save()


def run(send_sms):
    settings = setup.load()
    folder = setup.prepare_directory()
    with storage.lock(folder/'.lock'):
        path = folder/'session.json'
        state = storage.read_json(path) if path.exists() else {}
        if not state.get('cookie'):
            raise SessionRequired()
        exchange = Exchange(settings, state, 'device_phone_verification')
        try:
            verify(exchange, lambda destination, message: send_sms(exchange, destination, message))
            exchange.report['processing_status'] = 'complete'
        except Pending as error:
            exchange.report.update(processing_status='incomplete', required_action=error.action)
        except (KeyboardInterrupt, EOFError):
            exchange.report.update(processing_status='incomplete', error='interrupted')
        except Exception:
            exchange.report.update(processing_status='incomplete', error='device_phone_processing_error')
        state['last_operation'] = 'device_phone_verification'
        exchange.save()
        return exchange.report
