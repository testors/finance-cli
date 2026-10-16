"""One reserved workflow, separate bank/CA cookies, and redacted stage reports."""
import base64
from datetime import datetime, timezone
from email.message import Message
import http.cookiejar
import json
import urllib.request
import uuid

from finance_cli.core import storage
from . import setup, transport


class Exchange:
    def __init__(self, settings, state, operation):
        self.settings, self.state = settings, state
        self.folder = setup.prepare_directory()
        self.attempt = uuid.uuid4().hex
        self.run = storage.directory(storage.directory(self.folder / 'runs') / self.attempt)
        self.report = {'operation': operation, 'attempt': self.attempt,
                       'created_at': datetime.now(timezone.utc).isoformat(), 'network_used': False,
                       'bank_result': 'unknown', 'processing_status': 'prepared', 'local_status': 'complete',
                       'automatic_retry': False, 'stages': []}
        storage.write_new(self.run / 'report.json', (json.dumps(self.report)+'\n').encode())
        self.jar = http.cookiejar.CookieJar()
        for fields in state.get('ca_cookies', []):
            self.jar.set_cookie(http.cookiejar.Cookie(**fields))

    def warning(self, code):
        self.report.setdefault('warnings', []).append(code)
        self.report['local_status'] = 'incomplete'

    def save(self):
        try:
            storage.atomic_json(self.folder / 'session.json', self.state)
            self.report['session_saved'] = True
        except Exception:
            self.report['session_saved'] = False
            self.warning('session_save_error')
        try:
            storage.atomic_json(self.run / 'report.json', self.report)
        except Exception:
            self.warning('report_save_error')

    def reserve(self, stage, *, transaction=None):
        value = {'stage': stage, 'processing_status': 'sending', 'result': 'unknown'}
        if transaction:
            value['transaction'] = transaction
        self.report['stages'].append(value)
        self.report['network_used'] = True
        # A failed reservation stops before this new network request.
        storage.atomic_json(self.run / 'report.json', self.report)
        return value

    def record_response(self, reply):
        index = len(self.report['stages'])
        try:
            storage.write_new(self.run / f'response-{index}.json', json.dumps({
                'status': reply.status, 'headers': reply.headers,
                'body_base64': base64.b64encode(reply.body).decode()}).encode())
        except Exception:
            self.warning('response_save_error')

    def bank(self, stage, transaction, body, *, device_id=None, path=transport.ENDPOINT, response_parser=transport.parse):
        settings = self.settings
        if device_id is not None:
            settings = {**settings, 'device': {**settings['device'], 'device_id': device_id}}
        payload = transport.encode(transaction, body, settings)
        recorded = self.reserve(stage, transaction=transaction)
        reply = transport.post(payload, self.state.get('cookie', ''), path=path)
        verdict, document = response_parser(reply)
        recorded.update(verdict)
        recorded['result'] = verdict['bank_result']
        try:
            transport.update_cookie(self.state, reply.headers)
            if document is not None:
                transport.update_challenges(self.state, document)
        except Exception:
            self.warning('bank_state_update_error')
        self.record_response(reply)
        self.save()
        return recorded, document

    def ca(self, stage, path, body):
        payload = body.encode() if isinstance(body, str) else json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode()
        request = urllib.request.Request('https://ca.shinhan.com'+path)
        self.jar.add_cookie_header(request)
        recorded = self.reserve(stage)
        reply = transport.post_certificate(payload, request.get_header('Cookie', ''), path=path)
        recorded['http_status'] = reply.status
        if reply.error:
            recorded['error'] = reply.error
        elif reply.status is None or not 200 <= reply.status < 300:
            recorded['error'] = 'http_status_error'
        elif reply.status in (204, 205) or not reply.body:
            recorded['error'] = 'response_body_missing'
        else:
            recorded.update(result='http_success', processing_status='received')
        try:
            message = Message()
            for key, value in reply.headers:
                message.add_header(key, value)
            class Response:
                def info(self):
                    return message
            self.jar.extract_cookies(Response(), request)
            fields = ('version', 'name', 'value', 'port', 'port_specified', 'domain', 'domain_specified',
                      'domain_initial_dot', 'path', 'path_specified', 'secure', 'expires', 'discard',
                      'comment', 'comment_url', 'rfc2109')
            self.state['ca_cookies'] = [{**{field: getattr(cookie, field) for field in fields},
                                        'rest': cookie._rest} for cookie in self.jar]
        except Exception:
            self.warning('ca_cookie_save_error')
        self.record_response(reply)
        self.save()
        return recorded, reply.body

    def cmp(self, stage, path, message):
        from .cmp import wire
        payload = wire(message)
        recorded = self.reserve(stage)
        # CMP has its own byte transport and does not reuse either JSON cookie jar.
        reply = transport.post_cmp(payload, path=path)
        recorded['http_status'] = reply.status
        if reply.error:
            recorded['error'] = reply.error
        elif reply.status is None or not 200 <= reply.status < 300:
            recorded['error'] = 'http_status_error'
        else:
            recorded.update(result='http_success', processing_status='received')
        self.record_response(reply)
        self.save()
        return recorded, reply.body

    def web(self, stage, transaction, body, *, program):
        from . import web
        payload = web.encode(transaction, body, self.settings, program)
        recorded = self.reserve(stage, transaction=transaction)
        reply = transport.post_web(payload, self.state.get('cookie', ''))
        verdict, document = web.parse(reply)
        recorded.update(verdict)
        recorded['result'] = verdict['bank_result']
        try:
            transport.update_cookie(self.state, reply.headers)
            if document is not None:
                transport.update_challenges(self.state, document)
        except Exception:
            self.warning('bank_state_update_error')
        try:
            if verdict['bridge_success'] and verdict['callback_ready']:
                web.update_challenges(self.state, document)
        except Exception:
            self.warning('web_state_update_error')
        self.record_response(reply)
        self.save()
        return recorded, document
