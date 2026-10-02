"""One corporate HTTP attempt per stage, with an isolated cookie jar."""
import base64
import gzip
import json

from finance_cli.core import storage
from finance_cli.services.hana import request_activity
from finance_cli.services.hana.onesign_io import send_http
from . import protocol, store


class Client:
    def __init__(self, directory, profile, result, *, exchange=send_http):
        self.directory, self.profile, self.result, self.exchange = directory, profile, result, exchange
        self.cookies = []
        self.saved = {'channel': 'corporate', 'cookies': [], 'login_verified': False}

    def request(self, stage, body=None, *, native=False, observe=None, assessor=protocol.assess, redact=()):
        protocol.require(stage in protocol.PATHS, 'corporate_endpoint_not_allowed')
        raw = (b'' if body is None else protocol.native_form(body)) if native else protocol.form(
            {**(body or {}), 'COMM_HEAD': (body or {}).get('COMM_HEAD', {})})
        method = 'POST' if native or raw else 'GET'
        agent = self.profile['custom_user_agent']
        content_type = ('application/json' if body is None else 'application/x-www-form-urlencoded') if native else 'application/x-www-form-urlencoded; charset=UTF-8'
        headers = {'Accept': 'application/json', 'Content-Type': content_type,
                   'CUSTOM_USER_AGENT': json.dumps(agent, ensure_ascii=True, separators=(',', ':')),
                   'User-Agent': 'okhttp/5.0.0-alpha.10' if native else agent['userAgent'], 'Accept-Encoding': 'gzip'}
        if native:
            headers.update({'charset': 'UTF-8', 'Cache-Control': 'no-cache'})
        attempt = self.directory / stage
        attempt.mkdir(mode=0o700)  # Exclusive durable reservation, before any request.
        recorded = protocol.native_form({k: '[redacted]' if k in redact else v for k, v in body.items()}) if redact else raw
        store.record(attempt / 'request.json', {'method': method, 'path': protocol.PATHS[stage], 'headers': headers,
                                               'body': base64.b64encode(recorded).decode()})
        store.record(attempt / 'attempt.json', {'automatic_retry': False})
        receipt = {'stage': stage, 'service_status': 'unconfirmed', 'processing_status': 'prepared'}
        self.result['stages'].append(receipt)
        request_activity.before_request('bank')
        self.result['network_used'] = True
        receipt['processing_status'] = 'sent'
        try:
            status, head, data, cookies = self.exchange('bank', method, protocol.ORIGIN + protocol.PATHS[stage],
                                                       headers, raw if method == 'POST' else None, self.cookies, 120)
        except Exception:
            receipt['processing_status'] = 'transport_interrupted'
            raise protocol.Stop('transport_interrupted_no_automatic_retry') from None
        receipt.update(http_status=status, processing_status='received')
        try:
            decoded = gzip.decompress(data) if dict((k.lower(), v) for k, v in head).get('content-encoding', '').lower() == 'gzip' else data
            value = json.loads(decoded)
        except (ValueError, OSError, EOFError):
            raise protocol.Stop('response_decode_failed') from None
        receipt.update(assessor(status, value))
        payload = value.get('data') if isinstance(value, dict) else None
        if observe is not None:
            observe(receipt, payload)  # Preserve login success before saving anything.
        self.cookies = cookies
        self.saved['cookies'] = cookies
        try:
            store.record(attempt / 'response.json', {'status': status, 'headers': head, 'body': value})
            storage.atomic_json(self.directory / 'session.json', self.saved)
        except (OSError, ValueError):
            receipt['processing_status'] = 'storage_failed'
            raise protocol.Stop('response_storage_failed') from None
        receipt['processing_status'] = 'stored'
        protocol.require(receipt['service_status'] == 'accepted', receipt['reason'])
        protocol.require(isinstance(payload, dict), 'response_data_unavailable')
        return payload
