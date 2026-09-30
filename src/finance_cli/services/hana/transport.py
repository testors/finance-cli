"""One recorded HTTP attempt. No redirects, no retries, no automatic replay.

The attempt directory is created exclusively before the request leaves, so an
interrupted or timed-out attempt can never be sent again by mistake. Request and
response bytes stay in the private session; cookies belong to the session only.
"""
import http.cookiejar
import json
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone

from finance_cli.core import storage
from . import store

USER_AGENT = 'HanaBankOQF/1.0.27 (Android; Mobile) okhttp/4.12.0'
LIMIT = 2 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def opener(jar):
    return urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(jar),
                                       urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def headers_by_name(headers):
    return {name.lower(): value for name, value in headers}


def body_bytes(request):
    # Axios XHR removes Content-Type and sends no body for an omitted argument.
    omit = request.get('omit_body', False)
    if type(omit) is not bool or (omit and (request['body'] is not None
            or any(k.lower() == 'content-type' for k in request['headers']))):
        raise ValueError('omitted_body_must_have_no_content_type_or_value')
    if omit:
        return None
    if request['body'] is not None:
        return json.dumps(request['body'], ensure_ascii=False, separators=(',', ':')).encode()
    return b'' if request['method'] == 'POST' else None


def send(session, stage, request, assessor):
    """Send one request. The assessor decides acceptance from the service verdict."""
    data = body_bytes(request)
    output = store.make_directory(store.child(session, store.name(stage)))
    recorded = {k: v for k, v in request.items() if k != 'live_verified'}
    recorded['mode'] = 'HTTP attempt; see response.json or failure.json for outcome'
    store.write_new(store.child(output, 'request.json'), recorded)
    store.write_new(store.child(output, 'attempt.json'), {
        'started_at': datetime.now(timezone.utc).isoformat(), 'stage': stage, 'automatic_retries': 0})
    cookie_file = store.child(session, 'cookies.txt')
    jar = http.cookiejar.MozillaCookieJar(str(cookie_file))
    if cookie_file.exists():
        jar.load(ignore_discard=True)
    req = urllib.request.Request(request['url'], method=request['method'], headers=request['headers'], data=data)
    try:
        try:
            response = opener(jar).open(req, timeout=30)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            status, headers = response.code, list(response.headers.items())
            body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise ValueError('response_exceeded_size_limit')
        assessment = assessor(stage, status, headers, body)
        record = {'status': status, 'headers': headers, 'body_bytes': len(body),
                  'assessment': assessment, 'observed_at': datetime.now(timezone.utc).isoformat()}
        store.write_new(store.child(output, 'body.bin'), body)
        store.write_new(store.child(output, 'response.json'), record)
        if not cookie_file.exists():
            storage.write_new(cookie_file, b'')
        jar.save(ignore_discard=True)
        return {'stage': stage, 'http_status': status, **assessment,
                'body_bytes': len(body), 'cookie_count': len(jar),
                'response_header_names': sorted({k.lower() for k, _ in headers}),
                'record_directory': stage, 'network_used': True}
    except (urllib.error.URLError, OSError, ValueError, socket.timeout) as error:
        # The outcome is unknown. Keep the attempt marker and never replay.
        store.write_new(store.child(output, 'failure.json'), {
            'error_type': type(error).__name__, 'outcome': 'unknown; no automatic replay'})
        raise ValueError('request_did_not_finish_no_automatic_replay') from None


def read_receipt(session, stage):
    """The saved request, response and body bytes of one attempt."""
    if hasattr(session, 'read_receipt'):
        return session.read_receipt(stage)
    directory = store.child(session, store.name(stage))
    if store.child(directory, 'failure.json').exists():
        raise ValueError('receipt_has_failure_marker')
    request = store.read_json(store.child(directory, 'request.json'))
    response = store.read_json(store.child(directory, 'response.json'))
    raw = storage.read(store.child(directory, 'body.bin'))
    if response.get('body_bytes') != len(raw) or len(raw) > LIMIT:
        raise ValueError('receipt_body_size_differs')
    if datetime.fromisoformat(response['observed_at']).tzinfo is None:
        raise ValueError('receipt_timestamp_needs_timezone')
    return request, response, raw
