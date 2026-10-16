"""Single-attempt bank transport; service judgement is separate from local IO."""
import base64
from dataclasses import dataclass, field
import gzip
import http.client
from http.cookies import SimpleCookie
import io
import json
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BANK_HOST = 'nssol.shinhan.com'
ENDPOINT = '/serviceEndpoint/httpDigital'
LIMIT = 32*1024*1024


def encode(transaction, body, settings):
    header = {'trxCd': transaction, 'language': '1', 'subChannel': '03',
              'uuid': settings['device']['device_id'], 'encG': '1', 'appG': 'supersol'}
    key = bytes.fromhex(settings['bank_key'])
    plaintext = json.dumps(body, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    encrypted = AES.new(key, AES.MODE_CBC, key[:16]).encrypt(pad(plaintext, 16))
    return json.dumps({'dataHeader': header, 'dataBody': base64.b64encode(encrypted).decode('ascii')},
                      ensure_ascii=False, separators=(',', ':')).encode('utf-8')


@dataclass(repr=False)
class Reply:
    status: int | None = None
    headers: list = field(default_factory=list)
    body: bytes = b''
    error: str | None = None


def _post(host, payload, headers, path, timeout):
    connection = http.client.HTTPSConnection(host, timeout=timeout)
    reply = Reply()
    try:
        connection.request('POST', path, payload, headers)
        response = connection.getresponse()
        reply.status, reply.headers = response.status, response.getheaders()
        reply.body = response.read(LIMIT+1)
        if len(reply.body) > LIMIT:
            reply.error, reply.body = 'response_too_large', b''
        elif response.getheader('Content-Encoding') == 'gzip':
            with gzip.GzipFile(fileobj=io.BytesIO(reply.body)) as stream:
                reply.body = stream.read(LIMIT+1)
            if len(reply.body) > LIMIT:
                reply.error, reply.body = 'response_too_large', b''
    except (OSError, http.client.HTTPException, EOFError):
        reply.error = 'transport_error'
    finally:
        try:
            connection.close()
        except OSError:
            pass  # Closing cannot erase an already received response.
    # Deliberately no redirect, recovery, retry or automatic login.
    return reply


def post(payload, cookie='', *, path=ENDPOINT):
    headers = {'Content-Type': 'application/json; charset=UTF-8', 'Accept-Encoding': 'gzip'}
    if cookie:
        headers['Cookie'] = cookie
    return _post(BANK_HOST, payload, headers, path, 60)


def post_web(payload, cookie='', *, path=ENDPOINT):
    headers = {'Content-Type': 'application/json', 'Accept-Encoding': 'gzip'}
    if cookie:
        headers['Cookie'] = cookie
    return _post(BANK_HOST, payload, headers, path, 60)


def post_certificate(payload, cookie='', *, path):
    headers = {'Content-Type': 'application/json; charset=utf-8', 'Accept': 'application/json',
               'Accept-Encoding': 'gzip'}
    if cookie:
        headers['Cookie'] = cookie
    return _post('ca.shinhan.com', payload, headers, path, 30)


def post_cmp(payload, *, path):
    return _post('ca.shinhan.com', payload, {'Content-Type': 'application/pkixcmp',
                 'Accept-Encoding': 'gzip'}, path, 10)


def update_cookie(state, headers):
    for name, value in headers:
        if name.lower() != 'set-cookie':
            continue
        parsed = SimpleCookie()
        parsed.load(value)
        if 'JSESSIONID' not in parsed:
            continue
        item = parsed['JSESSIONID']
        domain = item['domain'].lower().lstrip('.') or BANK_HOST
        if BANK_HOST != domain and not BANK_HOST.endswith('.'+domain):
            continue
        # The bank jar stores only the first matching session cookie's name/value.
        state['cookie'] = item.OutputString(attrs=[])
        break


def primitive(value):
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return json.dumps(value, allow_nan=False, separators=(',', ':'))
    raise ValueError('invalid_primitive')


def update_challenges(state, document):
    header = document['dataHeader']
    first, second = primitive(header.get('secChal1')), primitive(header.get('secChal2'))
    if first or second:
        state['challenges'] = [first, second]


def parse(reply):
    """Return a public judgement and private parsed response, without raw errors."""
    result = {'http_status': reply.status, 'bank_result': 'unknown', 'processing_status': 'incomplete'}
    if reply.error:
        result['error'] = reply.error
        return result, None
    try:
        document = json.loads(reply.body)
    except (ValueError, UnicodeError):
        document = None
    if reply.status is None or not 200 <= reply.status < 300:
        result['error'] = 'http_status_error'
    elif reply.status in (204, 205):
        result['error'] = 'response_body_missing'
    elif not isinstance(document, dict) or not isinstance(document.get('dataHeader'), dict):
        result['error'] = 'response_decode_error'
    else:
        header = document['dataHeader']
        verdict = header.get('result')
        if verdict in ('SUCCESS', 'FAIL'):
            result['bank_result'] = 'success' if verdict == 'SUCCESS' else 'failure'
            result['processing_status'] = 'complete'
            if verdict == 'FAIL':
                result['error'] = 'bank_rejected'
            # Only a bounded protocol code is public; messages/global IDs stay private.
            code = header.get('resultCode')
            if isinstance(code, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}', code):
                result['bank_code'] = code
        else:
            result['error'] = 'unexpected_bank_result'
    return result, document
