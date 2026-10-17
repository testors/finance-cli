"""GET transport used by the queue SDK; no bank cookies or bank-status rules."""
from email.message import Message
import http.client
import http.cookiejar
import socket
import ssl
import urllib.parse
import urllib.request

from .netfunnel_protocol import LocalError

LIMIT = 32*1024*1024


def form(value):
    value = '' if value is None else str(value)
    chars, position = [], 0
    while position < len(value):
        code = ord(value[position]); position += 1
        if 0xd800 <= code <= 0xdbff and position < len(value) and 0xdc00 <= ord(value[position]) <= 0xdfff:
            code = 0x10000+((code-0xd800) << 10)+ord(value[position])-0xdc00
            position += 1
        chars.append('?' if 0xd800 <= code <= 0xdfff else chr(code))
    # Java URLEncoder permits '*', encodes '~', and uses '+' for space.
    safe = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_. *'
    return ''.join('+' if byte == 32 else chr(byte) if byte in safe else '%'+format(byte, '02X')
                   for byte in ''.join(chars).encode('utf-8'))


def request_url(url, params):
    query = '&'.join(form(name)+'='+form(value) for name, value in params)
    return url+('&' if url.endswith('?') else '?')+query if len(query) > 1 else url


def may_retry(error, attempt, sent):
    if attempt > 3:
        return False
    if isinstance(error, http.client.RemoteDisconnected):
        return True
    if isinstance(error, (TimeoutError, InterruptedError, socket.gaierror, ssl.SSLCertVerificationError)):
        return False
    return isinstance(error, OSError) and not sent


def charset(headers):
    value = headers.get('Content-Type', '')
    quoted, escaped = False, False
    for index, char in enumerate(value):
        if char == ',' and not quoted:
            value = value[:index]; break
        if char == '"' and not escaped:
            quoted = not quoted
        escaped = char == '\\' and not escaped
    message = Message()
    message['Content-Type'] = value
    encoding = message.get_param('charset')
    return 'iso-8859-1' if encoding is None else encoding


def get(url, params=(), timeout=3, *, observe=None):
    # A fresh Apache client has a fresh cookie store for each SDK command, but
    # cookies received during redirects belong to this one HTTP execution.
    target = request_url(url, params)
    jar, seen = http.cookiejar.CookieJar(), set()
    redirects, attempt = 0, 0
    def event(**values):
        if observe is not None:
            try:
                observe(values)
            except Exception:
                pass  # Diagnostics do not alter the request sequence or result.
    while True:
        parts = urllib.parse.urlsplit(target)
        if parts.scheme not in ('http', 'https') or not parts.hostname:
            raise ValueError('netfunnel_url')
        connection_type = http.client.HTTPSConnection if parts.scheme == 'https' else http.client.HTTPConnection
        request = urllib.request.Request(target)
        jar.add_cookie_header(request)
        headers = {'Connection': 'Keep-Alive', 'User-Agent': 'Apache-HttpClient/UNAVAILABLE (java 1.4)',
                   **dict(request.header_items())}
        path = urllib.parse.urlunsplit(('', '', parts.path or '/', parts.query, ''))
        path = urllib.parse.quote(path, safe="/?:@&=+$,;~*'()!%[]-._")
        while True:
            connection = connection_type(parts.hostname, parts.port, timeout=timeout if timeout > 0 else None)
            try:
                # Route establishment is outside the platform request retry loop.
                event(kind='http_connect')
                connection.connect()
                connection.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                attempt += 1
                sent = False
                event(kind='http_attempt', attempt=attempt)
                try:
                    # Do not add Python's implicit Accept-Encoding: identity.
                    connection.putrequest('GET', path, skip_accept_encoding=True)
                    for name, value in headers.items():
                        connection.putheader(name, value)
                    connection.endheaders()
                    sent = True
                    response = connection.getresponse()
                except (OSError, http.client.HTTPException) as error:
                    retry = may_retry(error, attempt, sent)
                    event(kind='http_error', retry=retry)
                    if retry:
                        continue
                    raise
                jar.extract_cookies(response, request)
                status = response.status
                event(kind='http_response', http_status=status)
                if status in (301, 302, 303, 307):
                    if redirects >= 100:
                        raise ValueError('netfunnel_redirect_limit')
                    redirects += 1
                    location = response.getheader('Location')
                    if location is None or any(ord(c) <= 32 for c in location):
                        raise ValueError('netfunnel_redirect_location')
                    follow = urllib.parse.urljoin(target, location)
                    follow, _ = urllib.parse.urldefrag(follow)
                    if follow in seen:
                        raise ValueError('netfunnel_redirect_cycle')
                    seen.add(follow)
                    target = follow
                    break
                if status < 200:
                    raise LocalError('netfunnel_interim_response_unverified')
                if status in (204, 304):
                    # These responses have no entity for EntityUtils.toString.
                    raise ValueError('netfunnel_response_entity_missing')
                length = response.getheader('Content-Length')
                if length is not None and int(length) > 2**31-1:
                    raise ValueError('netfunnel_response_entity_too_large')
                body = response.read(LIMIT+1)
                if len(body) > LIMIT:
                    raise LocalError('netfunnel_response_limit')
                event(kind='http_body', bytes=len(body))
                # Status does not decide queue admission, and the SDK wrapper
                # does not request or automatically decode gzip content.
                return body.decode(charset(response.headers), errors='replace')
            finally:
                try:
                    connection.close()
                except Exception:
                    pass
