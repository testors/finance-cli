"""Explicit HTTP/1 exchange executor for CodeGuard's supported normal path.

No environment provider, implicit send permission, retry, redirect, proxy,
platform cookie jar or response cache. Known normal header/body conversions
are supported; transport differences remain processing boundaries, not guessed
Java errors or server verdicts. Raw exchanges remain in memory only.
"""
from dataclasses import dataclass, field
import gzip
import http.client
import ssl
import zlib
from urllib.parse import urlsplit, parse_qs

from .android_headers import read_header_lines, HeaderFields
from .bootstrap import _tls_context
from .codeguard_effects import JavaFault
from .codeguard_http_values import MemoryReader
from .codeguard_rule import AnalysisLimit


class HTTPBoundary(AnalysisLimit):
    def __init__(self, stage):
        self.stage = stage
        super().__init__('codeguard_http_' + stage)


class _HeaderTap:
    """Retain actual HTTP header lines before Python's email parser folds them."""
    def __init__(self, stream):
        self.stream, self.lines = stream, []

    def readline(self, limit=-1):
        line = self.stream.readline(limit)
        self.lines.append(line)
        return line

    def __getattr__(self, name): return getattr(self.stream, name)


class _Response(http.client.HTTPResponse):
    def begin(self):
        if self.headers is not None: return
        tap = _HeaderTap(self.fp)
        self.fp = tap
        try:
            super().begin()
        finally:
            self.header_lines = tuple(tap.lines)
            if self.fp is tap: self.fp = tap.stream


def _headers(response):
    # 100 Continue may precede the final status block. Other interim statuses
    # are not silently treated as final success by this bounded executor.
    lines = response.header_lines
    starts = [i for i, line in enumerate(lines) if line.startswith(b'HTTP/')]
    if not starts: raise HTTPBoundary('status_line')
    block = lines[starts[-1]:]
    try:
        text = [line.removesuffix(b'\n').removesuffix(b'\r').decode('ascii') for line in block]
    except UnicodeDecodeError:
        raise HTTPBoundary('header_charset') from None
    # Python and OkHttp differ on malformed/folded headers. Do not silently
    # claim their framing/cookie interpretation agrees on those inputs.
    for line in text[1:-1]:
        if ':' not in line or line.startswith((' ', '\t', ':')):
            raise HTTPBoundary('header_framing')
        name = line.split(':', 1)[0]
        if any(c.isspace() for c in name): raise HTTPBoundary('header_framing')
    fields = read_header_lines(text[1:], status_line=text[0])
    lengths = fields.get('Content-Length')
    encodings = fields.get('Transfer-Encoding')
    if lengths is not None and (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()):
        raise HTTPBoundary('content_length')
    if encodings is not None and (tuple(value.lower() for value in encodings) != ('chunked',) or lengths is not None):
        raise HTTPBoundary('transfer_encoding')
    return fields


@dataclass(repr=False, eq=False)
class _Connection:
    url: str
    command: int
    target: str
    method: str = 'GET'
    read_timeout: int = 0
    connect_timeout: int = 0
    do_input: bool = True
    do_output: bool = False
    headers: dict = field(default_factory=dict)
    output: bytearray = field(default_factory=bytearray)
    output_closed: bool = False
    client: object = None
    response: object = None
    header_fields: object = None
    input: object = None
    sent: bool = False
    failed: bool = False


@dataclass(repr=False, eq=False)
class _Reader:
    connection: _Connection
    value: object = None
    closed: bool = False


HTTP_EFFECTS = frozenset(('http_open', 'http_call', 'write_bytes', 'flush_output',
    'close_output', 'headers_for_logging', 'urlconnection_response_headers',
    'set_cookie_header_values', 'input_stream_reader', 'read_line', 'close_reader'))


class CodeGuardHTTP:
    """One caller-owned scope. Constructing/opening does not perform IO.

    endpoint is one exact HTTPS endpoint; loopback test endpoints also use TLS.
    default_user_agent is explicit protocol metadata, never read from the host.
    max_requests/max_body_bytes are processing budgets, not service conditions.
    Context must verify chain and hostname. No custom TLS verifier is installed.
    """
    def __init__(self, *, endpoint, send=False, default_user_agent,
                 max_requests, max_body_bytes=1024*1024, tls_context=None):
        try:
            if type(endpoint) is not str or not endpoint.isascii(): raise ValueError
            parsed = urlsplit(endpoint)
            parsed.port  # reject an invalid port before creating a connection
        except ValueError:
            raise HTTPBoundary('endpoint_configuration') from None
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or not parsed.path.endswith('/CodeGuard/check.jsp')):
            raise HTTPBoundary('endpoint_configuration')
        if type(send) is not bool or type(max_requests) is not int or max_requests < 1:
            raise HTTPBoundary('scope_configuration')
        if type(max_body_bytes) is not int or max_body_bytes < 1:
            raise HTTPBoundary('scope_configuration')
        if (type(default_user_agent) is not str or not default_user_agent
                or not default_user_agent.isascii() or '\r' in default_user_agent or '\n' in default_user_agent):
            raise HTTPBoundary('user_agent_configuration')
        context = _tls_context() if tls_context is None else tls_context
        if (context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname
                or context.keylog_filename is not None):
            raise HTTPBoundary('tls_configuration')
        context.set_alpn_protocols(['http/1.1'])
        self.endpoint, self.address, self.context = endpoint, parsed, context
        self.send, self.default_user_agent = send, default_user_agent
        self.max_requests, self.max_body_bytes = max_requests, max_body_bytes
        self.attempts, self.connections, self.events = 0, [], []
        self.closed = False

    def _owned(self, connection):
        if self.closed: raise HTTPBoundary('closed_scope')
        if not any(connection is current for current in self.connections):
            raise HTTPBoundary('foreign_connection')
        if connection.failed: raise HTTPBoundary('failed_connection_not_retried')
        return connection

    def _connect(self, connection):
        self._owned(connection)
        if connection.client is not None: return
        if not self.send: raise HTTPBoundary('send_not_enabled')
        if self.attempts >= self.max_requests: raise HTTPBoundary('request_budget')
        if connection.method not in ('GET', 'POST') or (connection.method == 'POST' and connection.command != 300):
            raise HTTPBoundary('request_method')
        self.attempts += 1  # reserve before attempting TLS; failure never retries
        self.events.append({'command':connection.command, 'phase':'connect_attempt'})
        connection.client = http.client.HTTPSConnection(self.address.hostname, self.address.port or 443,
            timeout=connection.connect_timeout/1000 or None, context=self.context)
        connection.client.response_class = _Response
        connection.client.connect()
        connection.client.sock.settimeout(connection.read_timeout/1000 or None)
        self.events.append({'command':connection.command, 'phase':'tls_verified'})

    def _response(self, connection):
        self._connect(connection)
        if connection.response is not None: return connection.response
        if connection.sent: raise HTTPBoundary('response_not_retried')
        headers = dict(connection.headers)
        if 'user-agent' not in headers: headers['user-agent'] = ('User-Agent', self.default_user_agent)
        if 'connection' not in headers: headers['connection'] = ('Connection', 'Keep-Alive')
        if 'accept-encoding' not in headers: headers['accept-encoding'] = ('Accept-Encoding', 'gzip')
        body = bytes(connection.output) if connection.do_output else None
        connection.sent = True
        self.events.append({'command':connection.command, 'phase':'request_attempt'})
        connection.client.request(connection.method, connection.target, body=body,
                                  headers={name:value for name,value in headers.values()})
        connection.response = connection.client.getresponse()
        status = connection.response.status
        self.events.append({'command':connection.command, 'phase':'response_headers', 'http_status':status})
        if status < 200 or (300 <= status < 400 and status != 304):
            raise HTTPBoundary('redirect_or_interim_response')
        connection.header_fields = _headers(connection.response)
        if (connection.header_fields.last('Content-Encoding') or '').lower() == 'gzip':
            # The request's automatic gzip mode removes these from the exposed
            # headers, but the lower HTTPResponse still knows its wire framing.
            if 'accept-encoding' not in connection.headers:
                connection.input = gzip.GzipFile(fileobj=connection.response)
                connection.header_fields = HeaderFields(tuple((k,v) for k,v in connection.header_fields.pairs
                    if k.lower() not in ('content-encoding', 'content-length')), connection.header_fields.status_line)
        if connection.input is None: connection.input = connection.response
        return connection.response

    def _call(self, connection, method, args):
        self._owned(connection)
        if connection.client is not None and method.startswith('set'):
            raise HTTPBoundary('configuration_after_connect')
        if method in ('setReadTimeout', 'setConnectTimeout'):
            value, = args
            if type(value) is not int or value < 0: raise HTTPBoundary('timeout_value')
            setattr(connection, 'read_timeout' if method == 'setReadTimeout' else 'connect_timeout', value)
        elif method == 'setRequestMethod':
            connection.method, = args
        elif method in ('setDoInput', 'setDoOutput'):
            value, = args
            if type(value) is not bool: raise HTTPBoundary('boolean_value')
            setattr(connection, 'do_input' if method == 'setDoInput' else 'do_output', value)
        elif method == 'setRequestProperty':
            name, value = args
            if (type(name) is not str or type(value) is not str or not name.isascii() or not value.isascii()
                    or not name or any(c in name+value for c in '\r\n')
                    or any(not (c.isalnum() or c in "!#$%&'*+-.^_`|~") for c in name)):
                raise HTTPBoundary('request_header_value')
            connection.headers[name.lower()] = (name, value)
        elif method in ('connect', 'getOutputStream'):
            self._connect(connection)
            if method == 'getOutputStream':
                if not connection.do_output: raise HTTPBoundary('output_not_enabled')
                return connection
        elif method in ('getResponseCode', 'getInputStream'):
            response = self._response(connection)
            if method == 'getResponseCode': return response.status
            if not connection.do_input: raise HTTPBoundary('input_not_enabled')
            if response.status >= 400:
                # Deterministic getInputStream branch, not a translation of a
                # Python network exception. The URL stays out of repr/logs.
                raise JavaFault('FileNotFoundException', message=connection.url,
                    java_string='java.io.FileNotFoundException: '+connection.url, bases=('IOException',))
            return connection
        else:
            raise HTTPBoundary('unsupported_connection_call')

    def resolve(self, effect):
        connection = None
        try:
            if self.closed: raise HTTPBoundary('closed_scope')
            kind, args = effect.kind, effect.args
            if kind == 'http_open':
                url, = args
                parsed = urlsplit(url)
                if url.split('?', 1)[0] != self.endpoint or parsed.fragment:
                    raise HTTPBoundary('endpoint_mismatch')
                command = parse_qs(parsed.query).get('CODEGUARD_CMD')
                if command not in (['101'], ['200'], ['300']): raise HTTPBoundary('command_scope')
                connection = _Connection(url, int(command[0]), parsed.path+'?'+parsed.query)
                self.connections.append(connection)
                return connection
            if kind == 'http_call':
                connection, method, params = args
                return self._call(connection, method, params)
            if kind in ('write_bytes', 'flush_output', 'close_output'):
                connection = self._owned(args[0])
                if connection.sent or connection.output_closed: raise HTTPBoundary('closed_output')
                if kind == 'write_bytes':
                    if type(args[1]) is not bytes: raise HTTPBoundary('output_value')
                    connection.output.extend(args[1])
                elif kind == 'close_output': connection.output_closed = True
                return None
            if kind in ('headers_for_logging', 'urlconnection_response_headers', 'set_cookie_header_values'):
                connection = self._owned(args[0])
                self._response(connection)
                if kind == 'headers_for_logging': return None  # do not emit values
                if kind == 'set_cookie_header_values': return connection.header_fields.get(args[1])
                return connection.header_fields
            if kind == 'input_stream_reader': return _Reader(self._owned(args[0]))
            if kind in ('read_line', 'close_reader'):
                reader, = args
                if not isinstance(reader, _Reader) or reader.closed: raise HTTPBoundary('reader_state')
                connection = self._owned(reader.connection)
                if kind == 'close_reader':
                    reader.closed = True
                    connection.input.close()
                    return None
                if reader.value is None:
                    source = connection.input
                    if source is None: raise HTTPBoundary('input_stream_missing')
                    if source is connection.response and source.length is not None:
                        if source.length > self.max_body_bytes: raise HTTPBoundary('body_budget')
                        body = source.read()  # detect truncated Content-Length
                    else:
                        body = source.read(self.max_body_bytes+1)
                    if len(body) > self.max_body_bytes: raise HTTPBoundary('body_budget')
                    reader.value = MemoryReader.from_bytes(body)
                return reader.value.read_line()
            raise HTTPBoundary('unsupported_effect')
        except JavaFault:
            raise
        except AnalysisLimit:
            if isinstance(connection, _Connection) and any(connection is current for current in self.connections):
                connection.failed = True
            raise
        except (OSError, http.client.HTTPException, EOFError, ValueError, zlib.error):
            if isinstance(connection, _Connection) and any(connection is current for current in self.connections):
                connection.failed = True
            raise HTTPBoundary('transport_or_stream') from None

    def close(self):
        """Final owner cleanup cannot overwrite an already-returned token."""
        self.closed = True
        for connection in self.connections:
            if connection.client is not None:
                try: connection.client.close()
                except OSError:
                    self.events.append({'command':connection.command, 'phase':'cleanup_error'})


def project_http_steps(generator, *, transport):
    """Execute only HTTP effects, preserving caller state and catch scopes."""
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            value = transport.resolve(effect) if effect.kind in HTTP_EFFECTS else (yield effect)
        except Exception as fault:
            pending = fault
