"""Offline yessign LDAP wire/selection replay, not a network client.

No socket, TLS policy, directory writes, trust installation or Java object
deserialization. Input is public response bytes; values are kept out of repr.
SDK IO failures, uncaught runtime failures and backend gaps remain distinct.
"""
from dataclasses import dataclass
from io import BytesIO

from .cms import _tlv
from .cert_factory import _node, CertificateBackendLimit
from .cert_names import sdk_lower
from .cert_rules import java_int
from .codeguard_codec import java_utf8


class LdapIOError(ValueError):
    """A definite original IOException, without server text/identities."""


class LdapRuntimeError(ValueError):
    """Original runtime exception, NOT caught by processLdap's IO handlers."""


class _NoToken(Exception):
    pass


class _Tokenizer:
    def __init__(self, text, delimiters=' \t\n\r\f'):
        self.text, self.delimiters, self.position = text, delimiters, 0

    def _start(self):
        pos = self.position
        while pos < len(self.text) and self.text[pos] in self.delimiters:
            pos += 1
        return pos

    def more(self):
        return self._start() < len(self.text)  # does not advance currentPosition

    def next(self, delimiters=None):
        if delimiters is not None:
            self.delimiters = delimiters
        start = self._start()
        if start == len(self.text):
            raise _NoToken()
        pos = start
        while pos < len(self.text) and self.text[pos] not in self.delimiters:
            pos += 1
        self.position = pos
        return self.text[start:pos]


def _substring(text, start):
    raw = text.encode('utf-16-le','surrogatepass')
    if start*2 > len(raw):
        raise LdapRuntimeError('uri_substring_bounds')
    return raw[start*2:].decode('utf-16-le','surrogatepass')


@dataclass(frozen=True, repr=False)
class LdapLocation:
    scheme: str
    host: str
    port: str
    dn: str | None
    attribute: str | None


def parse_uri(text):
    """StringTokenizer delimiter changes, not RFC URL parsing/percent decoding.

    Scheme is only stored: the original processLdap uses a plain Socket for
    every scheme. This codec neither connects nor interprets ldaps as TLS.
    """
    if text is None:
        return None
    try:
        tokenizer = _Tokenizer(text)
        scheme = tokenizer.next('://')
        if not tokenizer.more(): return None
        rest = _substring(tokenizer.next(''),3)
        tokenizer = _Tokenizer(rest)
        host = tokenizer.next(':')
        if tokenizer.more():
            port = tokenizer.next('/')
            if not tokenizer.more(): return None
            port = _substring(port,1)
        else:
            tokenizer = _Tokenizer(rest)
            host = tokenizer.next('/')
            if not tokenizer.more(): return None
            port = '389'
        query = _Tokenizer(_substring(tokenizer.next(''),1),'?')
        dn = query.next() if query.more() else None
        attribute = query.next() if query.more() else None
        return LdapLocation(scheme,host,port,dn,attribute)
    except _NoToken:
        return None


def _number(value, tag=2):
    length = max(1,(value.bit_length()+8)//8)
    raw = value.to_bytes(length,'big',signed=True)
    while len(raw)>1 and ((raw[0]==0 and raw[1]<128) or (raw[0]==255 and raw[1]>=128)):
        raw = raw[1:]
    return _tlv(tag,raw)


def message(message_id, tag, contents):
    message_id = java_int(message_id)
    if message_id == 0:
        raise LdapIOError('request_message_id_zero')
    # DERApplicationSpecific uses constructed whenever contents is nonempty.
    return _tlv(48,_number(message_id)+_tlv((96 if contents else 64)|tag,contents))


def bind_request(message_id):
    return message(message_id,0,_number(3)+_tlv(4,b'')+_tlv(128,b''))


def _search_contents(location):
    if location.dn is None:
        raise LdapRuntimeError('search_dn_null')
    attributes = b'' if not location.attribute else _tlv(4,java_utf8(location.attribute))
    fields = (_tlv(4,java_utf8(location.dn))+_number(0,10)*2+_number(0)*2+
              _tlv(1,b'\0')+_tlv(135,b'objectclass')+_tlv(48,attributes))
    return fields


def search_request(message_id, location):
    return message(message_id,3,_search_contents(location))


def unbind_request(message_id):
    return message(message_id,2,b'')


def read_frame(stream):
    """Original c()/length helper; no canonical-length or tag restriction."""
    def read_exact(size):
        result = bytearray()
        while len(result)<size:
            try: chunk = stream.read(size-len(result))
            except OSError: raise LdapIOError('frame_read_io') from None
            if not chunk: raise LdapIOError('frame_eof')
            result.extend(chunk)
        return bytes(result)
    tag, first = read_exact(1), read_exact(1)
    value, extra = first[0], b''
    if value == 128:
        raise LdapIOError('frame_indefinite_length')
    if value > 127:
        count = value & 127
        if count > 4:
            raise LdapIOError('frame_length_over_four_bytes')
        extra = read_exact(count)
        value = java_int(int.from_bytes(extra,'big'))
        if value < 0:
            raise LdapIOError('frame_negative_length')
    return tag+first+extra+read_exact(value)


def _kind(node, kind):
    if node.kind != kind:
        # ASN.1 getInstance accepts additional tagged/constructed forms. Those
        # are not falsely classified as runtime rejection by this adapter.
        raise CertificateBackendLimit('LDAP ASN.1 constructor boundary')
    return node


def _fields(node, minimum):
    values = _kind(node,(0,1,16)).children()
    if len(values)<minimum: raise LdapRuntimeError('ldap_sequence_index')
    return values


def _tagged_object_sequence(node):
    if node.kind[:2] != (2,1):
        raise CertificateBackendLimit('LDAP tagged sequence boundary')
    children = node.children()
    if len(children)==1:
        return _kind(children[0],(0,1,16))
    return _node(_tlv(48,node.contents))


def _protocol(frame):
    fields = _fields(_node(frame),2)
    if fields[0].kind not in ((0,0,2),(0,0,4)):
        raise CertificateBackendLimit('LDAP message integer constructor boundary')
    # No request/response message ID comparison or zero/positive check.
    op = fields[1]
    if op.kind[0] != 1:
        raise CertificateBackendLimit('LDAP application class boundary')
    if len(fields)>2:
        control = fields[2]
        if control.kind[0] != 2: raise LdapRuntimeError('ldap_control_cast')
        if control.kind[2] == 0: _tagged_object_sequence(control)
    return op


def _result(op, *, bind=False):
    fields = _fields(_node(_tlv(48,op.contents)),3)
    code = _kind(fields[0],(0,0,10)).contents
    _kind(fields[1],(0,0,4))
    _kind(fields[2],(0,0,4))
    if len(fields)>3:
        if fields[3].kind[0] != 2: raise LdapRuntimeError('ldap_referral_cast')
        if fields[3].kind[2] == 3: _tagged_object_sequence(fields[3])
    if bind:
        for part in fields[3:]:
            if part.kind[0] != 2: raise LdapRuntimeError('ldap_sasl_cast')
            if part.kind[2] == 7 and part.kind[1]:
                raise CertificateBackendLimit('LDAP SASL tagged octet boundary')
        if not code: raise LdapRuntimeError('ldap_empty_result_integer')
        return java_int(int.from_bytes(code,'big',signed=True))
    # Completion helper constructs LDAPResult but never calls getValue().
    return None


def _utf8_lower(raw, locale_language):
    try: text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise CertificateBackendLimit('LDAP Android UTF-8 replacement boundary') from None
    return sdk_lower(text,locale_language)


def _entry_values(op, attribute, locale_language):
    fields = _fields(_node(_tlv(48,op.contents)),2)
    _kind(fields[0],(0,0,4))
    raw_attributes = _fields(fields[1],0)
    if not raw_attributes: raise LdapIOError('search_no_attributes')
    attributes = []
    # getAttributeUnit parses ALL PartialAttribute constructors before filtering.
    for raw in raw_attributes:
        parts = _fields(raw,2)
        attributes.append((_kind(parts[0],(0,0,4)).contents,_kind(parts[1],(0,1,17))))
    result = []
    for name,values in attributes:
        if attribute is not None and sdk_lower(attribute,locale_language) not in _utf8_lower(name,locale_language):
            continue
        for value in values.children():
            raw = _kind(value,(0,0,4)).contents
            if not raw: continue
            # UTF-8 replacement cannot erase bytes into ASCII "null"; nor can
            # Unicode lowercase turn a non-ASCII codepoint into n/u/l. Thus
            # binary certificate/CRL bytes need no lossy text conversion here.
            if raw.isascii() and raw.lower() == b'null': continue
            result.append(raw)
    return tuple(result)


@dataclass(frozen=True, repr=False)
class LdapReplay:
    code: int
    values: tuple
    requests: tuple
    failure_stage: str | None = None
    io_error: str | None = None
    completion_io_ignored: bool = False


@dataclass(frozen=True,repr=False)
class LdapEffect:
    kind: str
    data: bytes | None = None


def exchange_steps(location, *, message_id, locale_language):
    """Describe bind + FIRST search entry + one completion frame as IO effects.

    This begins AFTER connection setup: port/DNS/socket outcomes aren't inferred.
    Empty vectors still have wrapper code 1. Referral is an error, not a
    redirect. Failure text and Java Vector serialization are not fabricated.
    Only observed IO errors become wrapper code 0; backend gaps propagate.
    """
    requests, current = [], java_int(message_id)
    stage, ignored = 'generate_bind', False
    def completion():
        try: _result(_protocol((yield LdapEffect('read_frame'))))
        except LdapIOError: return True
        return False
    try:
        bind_id, current = current, java_int(current+1)
        requests.append(bind_request(bind_id))
        stage = 'send_bind'
        yield LdapEffect('write_frame',requests[-1])
        stage = 'receive_bind'
        frame = yield LdapEffect('read_frame')
        stage = 'process_bind'
        op = _protocol(frame)
        if op.kind[2] != 1: raise LdapIOError('not_bind_response')
        if _result(op,bind=True) != 0: raise LdapIOError('bind_result_nonzero')
        stage = 'generate_search'
        # SearchRequest construction precedes k++ (including null-DN failure).
        contents = _search_contents(location)
        search_id, current = current, java_int(current+1)
        requests.append(message(search_id,3,contents))
        stage = 'send_search'
        yield LdapEffect('write_frame',requests[-1])
        stage = 'receive_search'
        frame = yield LdapEffect('read_frame')
        stage = 'process_search'
        op = _protocol(frame)
        if op.kind[2] == 19:
            # Original referral diagnostic construction catches Exception;
            # then drains exactly one completion frame and reports IO failure.
            ignored = yield from completion()
            raise LdapIOError('search_referral')
        if op.kind[2] == 5:
            _result(op)
            raise LdapIOError('search_done_without_entry')
        if op.kind[2] != 4: raise LdapIOError('search_invalid_tag')
        values = _entry_values(op,location.attribute,locale_language)
        ignored = yield from completion()
    except LdapIOError as exc:
        # Bind generation/send failure closes without unbind; every later IO path
        # attempts unbind. Unbind errors are swallowed by the SDK helper.
        if stage not in ('generate_bind','send_bind'):
            try:
                requests.append(unbind_request(current))
                yield LdapEffect('write_frame',requests[-1])
            except LdapIOError: pass
        return LdapReplay(0,(),tuple(requests),stage,str(exc),ignored)
    try:
        requests.append(unbind_request(current))
        yield LdapEffect('write_frame',requests[-1])
    except LdapIOError: pass
    return LdapReplay(1,values,tuple(requests),completion_io_ignored=ignored)


def replay_responses(data, location, *, message_id, locale_language):
    """Same exchange state machine, using only local response bytes."""
    stream = BytesIO(data)
    generator = exchange_steps(location,message_id=message_id,locale_language=locale_language)
    value,error = None,None
    while True:
        try: effect=generator.throw(error) if error is not None else generator.send(value)
        except StopIteration as done: return done.value
        error=None
        try: value=read_frame(stream) if effect.kind=='read_frame' else None
        except LdapIOError as exc: error=exc


def inspect_responses(data, uri, *, message_id, locale_language):
    """Identity-free CLI report. A completed replay is not certificate trust."""
    result = {'offline':True,'network_attempted':False,'certificate_validation_performed':False,
              'live_login_ready':False,'transport_context':'post_connect_replay_only'}
    try:
        location = parse_uri(uri)
        if location is None:
            return {**result,'analysis_status':'uri_parse_returned_null'}
        replay = replay_responses(data,location,message_id=message_id,locale_language=locale_language)
        return {**result,'analysis_status':'ldap_replay_completed','ldap_wrapper_code':replay.code,
                'value_count':len(replay.values),'request_lengths':[len(r) for r in replay.requests],
                'failure_stage':replay.failure_stage,'io_error':replay.io_error,
                'completion_io_ignored':replay.completion_io_ignored}
    except LdapRuntimeError as exc:
        return {**result,'analysis_status':'original_runtime_exception','runtime_error':str(exc)}
    except CertificateBackendLimit as exc:
        return {**result,'analysis_status':'unmodeled','message':str(exc)}
