"""Offline OkHttp-compatible entity-body to String conversion.

Input is an already transfer-decoded HTTP entity, not a socket/wire capture.
No networking, cookies, TLS, chunk framing or Content-Length enforcement here.
Runtime charset gaps are analysis limits/diagnostics, never server rejections.
"""
from dataclasses import dataclass, field
import re
import zlib


class BodyAnalysisLimit(ValueError):
    """Cannot determine the Android charset mapping, not an app error code."""


class BodySizeLimit(BodyAnalysisLimit):
    """Optional caller resource budget, NEVER an original app rejection."""


class GzipRuntimeError(ValueError):
    """Original GzipSource reaches an IllegalArgumentException, not IOException."""


TOKEN = r"[a-zA-Z0-9!#$%&'*+.^_`{|}~\-]+"
TYPE_SUBTYPE = re.compile(f'({TOKEN})/({TOKEN})')
PARAMETER = re.compile(r';[ \t\n\x0b\f\r]*(?:(' + TOKEN + r')=(?:(' + TOKEN + r')|"([^"]*)"))?')
# Preserve the compatibility constants and check order, including UTF-32.
BOMS = ((bytes.fromhex('efbbbf'), 'utf-8'),
        (bytes.fromhex('feff'), 'utf-16-be'),
        (bytes.fromhex('fffe'), 'utf-16-le'),
        (bytes.fromhex('0000ffff'), 'utf-32-be'),
        (bytes.fromhex('ffff0000'), 'utf-32-le'))


def last_header(headers, name):
    for key, value in reversed(tuple(headers)):
        if key.lower() == name.lower():
            return value
    return None


def media_charset(content_type):
    """MediaType.parse/charset: None covers absent/invalid/no charset parameter.

    Conflicting spellings are compared literally ignoring case, not by codec
    alias equivalence. Spaces around '=' are not accepted by the compatibility regex.
    """
    if content_type is None:
        return None
    match = TYPE_SUBTYPE.match(content_type)
    if match is None:
        return None
    cursor, charset = match.end(), None
    while cursor < len(content_type):
        match = PARAMETER.match(content_type, cursor)
        if match is None:
            return None
        name, token, quoted = match.groups()
        if name is not None and name.lower() == 'charset':
            value = token if token is not None else quoted
            if token is not None and len(value) > 2 and value.startswith("'") and value.endswith("'"):
                value = value[1:-1]
            if charset is not None and value.lower() != charset.lower():
                return None
            charset = value
        cursor = match.end()
    return charset


def common_charset(name):
    """Verified common labels; custom/other Android providers remain unresolved.

    A supplied resolver may return None for a KNOWN unsupported Java charset,
    causing the original UTF-8 fallback. Python codec availability alone is not
    evidence of Android support. Illegal Java charset names do fall back.
    """
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:+\-]*', name):
        return None
    aliases = {
        'utf-8': 'utf-8', 'utf8': 'utf-8',
        'utf-16': 'utf-16-be', 'utf-16be': 'utf-16-be', 'utf-16le': 'utf-16-le',
        'utf-32be': 'utf-32-be', 'utf-32le': 'utf-32-le',
        'us-ascii': 'ascii', 'ascii': 'ascii',
        'iso-8859-1': 'latin-1', 'iso_8859-1': 'latin-1', 'latin1': 'latin-1',
        'euc-kr': 'euc-kr', 'euc_kr': 'euc-kr',
    }
    try:
        return aliases[name.lower()]
    except KeyError:
        raise BodyAnalysisLimit('Android charset mapping is not modeled') from None


def _has_body(method, status, headers):
    if method == 'HEAD':
        return False
    value = last_header(headers, 'content-length')
    length = -1
    if value is not None and re.fullmatch(r'[+-]?\d+', value) and all(ord(c) <= 65535 for c in value):
        negative = value.startswith('-')
        number = 0
        for char in value.lstrip('+-'):
            number = number * 10 + int(char)
            if number > 2**63 - (not negative):
                break
        else:
            length = -number if negative else number
    return (not (100 <= status < 200 or status in (204, 304)) or length != -1
            or (last_header(headers, 'transfer-encoding') or '').lower() == 'chunked')


def gunzip_app(data, *, max_output=None):
    """Okio GzipSource: one member, CRC+ISIZE, no extra CM/reserved-bit gate."""
    if max_output is not None and max_output < 0:
        raise ValueError('negative output budget')
    def require(end):
        if end > len(data):
            raise OSError('truncated gzip entity')

    require(10)
    if data[:2] != b'\x1f\x8b':
        raise OSError('gzip magic mismatch')
    flags, cursor = data[3], 10
    if flags & 4:
        require(cursor+2)
        # Original readShortLe is signed, unlike the RFC's unsigned XLEN.
        length = int.from_bytes(data[cursor:cursor+2], 'little', signed=True)
        if length < 0:
            raise GzipRuntimeError('negative gzip extra length')
        cursor += 2 + length
        require(cursor)
    for flag in (8, 16):
        if flags & flag:
            end = data.find(b'\0', cursor)
            if end < 0:
                raise OSError('unterminated gzip header field')
            cursor = end + 1
    if flags & 2:
        require(cursor+2)
        if int.from_bytes(data[cursor:cursor+2], 'little') != zlib.crc32(data[:cursor]) & 65535:
            raise OSError('gzip header CRC mismatch')
        cursor += 2
    inflater = zlib.decompressobj(-15)
    try:
        plain = inflater.decompress(data[cursor:], 0 if max_output is None else max_output + 1)
        if max_output is not None and len(plain) > max_output:
            raise BodySizeLimit('decoded body budget exceeded')
        plain += inflater.flush()
    except zlib.error:
        raise OSError('invalid gzip deflate body') from None
    if not inflater.eof:
        raise OSError('truncated gzip deflate body')
    trailer = inflater.unused_data
    if len(trailer) != 8:
        raise OSError('gzip truncated trailer or unconsumed source')
    if int.from_bytes(trailer[:4], 'little') != zlib.crc32(plain) & 0xffffffff:
        raise OSError('gzip content CRC mismatch')
    if int.from_bytes(trailer[4:], 'little') != len(plain) & 0xffffffff:
        raise OSError('gzip ISIZE mismatch')
    return plain


@dataclass(frozen=True)
class BodyText:
    text: str = field(repr=False)
    charset: str
    bom_length: int
    gzip_decoded: bool
    headers: tuple = field(repr=False)
    issues: tuple[str, ...] = ()


def decode_body(data, headers=(), *, request_headers=(), method='POST', status=200,
                charset_resolver=common_charset, max_decoded_bytes=None):
    """Bridge transparent-gzip + ResponseBody.string; no status success gate.

    Call only when the application actually consumes the body. Invalid byte
    replacement and legacy Korean/UTF-32 runtime differences are diagnostic;
    diagnostics do not change QueryClient's response success decision.
    """
    headers = tuple(headers)
    transparent = (last_header(request_headers, 'accept-encoding') is None
                   and last_header(request_headers, 'range') is None)
    unzip = (transparent and (last_header(headers, 'content-encoding') or '').lower() == 'gzip'
             and _has_body(method, status, headers))
    if unzip:
        data = gunzip_app(data, max_output=max_decoded_bytes)
        headers = tuple((k, v) for k, v in headers if k.lower() not in ('content-encoding', 'content-length'))
    if max_decoded_bytes is not None and len(data) > max_decoded_bytes:
        raise BodySizeLimit('decoded body budget exceeded')
    bom_length, charset = 0, None
    for marker, codec in BOMS:
        if data.startswith(marker):
            bom_length, charset = len(marker), codec
            data = data[bom_length:]
            break
    if charset is None:
        label = media_charset(last_header(headers, 'content-type'))
        charset = (charset_resolver(label) if label is not None else None) or 'utf-8'
    issues = []
    if charset in ('euc-kr', 'utf-32-be', 'utf-32-le'):
        issues.append('android_charset_boundary_unverified')
    try:
        text = data.decode(charset)
    except UnicodeDecodeError:
        text = data.decode(charset, errors='replace')
        issues.append('android_malformed_replacement_boundary_unverified')
    return BodyText(text, charset, bom_length, unzip, headers, tuple(issues))
