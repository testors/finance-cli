"""Response semantics of the mobile client and its web pages.

Business acceptance follows the service's own header verdict. Lenient native
literals and JavaScript truthiness are reproduced only where a verdict or a
continuation cursor depends on them.
"""
import base64
import json
import math
import re
from decimal import Decimal

from finance_cli.core.errors import ProtocolError, require

MISSING = object()


def string(value, reason='invalid_json_string'):
    require(value is not MISSING, reason)
    if isinstance(value, str):
        return value
    if value is None:
        return 'null'
    if type(value) is bool:
        return 'true' if value else 'false'
    if type(value) is float:
        if not math.isfinite(value):
            return 'NaN' if math.isnan(value) else 'Infinity' if value > 0 else '-Infinity'
        if value and (abs(value) >= 1e7 or abs(value) < 1e-3):
            mantissa, exponent = format(Decimal(repr(value)).normalize(), 'E').split('E')
            return mantissa + ('.0' if '.' not in mantissa else '') + 'E' + str(int(exponent))
        return format(Decimal(repr(value)), 'f')
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


class KotlinLiteral(str):
    pass


class KotlinTokener:
    """Lenient unquoted literals, no comments and no trailing comma."""
    def __init__(self, raw, string_values):
        self.raw = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else raw
        self.pos, self.string_values = 0, string_values

    def space(self):
        while self.pos < len(self.raw) and self.raw[self.pos] in ' \t\r\n':
            self.pos += 1

    def take(self, expected):
        self.space()
        require(self.raw[self.pos:self.pos + 1] == expected, 'invalid_native_json')
        self.pos += 1

    def value(self, key=False):
        self.space()
        ch = self.raw[self.pos:self.pos + 1]
        require(bool(ch), 'invalid_native_json')
        if ch == '"':
            try:
                value, size = json.JSONDecoder(strict=False).raw_decode(self.raw[self.pos:])
            except ValueError:
                raise ProtocolError('invalid_native_json') from None
            self.pos += size
            return value
        if ch in '{[':
            require(not key, 'invalid_native_json_key')
            self.pos += 1
            result = {} if ch == '{' else []
            end = '}' if ch == '{' else ']'
            self.space()
            if self.raw[self.pos:self.pos + 1] == end:
                self.pos += 1
                return result
            while True:
                if ch == '{':
                    name = self.value(key=True)
                    self.take(':')
                    result[name] = self.value()
                else:
                    result.append(self.value())
                self.space()
                if self.raw[self.pos:self.pos + 1] == end:
                    self.pos += 1
                    return result
                self.take(',')
        start = self.pos
        while self.pos < len(self.raw) and self.raw[self.pos] not in '{}[]:,"\\ \t\r\n':
            self.pos += 1
        literal = self.raw[start:self.pos]
        require(bool(literal), 'invalid_native_json_literal')
        if key:
            return literal
        if literal == 'null':
            return None
        if self.string_values:
            return KotlinLiteral(literal)
        try:
            return json.loads(literal)
        except ValueError:
            return literal


def kotlin_object(raw, *, string_values=False, string_fields=(), string_defaults=()):
    parser = KotlinTokener(raw, string_values or bool(string_fields) or bool(string_defaults))
    result = parser.value()
    parser.space()
    require(parser.pos == len(parser.raw) and isinstance(result, dict), 'invalid_native_json')
    if string_values:
        require(all(isinstance(value, str) for value in result.values()), 'invalid_native_json_string')
    for name in string_fields:
        require(name in result and isinstance(result[name], str), 'invalid_native_json_string')
    for name in string_defaults:
        if result.get(name) is None:
            result[name] = ''
        require(isinstance(result[name], str), 'invalid_native_json_string')

    def native_value(value):
        if isinstance(value, KotlinLiteral):
            try:
                return json.loads(value)
            except ValueError:
                return str(value)
        if isinstance(value, dict):
            return {k: native_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [native_value(v) for v in value]
        return value
    if string_fields or string_defaults:
        result = {name: str(value) if name in (*string_fields, *string_defaults) else native_value(value)
                  for name, value in result.items()}
    return result


def web_value(raw):
    """Axios silentJSONParsing: JSON value on success, original text otherwise."""
    raw = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else raw
    try:
        return json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except ValueError:
        return raw


def bank_business_headers(headers, *, web):
    """Axios rejects only the string 1; the native mapper requires the string 0.

    XHR combines duplicate headers; OkHttp returns the last one. The common
    header is consumed on native success, but not on web success.
    """
    values = {}
    for name, value in headers:
        name = name.lower()
        values[name] = values[name] + ', ' + value if web and name in values else value

    def decode(name):
        raw = values.get(name)
        require(isinstance(raw, str) and bool(raw), 'missing_business_header')
        try:
            # The JavaScript decoder accepts omitted padding and whitespace, not commas.
            clean = re.sub(r'\s', '', raw).replace('-', '+').replace('_', '/')
            decoded = base64.b64decode(clean + '=' * (-len(clean) % 4), validate=True)
            return web_value(decoded) if web else kotlin_object(decoded)
        except (ValueError, UnicodeError):
            raise ProtocolError('invalid_business_header') from None
    system = decode('hana-sys-header')
    require(isinstance(system, dict) and isinstance(system.get('CHNL_SYS_HDPT'), dict), 'invalid_business_header')
    code = system['CHNL_SYS_HDPT'].get('PROC_RSLT_DV_CD')
    if web:
        require(code != '1', 'bank_http_or_business_failure')
    else:
        common = decode('hana-com-header')
        require(isinstance(common.get('CNL_HDPT'), dict), 'invalid_business_header')
        require(type(code) in (str, int, float, bool) and string(code) == '0', 'bank_http_or_business_failure')
    return code


def truthy(value):
    return not (value is None or value is False or type(value) in (int, float) and value == 0
                or type(value) is float and math.isnan(value)
                or isinstance(value, str) and value == '')
