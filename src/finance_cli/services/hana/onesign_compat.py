# SPDX-License-Identifier: Apache-2.0
"""Response semantics used by the original Android/JavaScript clients.

Android JSONTokener/JSON conversion is ported from the pinned Apache-2.0
Android libcore (Copyright AOSP 2010).
The Apache-2.0 license is in LICENSES/Apache-2.0.txt.
Persisted CLI records and JOSE headers use their separate strict decoders.
"""
import json
import math
import re
from decimal import Decimal

from .onesign_crypto import ProtocolError, require

MISSING = object()


def java_double(value):
    value = value.strip(' \t\n\r\f\v\0')
    pattern = r'[+-]?(?:NaN|Infinity|(?:(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|0[xX](?:[0-9a-fA-F]+\.?[0-9a-fA-F]*|\.[0-9a-fA-F]+)[pP][+-]?[0-9]+)[dDfF]?)'
    if not re.fullmatch(pattern, value):
        raise ValueError('Not a Java double')
    if value[-1:] in 'dDfF' and value not in ('NaN', '+NaN', '-NaN', 'Infinity', '+Infinity', '-Infinity'):
        value = value[:-1]
    return float.fromhex(value) if '0x' in value.lower() else float(value)


def integer(value, reason='invalid_json_integer', *, bits=32):
    if isinstance(value, str):
        try:
            value = java_double(value)
        except (ValueError, OverflowError):
            raise ProtocolError(reason) from None
    if type(value) is int:
        return (value + 2 ** (bits - 1)) % (2 ** bits) - 2 ** (bits - 1)
    if type(value) is float:
        if math.isnan(value):
            return 0
        return max(-(2 ** (bits - 1)), min(2 ** (bits - 1) - 1, int(value) if math.isfinite(value)
                                           else 2 ** bits if value > 0 else -(2 ** bits)))
    raise ProtocolError(reason)


def boolean(value, reason='invalid_json_boolean'):
    if isinstance(value, str) and value.lower() in ('true', 'false'):
        return value.lower() == 'true'
    require(type(value) is bool, reason)
    return value


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


def get_string(value, name):
    return string(value.get(name, MISSING))


class KotlinLiteral(str):
    pass


class KotlinTokener:
    """STLmnf: lenient unquoted literals, no comments/trailing comma."""
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
        result = {name: str(value) if name in (*string_fields, *string_defaults) else native_value(value) for name, value in result.items()}
    return result


def bank_business_headers(headers, *, web):
    """Axios IL rejects only string 1; native mapper requires string 0.

    XHR combines duplicate headers; OkHttp Headers.get returns the last.
    The common header is consumed on native success, but not web success.
    """
    import base64
    values = {}
    for name, value in headers:
        name = name.lower()
        values[name] = values[name] + ', ' + value if web and name in values else value
    def decode(name):
        raw = values.get(name)
        require(isinstance(raw, str) and bool(raw), 'missing_business_header')
        try:
            # JS base64 decoder accepts padding omission/whitespace, not commas.
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


class Tokener:
    def __init__(self, raw):
        self.raw = (raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else raw).removeprefix('\ufeff')
        self.pos = 0

    def clean(self):
        while self.pos < len(self.raw):
            ch = self.raw[self.pos]
            self.pos += 1
            if ch in '\t \n\r':
                continue
            if ch == '#' or ch == '/' and self.raw[self.pos:self.pos + 1] == '/':
                while self.pos < len(self.raw) and self.raw[self.pos] not in '\r\n':
                    self.pos += 1
                continue
            if ch == '/' and self.raw[self.pos:self.pos + 1] == '*':
                end = self.raw.find('*/', self.pos + 1)
                require(end >= 0, 'invalid_android_json')
                self.pos = end + 2
                continue
            return ch
        return ''

    def value(self):
        ch = self.clean()
        require(bool(ch), 'invalid_android_json')
        if ch == '{':
            result = {}
            first = self.clean()
            if first == '}':
                return result
            if first:
                self.pos -= 1
            while True:
                key = self.value()
                require(isinstance(key, str), 'invalid_android_json_name')
                require(self.clean() in (':', '='), 'invalid_android_json')
                if self.raw[self.pos:self.pos + 1] == '>':
                    self.pos += 1
                item = self.value()
                require(type(item) is not float or math.isfinite(item), 'invalid_android_json_number')
                result[key] = item
                separator = self.clean()
                if separator == '}':
                    return result
                require(separator in (',', ';'), 'invalid_android_json')
        if ch == '[':
            result, trailing = [], False
            while True:
                first = self.clean()
                require(bool(first), 'invalid_android_json')
                if first == ']':
                    return result + ([None] if trailing else [])
                if first in ',;':
                    result.append(None)
                    trailing = True
                    continue
                self.pos -= 1
                result.append(self.value())
                separator = self.clean()
                if separator == ']':
                    return result
                require(separator in (',', ';'), 'invalid_android_json')
                trailing = True
        if ch in ('"', "'"):
            result = ''
            while self.pos < len(self.raw):
                char = self.raw[self.pos]
                self.pos += 1
                if char == ch:
                    return result
                if char == '\\':
                    require(self.pos < len(self.raw), 'invalid_android_json')
                    char = self.raw[self.pos]
                    self.pos += 1
                    if char == 'u':
                        digits = self.raw[self.pos:self.pos + 4]
                        require(re.fullmatch('[0-9a-fA-F]{4}', digits) is not None, 'invalid_android_json')
                        char, self.pos = chr(int(digits, 16)), self.pos + 4
                    else:
                        char = {'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}.get(char, char)
                result += char
            raise ProtocolError('invalid_android_json')
        self.pos -= 1
        start = self.pos
        while self.pos < len(self.raw) and self.raw[self.pos] not in '{}[]/\\:,=;# \t\f\r\n':
            self.pos += 1
        literal = self.raw[start:self.pos]
        require(bool(literal), 'invalid_android_json')
        if literal.lower() in ('null', 'true', 'false'):
            return {'null': None, 'true': True, 'false': False}[literal.lower()]
        if '.' not in literal:
            base, number = (16, literal[2:]) if literal.startswith(('0x', '0X')) else (8, literal[1:]) if literal.startswith('0') and len(literal) > 1 else (10, literal)
            try:
                require(re.fullmatch(r'[+-]?[0-9a-fA-F]+', number) is not None, 'not_integer_literal')
                number = int(number, base)
                if -(2 ** 63) <= number < 2 ** 63:
                    return number
            except (ValueError, ProtocolError):
                pass
        try:
            return java_double(literal)
        except (ValueError, OverflowError):
            return literal


def android_object(raw):
    result = Tokener(raw).value()
    require(isinstance(result, dict), 'json_object_required')
    return result


def web_value(raw):
    """Axios silentJSONParsing: JSON value on success, original text otherwise."""
    raw = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else raw
    try:
        return json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except ValueError:
        return raw


def truthy(value):
    return not (value is None or value is False or type(value) in (int, float) and value == 0
                or type(value) is float and math.isnan(value)
                or isinstance(value, str) and value == '')


def cloud_status(value):
    """CloudStatusInfo skips malformed optional entries and keeps list order."""
    def cert(item):
        return {name: get_string(item, name) for name in ('fingerprint', 'subjectDer', 'serial', 'subject',
                'issuer', 'notBefore', 'notAfter', 'policyOID', 'pinSalt', 'pinVersion')}

    def user(item):
        return {'uid': get_string(item, 'uid'), 'name': get_string(item, 'name'),
                'identity': string(item['identity']) if 'identity' in item else ''}

    def device(item):
        return {**{name: get_string(item, name) for name in ('deviceName', 'updatedAt', 'createdAt', 'notAfter', 'pubkId')},
                'loginCount': integer(item.get('loginCount')), 'oneTimeDevice': boolean(item.get('oneTimeDevice'))}

    def optional(parser, item):
        try:
            return parser(item) if isinstance(item, dict) else None
        except ProtocolError:
            return None

    result = {'userInfo': optional(user, value.get('userInfo')), 'device': optional(device, value.get('device'))}
    for name, parser in (('certInfos', cert), ('devices', device)):
        rows = value.get(name)
        result[name] = [parsed for row in rows if (parsed := optional(parser, row)) is not None] if isinstance(rows, list) else []
    return result
