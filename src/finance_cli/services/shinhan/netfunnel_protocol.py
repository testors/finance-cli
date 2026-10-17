"""NetFunnel command state and native response values, separate from bank results."""
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
import math
import re
import struct
import unicodedata


class CodeError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__('netfunnel_command_error')


class LocalError(Exception):
    """A local limit has no established native SDK error/bypass counterpart."""


CODES = {0, 100, 101, 102, 104, 105, 106, 107, 108, 110, 111, 112, 113,
         200, 201, 202, 300, 301, 302, 303, *range(500, 516), *range(900, 910),
         920, 921, 922, 925, 926, 927, 928, *range(991, 1000)}


def integer(text):
    negative = text.startswith('-')
    digits = text[1:] if text.startswith(('-', '+')) else text
    if not digits:
        raise ValueError('netfunnel_integer')
    number = 0
    for char in digits:
        if ord(char) > 65535:
            raise ValueError('netfunnel_integer')
        number = number*10+unicodedata.decimal(char)
        if number > 2**31-int(not negative):
            raise ValueError('netfunnel_integer_range')
    return -number if negative else number


def bounded_exponent(text, limit):
    number = 0
    for digit in text.lstrip('+-'):
        number = min(number*10+ord(digit)-48, limit)
    return -number if text.startswith('-') else number


def float32(text):
    text = text.strip(''.join(map(chr, range(33))))
    if not re.fullmatch(r'[+-]?(?:NaN|Infinity|(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|0[xX][0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?[pP][+-]?[0-9]+|0[xX]\.[0-9a-fA-F]+[pP][+-]?[0-9]+)[fFdD]?)', text):
        raise ValueError('netfunnel_float')
    if text.lstrip('+-') in ('NaN', 'Infinity'):
        return float(text)
    sign = 0x80000000 if text.startswith('-') else 0
    value = text.lstrip('+-')
    if value[-1:] in 'fFdD':
        value = value[:-1]
    if value.lower().startswith('0x'):
        mantissa, power = re.split('[pP]', value[2:])
        fraction_digits = len(mantissa.partition('.')[2])
        digits = mantissa.replace('.', '').lstrip('0')
        power = bounded_exponent(power, len(mantissa)*4+200)-fraction_digits*4
        order = (len(digits)-1)*4+int(digits[:1] or '0', 16).bit_length()+power
        if not digits or order < -150:
            exact = Fraction(0)
        elif order > 129:
            return -math.inf if sign else math.inf
        else:
            numerator = int(digits, 16)
            exact = Fraction(numerator << max(power, 0), 1 << max(-power, 0))
    else:
        mantissa, _, power = re.sub('[eE]', 'e', value).partition('e')
        power = bounded_exponent(power or '0', len(mantissa)+200)
        digits = mantissa.replace('.', '')
        nonzero = digits.lstrip('0')
        order = len(mantissa.partition('.')[0])-(len(digits)-len(nonzero))-1+power
        if not nonzero or order < -46:
            exact = Fraction(0)
        elif order > 38:
            return -math.inf if sign else math.inf
        else:
            exact = Fraction(Decimal(mantissa+'e'+str(power)))
    return binary32(exact, sign)


def binary32(exact, sign=0):
    # Round once, directly to binary32 (decimal->binary64->binary32 can double round).
    if not exact:
        bits = 0
    else:
        n, d = exact.numerator, exact.denominator
        exponent = n.bit_length()-d.bit_length()
        if (n < d << exponent) if exponent >= 0 else (n << -exponent < d):
            exponent -= 1
        scale = max(exponent-23, -149)
        numerator, denominator = n << max(-scale, 0), d << max(scale, 0)
        q, r = divmod(numerator, denominator)
        q += int(2*r > denominator or 2*r == denominator and q % 2 == 1)
        if q >= 2**24:
            exponent += 1; q >>= 1
        bits = 0x7f800000 if exponent > 127 else q if exponent < -126 else ((exponent+127) << 23)+(q-2**23)
    return struct.unpack('!f', struct.pack('!I', bits | sign))[0]


@dataclass
class Response:
    code: int = 0
    key: str = ''
    utime: int = 0
    host: str = ''
    port: int = 0
    ttl: int = 0
    tps: float = 0.0
    nwait: int = 0
    nnext: int = 0

    def wait_seconds(self, maximum=30, minimum=1):
        return max(min(self.ttl, maximum) if maximum > 0 else self.ttl, minimum)

    def clear(self):
        self.__dict__.update(Response().__dict__)


def parse(text):
    position = text.find(':')  # Null input fails outside the native parser's catch.
    if position < 0:
        raise CodeError(905)
    try:
        code = integer(text[:position])
        result = Response(code=code if code in CODES else 0)
        for part in text[position+1:].split('&'):
            items = part.split('=')
            while items and items[-1] == '':
                items.pop()
            if len(items) < 2:
                continue
            name, value = items[:2]
            if name in ('key', 'ip'):
                setattr(result, 'host' if name == 'ip' else name, value)
            elif name == 'tps':
                result.tps = float32(value)
            elif name in ('utime', 'port', 'ttl', 'nwait', 'nnext'):
                setattr(result, name, integer(value))
        return result
    except Exception:
        raise CodeError(905) from None


@dataclass
class Property:
    service: str
    action: str
    protocol: str = 'http'
    host: str = 'apc.shinhan.com'
    port: int = 80
    path: str = 'ts.wseq'
    timeout: int = 3
    host_fixed: bool = True
    user_data: str = ''
    bypass: bool = False
    error_bypass: bool = True
    retry: int = 2
    max_ttl: int = 30
    stale_seconds: int = 180
    stale_count: int = 10
    ui_time_limit: int = 0
    ui_count_limit: int = 0


def url(protocol, host, port, path, query=None):
    result = (protocol+'://' if protocol else '')+(host or '')
    if port > 0 and (protocol, port) not in (('http', 80), ('https', 443)):
        result += ':'+str(port)
    return result+'/'+(path or '')+('?' + query if query else '')


class Client:
    def __init__(self, properties, send):
        self.properties, self.send = properties, send
        self.response = Response()

    def execute(self, opcode):
        if opcode not in (5101, 5002, 5003, 5004):
            raise CodeError(998)
        p = self.properties
        if opcode == 5101:
            if p is None:
                raise CodeError(904)
            self.response.clear()
            params = [('opcode', '5101'), ('sid', p.service), ('aid', p.action)]
            user = ''.join(c for c in (p.user_data or '') if not unicodedata.category(c).startswith('Z'))
            if user:
                params.append(('user_data', user))
        else:
            if not self.response.key:
                return
            params = [('opcode', str(opcode)), ('key', self.response.key)]
        host, port = p.host, p.port
        if opcode != 5101 and not p.host_fixed and self.response.host and self.response.port > 0:
            host, port = self.response.host, self.response.port
        target = url(p.protocol, host, port, p.path)
        try:
            text = self.send(target, params, p.timeout)
            if opcode == 5004:
                self.response.clear()  # No completion body parsing.
            else:
                self.response = parse(text)
        except (CodeError, LocalError):
            raise
        except Exception:
            raise CodeError(920) from None
