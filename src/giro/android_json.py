"""Bounded Android org.json reader/string coercion, NOT Gson or json.loads.

Handles JSONTokener, JSONObject, JSONArray, JSON and JSONStringer semantics. Exception wire text stays in memory;
repr/str never disclose the document. Unmodeled numeric text is AnalysisLimit,
not a fabricated JSONException or a new server rejection condition.
"""
from dataclasses import dataclass
import math
import re

from .codeguard_effects import JavaFault
from .codeguard_rule import AnalysisLimit


@dataclass(repr=False)
class JSONObject:
    values: dict


@dataclass(repr=False)
class JSONArray:
    values: list


class NumberSyntaxError(ValueError):
    """Internal modeled NumberFormatException, distinct from AnalysisLimit."""


def _fault(message):
    return JavaFault('JSONException', message=message, java_string='org.json.JSONException: '+message)


def _units(text):
    raw = text.encode('utf-16-le', 'surrogatepass')
    return ''.join(chr(raw[i] | raw[i+1]<<8) for i in range(0,len(raw),2))


def _string(units):
    return units.encode('utf-16-le','surrogatepass').decode('utf-16-le','surrogatepass')


def java_integer(text, *, base=10, bits=64):
    """ASCII Long/Integer.parse; invalid values raise ValueError internally.

    Unicode numeric character tables are deliberately not guessed from Python.
    """
    if text is None or not text: raise NumberSyntaxError('integer syntax')
    sign = -1 if text[0]=='-' else 1
    digits = text[1:] if text[0] in '+-' else text
    if not digits: raise NumberSyntaxError('integer syntax')
    result = 0
    for ch in digits:
        if ord(ch)>127:
            if ch.isnumeric(): raise AnalysisLimit('Android Unicode numeric digit table unresolved')
            raise NumberSyntaxError('integer syntax')
        digit = '0123456789abcdefghijklmnopqrstuvwxyz'.find(ch.lower())
        if digit<0 or digit>=base: raise NumberSyntaxError('integer syntax')
        result = result*base+digit
        if result > 2**(bits-1)-(sign>0): raise NumberSyntaxError('integer range')
    return sign*result


_DECIMAL = re.compile(r'[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)[fFdD]?\Z')
_HEX = re.compile(r'[+-]?0[xX](?:[0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?|\.[0-9a-fA-F]+)[pP][+-]?[0-9]+[fFdD]?\Z')


def _double(text):
    trimmed = text.strip(''.join(map(chr,range(33))))
    if re.fullmatch(r'[+-]?(?:NaN|Infinity)',trimmed):
        return float(trimmed)
    if not (_DECIMAL.fullmatch(trimmed) or _HEX.fullmatch(trimmed)):
        raise ValueError('double syntax')
    if trimmed[-1:] in ('d','D','f','F'): trimmed = trimmed[:-1]
    try:
        return float.fromhex(trimmed) if 'x' in trimmed.lower() else float(trimmed)
    except OverflowError:
        return -math.inf if trimmed.startswith('-') else math.inf


def double_text(value):
    """Verified exact, short fixed-point subset of Double.toString.

    Binary64 parsing and object storage do not require rendering, so unfamiliar
    unused numbers do not block a document. General FloatingDecimal is pending.
    """
    if math.isnan(value): return 'NaN'
    if math.isinf(value): return '-Infinity' if value<0 else 'Infinity'
    if value==0: return '-0.0' if math.copysign(1,value)<0 else '0.0'
    numerator,denominator = value.as_integer_ratio()
    if 0.001<=abs(value)<1e7 and denominator<=16:
        places = denominator.bit_length()-1
        scaled = abs(numerator)*5**places
        digits = str(scaled)
        if len(digits)<=15:
            if places:
                digits = digits.zfill(places+1)
                result = (digits[:-places]+'.'+digits[-places:]).rstrip('0')
            else:
                result = digits+'.0'
            return ('-' if numerator<0 else '')+result
    raise AnalysisLimit('Android general Double.toString/FloatingDecimal rendering unresolved')


def _check_number(value):
    if type(value) is float and not math.isfinite(value):
        raise _fault('Forbidden numeric value: '+double_text(value))


def _number_text(value):
    _check_number(value)
    if type(value) is int: return str(value)
    if value==0 and math.copysign(1,value)<0: return '-0'
    as_long = max(-2**63,min(2**63-1,int(value)))
    if value==float(as_long): return str(as_long)
    return double_text(value)


def _quote(text):
    escapes = {'\b':'\\b','\t':'\\t','\n':'\\n','\f':'\\f','\r':'\\r',
               '"':'\\"','/':'\\/','\\':'\\\\'}
    return '"'+''.join(escapes.get(c,('\\u%04x'%ord(c)) if ord(c)<=31 else c) for c in text)+'"'


def _render(value):
    if value is None: return 'null'
    if type(value) is bool: return str(value).lower()
    if type(value) in (int,float): return _number_text(value)
    if type(value) is str: return _quote(value)
    if isinstance(value,JSONObject):
        return '{'+','.join(_quote(k)+':'+_render(v) for k,v in value.values.items())+'}'
    if isinstance(value,JSONArray): return '['+','.join(_render(v) for v in value.values)+']'
    raise AnalysisLimit('Android JSON object class unresolved')


def java_text(value):
    if value is None: return 'null'  # JSONObject.NULL inside this parser
    if type(value) is str: return value
    if type(value) is bool: return str(value).lower()
    if type(value) is int: return str(value)
    if type(value) is float: return double_text(value)
    if isinstance(value,(JSONObject,JSONArray)):
        try: return _render(value)
        except JavaFault: return None  # JSONObject/JSONArray.toString catches JSONException
    raise AnalysisLimit('Android JSON string conversion class unresolved')


def _class_name(value):
    if value is None: return 'org.json.JSONObject$1'
    if type(value) is bool: return 'java.lang.Boolean'
    if type(value) is str: return 'java.lang.String'
    if type(value) is int: return 'java.lang.Integer' if -2**31<=value<2**31 else 'java.lang.Long'
    if type(value) is float: return 'java.lang.Double'
    return 'org.json.JSONObject' if isinstance(value,JSONObject) else 'org.json.JSONArray'


def _display(value):
    rendered = java_text(value)
    return 'null' if rendered is None else rendered


def string_field(obj, name, default):
    """Updater's isNull(name) ? default : getString(name), no guessed schema."""
    if not isinstance(obj,JSONObject): raise AnalysisLimit('Android JSONObject adapter value required')
    value = obj.values.get(name)
    if value is None: return default
    rendered = java_text(value)
    if rendered is None:
        raise _fault('Value null at '+name+' of type '+_class_name(value)+' cannot be converted to String')
    return rendered


def _field_value(obj, name):
    if not isinstance(obj, JSONObject):
        raise AnalysisLimit('Android JSONObject adapter value required')
    return obj.values.get(name)


def _type_fault(value, name, required):
    return _fault('Value '+_display(value)+' at '+str(name)+' of type '+
                  _class_name(value)+' cannot be converted to '+required)


def _double_int(value):
    if math.isnan(value): return 0
    if value >= 2**31-1: return 2**31-1
    if value <= -2**31: return -2**31
    return int(value)  # Java narrowing truncates toward zero


def int_field(obj, name, default=0):
    """isNull ? default : getInt; Number.intValue differs from String parsing."""
    value = _field_value(obj, name)
    if value is None: return default
    if type(value) is int: return (value+2**31) % 2**32-2**31
    if type(value) is float: return _double_int(value)
    if type(value) is str:
        try: return _double_int(_double(value))
        except ValueError: pass
    raise _type_fault(value, name, 'int')


def boolean_field(obj, name, default=False):
    """isNull ? default : getBoolean; numeric truthiness/trim are not used."""
    value = _field_value(obj, name)
    if value is None: return default
    if type(value) is bool: return value
    if type(value) is str:
        # U+017F is the non-ASCII simple-case equivalent of the 's' in false.
        # Do not equate Python's general full case folding with Java's tables.
        if any(ord(ch)>127 and ch!='ſ' for ch in value):
            raise AnalysisLimit('Android Unicode boolean case table unresolved')
        lowered = value.replace('ſ', 's').lower()
        if lowered == 'true': return True
        if lowered == 'false': return False
    raise _type_fault(value, name, 'boolean')


def array_string_at(array, index):
    """JSONArray.getString for parsed arrays (None represents JSONObject.NULL)."""
    if not isinstance(array, JSONArray) or type(index) is not int:
        raise AnalysisLimit('Android JSONArray and integer index required')
    if not 0 <= index < len(array.values):
        raise _fault('Index '+str(index)+' out of range [0..'+str(len(array.values))+')')
    value = array.values[index]
    rendered = java_text(value)
    if rendered is None: raise _type_fault(value, index, 'String')
    return rendered


class _Tokener:
    def __init__(self,text):
        self.text = _units(text[1:] if text.startswith('\ufeff') else text)
        self.pos = 0

    def error(self,message):
        return _fault(message+' at character '+str(self.pos)+' of '+_string(self.text))

    def clean(self):
        while self.pos<len(self.text):
            ch = self.text[self.pos]
            self.pos += 1
            if ch in '\t\n\r ': continue
            if ch=='/' and self.pos<len(self.text):
                peek = self.text[self.pos]
                if peek=='*':
                    self.pos += 1
                    end = self.text.find('*/',self.pos)
                    if end<0: raise self.error('Unterminated comment')
                    self.pos = end+2
                    continue
                if peek!='/': return ch
                self.pos += 1
            elif ch!='#': return ch
            while self.pos<len(self.text):
                char = self.text[self.pos]
                self.pos += 1
                if char in '\r\n': break
        return None

    def string(self,quote):
        chars = []
        while self.pos<len(self.text):
            char = self.text[self.pos]
            self.pos += 1
            if char==quote: return _string(''.join(chars))
            if char=='\\':
                if self.pos==len(self.text): raise self.error('Unterminated escape sequence')
                char = self.text[self.pos]
                self.pos += 1
                if char=='u':
                    if self.pos+4>len(self.text): raise self.error('Unterminated escape sequence')
                    digits = self.text[self.pos:self.pos+4]
                    self.pos += 4
                    try: char = chr(java_integer(digits,base=16,bits=32)&65535)
                    except NumberSyntaxError: raise self.error('Invalid escape sequence: '+_string(digits)) from None
                else: char = {'b':'\b','f':'\f','n':'\n','r':'\r','t':'\t'}.get(char,char)
            chars.append(char)
        raise self.error('Unterminated string')

    def literal(self):
        start = self.pos
        while self.pos<len(self.text) and self.text[self.pos] not in '{}[]/\\:,=;# \t\f\r\n':
            self.pos += 1
        literal = _string(self.text[start:self.pos])
        if not literal: raise self.error('Expected literal value')
        if literal.casefold()=='null': return None
        if literal.casefold()=='true': return True
        if literal.casefold()=='false': return False
        if '.' not in literal:
            number,base = literal,10
            if literal.startswith(('0x','0X')): number,base = literal[2:],16
            elif literal.startswith('0') and len(literal)>1: number,base = literal[1:],8
            try: return java_integer(number,base=base)
            except NumberSyntaxError: pass
        try: return _double(literal)
        except ValueError: return literal

    def value(self):
        ch = self.clean()
        if ch is None: raise self.error('End of input')
        if ch in ('"',"'"): return self.string(ch)
        if ch=='{': return self.object()
        if ch=='[': return self.array()
        self.pos -= 1
        return self.literal()

    def object(self):
        result = JSONObject({})
        first = self.clean()
        if first=='}': return result
        if first is not None: self.pos -= 1
        while True:
            name = self.value()
            if type(name) is not str:
                raise self.error('Names must be strings, but '+_display(name)+' is of type '+_class_name(name))
            if self.clean() not in (':','='): raise self.error("Expected ':' after "+name)
            if self.pos<len(self.text) and self.text[self.pos]=='>': self.pos += 1
            value = self.value()
            _check_number(value)  # put(Object) checks numbers, JSONArray.put does not
            result.values[name] = value  # last value, original insertion position
            ch = self.clean()
            if ch=='}': return result
            if ch not in (',',';'): raise self.error('Unterminated object')

    def array(self):
        result,trailing = JSONArray([]),False
        while True:
            ch = self.clean()
            if ch is None: raise self.error('Unterminated array')
            if ch in (',',';'):
                result.values.append(None)
                trailing = True
                continue
            if ch==']':
                if trailing: result.values.append(None)
                return result
            self.pos -= 1
            result.values.append(self.value())
            ch = self.clean()
            if ch==']': return result
            if ch not in (',',';'): raise self.error('Unterminated array')
            trailing = True


def _parse_container(text, container, name):
    if type(text) is not str: raise AnalysisLimit('explicit Java String JSON input required')
    try:
        value = _Tokener(text).value()
        if not isinstance(value,container):
            raise _fault('Value '+_display(value)+' of type '+_class_name(value)+' cannot be converted to '+name)
        return value  # no added EOF check: original reads only nextValue
    except RecursionError:
        raise AnalysisLimit('Python/Android JSON recursion resource boundary') from None


def parse_object(text):
    return _parse_container(text, JSONObject, 'JSONObject')


def parse_array(text):
    return _parse_container(text, JSONArray, 'JSONArray')
