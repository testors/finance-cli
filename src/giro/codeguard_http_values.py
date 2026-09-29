"""Pure CodeGuard HTTP value adapters, composable with existing generators.

No HTTP client, SDK, native/environment observations, clock, trust or IO. Handles
only statically reconstructed value conversions; all other effects pass through.
"""
from dataclasses import dataclass

from .android_json import parse_object, string_field
from .android_cookie import parse_cookies, CookieValue
from .codeguard_rule import AnalysisLimit

PURE_EFFECTS = frozenset(('json_object','json_string_field','http_cookie_parse',
                          'http_cookie_string','java_decode_default_charset'))


def decode_default_utf8(data):
    """Charset.defaultCharset=UTF_8; invalid-byte replacement remains pending."""
    if type(data) is not bytes: raise AnalysisLimit('explicit input byte array required')
    try: return data.decode('utf-8')
    except UnicodeDecodeError:
        raise AnalysisLimit('Android UTF-8 malformed-byte replacement boundary') from None


@dataclass(repr=False)
class MemoryReader:
    """BufferedReader.readLine for an explicitly complete UTF-8 byte body.

    No stream/IO exception or partial-read simulation. Use original effects for
    actual stream observations. Only CR/LF delimit; Unicode separators do not.
    """
    text: str
    position: int = 0

    @classmethod
    def from_bytes(cls,data): return cls(decode_default_utf8(data))

    def read_line(self):
        if self.position==len(self.text): return None
        start = self.position
        while self.position<len(self.text) and self.text[self.position] not in '\r\n':
            self.position+=1
        result = self.text[start:self.position]
        if self.position<len(self.text):
            ch = self.text[self.position]
            self.position+=1
            if ch=='\r' and self.position<len(self.text) and self.text[self.position]=='\n':
                self.position+=1
        return result


def decode_value(effect, *, locale_language):
    kind,args = effect.kind,effect.args
    if kind=='json_object': return parse_object(*args)
    if kind=='json_string_field': return string_field(*args)
    if kind=='http_cookie_parse': return parse_cookies(*args,locale_language=locale_language)
    if kind=='http_cookie_string':
        if not isinstance(args[0],CookieValue): raise AnalysisLimit('parsed Android CookieValue required')
        return args[0].wire_text()
    if kind=='java_decode_default_charset': return decode_default_utf8(*args)
    raise AnalysisLimit('effect is not a pure HTTP value conversion')


def decode_values_steps(generator, *, locale_language):
    """Resolve pure values, preserving JavaFault throws into original catches.

    AnalysisLimit/Python faults never become a successful parse or Java failure.
    Unknown operations remain explicit effects, not synthetic success values.
    """
    value,pending = None,None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as finished:
            return finished.value
        pending = None
        try:
            if effect.kind in PURE_EFFECTS:
                value = decode_value(effect,locale_language=locale_language)
            else:
                value = yield effect
        except Exception as fault:
            # Forward the SAME object (including LinkFault/AnalysisLimit), not
            # reclassify it. Only the nested generator's own catches apply.
            pending = fault
