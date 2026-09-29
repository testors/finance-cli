"""Gson JsonReader-compatible token rules.

String/object/list adapters only; not a general replacement for every Gson
adapter. Keeps duplicate members for the model reader, including earlier
invalid values. No original Java/DEX code is executed.
"""
import re


class JsonNumber(str):
    """Number spelling, as returned by JsonReader.nextString()."""


class JsonObject(dict):
    def __init__(self, pairs):
        super().__init__(pairs)
        self.pairs = pairs


_NUMBER = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z')
_DELIMITERS = frozenset(' \t\r\n\f{}[]:,;=#/\\')
_ESCAPES = {'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t',
            '"': '"', "'": "'", '/': '/', '\\': '\\', '\n': '\n'}


class _Reader:
    def __init__(self, text):
        self.text = text
        # fillBuffer consumes one initial BOM, not arbitrary whitespace/BOMs.
        self.pos = 1 if text.startswith('\ufeff') else 0

    def fail(self):
        # Do not include response contents (account data) in errors.
        raise ValueError('Gson token/model input could not be read')

    def skip(self, *, lenient=True):
        text = self.text
        while self.pos < len(text):
            if text[self.pos] in ' \t\r\n':
                self.pos += 1
            elif text.startswith('/*', self.pos) and lenient:
                end = text.find('*/', self.pos + 2)
                if end < 0:
                    self.fail()
                self.pos = end + 2
            elif lenient and (text.startswith('//', self.pos) or text[self.pos] == '#'):
                while self.pos < len(text) and text[self.pos] not in '\r\n':
                    self.pos += 1
            else:
                break
        return text[self.pos:self.pos+1]

    def quoted(self):
        quote = self.text[self.pos]
        self.pos += 1
        result = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            self.pos += 1
            if char == quote:
                # Java strings are UTF-16, including unpaired surrogates.
                return ''.join(result).encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')
            if char == '\\':
                if self.pos == len(self.text):
                    self.fail()
                char = self.text[self.pos]
                self.pos += 1
                if char == 'u':
                    digits = self.text[self.pos:self.pos+4]
                    if not re.fullmatch('[0-9a-fA-F]{4}', digits):
                        self.fail()
                    char = chr(int(digits, 16))
                    self.pos += 4
                elif char in _ESCAPES:
                    char = _ESCAPES[char]
                else:
                    self.fail()
            result.append(char)
        self.fail()

    def literal(self):
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] not in _DELIMITERS:
            self.pos += 1
        if self.pos == start:
            self.fail()
        return self.text[start:self.pos]

    def value(self):
        char = self.skip()
        if not char:
            self.fail()
        if char in ('"', "'"):
            return self.quoted()
        if char == '{':
            return self.object()
        if char == '[':
            return self.array()
        token = self.literal()
        if token.lower() in ('true', 'false', 'null'):
            return {'true': True, 'false': False, 'null': None}[token.lower()]
        # peekNumber gives up at its 1024-char buffer size. Longer literals
        # still succeed in lenient mode, as strings, not numeric tokens.
        return JsonNumber(token) if len(token) < 1024 and _NUMBER.fullmatch(token) else token

    def object(self):
        self.pos += 1
        pairs = []
        if self.skip() == '}':
            self.pos += 1
            return JsonObject(pairs)
        while True:
            char = self.skip()
            key = self.quoted() if char in ('"', "'") else self.literal()
            separator = self.skip()
            if separator not in (':', '='):
                self.fail()
            self.pos += 1
            if separator == '=' and self.text[self.pos:self.pos+1] == '>':
                self.pos += 1
            pairs.append((key, self.value()))
            separator = self.skip()
            self.pos += 1
            if separator == '}':
                return JsonObject(pairs)
            if separator not in (',', ';'):
                self.fail()
            # Trailing object separators fail (unlike trailing array slots).

    def array(self):
        self.pos += 1
        items = []
        if self.skip() == ']':
            self.pos += 1
            return items
        while True:
            char = self.skip()
            items.append(None if char in (',', ';', ']') else self.value())
            separator = self.skip()
            self.pos += 1
            if separator == ']':
                return items
            if separator not in (',', ';'):
                self.fail()


def loads(text):
    """Gson.fromJson(String, Type): lenient value, then strict end-of-input.

    Null/empty input bypasses assertFullConsumption; the query layer still
    rejects a null query. Recursive Python storage is not Java's stack model.
    """
    reader = _Reader(text)
    reader.skip()
    if text.startswith(")]}'\n", reader.pos):
        reader.pos += 5
    if not reader.skip():
        return None
    value = reader.value()
    if value is not None and reader.skip(lenient=False):
        reader.fail()
    return value
