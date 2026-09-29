"""SDK X509Name byte-input constructor, comparison and default rendering.

Not Android X500Principal canonicalization. The SDK reads only the first AVA
of each RDN and uses the OUTER index for the other name's string type during
unordered comparison. These compatibility quirks must not be repaired silently.
"""
from dataclasses import dataclass, field
import re

from .cert_factory import _node, SEQUENCE, SET, OID, CertificateBackendLimit

_SYMBOLS = {f'2.5.4.{n}': s for n, s in (
    (3,'CN'),(4,'SN'),(5,'SNUM'),(6,'C'),(7,'L'),(8,'S'),(9,'ST'),(10,'O'),(11,'OU'),
    (12,'T'),(15,'BC'),(42,'G'),(43,'I'),(44,'GENERATION'),(45,'UNIID'),(46,'DNQLF'),(65,'PSEUDO'))}
_SYMBOLS.update({'0.9.2342.19200300.100.1.25':'DC', '1.2.840.113549.1.9.1':'E',
                 '0.9.2342.19200300.100.1.3':'MAILBOX', '0.9.2342.19200300.100.1.1':'LDAPUID'})


def _trim(text):
    return text.strip(''.join(chr(i) for i in range(33)))  # Java String.trim, not Unicode strip


def _collapse(text):
    return re.sub(' +', ' ', text)


def sdk_lower(text, locale_language):
    if not text.isascii():
        raise CertificateBackendLimit('Android non-ASCII locale lowercase remains unresolved')
    if locale_language is None:
        raise CertificateBackendLimit('Android default locale must be explicit')
    if locale_language.lower() in ('tr', 'az'):
        text = text.replace('I', '\u0131')
    return text.lower()


@dataclass(frozen=True, repr=False)
class SDKName:
    # (OID, DERString.getString(), DERString.getType()) in original RDN order.
    entries: tuple = field(repr=False)

    @classmethod
    def from_der(cls, data):
        from asn1crypto.core import ObjectIdentifier
        name = _node(data)
        if name.kind != SEQUENCE:
            raise CertificateBackendLimit('SDK Name sequence parsing unresolved')
        entries = []
        for rdn in name.children():
            if rdn.kind != SET or not rdn.children():
                raise CertificateBackendLimit('SDK Name RDN cast/index failure boundary')
            ava = rdn.children()[0]  # additional AVAs are not visited by SDK
            fields = ava.children()
            if ava.kind != SEQUENCE or len(fields) < 2 or fields[0].kind != OID:
                raise CertificateBackendLimit('SDK Name AVA cast/index failure boundary')
            value = fields[1]
            if value.kind[:2] != (0,0):
                raise CertificateBackendLimit('SDK Name nonprimitive string boundary')
            tag, raw = value.kind[2], value.contents
            try:
                if tag in (18,19,22,26):
                    text = raw.decode('latin1')
                elif tag in (12,20):  # T61String(byte[]) uses default UTF-8, NOT Latin-1
                    text = raw.decode('utf-8')
                elif tag == 30:
                    text = raw[:len(raw)//2*2].decode('utf-16-be', 'surrogatepass')
                elif tag == 28:
                    # DERUniversalString.getString's signed >>>4 then %15.
                    digits = '0123456789abcdef'
                    text = ''.join(digits[(((b if b < 128 else b-256) & 0xffffffff) >> 4) % 15]
                                   + digits[b & 15] for b in raw)
                else:
                    raise CertificateBackendLimit('SDK DERString type not modeled')
                oid = ObjectIdentifier.load(fields[0].encoded).dotted
            except (UnicodeError, ValueError):
                raise CertificateBackendLimit('SDK Name byte decoding boundary unresolved') from None
            entries.append((oid,text,tag))
        return cls(tuple(entries))

    def equals(self, other, *, locale_language):
        if other is self:
            return True
        if not isinstance(other, SDKName) or len(self.entries) != len(other.entries):
            return False
        used = set()
        for i, (oid, value, tag) in enumerate(self.entries):
            for j, (other_oid, other_value, _) in enumerate(other.entries):
                # Original uses other.d.elementAt(i), NOT candidate index j.
                if j in used or oid != other_oid or tag != other.entries[i][2]:
                    continue
                if tag in (0,19):
                    a = _collapse(sdk_lower(_trim(value), locale_language))
                    b = _collapse(sdk_lower(_trim(other_value), locale_language))
                else:
                    a, b = value, other_value
                if a == b:
                    used.add(j)
                    break
            else:
                return False
        return True

    def render(self, *, locale_language, reverse=True):
        parts = []
        for oid, value, tag in (reversed(self.entries) if reverse else self.entries):
            if tag in (0,19):
                value = _collapse(_trim(value))
            label = sdk_lower(_SYMBOLS[oid], locale_language) if oid in _SYMBOLS else oid
            escaped = ''.join(('\\' if ch in ',"\\+<>;' else '')+ch for ch in value)
            parts.append(label+'='+escaped)
        return ','.join(parts)
