"""Offline yessign certificate-input framing, NOT certificate validation.

Returns an UNVALIDATED ASN.1 payload (possibly CMS SignedData, not necessarily
a certificate). Does not parse ASN.1, check signatures, policy, time or CRLs,
fetch anything or install a recipient. Keep those actual app gates upstream of
CMS use.
"""
import re

from .errors import GiroError


class CertificateInputError(GiroError):
    """Input framing failed; not a CertValidException/server response code."""


_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
_TABLE = [0] * 128
for _i, _ch in enumerate(_ALPHABET):
    _TABLE[ord(_ch)] = _i


def base64_decode_string(text: str | None) -> bytes:
    """com.yessign.util.Base64.decode(String), including its loose lookup.

    This is NOT btworks/codeguard/Base64 nor the native rule decoder. Java's
    default regex \\s removes ASCII whitespace only. Unknown ASCII table entries
    are zero; non-ASCII fails only when indexed. Preserve the original final-
    quartet indexing even for non-multiple-of-four lengths.
    """
    if text is None or text == '':
        return b''
    clean = re.sub(r'[ \t\n\x0b\f\r]+', '', text)
    utf16 = clean.encode('utf-16-le', errors='surrogatepass')
    units = [int.from_bytes(utf16[i:i+2], 'little') for i in range(0, len(utf16), 2)]
    size = len(units)

    def char_at(index):
        if not 0 <= index < size:
            raise CertificateInputError('Base64 string index out of bounds')
        return units[index]

    def lookup(index):
        char = char_at(index)
        if char >= len(_TABLE):
            raise CertificateInputError('Base64 lookup index out of bounds')
        return _TABLE[char]

    padding = 2 if char_at(size-2) == 61 else 1 if char_at(size-1) == 61 else 0
    length = (size // 4 - 1) * 3 + (3-padding) if padding else size // 4 * 3
    if length < 0:
        raise CertificateInputError('Base64 negative output length')
    output = bytearray(length)

    def put(index, value):
        if not 0 <= index < length:
            raise CertificateInputError('Base64 output index out of bounds')
        output[index] = value & 255

    for i in range(0, size-4, 4):
        a, b, c, d = (lookup(i+j) for j in range(4))
        offset = (i // 4) * 3
        put(offset, (a << 2) | (b >> 4))
        put(offset+1, (b << 4) | (c >> 2))
        put(offset+2, d | (c << 6))
    a, b = lookup(size-4), lookup(size-3)
    if padding == 2:
        put(length-1, (a << 2) | (b >> 4))
    else:
        c = lookup(size-2)
        put(length-(3-padding), (a << 2) | (b >> 4))
        put(length-(2-padding), (b << 4) | (c >> 2))
        if not padding:
            put(length-1, lookup(size-1) | (c << 6))
    return bytes(output)


def certificate_payload(data: bytes) -> bytes:
    """Recover binary payload using the factory's byte-stream/PEM framing.

    Deliberately does NOT strip trailing DER data, unwrap SignedData, assert
    certificate acceptance, or require a PEM footer when the line path does not.
    The factory's inline fallback advances 27/32, the exact header lengths.
    """
    if data[:1] == b'\x30':
        return data
    headers = (b'-----BEGIN CERTIFICATE-----', b'-----BEGIN X509 CERTIFICATE-----')
    footers = (b'-----END CERTIFICATE-----', b'-----END X509 CERTIFICATE-----')
    # a(InputStream) drops CR anywhere and drops an unfinished last line at EOF.
    lines = [line.replace(b'\r', b'') for line in data.split(b'\n')[:-1]]
    found = False
    body = []
    for line in lines:
        if not found:
            if line in headers:
                found = True
        elif line in footers:
            break
        else:
            body.append(line)
    if b''.join(body):
        # Stream.read() byte -> Java char, not a UTF-8 reader.
        return base64_decode_string(b''.join(body).decode('latin-1'))
    # ByteArrayInputStream reset to the marked beginning. Android's default
    # charset is UTF-8 in this path; non-ASCII charset equivalence is not claimed.
    text = data.decode('utf-8', errors='replace')
    begin = -1
    end = -1
    for header, advance in zip(headers, (27, 32)):
        position = text.find(header.decode('ascii'))
        if position != -1:
            begin = position + advance
            break
    for footer in footers:
        position = text.rfind(footer.decode('ascii'))
        if position != -1:
            end = position
            break
    if begin <= 0 or end <= 0 or begin >= end:
        raise CertificateInputError('PEM framing failed')
    return base64_decode_string(text[begin:end])
