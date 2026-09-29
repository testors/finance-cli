"""Recovered NFilter public-key envelope, for offline compatibility analysis.

This is the vendor's envelope, not an X.509 SubjectPublicKeyInfo structure.
The shared SDK MAC constant must be supplied by the analysis caller.
"""
import hashlib
import hmac


def der(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else bytes([0x80 | ((size.bit_length() + 7) // 8)]) + size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + value


def valid_point_encoding(point):
    return ((len(point) == 22 and point[0] in (2, 3)) or
            (len(point) == 43 and point[0] in (4, 6, 7)))


def public_key_envelope(info, public_point, mac_key):
    if not valid_point_encoding(public_point):
        raise ValueError('Expected a WTLS5 public point')
    if len(mac_key) != 20:
        raise ValueError('Expected the 20-byte SDK public-key MAC constant')
    body = der(0x13, info) + der(4, public_point)
    inner = der(0x30, body)
    # The SDK hashes body-length bytes starting at the SEQUENCE tag. This
    # intentionally excludes the last two bytes for these short envelopes.
    mac = hmac.new(mac_key, inner[:len(body)], hashlib.sha1).digest()
    return der(0x30, inner + der(4, mac))


def read_der(data, offset=0):
    if offset + 2 > len(data):
        raise ValueError('Truncated DER')
    tag, size = data[offset:offset + 2]
    start = offset + 2
    if size & 0x80:
        count = size & 0x7f
        if not 1 <= count <= 4 or start + count > len(data):
            raise ValueError('Invalid DER length')
        size = int.from_bytes(data[start:start + count], 'big')
        start += count
    end = start + size
    if end > len(data):
        raise ValueError('Truncated DER value')
    return tag, data[start:end], end


def decode_public_key_envelope(encoded, mac_key):
    tag, outer, end = read_der(encoded)
    if tag != 0x30 or end != len(encoded):
        raise ValueError('Expected one public-key envelope')
    tag, body, inner_end = read_der(outer)
    mac_tag, mac, end = read_der(outer, inner_end)
    if tag != 0x30 or mac_tag != 4 or end != len(outer) or len(mac) != 20:
        raise ValueError('Invalid public-key envelope structure')
    expected = hmac.new(mac_key, outer[:len(body)], hashlib.sha1).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError('Public-key envelope MAC mismatch')
    info_tag, info, offset = read_der(body)
    point_tag, point, end = read_der(body, offset)
    if info_tag != 0x13 or point_tag != 4 or end != len(body):
        raise ValueError('Invalid public-key envelope fields')
    if not valid_point_encoding(point):
        raise ValueError('Expected a WTLS5 public point')
    return info, point
