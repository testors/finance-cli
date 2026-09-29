"""Offline reproduction of the public web bundle's getSignTbsData string path.

Input is the ordered, already formatted sign form, including any transaction
suffixes and server timestamp. This creates signing text, not a signature.
"""


def javascript_escape(value):
    """Legacy JavaScript escape(): UTF-16 units, not UTF-8 URL encoding."""
    safe = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@*_+-./'
    encoded = value.encode('utf-16-be', errors='surrogatepass')
    parts = []
    for i in range(0, len(encoded), 2):
        unit = int.from_bytes(encoded[i:i + 2], 'big')
        if unit < 128 and unit in safe:
            parts.append(chr(unit))
        elif unit < 256:
            parts.append(f'%{unit:02X}')
        else:
            parts.append(f'%u{unit:04X}')
    return ''.join(parts)


def signing_text(form):
    if not isinstance(form, list) or not form:
        raise ValueError('Expected a nonempty ordered sign-form array')
    raw_fields = {'sign_sslsignctime', 'sign_eltsgnData'}
    parts = []
    for field in form:
        if not isinstance(field, dict) or set(field) != {'signid', 'name', 'value'}:
            raise ValueError('Each sign field must contain exactly signid, name, value')
        if not all(isinstance(v, str) for v in field.values()):
            raise ValueError('Sign-form inputs must be formatted strings')
        label, name, value = field['signid'], field['name'], field['value']
        if name not in raw_fields and label not in raw_fields:
            value = javascript_escape(value)
        # Preserve the web builder's literal order and concatenation. Replacing
        # this with json.dumps changes the bytes to be signed.
        parts.append('"' + label + '[' + name + ']":"' + value + '"')
    return '{' + ','.join(parts) + '}'
