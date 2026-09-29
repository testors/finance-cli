"""CodeGuard byte codecs; no SDK or network execution.

These are NOT a complete attestation or token issuer. In particular the native
environment/file digest and getNonce's inputs are not guessed. Codec errors are
separate from Giro response codes. Never use these legacy formats in new systems.
"""
import base64
import hashlib
import hmac

from .codeguard_rule import AnalysisLimit, NativeRuleError, parse_rule, parsing_positions
from .crypto import _cbc

# Public protocol constants, NOT an account/session key. libCodeGuard .data
# VA 0x12190 and MainService.generateEncResponse have identical values.
RULE_KEY = bytes.fromhex('3e0152c70c303f02c1e5b73ce1c62283')
RULE_IV = bytes.fromhex('1feac101a2a77baae31971322f1c08e3')
_ALPHABET = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
_HASHES = ('sha1', 'md5', 'sha256')


class CodeGuardCodecError(ValueError):
    """Explicit codec failure, never a Giro responseCode or log of its input."""


class NativeBase64Error(CodeGuardCodecError):
    def __init__(self, code):
        self.native_code = code
        super().__init__(f'native base64 returned {code}')


def java_utf8(text):
    # Combine explicit UTF-16 surrogate pairs; replace unpaired ones with '?'.
    if text is None:
        raise CodeGuardCodecError('java_null_string')
    return text.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass').encode('utf-8', 'replace')


def jni_modified_utf8(text):
    """GetStringUTFChars: NUL=C080, supplementary chars=two surrogate triples."""
    if text is None:
        return None
    raw = text.encode('utf-16-le', 'surrogatepass')
    output = bytearray()
    for pos in range(0, len(raw), 2):
        unit = int.from_bytes(raw[pos:pos+2], 'little')
        if 0 < unit < 128:
            output.append(unit)
        elif unit < 2048:
            output.extend((192 | (unit >> 6), 128 | (unit & 63)))
        else:
            output.extend((224 | (unit >> 12), 128 | ((unit >> 6) & 63), 128 | (unit & 63)))
    return bytes(output)


def java_base64_decode(text):
    """btworks Base64.a(String), NOT Android Base64 or yessign Base64.

    No whitespace skipping/alphabet rejection. Unknown UTF-8 bytes (including
    '=') contribute a zero sextet. Only the final two '=' reduce output size.
    Empty/non-multiple-of-four input returns null, not empty bytes or an error.
    """
    raw = java_utf8(text)
    if not raw or len(raw) % 4:
        return None
    output = bytearray()
    for offset in range(0, len(raw), 4):
        value = 0
        for byte in raw[offset:offset+4]:
            digit = _ALPHABET.find(bytes((byte,)))
            value = (value << 6) | max(digit, 0)
        output.extend(value.to_bytes(3, 'big'))
    trim = 2 if raw.endswith(b'==') else 1 if raw.endswith(b'=') else 0
    return bytes(output[:len(output)-trim])


def native_base64_table():
    table = bytearray([255] * 128)
    for value, byte in enumerate(_ALPHABET):
        table[byte] = value
    for byte, value in ((9, 224), (10, 240), (13, 241), (32, 224), (45, 242), (61, 0)):
        table[byte] = value
    return bytes(table)


_NATIVE_TABLE = native_base64_table()


def native_base64_decode(data):
    """libCodeGuard Base64_decode at 0x83d4 on the caller's C string.

    Retains 7-bit table aliases and the ORIGINAL pointer used for padding
    subtraction after whitespace trimming. Memory-unsafe cases are analysis
    limits, not a newly invented SDK rejection or a lenient-success guess.
    """
    raw = data.split(b'\0', 1)[0]
    if not raw:
        raise AnalysisLimit('native Base64 reads before an empty input')
    size = len(raw.rstrip(b'\r \n'))
    if not size:
        raise AnalysisLimit('native Base64 empty trimmed input')
    if size % 4:
        raise NativeBase64Error(-1)
    start = 0
    while size > 0 and _NATIVE_TABLE[raw[start] & 127] == 224:
        start += 1
        size -= 1
    while size > 3 and (_NATIVE_TABLE[raw[start+size-1] & 127] | 19) == 243:
        size -= 1
    output = bytearray()
    terminated = raw + b'\0'
    for pos in range(start, start+size, 4):
        if pos + 4 > len(terminated):
            raise AnalysisLimit('native Base64 quartet outside input')
        values = [_NATIVE_TABLE[byte & 127] for byte in terminated[pos:pos+4]]
        if any(value & 128 for value in values):
            raise NativeBase64Error(-1)
        value = values[0] << 18 | values[1] << 12 | values[2] << 6 | values[3]
        output.extend(value.to_bytes(3, 'big'))
    trim = 0
    while True:
        index = size - trim - 1  # deliberately NOT start+size-trim-1
        if index < 0:
            raise AnalysisLimit('native Base64 padding scan before input')
        if raw[index] != 61:
            break
        trim += 1
    length = len(output) - trim
    if length <= 0:
        raise NativeBase64Error(100)
    return bytes(output[:length])


def native_seed_decrypt(ciphertext, key, iv):
    """CAPI_Decrypt default padding mode (not Java's SEED_CBC.c).

    Invalid padding >16 or mismatched repeated bytes returns the whole buffer
    with rc=0. A last byte of zero leaves length unchanged. Preserve this
    original behavior; neither padding nor codec rc proves authenticity.
    """
    if len(ciphertext) % 8:
        raise CodeGuardCodecError('native_cipher_length_error')
    if not ciphertext or len(ciphertext) % 16:
        raise AnalysisLimit('native partial-block memory behavior not modeled')
    plain = _cbc(key, iv, ciphertext, decrypt=True)
    padding = plain[-1]
    if 1 <= padding <= 16 and plain[-padding:] == bytes((padding,)) * padding:
        return plain[:-padding]
    return plain


def decode_rule(encoded_rule):
    if encoded_rule is None:
        raise NativeRuleError(30)
    try:
        ciphertext = native_base64_decode(encoded_rule)
    except NativeBase64Error:
        raise NativeRuleError(31) from None
    try:
        plain = native_seed_decrypt(ciphertext, RULE_KEY, RULE_IV)
    except CodeGuardCodecError:
        raise NativeRuleError(32) from None
    if len(plain) < 8:
        raise AnalysisLimit('decodeRule subtracts eight beyond plaintext length')
    return plain[8:]


def java_seed_encrypt(plain, key, iv):
    key, iv = _java_key_iv(key, iv)
    padding = 16 - len(plain) % 16
    return _cbc(key, iv, plain + bytes((padding,)) * padding)


def java_seed_decrypt(ciphertext, key, iv):
    """Java SEED_CBC.c: subtract last byte only; no PKCS#7 validation.

    For >=16 bytes, a partial final block is left zero-filled by the Java
    array. A stricter length/padding gate would change the original outcome.
    """
    key, iv = _java_key_iv(key, iv)
    if ciphertext is None or len(ciphertext) < 16:
        raise CodeGuardCodecError('java_cipher_array_access_error')
    full = len(ciphertext) // 16 * 16
    plain = _cbc(key, iv, ciphertext[:full], decrypt=True) + bytes(len(ciphertext)-full)
    length = len(plain) - plain[-1]
    if length < 0:
        raise CodeGuardCodecError('java_negative_plaintext_array_size')
    return plain[:length]


def _java_key_iv(key, iv):
    # Constructor/key schedule and CBC loops read 16 bytes, not array.length.
    if key is None or iv is None or len(key) < 16 or len(iv) < 16:
        raise CodeGuardCodecError('java_key_or_iv_array_access_error')
    return key[:16], iv[:16]


def combine(opcode, left, right):
    """codeguard_combine: HMAC key=RIGHT, cyclic bitwise operands."""
    if opcode in (0, 1, 5):
        return hmac.digest(right, left, {0: 'sha256', 1: 'md5', 5: 'sha1'}[opcode])
    if opcode == 2:
        return left + right
    if opcode not in (3, 4, 6):
        raise AnalysisLimit('opcode outside parseRule output')
    if not left or not right:
        raise AnalysisLimit('zero-length native bitwise operand memory unmodeled')
    operation = {3: lambda a, b: a | b, 4: lambda a, b: a & b, 6: lambda a, b: a ^ b}[opcode]
    return bytes(operation(left[i % len(left)], right[i % len(right)])
                 for i in range(max(len(left), len(right))))


def evaluate_rule(plan, left, challenge, *, extra=None):
    """Only generateResponse's inner byte computation, not JNI start/getNonce.

    Caller must supply the actual left operand; no default clean-environment
    digest, process identity or protected check result is manufactured here.
    """
    current = combine(plan.operation_ids[0], left, challenge)
    if extra is not None:
        current = combine(plan.operation_ids[0], current, extra.split(b'\0', 1)[0])
    for index, operation in enumerate(plan.operation_ids[1:], 1):
        a = hashlib.new(_HASHES[plan.hash_ids[(index+1) % 2]], current).digest()
        b = hashlib.new(_HASHES[plan.hash_ids[index % 2]], current).digest()
        current = combine(operation, a, b)
    return current


def derive_rule_plan(encoded_rule, encoded_challenge, app_info, version):
    """Decode native inputs; Java caller strings use JNI modified UTF-8."""
    if encoded_challenge is None:
        raise NativeRuleError(20)
    try:
        challenge = native_base64_decode(jni_modified_utf8(encoded_challenge))
    except NativeBase64Error:
        raise NativeRuleError(21) from None
    rule = decode_rule(jni_modified_utf8(encoded_rule))
    return parse_rule(rule, parsing_positions(challenge, jni_modified_utf8(app_info),
                                              jni_modified_utf8(version)))


def wrap_response(response, *, encrypted_token=False):
    """MainService.generateEncResponse; input is an ALREADY computed response.

    Does not generate an attestation or token. Null/engine-error passthrough is
    the original branch, not a successful replacement for an error token.
    """
    if response is None or 'E101_ENGINE_LOAD_ERROR' in response:
        return response
    text = ('[ETOKEN]' if encrypted_token else '') + response
    return base64.b64encode(java_seed_encrypt(java_utf8(text), RULE_KEY, RULE_IV)).decode('ascii')


def java_form_encode(text):
    """Android default-UTF8 URLEncoder; space='+', '*' literal, '~' escaped."""
    safe = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-*_'
    return ''.join(chr(b) if b in safe else '+' if b == 32 else f'%{b:02X}' for b in java_utf8(text))
