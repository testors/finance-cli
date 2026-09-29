"""Offline codecs for the service protocol.

Not a protection bypass, token generator or login client.
Never reuse these legacy fixed-IV formats for new protocols.
"""
import re

from .errors import GiroError

API_IV = b"0123456789012345"
PIN_IV = b"MobileTransKey10"
BODY_CHARSET = 'euc-kr'


def _cbc(key, iv, data, *, decrypt=False):
    if not isinstance(key, bytes) or len(key) != 16:
        raise GiroError("SEED 세션 키는 정확히 16바이트여야 합니다.")
    if not isinstance(data, bytes) or not data or len(data) % 16:
        raise GiroError("SEED CBC 입력은 비어 있지 않은 16바이트 배수여야 합니다.")
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.decrepit.ciphers.algorithms import SEED
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
    except ImportError:
        raise GiroError("암호 코덱에는 SEED 지원 cryptography 패키지가 필요합니다.") from None
    try:
        cipher = Cipher(SEED(key), modes.CBC(iv))
        context = cipher.decryptor() if decrypt else cipher.encryptor()
    except UnsupportedAlgorithm:
        raise GiroError("설치된 암호 backend가 SEED CBC를 지원하지 않습니다.") from None
    return context.update(data) + context.finalize()


def encrypt_body(plaintext, key):
    """Caller supplies bytes; TransUtil uses euc-kr for string input."""
    if not isinstance(plaintext, bytes) or not plaintext:
        raise GiroError("비어 있지 않은 본문 bytes가 필요합니다.")
    padding = 16 - len(plaintext) % 16
    return _cbc(key, API_IV, plaintext + bytes([padding]) * padding)


def decrypt_body(ciphertext, key):
    data = _cbc(key, API_IV, ciphertext, decrypt=True)
    padding = data[-1]
    if not 1 <= padding <= 16 or data[-padding:] != bytes([padding]) * padding:
        raise GiroError("SEED 패딩 검증 실패")
    # This protocol has no authentication tag here; padding is not authenticity.
    return data[:-padding]


def hex_decode_app(text):
    """yessign Hex.decode(String), deliberately NOT bytes.fromhex validation.

    Odd UTF-16 length gets a leading zero. No whitespace skipping or nibble
    validity checks in the app. Non-ASCII locale-sensitive lowercasing remains
    a compatibility caveat; ASCII wire hex follows the exact arithmetic.
    """
    if text is None:
        return None
    if len(text.encode('utf-16-le', 'surrogatepass')) // 2 % 2:
        text = '0' + text
    raw = text.lower().encode('utf-16-le', 'surrogatepass')
    units = [int.from_bytes(raw[i:i+2], 'little') for i in range(0, len(raw), 2)]
    def nibble(char):
        return char - (48 if char < 97 else 87)
    try:
        return bytes(((nibble(units[i]) << 4) + nibble(units[i+1])) & 255
                     for i in range(0, len(units), 2))
    except IndexError:
        raise GiroError('Hex.decode의 문자 쌍 처리 실패') from None


def encrypt_text(text, key):
    return encrypt_body(text.encode(BODY_CHARSET, errors='replace'), key)


def decrypt_text(text, key):
    return decrypt_body(hex_decode_app(text), key).decode(BODY_CHARSET, errors='replace')


def _decode_word(value):
    # TransKeyCipher.DEC_WORD = E(G(value)), where E applies H twice per byte.
    def h(v):
        return (((v & 1) << 7) | ((v & 192) >> 6) | ((v & 48) >> 2)
                | ((v & 6) << 3) | ((v & 8) << 3)) & 255
    value = (((value & 61440) >> 12) | ((value & 15) << 12)
             | ((value & 240) << 4) | ((value & 3840) >> 4)) & 65535
    return (h(h(value >> 8)) | (h(h(value)) << 8)) & 65535


_KEYPAD_WORDS = (137, 25, 153, 41, 169, 57, 185, 73, 201, 9)
NUMERIC_KEYPAD = "".join(chr(_decode_word(word)) for word in _KEYPAD_WORDS)


def encode_pin(pin, key):
    """6 ASCII digits -> basic mTK_cipherData (96 bytes / 192 hex chars).

    Global.useModule=0; keypadType=4; SameKeyEncrypt=false in this profile.
    Each keypress restarts CBC at PIN_IV. No PKCS padding / HMAC / timestamp.
    Static reconstruction: not yet compared to a real login response.
    """
    if not isinstance(pin, str) or not re.fullmatch(r"[0-9]{6}", pin):
        raise GiroError("간편비밀번호는 ASCII 숫자 6자리여야 합니다.")
    result = []
    for digit in pin:
        block = bytes((5, NUMERIC_KEYPAD.index(digit) + 1)) + bytes(14)
        result.append(_cbc(key, PIN_IV, block))
    return b"".join(result).hex()
