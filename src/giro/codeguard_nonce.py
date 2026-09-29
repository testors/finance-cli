"""Independent offline arithmetic for cg_get_auth_code (not JNI getNonce).

The six digest inputs must come from the real caller; no environment values,
device identities, runtime checks or server-issued tokens are synthesized here.
"""
from functools import lru_cache
from importlib.resources import files
import json

from .codeguard_primitives import aria256_schedule, aria_block, native_md4_20, native_md5_hex
from .codeguard_rule import AnalysisLimit
from .codeguard_tables import SBOXES


def evaluate_graph(program, **inputs):
    """Evaluate a bounded, data-only byte DAG; no eval, native code or I/O."""
    values = []
    def resolve(value):
        if isinstance(value, dict):
            if 'a' in value:
                return inputs[value['a']]
            if 's' in value:
                parent, start, length = value['s']
                return resolve(parent)[start:start+length]
            if 'r' in value:
                return values[value['r']]
            if 'i' in value:
                name, index = value['i']
                return inputs[name][index]
            vector, index = value['b']
            return resolve(vector)[index]
        if isinstance(value, list):
            return bytes(resolve(x) for x in value)
        return value
    for node in program['nodes']:
        op, *args = node
        args = [resolve(a) for a in args]
        if op == 'xor': result = args[0] ^ args[1]
        elif op == 'and': result = args[0] & args[1]
        elif op == 'or': result = args[0] | args[1]
        elif op == 'add': result = args[0] + args[1]
        elif op == 'sub': result = args[0] - args[1]
        elif op == 'shl': result = args[0] << args[1]
        elif op == 'shr': result = args[0] >> args[1]
        elif op == 'byte': result = (args[0] >> (8*args[1])) & 255
        elif op == 'join': result = int.from_bytes(args[0], 'little')
        elif op == 'hex': result = (b'0123456789ABCDEF' if args[2] else b'0123456789abcdef')[(args[0] >> args[1]) & 15]
        elif op == 'sbox': result = SBOXES[args[0]][args[1]]
        elif op == 'schedule': result = aria256_schedule(args[0])
        elif op == 'native_schedule': result = native_schedule(*args)
        elif op == 'aria': result = aria_block(*args)
        elif op == 'md4': result = native_md4_20(args[0])
        elif op == 'md5hex': result = native_md5_hex(args[0])
        else: raise AnalysisLimit('unmodeled nonce expression: ' + op)
        values.append(result)
    return resolve(program['output'])


def native_hex32(text):
    """0x23500/0x23634: odd/null -> zeros; invalid digit keeps parsed prefix.

    This intentionally is not bytes.fromhex: spaces are not ignored, and a
    valid high nibble is kept when the following character is invalid.
    """
    out = bytearray(32)
    if text is None:
        return bytes(out)
    if not isinstance(text, bytes):
        raise TypeError('native hex input must be bytes or None')
    text = text.split(b'\0', 1)[0]
    if len(text) % 2:
        return bytes(out)
    if len(text) > 64:
        raise AnalysisLimit('native hex __memset_chk abort boundary')
    for i, ch in enumerate(text):
        value = ch-48 if 48 <= ch <= 57 else ch-55 if 65 <= ch <= 70 else ch-87 if 97 <= ch <= 102 else None
        if value is None:
            break
        out[i//2] += value << (4 if i % 2 == 0 else 0)
    return bytes(out)


def key_code_array(key_hex):
    """0x2358c..0x23618; unsafe native malloc sizes are not invented results."""
    if key_hex is None:
        raise AnalysisLimit('native strlen(NULL) in key-code setup')
    raw = key_hex.split(b'\0', 1)[0]
    # Native allocates strlen/2, then writes 32 bytes regardless of allocation.
    # Odd 65-byte input actually allocates 32 and leaves the parsed key all zero.
    if len(raw)//2 < 32:
        raise AnalysisLimit('native key-code allocation smaller than 32 bytes')
    key = native_hex32(raw)
    schedule = native_schedule(key)
    first = aria_block(key[:16], schedule)
    return first + aria_block(first, schedule)


@lru_cache(maxsize=1)
def schedule_program():
    return json.loads(files('giro').joinpath('codeguard_native_schedule.json').read_text(encoding='utf-8'))


def native_schedule(key, old=bytes(272)):
    if len(key) != 32 or len(old) != 272:
        raise ValueError('native key/old schedule need 32/272 bytes')
    return evaluate_graph(schedule_program(), key=key, old=old)


def selected_functions(work):
    if len(work) != 32:
        raise ValueError('key-code work buffer needs 32 bytes')
    cursor = 0
    selected = []
    for i in range(6):
        cursor += 1 if work[i] & 1 else 2
        selected.append(work[cursor] % 100)
    return tuple(selected)


@lru_cache(maxsize=1)
def load_programs():
    return json.loads(files('giro').joinpath('codeguard_nonce_programs.json').read_text(encoding='utf-8'))


def transform(index, work, code, previous):
    if index not in range(100) or any(len(x) != 32 for x in (work, code, previous)):
        raise ValueError('nonce transform needs index 0..99 and three 32-byte inputs')
    data = load_programs()
    return evaluate_graph({'nodes': data['nodes'], 'output': data['functions'][index]['output']}, work=work, code=code, previous=previous)


def cg_auth_code(key_hex, codes):
    """Pure arithmetic only; uppercase 64-character result, not a server token."""
    if len(codes) < 6:
        raise AnalysisLimit('native code array reads six entries')
    work = key_code_array(key_hex)
    previous = bytes(32)  # initialized ONCE, not at each selected function
    accumulator = bytes(32)
    for index, text in zip(selected_functions(work), codes[:6]):
        previous = transform(index, work, native_hex32(text), previous)
        accumulator = bytes(a ^ b for a, b in zip(accumulator, previous))
    return accumulator.hex().upper()
