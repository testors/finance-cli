#!/usr/bin/env python3
"""CodeGuard decoded rule selection.

Implements readByte/getParsingPosition/parseRule. Never loads the SDK,
decrypts server rules, computes responses/nonces or manufactures tokens. The
result is a symbolic computation plan, not evidence of an accepted environment.
The independent
codeguard_codec module evaluates these byte operations; this selector itself
only describes them and does not fabricate missing environment inputs.
"""
from dataclasses import asdict, dataclass
import hashlib
import json

HASHES = ('SHA-1', 'MD5', 'SHA-256')
OPERATIONS = ('HMAC-SHA256', 'HMAC-MD5', 'CONCAT', 'OR', 'AND', 'HMAC-SHA1', 'XOR')


class NativeRuleError(ValueError):
    """An explicit native rule/position failure, NOT a Giro responseCode."""
    def __init__(self, code):
        self.native_code = code
        super().__init__(f'native rule stage returned {code}')


class AnalysisLimit(ValueError):
    """Input outside safely modeled memory semantics; no app outcome inferred."""


@dataclass(frozen=True)
class RulePlan:
    hash_ids: tuple[int, int]
    operation_ids: tuple[int, ...]
    selected_offsets: tuple[int, ...]

    def describe(self, *, extra_present=False):
        """Describe byte operations without accepting any attestation inputs.

        A/B/extra are symbolic names only. In native HMAC(left,right), right is
        the key and left is the message. Empty extra != absent extra.
        """
        operations = tuple(OPERATIONS[i] for i in self.operation_ids)
        steps = [dict(output='s0', operation=operations[0], left='A', right='B')]
        current = 's0'
        if extra_present:
            steps.append(dict(output='s0_extra', operation=operations[0],
                              left=current, right='extra'))
            current = 's0_extra'
        for i, operation in enumerate(operations[1:], 1):
            steps.append(dict(output=f's{i}', operation=operation,
                              left=f'{HASHES[self.hash_ids[(i+1) % 2]]}({current})',
                              right=f'{HASHES[self.hash_ids[i % 2]]}({current})'))
            current = f's{i}'
        return dict(hash_algorithms=[HASHES[i] for i in self.hash_ids],
                    operation_count=len(operations), steps=steps,
                    hmac_order='key=right, message=left',
                    bitwise_length='max; repeat shorter operand',
                    response_generated=False)


def parsing_positions(challenge: bytes, app_info: bytes | None,
                      version: bytes | None) -> tuple[int, int, int]:
    """Inputs are native bytes, NOT Python strings or Base64 challenge text.

    C strlen applies to app_info/version, not challenge. JNI modified UTF-8
    conversion belongs to the caller and is deliberately not guessed here.
    """
    if app_info is None:
        raise NativeRuleError(40)
    if version is None:
        raise NativeRuleError(41)
    data = (app_info.split(b'\0', 1)[0] + challenge[(len(challenge)+1)//2:]
            + version.split(b'\0', 1)[0])
    return tuple(byte % 10 for byte in hashlib.sha1(data).digest()[:3])


def parse_rule(rule: bytes | None, positions: tuple[int, int, int]) -> RulePlan:
    """Input is AFTER decodeRule's SEED decryption and eight-byte removal.

    Selected bytes >= 127 give native code 51. Unselected bytes are never
    validated. Empty buffers have native out-of-bounds behavior, not a newly
    invented server rejection code. Invalid caller positions are tool limits.
    """
    if rule is None:
        raise NativeRuleError(50)
    if not rule:
        raise AnalysisLimit('empty rule: native buffer access is not modeled')
    if len(positions) != 3 or any(type(p) is not int or not 0 <= p <= 9 for p in positions):
        raise AnalysisLimit('positions must come from getParsingPosition')
    cursor = positions[0]
    offsets = []

    def read():
        nonlocal cursor
        if cursor >= len(rule):
            cursor %= len(rule)
        offsets.append(cursor)
        byte = rule[cursor]
        if byte >= 127:
            raise NativeRuleError(51)
        return byte

    first = read() % 3
    cursor += 1
    second = read() % 3
    if second == first:
        second = (second + 1) % 3
    cursor += 1 + positions[1]
    count = read() % 3 + 3
    cursor += 1 + positions[2]
    operations = []
    for _ in range(count):
        operations.append(read() % 7)
        cursor += 1
    return RulePlan((first, second), tuple(operations), tuple(offsets))


def main():
    # Reproducible synthetic example only; no account/challenge files or wire
    # output are needed to inspect the recovered selection algorithm.
    positions = parsing_positions(b'synthetic-challenge', b'example-app', b'1.0')
    plan = parse_rule(bytes(range(40)), positions)
    print(json.dumps(dict(synthetic=True, positions=positions,
                          selection=asdict(plan), plan=plan.describe()), indent=2))


if __name__ == '__main__':
    main()
