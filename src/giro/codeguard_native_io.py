"""Bounded native process/file stages with explicit observations.

This is not a native_start runner or an attestation provider. No host process,
Android identity, file, or network is consulted. Effects must be resolved by an
observation adapter; unavailable observations must not become fopen failures.
"""
import hashlib
import re

from .codeguard_codec import jni_modified_utf8
from .codeguard_effects import Effect
from .codeguard_rule import AnalysisLimit


PACKAGE_CHUNK_SIZE = 0x80000


def package_digest_read_steps(file_size):
    """Digest after successful fopen/fseek/ftell/rewind, before later JNI work.

    Each effect returns the bytes actually written by ONE fread(size=1). A
    short read overwrites only the buffer prefix. The requested length is
    hashed, including initial zeros or bytes retained from the previous read.
    fopen/seek failures, signed overflow and later probe/cleanup are outside
    this stage; no original failure is inferred from an unknown observation.
    """
    if type(file_size) is not int or not 0 <= file_size < 2**31:
        raise AnalysisLimit('resolved nonnegative native file size required')
    # C signed division truncates toward zero; size=0 still issues fread(0).
    full_reads = max(0, (file_size - 1) // PACKAGE_CHUNK_SIZE)
    buffer = bytearray(PACKAGE_CHUNK_SIZE)
    digest = hashlib.sha256()
    for index in range(full_reads + 1):
        requested = (PACKAGE_CHUNK_SIZE if index < full_reads else
                     file_size - full_reads * PACKAGE_CHUNK_SIZE)
        data = yield Effect('native_package_fread', (requested,))
        if type(data) is not bytes or len(data) > requested:
            raise AnalysisLimit('actual native fread bytes required')
        buffer[:len(data)] = data
        digest.update(memoryview(buffer)[:requested])
    return digest.digest()


def _tokens(line):
    if type(line) is not bytes or not 1 <= len(line) <= 255:
        raise AnalysisLimit('actual native fgets bytes required')
    # strtok skips repeated delimiters; whitespace and LF remain in values.
    tokens = [part for part in line.split(b'\0', 1)[0].split(b':') if part]
    if not tokens:
        raise AnalysisLimit('native strncmp on null strtok result')
    return tokens


def _value(tokens):
    if len(tokens) < 2:
        raise AnalysisLimit('native null status value')
    return tokens[1]


def _atoi(value):
    match = re.match(rb'[ \t\r\n\v\f]*([+-]?[0-9]+)', value)
    number = int(match[1]) if match else 0
    if not -(2**31) <= number < 2**31:
        raise AnalysisLimit('native atoi overflow')
    return number


def _trace_pass_steps(*, outer):
    stream = yield Effect('native_fopen', (b'/proc/self/status', b'r'))
    if stream is None:
        return 1 if outer else 0
    tracer, uid = 0, None
    while True:
        line = yield Effect('native_fgets', (stream, 256))
        if line is None:
            break
        tokens = _tokens(line)
        if tokens[0].startswith(b'TracerPid'):
            tracer = _atoi(_value(tokens))
            if tracer == 0:
                break
        if tokens[0].startswith(b'Uid'):
            uid = _value(tokens)
            break
    yield Effect('native_fclose', (stream,))
    if tracer == 0:
        return 0
    path = b'/proc/' + str(tracer).encode('ascii') + b'/status'
    stream = yield Effect('native_fopen', (path, b'r'))
    if stream is None:
        if outer:
            # The outer copy calls fclose(NULL). The helper returns zero.
            raise AnalysisLimit('native outer trace check closes null stream')
        return 0
    result = 1
    while True:
        line = yield Effect('native_fgets', (stream, 256))
        if line is None:
            break
        tokens = _tokens(line)
        if tokens[0].startswith(b'Uid'):
            other_uid = _value(tokens)
            if uid is None:
                raise AnalysisLimit('native trace check uses unresolved UID pointer')
            # Raw substring, not integer UID equality or a root-user test.
            result = int(other_uid not in uid)
            break
    yield Effect('native_fclose', (stream,))
    return result


def native_process_check_steps():
    """The TWO status passes in start, returning 0 or native error code 127.

    Zero only means this stage continued. JNI/paths/rules, OSCheck and the
    server decision are separate. Even unchanged files are read twice.
    """
    if (yield from _trace_pass_steps(outer=True)):
        return 127
    return 127 if (yield from _trace_pass_steps(outer=False)) else 0


def native_process_name(fgets_bytes, *, nonce):
    """Transform one successful cmdline fgets, before NewStringUTF/PM lookup.

    start (including its inner digest lookup) strips ':engine'. getNonce
    strips any colon. JNI conversion/lookup is not implied by these bytes.
    """
    if type(nonce) is not bool:
        raise AnalysisLimit('explicit native entrypoint required')
    if type(fgets_bytes) is not bytes or not 1 <= len(fgets_bytes) <= 255:
        raise AnalysisLimit('actual successful native cmdline fgets required')
    return fgets_bytes.split(b'\0', 1)[0].split(b':' if nonce else b':engine', 1)[0]


def native_paths_match(process_name, *paths):
    """Only the C strstr checks, after nonnull GetStringUTFChars results."""
    if (type(process_name) is not bytes or len(paths) not in (1, 2)
            or any(type(p) is not bytes for p in paths)):
        raise AnalysisLimit('resolved native path bytes required')
    name = process_name.split(b'\0', 1)[0]
    return all(name in path.split(b'\0', 1)[0] for path in paths)


def native_pid_stat_steps(pid):
    """start's PID string branch, after preceding JNI/path checks completed.

    The stat request is preserved, but neither its return code nor struct is
    consulted. Do not add numeric validation, process ownership or liveness.
    """
    if pid is None:
        # GetStringUTFChars has already been called before the null check.
        raise AnalysisLimit('null PID JNI call requires runtime observation')
    if type(pid) is not str:
        raise AnalysisLimit('resolved Java PID string required')
    raw = jni_modified_utf8(pid)
    if raw in (b'0', b'', b'null') or len(raw) <= 1:
        return 123
    path = b'/proc/' + raw + b'/stat'
    if len(path) >= 256:
        raise AnalysisLimit('native PID path buffer overflow')
    yield Effect('native_stat', (path,))
    return 0
