"""Statically recovered platform arithmetic and engine-file read sequence.

No OS/SDK execution, implicit file reads, system clock or key recovery search.
Each key calculation takes ONE explicit seed for this client's own exchange.
"""
from dataclasses import dataclass
import hashlib

from .codeguard_codec import java_base64_decode
from .codeguard_effects import Effect, JavaFault, observed_bool
from .codeguard_artifacts import DigestRead
from .codeguard_rule import AnalysisLimit


def key_bytes_from_seed(seed):
    """Random.setSeed(long); nextBytes(new byte[16]), plain Random instance.

    The initial Random() seed is overwritten. This is compatibility arithmetic,
    NOT a recommended general-purpose cryptographic key generator, and does
    not infer any existing client's key/seed or call currentTimeMillis itself.
    """
    if type(seed) is not int or not -(2**63) <= seed < 2**63:
        raise AnalysisLimit('explicit Java long seed required')
    state = (seed ^ 0x5deece66d) & ((1 << 48)-1)
    result = bytearray()
    for _ in range(4):
        state = (state*0x5deece66d + 11) & ((1 << 48)-1)
        # next(32) then four (byte)rnd, rnd>>=8 writes low byte first.
        result.extend((state >> 16).to_bytes(4,'little'))
    return bytes(result)


@dataclass(frozen=True, repr=False)
class ReadOnce:
    count: int
    data: bytes  # exactly the bytes the one read wrote, not unobserved tail bytes


def _digest_after_one_read(available, observation, md5):
    if type(available) is not int or not 0 <= available < 2**31:
        raise AnalysisLimit('actual FileInputStream.available nonnegative int required')
    if isinstance(observation, DigestRead):
        if available != observation.content.size:
            raise AnalysisLimit('complete immutable read size mismatch')
        return observation.content.md5 if observed_bool(md5) else observation.content.sha256
    if not isinstance(observation,ReadOnce) or type(observation.count) is not int:
        raise AnalysisLimit('actual single read observation required')
    if not -1 <= observation.count <= available or type(observation.data) is not bytes:
        raise AnalysisLimit('single read result shape unresolved')
    copied = max(0,observation.count)
    if len(observation.data) != copied:
        raise AnalysisLimit('missing/extra bytes in observed read result')
    digest = hashlib.md5() if observed_bool(md5) else hashlib.sha256()
    digest.update(observation.data)
    # new byte[available] is zero-initialized. Original ignores read count and
    # hashes all bytes; no retry/readFully. Stream zeros to avoid huge allocation.
    remaining = available-copied
    block = bytes(min(remaining,65536))
    while remaining:
        amount = min(remaining,len(block))
        digest.update(block[:amount])
        remaining -= amount
    return digest.digest()


def engine_exists_steps(main, application_info, expected, md5):
    """MainService.engineExist; application_info has ALREADY been obtained.

    BytesUtil.f compares the tail of the digest, not whole-array equality.
    No clean result is substituted for an unknown file/input observation.
    """
    main.append_log(',E19.1')
    try:
        directory = yield Effect('application_native_library_dir',(application_info,))
        if directory is None:
            return False
        path = directory + '/libCodeGuard.so'
        if not observed_bool((yield Effect('file_exists',(path,)))):
            return False
        main.append_log(',E19.6')
        stream = yield Effect('open_file_input',(path,))
        available = yield Effect('file_available',(stream,))
        if type(available) is int and available < 0:
            return False  # NegativeArraySizeException, before read/close
        observed = yield Effect('file_read_once',(stream,available))
        yield Effect('close_file_input',(stream,))
        digest = _digest_after_one_read(available,observed,md5)
        if expected is None:
            return False  # Base64 null String dereference inside catch
        expected_bytes = java_base64_decode(expected)
        if expected_bytes is None or len(expected_bytes) > len(digest):
            return False  # BytesUtil null/arraycopy bounds caught, not mismatch log
        matches = digest[len(digest)-len(expected_bytes):] == expected_bytes
        main.append_log(',E19.7' if matches else ',E19.8')
        return matches
    except JavaFault:
        return False
