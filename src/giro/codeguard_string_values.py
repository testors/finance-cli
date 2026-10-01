"""Pure JNI string value operations for Python-owned contents and buffers.

This is not a VM, Android provider or successful environment observation.
Opaque platform references, noncanonical input, null pointers and actual JNI
faults stay with the outer provider. Python failures are not Java exceptions.
"""
from dataclasses import dataclass

from .codeguard_codec import jni_modified_utf8
from .codeguard_native_jni import NativeStringValue, NativeUtfChars
from .codeguard_rule import AnalysisLimit


class ModifiedUtfBoundary(AnalysisLimit):
    def __init__(self):
        super().__init__('canonical modified UTF-8 string required')


def decode_modified_utf8(data):
    """Decode canonical JNI bytes, stopping at the first C-string NUL.

    NUL uses C0 80; supplementary characters use two surrogate triples.
    Noncanonical/invalid byte behavior is platform-specific and not inferred.
    A supplied byte sequence represents a bounded C string, not arbitrary
    native memory. No memory beyond it is read or synthesized.
    """
    if type(data) is not bytes:
        raise ModifiedUtfBoundary()
    raw = data.split(b'\0', 1)[0]
    units, offset = bytearray(), 0
    while offset < len(raw):
        first = raw[offset]
        width = 1 if first < 128 else 2 if 0xc0 <= first <= 0xdf else 3 if 0xe0 <= first <= 0xef else 0
        if not width or offset + width > len(raw):
            raise ModifiedUtfBoundary()
        tail = raw[offset + 1:offset + width]
        if any(not 0x80 <= b <= 0xbf for b in tail):
            raise ModifiedUtfBoundary()
        if width == 1:
            unit = first
        elif width == 2:
            unit = ((first & 31) << 6) | (tail[0] & 63)
            if unit < 128 and (unit != 0 or first != 0xc0 or tail[0] != 0x80):
                raise ModifiedUtfBoundary()
        else:
            unit = ((first & 15) << 12) | ((tail[0] & 63) << 6) | (tail[1] & 63)
            if unit < 2048:
                raise ModifiedUtfBoundary()
        units.extend(unit.to_bytes(2, 'big'))
        offset += width
    return units.decode('utf-16-be', 'surrogatepass')


@dataclass(repr=False, eq=False)
class _UtfBuffer:
    owner: NativeStringValue
    memory: object
    released: bool = False


UNRESOLVED = object()


class StringValues:
    """One independent native-call scope; handles are Python ownership tokens.

    These tokens are never addresses or claimed JNI pointer observations.
    Normal values use Python memory; actual VM allocation failures remain
    available through the observation-only path instead of being simulated.
    """
    def __init__(self):
        self._deleted = set()
        self.acquired_count = 0
        self.released_count = 0
        self.suspended = False

    def observe_external(self, effect, value):
        # A null result from a value-returning JNI call can leave an exception
        # pending. Do not continue resolving normal owned operations across it.
        # The outer provider must handle that exceptional path explicitly.
        if (effect.kind == 'native_jni' and value is None and
                effect.args[0] not in ('DeleteLocalRef', 'ReleaseStringUTFChars')):
            self.suspended = True

    def resolve(self, effect):
        if self.suspended or effect.kind != 'native_jni':
            return UNRESOLVED
        name, *args = effect.args
        if name == 'NewStringUTF' and type(args[0]) is bytes:
            try:
                text = decode_modified_utf8(args[0])
            except ModifiedUtfBoundary:
                return UNRESOLVED
            return NativeStringValue(text)
        if name == 'GetStringUTFChars' and isinstance(args[0], NativeStringValue):
            ref = args[0]
            if ref in self._deleted:
                raise AnalysisLimit('owned string reference already deleted')
            # Deliberately terminate our own buffer for its C-string consumers;
            # this does not assert all external JNI buffers are terminated.
            data = jni_modified_utf8(ref.text) + b'\0'
            handle = _UtfBuffer(ref, self)
            self.acquired_count += 1
            return NativeUtfChars(handle, data)
        if name == 'ReleaseStringUTFChars' and isinstance(args[1], _UtfBuffer):
            ref, handle = args
            if handle.memory is not self or handle.owner is not ref or handle.released or ref in self._deleted:
                raise AnalysisLimit('owned UTF buffer reference or lifetime mismatch')
            handle.released = True
            self.released_count += 1
            return None
        if name == 'DeleteLocalRef' and isinstance(args[0], NativeStringValue):
            if args[0] in self._deleted:
                raise AnalysisLimit('owned string reference already deleted')
            self._deleted.add(args[0])
            return None
        return UNRESOLVED


def project_string_values_steps(generator, *, values=None):
    """Resolve only the pure owned subset; forward all other effects/faults."""
    if values is None:
        values = StringValues()
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            value = values.resolve(effect)
            if value is UNRESOLVED:
                value = yield effect
                values.observe_external(effect, value)
        except Exception as fault:
            pending = fault


def _known_string(value):
    return NativeStringValue(value) if type(value) is str else value


def project_native_value_steps(generator, *, service, certificate_values=False):
    """Expand both native calls, marking ONLY their known String arguments.

    Environment providers may explicitly return NativeStringValue for contents
    they have resolved. Opaque IDs and missing platform results are untouched.
    Each invocation has its own owned buffer scope and returns plain str/None.
    certificate_values opts into the normal single-DER/SHA-256 Python backend;
    it does not resolve PackageManager or Signature.toByteArray observations.
    """
    from .codeguard_native_start import native_start_steps
    from .codeguard_native_nonce import native_nonce_steps
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            if effect.kind == 'native_start':
                body = native_start_steps(service, *(_known_string(v) for v in effect.args))
                value = yield from project_string_values_steps(body)
            elif effect.kind == 'native_get_nonce':
                key, challenge, mix, split = effect.args
                body = native_nonce_steps(service, _known_string(key), _known_string(challenge), mix, split)
                values = None
                if certificate_values:
                    from .codeguard_certificate_values import CertificateValues
                    values = CertificateValues()
                value = yield from project_string_values_steps(body, values=values)
            else:
                value = yield effect
        except Exception as fault:
            pending = fault
