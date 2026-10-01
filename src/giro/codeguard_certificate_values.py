"""Owned X.509/SHA-256 values for the normal native signer calculation.

This is an independent Python value backend, not a JVM/provider emulator.
Package selection and Signature.toByteArray remain external. Only complete,
unchanged single DER certificates are covered; other provider input behavior
and actual VM faults remain outside this backend.
"""
from dataclasses import dataclass
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .codeguard_native_jni import NativeStringValue
from .codeguard_rule import AnalysisLimit
from .codeguard_string_values import StringValues, UNRESOLVED


@dataclass(frozen=True, repr=False, eq=False)
class NativeByteArrayValue:
    """Explicit known array contents; never an inferred platform reference."""
    data: bytes

    def __post_init__(self):
        if type(self.data) is not bytes:
            raise AnalysisLimit('known byte array contents required')


def single_der_certificate(data):
    """Return the unchanged DER of one parsed certificate; not trust checking.

    A backend gap is not a Java CertificateException or certificate rejection.
    No validity, issuer, signature or key-usage verification is added here.
    """
    if type(data) is not bytes:
        raise AnalysisLimit('single DER certificate bytes required')
    try:
        certificate = x509.load_der_x509_certificate(data)
        encoded = certificate.public_bytes(Encoding.DER)
    except ValueError:
        raise AnalysisLimit('certificate input outside single DER value scope') from None
    if encoded != data:
        raise AnalysisLimit('certificate encoding outside unchanged DER value scope')
    return encoded


@dataclass(frozen=True, repr=False, eq=False)
class _Value:
    kind: str
    payload: object = None


@dataclass(frozen=True, repr=False, eq=False)
class _Method:
    owner: object
    operation: str


_CLASSES = {
    'java/io/ByteArrayInputStream': 'stream',
    'java/security/cert/CertificateFactory': 'factory',
    'java/security/MessageDigest': 'digest',
}
_METHODS = {
    ('stream', '<init>', '([B)V', False): 'stream.new',
    ('factory', 'getInstance', '(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;', True): 'factory.new',
    ('factory', 'generateCertificate', '(Ljava/io/InputStream;)Ljava/security/cert/Certificate;', False): 'certificate.parse',
    ('certificate', 'getEncoded', '()[B', False): 'certificate.encode',
    ('digest', 'getInstance', '(Ljava/lang/String;)Ljava/security/MessageDigest;', True): 'digest.new',
    ('digest', 'digest', '([B)[B', False): 'digest.calculate',
}


class CertificateValues(StringValues):
    """Explicit normal value operations, retaining external JNI boundaries.

    Class/method tokens describe Python operations, not successful VM lookup.
    Opting in chooses this backend for value work. Use observation-only native
    steps when inspecting provider selection, class loading or VM failures.
    """
    def __init__(self):
        super().__init__()
        self._classes = {name: _Value('class', name) for name in ('stream', 'factory', 'digest', 'certificate')}
        self._consumed_streams = set()

    def resolve(self, effect):
        result = super().resolve(effect)
        if result is not UNRESOLVED or self.suspended or effect.kind != 'native_jni':
            return result
        name, *args = effect.args
        if name == 'FindClass' and args[0] in _CLASSES:
            return self._classes[_CLASSES[args[0]]]
        if name == 'GetObjectClass' and isinstance(args[0], _Value):
            return self._classes.get(args[0].kind, UNRESOLVED)
        if name in ('GetMethodID', 'GetStaticMethodID') and isinstance(args[0], _Value):
            owner, method, descriptor = args
            if owner.kind != 'class':
                return UNRESOLVED
            operation = _METHODS.get((owner.payload, method, descriptor, name == 'GetStaticMethodID'))
            return _Method(owner, operation) if operation is not None else UNRESOLVED
        if name in ('NewObject', 'CallObjectMethod', 'CallStaticObjectMethod') and isinstance(args[1], _Method):
            receiver, method, *params = args
            return self._call(name, receiver, method, params)
        if name == 'GetArrayLength' and isinstance(args[0], NativeByteArrayValue):
            return len(args[0].data)
        if name == 'GetByteArrayElements' and isinstance(args[0], NativeByteArrayValue):
            return args[0].data
        return UNRESOLVED

    def _call(self, call, receiver, method, params):
        if (call == 'CallObjectMethod' and method.operation == 'certificate.encode' and not params
                and isinstance(receiver, _Value) and receiver.kind == 'certificate'):
            return NativeByteArrayValue(receiver.payload)
        if len(params) != 1:
            return UNRESOLVED
        argument = params[0]
        operation = method.operation
        if operation in ('stream.new', 'factory.new', 'digest.new'):
            expected_call = 'NewObject' if operation == 'stream.new' else 'CallStaticObjectMethod'
            if call != expected_call or receiver is not method.owner:
                return UNRESOLVED
            if operation == 'stream.new' and isinstance(argument, NativeByteArrayValue):
                return _Value('stream', argument.data)
            if isinstance(argument, NativeStringValue):
                if operation == 'factory.new' and argument.text == 'X.509':
                    return _Value('factory')
                if operation == 'digest.new' and argument.text == 'SHA-256':
                    return _Value('digest')
            return UNRESOLVED
        if call != 'CallObjectMethod' or not isinstance(receiver, _Value) or receiver.kind != method.owner.payload:
            return UNRESOLVED
        if operation == 'certificate.parse' and isinstance(argument, _Value) and argument.kind == 'stream':
            if argument in self._consumed_streams:
                raise AnalysisLimit('consumed certificate stream needs provider semantics')
            encoded = single_der_certificate(argument.payload)
            self._consumed_streams.add(argument)
            return _Value('certificate', encoded)
        if operation == 'digest.calculate' and isinstance(argument, NativeByteArrayValue):
            return NativeByteArrayValue(hashlib.sha256(argument.data).digest())
        return UNRESOLVED
