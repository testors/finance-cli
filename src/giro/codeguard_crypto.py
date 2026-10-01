"""Python key-exchange execution for CodeGuard's supported normal values.

Uses this client's clock, Java Random arithmetic and RSA PKCS#1 v1.5 encryption.
No device identity, security-check result, trust verdict or server token is
created here. VM/provider failure semantics remain explicit boundaries.
"""
from dataclasses import dataclass
import time

from cryptography import x509
from cryptography.exceptions import InternalError, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .codeguard_certificate_values import single_der_certificate
from .codeguard_effects import JavaFault
from .codeguard_platform import key_bytes_from_seed
from .codeguard_rule import AnalysisLimit


def epoch_millis():
    return time.time_ns() // 1_000_000


@dataclass(frozen=True, repr=False, eq=False)
class _Value:
    owner: object
    kind: str
    payload: object = None


@dataclass(repr=False, eq=False)
class _Cipher:
    owner: object
    key: object = None


CRYPTO_EFFECTS = frozenset(('clock_ms', 'new_java_random', 'java_random_seed_and_bytes',
    'android_parse_x509', 'certificate_public_key', 'rsa_cipher_instance',
    'rsa_cipher_init', 'rsa_cipher_final'))


class CodeGuardCrypto:
    """Own exchange keys only; no seed search or access to another client.

The default clock is real epoch time. A caller may supply an explicit clock
for deterministic testing. Certificates must be unchanged single DER values;
parsing does not add expiry/signature/trust checks absent from this stage.
"""
    def __init__(self, *, clock=epoch_millis):
        if not callable(clock): raise AnalysisLimit('CodeGuard clock callable required')
        self.clock, self._owner = clock, object()

    def _value(self, value, kind):
        if not isinstance(value, _Value) or value.owner is not self._owner or value.kind != kind:
            raise AnalysisLimit('CodeGuard crypto value belongs to another operation')
        return value.payload

    def _cipher(self, value):
        if not isinstance(value, _Cipher) or value.owner is not self._owner:
            raise AnalysisLimit('CodeGuard cipher belongs to another operation')
        return value

    def resolve(self, effect):
        try:
            kind, args = effect.kind, effect.args
            if kind == 'clock_ms':
                value = self.clock()
                if type(value) is not int or not -2**63 <= value < 2**63:
                    raise AnalysisLimit('CodeGuard clock requires epoch millisecond long')
                return value
            if kind == 'new_java_random':
                # The constructor seed is overwritten before any output.
                return _Value(self._owner, 'random')
            if kind == 'java_random_seed_and_bytes':
                random, seed, size = args
                self._value(random, 'random')
                if type(size) is not int or size != 16:
                    raise AnalysisLimit('CodeGuard exchange uses sixteen key bytes')
                return key_bytes_from_seed(seed)
            if kind == 'android_parse_x509':
                data, = args
                der = single_der_certificate(data)
                return _Value(self._owner, 'certificate', x509.load_der_x509_certificate(der))
            if kind == 'certificate_public_key':
                certificate, = args
                return _Value(self._owner, 'public_key', self._value(certificate, 'certificate').public_key())
            if kind == 'rsa_cipher_instance':
                if args != ('RSA/NONE/PKCS1Padding',):
                    raise AnalysisLimit('CodeGuard cipher transformation is unresolved')
                return _Cipher(self._owner)
            if kind == 'rsa_cipher_init':
                cipher, mode, key = args
                cipher = self._cipher(cipher)
                key = self._value(key, 'public_key')
                if type(mode) is not int or mode != 1 or not isinstance(key, rsa.RSAPublicKey):
                    raise AnalysisLimit('CodeGuard RSA encryption input is unresolved')
                cipher.key = key
                return None
            if kind == 'rsa_cipher_final':
                cipher, data = args
                cipher = self._cipher(cipher)
                if cipher.key is None or type(data) is not bytes or len(data) != 16:
                    raise AnalysisLimit('CodeGuard RSA key state is unresolved')
                return cipher.key.encrypt(data, padding.PKCS1v15())
            raise AnalysisLimit('unsupported CodeGuard crypto effect')
        except (AnalysisLimit, JavaFault):
            raise
        except (ValueError, OSError, UnsupportedAlgorithm, InternalError):
            # Do not leak provider details or turn them into an invented Java
            # exception/empty KEY that would make the exchange proceed.
            raise AnalysisLimit('CodeGuard crypto provider boundary') from None


def project_crypto_steps(generator, *, crypto):
    """Resolve crypto/clock effects; keep environment and IO effects external."""
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            value = crypto.resolve(effect) if effect.kind in CRYPTO_EFFECTS else (yield effect)
        except Exception as fault:
            pending = fault
