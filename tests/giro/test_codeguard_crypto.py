"""Synthetic key-exchange execution and standard JDK cross-decryption."""
import base64
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from giro.codeguard_crypto import CodeGuardCrypto, CRYPTO_EFFECTS, project_crypto_steps
from giro.codeguard_effects import Effect, JavaFault
from giro.codeguard_platform import key_bytes_from_seed
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_updater import wrapped_key_steps, challenge_steps
from cg_exchange_fixture import Transcript, drive


def certificate(key):
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'SYNTHETIC EXCHANGE')])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(17)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2020, 1, 2, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.der = certificate(cls.private)

    def setUp(self):
        self.obs = Transcript(cert=base64.b64encode(self.der).decode())

    def wrap(self, crypto):
        return drive(project_crypto_steps(wrapped_key_steps(self.obs.runtime, self.obs.agent),
                                          crypto=crypto), self.obs.reply)

    def decrypt(self, value):
        return self.private.decrypt(base64.b64decode(value), padding.PKCS1v15())

    def test_epoch_clock_is_read_at_key_generation_and_both_keys_are_assigned(self):
        crypto = CodeGuardCrypto()
        with patch('giro.codeguard_crypto.time.time_ns', return_value=123456789987654) as clock:
            self.assertEqual(clock.call_count, 0)
            wrapped = self.wrap(crypto)
            clock.assert_called_once_with()
        expected = key_bytes_from_seed(123456789)
        self.assertEqual(self.decrypt(wrapped), expected)
        self.assertIs(self.obs.agent.key, self.obs.runtime.data.key)
        self.assertEqual(self.obs.agent.key, expected)
        self.assertTrue(CRYPTO_EFFECTS.isdisjoint(self.obs.kinds()))

    def test_repeated_calls_replace_keys_and_do_not_make_padding_deterministic(self):
        ticks = iter((10, 10, 11))
        crypto = CodeGuardCrypto(clock=lambda: next(ticks))
        values = [self.wrap(crypto) for _ in range(3)]
        self.assertEqual([self.decrypt(v) for v in values], [key_bytes_from_seed(s) for s in (10,10,11)])
        self.assertNotEqual(values[0], values[1])
        self.assertEqual(self.obs.agent.key, key_bytes_from_seed(11))

    def test_preference_lookup_observes_already_updated_keys(self):
        self.obs.agent.certificate_text = ''
        def preference(effect):
            self.assertEqual(self.obs.agent.key, key_bytes_from_seed(100))
            self.assertIs(self.obs.agent.key, self.obs.runtime.data.key)
            self.assertEqual(effect.args[1], 'CERT')
            return base64.b64encode(self.der).decode()
        self.obs.overrides['preference_read'] = preference
        self.assertEqual(self.decrypt(self.wrap(CodeGuardCrypto(clock=lambda:100))), key_bytes_from_seed(100))

    def test_expired_and_changed_signature_certificate_is_parsed_without_trust_gate(self):
        for der in (self.der, self.der[:-1]+bytes([self.der[-1]^1])):
            self.obs.agent.certificate_text = base64.b64encode(der).decode()
            self.assertEqual(self.decrypt(self.wrap(CodeGuardCrypto(clock=lambda:0))), key_bytes_from_seed(0))

    def test_unhandled_certificate_and_key_types_preserve_new_key_without_http(self):
        ec_der = certificate(ec.generate_private_key(ec.SECP256R1()))
        for data in (b'not a certificate', self.der+b'extra', ec_der):
            self.obs.agent.certificate_text = base64.b64encode(data).decode()
            self.obs.runtime.data.cookie = 'prior-cookie'
            crypto = CodeGuardCrypto(clock=lambda:3)
            steps = challenge_steps(self.obs.runtime, self.obs.agent, self.obs.main, 'APP')
            with self.assertRaises(AnalysisLimit) as caught:
                drive(project_crypto_steps(steps, crypto=crypto), self.obs.reply)
            self.assertNotIsInstance(caught.exception, JavaFault)
            self.assertEqual(self.obs.runtime.data.cookie, '')
            self.assertEqual(self.obs.agent.key, key_bytes_from_seed(3))
            self.assertEqual(self.obs.requests, [])

    def test_unknown_python_provider_error_does_not_become_empty_key_or_java_error(self):
        with patch('giro.codeguard_crypto.padding.PKCS1v15', side_effect=ValueError('SENSITIVE PROVIDER')):
            with self.assertRaises(AnalysisLimit) as caught: self.wrap(CodeGuardCrypto(clock=lambda:4))
        self.assertEqual(str(caught.exception), 'CodeGuard crypto provider boundary')
        self.assertEqual(self.obs.agent.key, key_bytes_from_seed(4))
        self.assertEqual(self.obs.requests, [])

    def test_bad_clock_keeps_prior_keys_and_is_not_replaced_with_a_default(self):
        for value in (None, True, '5', 2**63):
            self.obs.runtime.data.key = self.obs.agent.key = b'prior'
            with self.assertRaises(AnalysisLimit): self.wrap(CodeGuardCrypto(clock=lambda:value))
            self.assertEqual(self.obs.agent.key, b'prior')

    def test_owned_objects_and_supported_operations_are_required(self):
        a, b = CodeGuardCrypto(), CodeGuardCrypto()
        random = a.resolve(Effect('new_java_random'))
        with self.assertRaises(AnalysisLimit): b.resolve(Effect('java_random_seed_and_bytes',(random,0,16)))
        with self.assertRaises(AnalysisLimit): a.resolve(Effect('java_random_seed_and_bytes',(random,0,32)))
        with self.assertRaises(AnalysisLimit): a.resolve(Effect('rsa_cipher_instance',('RSA/OAEP',)))
        cipher = a.resolve(Effect('rsa_cipher_instance',('RSA/NONE/PKCS1Padding',)))
        with self.assertRaises(AnalysisLimit): a.resolve(Effect('rsa_cipher_final',(cipher,b'K'*16)))
        with self.assertRaises(AnalysisLimit): b.resolve(Effect('rsa_cipher_final',(cipher,b'K'*16)))
        self.assertNotIn('payload', repr(random))
        self.assertNotIn('key=', repr(cipher))

    def test_external_environment_effects_and_observed_faults_are_forwarded(self):
        fault = JavaFault('IOException', message='synthetic', java_string='java.io.IOException: synthetic')
        def steps():
            value = yield Effect('native_start', ('input',))
            self.assertEqual(value, 'explicit observation')
            try: yield Effect('preference_read', ('context','key',None))
            except JavaFault as received:
                self.assertIs(received, fault)
                return 'original catch'
        generator = project_crypto_steps(steps(), crypto=CodeGuardCrypto())
        self.assertEqual(next(generator).kind, 'native_start')
        self.assertEqual(generator.send('explicit observation').kind, 'preference_read')
        with self.assertRaises(StopIteration) as done: generator.throw(fault)
        self.assertEqual(done.exception.value, 'original catch')

    def test_explicit_java_clock_fault_keeps_the_existing_updater_catch(self):
        fault = JavaFault('RuntimeException', message='synthetic', java_string='java.lang.RuntimeException: synthetic')
        def clock(): raise fault
        self.obs.agent.key = self.obs.runtime.data.key = b'prior'
        self.assertEqual(self.wrap(CodeGuardCrypto(clock=clock)), '')
        self.assertEqual(self.obs.agent.key, b'prior')

    def test_standard_jdk_decrypts_product_key_and_product_decrypts_jdk_wrap(self):
        java = shutil.which('java')
        if java is None: self.skipTest('JDK unavailable for development comparison')
        wrapped = self.wrap(CodeGuardCrypto(clock=lambda:-123456789))
        private = self.private.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        lines = [base64.b64encode(private).decode(), base64.b64encode(self.der).decode(), wrapped]
        result = subprocess.run([java, str(Path(__file__).parent/'java/ExchangeKeyVector.java')],
            input='\n'.join(lines)+'\n', capture_output=True, text=True, check=True, timeout=30)
        plain, encrypted = result.stdout.splitlines()
        self.assertEqual(base64.b64decode(plain), key_bytes_from_seed(-123456789))
        self.assertEqual(self.decrypt(encrypted), key_bytes_from_seed(-123456789))


if __name__ == '__main__': unittest.main()
