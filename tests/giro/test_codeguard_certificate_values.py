"""Synthetic signer values, preserving external package/environment inputs."""
import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding

from giro.codeguard_certificate_values import (CertificateValues, NativeByteArrayValue,
                                              single_der_certificate)
from giro.codeguard_effects import Effect
from giro.codeguard_native_jni import NativeStringValue
from giro.codeguard_native_nonce import native_nonce_steps
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_service import generate_token_steps
from giro.codeguard_string_values import (UNRESOLVED, project_string_values_steps,
                                         project_native_value_steps)
from cg_exchange_fixture import Transcript, drive
from test_codeguard_native_nonce import NonceObservations, KEY, CHALLENGE
from test_codeguard_native_start import NativeObservations, rule
from test_codeguard_string_values import path_values


def jni(name, *args): return Effect('native_jni', (name, *args))


def synthetic_certificates():
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'SYNTHETIC SIGNER')])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .serial_number(7).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2020, 1, 2, tzinfo=timezone.utc))
        .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.3.4.5'), b'\x05\x00'), True))
    result = []
    for key in (rsa.generate_private_key(public_exponent=65537, key_size=2048), ec.generate_private_key(ec.SECP256R1())):
        result.append(builder.public_key(key.public_key()).sign(key, hashes.SHA256()).public_bytes(Encoding.DER))
    # Corrupt the RSA signature without changing the certificate structure.
    result.append(result[0][:-1] + bytes([result[0][-1] ^ 1]))
    return result


class CertificateValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificates = synthetic_certificates()

    def observer(self):
        def override(e):
            if e.kind == 'native_jni' and e.args[:3] == ('CallObjectMethod', 'signature', 'toByteArray'):
                return True, NativeByteArrayValue(self.certificates[0])
            return False, None
        obs = NonceObservations(override=override)
        obs.der = self.certificates[0]
        obs.digest = hashlib.sha256(obs.der).digest()
        return obs

    def test_single_der_is_unchanged_without_trust_validity_usage_or_signature_checks(self):
        for der in self.certificates:
            self.assertEqual(single_der_certificate(der), der)

    def test_non_der_and_trailers_are_backend_boundaries_not_java_rejections(self):
        der = self.certificates[0]
        pem = x509.load_der_x509_certificate(der).public_bytes(Encoding.PEM)
        for data in (None, 'opaque-array', b'', b'0\x80\0\0', b'0\x01\0', pem, der+b'junk', der+der):
            with self.assertRaises(AnalysisLimit) as caught:
                single_der_certificate(data)
            self.assertNotIn('opaque-array', str(caught.exception))

    def test_standard_jdk_encoded_bytes_and_digest_match_for_normal_der(self):
        java = shutil.which('java')
        if java is None: self.skipTest('JDK unavailable for development comparison')
        result = subprocess.run([java, str(Path(__file__).parent/'java/SignerCertificateVector.java')],
            input=''.join(base64.b64encode(der).decode()+'\n' for der in self.certificates),
            capture_output=True, text=True, timeout=30, check=True)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), len(self.certificates))
        for der, line in zip(self.certificates, lines):
            encoded, digest, remaining = line.split(':')
            self.assertEqual(base64.b64decode(encoded), single_der_certificate(der))
            self.assertEqual(digest, hashlib.sha256(der).hexdigest())
            self.assertEqual(remaining, '0')

    def test_known_byte_arrays_do_not_expose_contents_in_repr(self):
        value = NativeByteArrayValue(b'SYNTHETIC-SENSITIVE')
        self.assertNotIn('SYNTHETIC-SENSITIVE', repr(value))
        self.assertEqual(value.data, b'SYNTHETIC-SENSITIVE')
        self.assertIsNot(value, NativeByteArrayValue(value.data))
        with self.assertRaises(AnalysisLimit): NativeByteArrayValue(None)

    def test_array_length_and_elements_require_explicit_known_contents(self):
        values = CertificateValues()
        self.assertEqual(values.resolve(jni('GetArrayLength', NativeByteArrayValue(b'ab'))), 2)
        self.assertEqual(values.resolve(jni('GetByteArrayElements', NativeByteArrayValue(b'ab'))), b'ab')
        for ref in ('opaque', b'ab', None):
            self.assertIs(values.resolve(jni('GetArrayLength', ref)), UNRESOLVED)
            self.assertIs(values.resolve(jni('GetByteArrayElements', ref)), UNRESOLVED)

    def test_android_lookup_and_signature_selection_remain_external(self):
        values = CertificateValues()
        for e in (jni('FindClass', 'android/content/pm/Signature'),
                  jni('GetObjectArrayElement', 'signatures', 0),
                  jni('CallObjectMethod', 'signature', 'toByteArray'),
                  jni('CallBooleanMethod', 'class', 'isInstance', 'manager'),
                  Effect('native_fopen', (b'/proc/self/status', b'r'))):
            self.assertIs(values.resolve(e), UNRESOLVED)

    def test_exact_method_descriptor_and_supported_algorithm_required(self):
        values = CertificateValues()
        cls = values.resolve(jni('FindClass', 'java/security/MessageDigest'))
        descriptor = '(Ljava/lang/String;)Ljava/security/MessageDigest;'
        self.assertIs(values.resolve(jni('GetMethodID', cls, 'getInstance', descriptor)), UNRESOLVED)
        self.assertIs(values.resolve(jni('GetStaticMethodID', cls, 'getInstance', '()V')), UNRESOLVED)
        method = values.resolve(jni('GetStaticMethodID', cls, 'getInstance', descriptor))
        for arg in ('SHA-256', None, NativeStringValue('SHA-1')):
            self.assertIs(values.resolve(jni('CallStaticObjectMethod', cls, method, arg)), UNRESOLVED)

    def test_opaque_stream_input_and_consumed_stream_need_provider_observation(self):
        values = CertificateValues()
        cls = values.resolve(jni('FindClass', 'java/io/ByteArrayInputStream'))
        init = values.resolve(jni('GetMethodID', cls, '<init>', '([B)V'))
        self.assertIs(values.resolve(jni('NewObject', cls, init, 'opaque-bytes')), UNRESOLVED)
        stream = values.resolve(jni('NewObject', cls, init, NativeByteArrayValue(self.certificates[0])))
        factory_class = values.resolve(jni('FindClass', 'java/security/cert/CertificateFactory'))
        create = values.resolve(jni('GetStaticMethodID', factory_class, 'getInstance', '(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;'))
        factory = values.resolve(jni('CallStaticObjectMethod', factory_class, create, NativeStringValue('X.509')))
        generate = values.resolve(jni('GetMethodID', factory_class, 'generateCertificate', '(Ljava/io/InputStream;)Ljava/security/cert/Certificate;'))
        certificate = values.resolve(jni('CallObjectMethod', factory, generate, stream))
        self.assertNotIn('SYNTHETIC SIGNER', repr(certificate)+repr(stream))
        with self.assertRaises(AnalysisLimit): values.resolve(jni('CallObjectMethod', factory, generate, stream))

    def test_external_null_suspends_pure_provider_resolution(self):
        values = CertificateValues()
        values.observe_external(jni('GetObjectArrayElement', 'signatures', 0), None)
        for e in (jni('FindClass', 'java/security/cert/CertificateFactory'),
                  jni('GetByteArrayElements', NativeByteArrayValue(b'known')),
                  jni('NewStringUTF', b'known')):
            self.assertIs(values.resolve(e), UNRESOLVED)

    def test_python_failure_does_not_become_certificate_exception_or_null(self):
        with patch('giro.codeguard_certificate_values.x509.load_der_x509_certificate', side_effect=MemoryError('synthetic')):
            with self.assertRaises(MemoryError): single_der_certificate(self.certificates[0])

    def test_nonce_computes_der_digest_for_all_modes_and_retains_package_selection(self):
        for mix in (False, True):
            for split in (False, True):
                obs, values = self.observer(), CertificateValues()
                gen = native_nonce_steps('service', NativeStringValue(KEY), NativeStringValue(CHALLENGE), mix, split)
                actual = drive(project_string_values_steps(gen, values=values), lambda e: path_values(obs, e))
                self.assertEqual(actual, obs.expected(mix=mix, split=split))
                self.assertEqual(obs.calls('GetObjectArrayElement'), [('signatures', 0)])
                self.assertTrue(any(a[1] == 'getPackageInfo' and a[-1] == 64 for a in obs.calls('CallObjectMethod')))
                self.assertTrue(any(a[1] == 'toByteArray' for a in obs.calls('CallObjectMethod')))
                self.assertFalse(any(a[1] in ('generateCertificate','getEncoded','digest') for a in obs.calls('CallObjectMethod')))
                self.assertEqual(obs.calls('GetByteArrayElements'), [])
                self.assertEqual(obs.calls('GetArrayLength'), [])

    def test_real_der_calculation_reaches_same_cmd300_with_two_native_responses(self):
        transcript = Transcript([(200, {'CODE_CHALLENGE': 'TQ==::'+rule()}), (300, {'CODE_TOKEN': 'SYNTHETIC'})])
        transcript.main.pid = '123'
        first, second = NativeObservations(), self.observer()
        stage = 'first'
        def reply(e):
            nonlocal stage
            if e.kind == 'check_zip_os14': stage = 'second'
            if e.kind.startswith('native_'): return path_values(first if stage == 'first' else second, e)
            return transcript.reply(e)
        gen = generate_token_steps(transcript.main, transcript.runtime, transcript.agent,
            server_url='https://synthetic.invalid/', timeout=1000, root_check=True,
            rooting_info=False, encrypted_token=False)
        self.assertEqual(drive(project_native_value_steps(gen, service='service', certificate_values=True), reply), 'SYNTHETIC')
        form = parse_qs(transcript.writes[-1][1].decode())
        self.assertEqual(form['CODE_RESPONSE2'], [second.expected(challenge='TQ==', key=hashlib.sha256(b'TQ==').hexdigest().upper())])
        self.assertEqual(second.calls('GetByteArrayElements'), [])
        self.assertEqual([r[0] for r in transcript.requests], [200, 300])


if __name__ == '__main__': unittest.main()
