"""Synthetic certificate containers, package observations and token exchange."""
import base64
import hashlib
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from giro.cms import _tlv
from giro.codeguard_effects import Effect
from giro.codeguard_certificate_values import NativeByteArrayValue
from giro.codeguard_fingerprint_values import (read_certificate_value, KnownCertificateStream,
    FingerprintValues, project_fingerprint_values_steps)
from giro.codeguard_inputs import NonceArtifacts, nonce_artifact_codes, fallback_nonce_key
from giro.codeguard_nonce import cg_auth_code
from giro.codeguard_package import (fingerprint_certificate_steps, check_fingerprint_steps,
                                    project_package_steps)
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_service import generate_token_steps
from giro.codeguard_string_values import UNRESOLVED, project_native_value_steps
from cg_exchange_fixture import Transcript, drive
from test_codeguard_certificate_values import synthetic_certificates
from test_codeguard_native_nonce import NonceObservations
from test_codeguard_native_start import NativeObservations, rule
from test_codeguard_package import PackageObservations, Entry, fault
from test_codeguard_string_values import path_values


def bag(certificates, *, version=b'\x01', certificate_tag=True, tail=b'\x31\x00'):
    fields = _tlv(2, version) + b'\x31\x00' + _tlv(48, b'\x06\t*\x86H\x86\xf7\r\x01\x07\x01')
    if certificate_tag: fields += _tlv(160, b''.join(certificates))
    return _tlv(48, b'\x06\t*\x86H\x86\xf7\r\x01\x07\x02' + _tlv(160, _tlv(48, fields + tail)))


def call(name, *args): return Effect('package_java', (name, *args))


class FingerprintValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.certificates = synthetic_certificates()

    def fingerprint(self, data):
        stream = KnownCertificateStream(data)
        def external(e): self.fail('known fingerprint unexpectedly needs external value')
        value = drive(project_fingerprint_values_steps(fingerprint_certificate_steps(stream)), external)
        return value, stream.position

    def package(self, certificates):
        obs = PackageObservations()
        obs.archives[obs.source] = [Entry('META-INF/CERT.RSA', bag(certificates))]
        return obs

    def package_reply(self, obs, effect):
        if effect.kind == 'package_java' and effect.args[0] == 'zip.getInputStream':
            obs.effects.append(effect)
            return KnownCertificateStream(effect.args[2].data)
        if effect.kind == 'package_java' and effect.args == ('certificate.getEncoded', None):
            obs.effects.append(effect)
            return fault('NullPointerException')  # explicit runtime-failure observation
        return obs.reply(effect)

    def test_normal_der_and_signed_data_have_same_fingerprint(self):
        der = self.certificates[0]
        for data in (der, bag([der])):
            actual, consumed = self.fingerprint(data)
            self.assertEqual(actual, base64.b64encode(hashlib.sha256(der).digest()).decode())
            self.assertEqual(consumed, len(data))

    def test_wire_order_is_preserved_without_sorting_or_leaf_selection(self):
        for certs in (self.certificates[:2], self.certificates[1::-1], [self.certificates[0]]*2):
            result = read_certificate_value(bag(certs))
            self.assertEqual(result.der, certs[0])
            self.assertEqual(result.certificate_count, 2)
            self.assertEqual(result.container, 'signed_data')

    def test_later_bad_certificate_does_not_return_first_good_certificate(self):
        with self.assertRaises(AnalysisLimit):
            read_certificate_value(bag([self.certificates[0], b'0\x03\x02\x01\x01']))

    def test_signature_validity_and_signer_infos_are_not_trust_checks(self):
        damaged_signature = self.certificates[2]
        for tail in (b'\x31\x00', b''):
            result = read_certificate_value(bag([damaged_signature], tail=tail))
            self.assertEqual(result.der, damaged_signature)

    def test_empty_and_absent_certificates_produce_null_value_not_empty_hash(self):
        for tag in (False, True):
            value = read_certificate_value(bag([], certificate_tag=tag))
            self.assertIsNone(value.der)
            self.assertEqual(value.certificate_count, 0)
        stream = KnownCertificateStream(bag([]))
        gen = project_fingerprint_values_steps(fingerprint_certificate_steps(stream))
        effect = next(gen)
        self.assertEqual(effect.args, ('certificate.getEncoded', None))
        self.assertEqual(stream.position, len(stream.data))
        gen.close()

    def test_complete_object_consumption_preserves_trailing_stream_bytes(self):
        first, second = bag([self.certificates[0]]), self.certificates[1]
        stream, values = KnownCertificateStream(first+second), FingerprintValues()
        factory = values.resolve(call('certificateFactory.getInstance', 'X.509'))
        for data, position in ((self.certificates[0], len(first)), (second, len(first)+len(second))):
            cert = values.resolve(call('certificateFactory.generateCertificate', factory, stream))
            self.assertEqual(values.resolve(call('certificate.getEncoded', cert)), data)
            self.assertEqual(stream.position, position)
        with self.assertRaises(AnalysisLimit): values.resolve(call('certificateFactory.generateCertificate', factory, stream))

    def test_unresolved_framing_does_not_become_original_certificate_failure(self):
        definite = bag([self.certificates[0]])
        for data in (None, 'opaque', b'', b'PEM', b'0\x80'+definite[4:]+b'\0\0',
                     bag([], version=b'\0'), bag([], version=b'\x80'), bag([], version=b'\0\x01'),
                     bag([b'\xa1\x00'])):
            with self.assertRaises(AnalysisLimit): read_certificate_value(data)

    def test_platform_stream_or_class_cast_is_not_inferred(self):
        values = FingerprintValues()
        factory = values.resolve(call('certificateFactory.getInstance', 'X.509'))
        for opaque in (None, b'raw bytes', 'stream-ref'):
            self.assertIs(values.resolve(call('certificateFactory.generateCertificate', factory, opaque)), UNRESOLVED)
        self.assertIs(values.resolve(call('cast.X509Certificate', 'unknown')), UNRESOLVED)
        self.assertIs(values.resolve(call('zip.getInputStream', 'archive', 'entry')), UNRESOLVED)

    def test_digest_reset_matches_repeated_message_digest_use(self):
        values = FingerprintValues()
        digest = values.resolve(call('messageDigest.getInstance', 'SHA256'))
        values.resolve(call('messageDigest.update', digest, b'ab'))
        values.resolve(call('messageDigest.update', digest, b'c'))
        self.assertEqual(values.resolve(call('messageDigest.digest', digest)), hashlib.sha256(b'abc').digest())
        self.assertEqual(values.resolve(call('messageDigest.digest', digest)), hashlib.sha256(b'').digest())
        self.assertIs(values.resolve(call('messageDigest.update', digest, None)), UNRESOLVED)

    def test_known_values_do_not_expose_content_in_repr(self):
        stream = KnownCertificateStream(b'SYNTHETIC SENSITIVE')
        self.assertNotIn('SYNTHETIC SENSITIVE', repr(stream))
        self.assertNotIn('SYNTHETIC SIGNER', repr(read_certificate_value(bag(self.certificates))))
        with self.assertRaises(AnalysisLimit): KnownCertificateStream(None)

    def test_python_failure_is_not_java_fault_or_empty_baseline(self):
        obs = self.package([self.certificates[0]])
        with patch('giro.codeguard_fingerprint_values.single_der_certificate', side_effect=MemoryError('synthetic')):
            with self.assertRaises(MemoryError):
                drive(project_fingerprint_values_steps(check_fingerprint_steps('context')),
                      lambda e: self.package_reply(obs, e))
        self.assertEqual(obs.errors['FingerPrint'], '')

    def test_package_comparison_uses_selected_der_not_container_bytes(self):
        obs = self.package([self.certificates[0]])
        # Different containers and extra later certificates retain the same first DER.
        obs.archives[obs.source].append(Entry('META-INF/SECOND.RSA', bag(self.certificates)))
        self.assertTrue(drive(project_fingerprint_values_steps(check_fingerprint_steps('context')),
                             lambda e: self.package_reply(obs, e)))
        self.assertEqual(obs.calls('messageDigest.digest'), [])
        self.assertEqual(obs.calls('certificateFactory.generateCertificate'), [])

    def test_mismatch_keeps_second_fingerprint_and_original_false_branch(self):
        obs = self.package([self.certificates[0]])
        obs.archives[obs.source].append(Entry('META-INF/SECOND.RSA', bag([self.certificates[1]])))
        self.assertFalse(drive(project_fingerprint_values_steps(check_fingerprint_steps('context')),
                              lambda e: self.package_reply(obs, e)))
        self.assertEqual(obs.errors['FingerPrint'], base64.b64encode(hashlib.sha256(self.certificates[1]).digest()).decode())

    def test_observed_null_receiver_fault_keeps_original_empty_fingerprint(self):
        for second, expected in (([], True), ([self.certificates[0]], False)):
            obs = self.package([])
            obs.archives[obs.source].append(Entry('META-INF/SECOND.RSA', bag(second)))
            self.assertEqual(drive(project_fingerprint_values_steps(check_fingerprint_steps('context')),
                                   lambda e: self.package_reply(obs, e)), expected)
            self.assertTrue(obs.calls('certificate.getEncoded'))

    def test_zip_fingerprint_signer_values_and_both_native_responses_reach_cmd300(self):
        transcript = Transcript([(200, {'CODE_CHALLENGE': 'TQ==::'+rule()}), (300, {'CODE_TOKEN': 'SYNTHETIC'})])
        transcript.main.pid = '123'
        first, second, package = NativeObservations(), NonceObservations(), PackageObservations()
        second.der = self.certificates[0]
        second.digest = hashlib.sha256(second.der).digest()
        second.files = {}
        def signature(e):
            if e.kind == 'native_jni' and e.args[:3] == ('CallObjectMethod', 'signature', 'toByteArray'):
                return True, NativeByteArrayValue(second.der)
            return False, None
        second.override = signature
        package.archives[package.source] = [Entry(e.name, bag([second.der]) if e.name.endswith('.RSA') else e.data)
                                            for e in package.archives[package.source]]
        stage = 'first'
        def reply(e):
            nonlocal stage
            if e.kind == 'package_java':
                stage = 'second'
                if e.args[0] == 'zip.getInputStream' and e.args[2].name.endswith('.RSA'):
                    result = self.package_reply(package, e)
                else: result = package.reply(e)
                second.files = {key.encode(): value for key, value in package.files.items()}
                return result
            if e.kind.startswith('native_'): return path_values(first if stage == 'first' else second, e)
            return transcript.reply(e)
        gen = generate_token_steps(transcript.main, transcript.runtime, transcript.agent,
            server_url='https://synthetic.invalid/', timeout=1000, root_check=True,
            rooting_info=False, encrypted_token=False)
        gen = project_package_steps(project_native_value_steps(gen, service='service', certificate_values=True), certificate_values=True)
        self.assertEqual(drive(gen, reply), 'SYNTHETIC')
        materials = NonceArtifacts(*(package.files[package.destination+suffix] for suffix in (
            '/lib/libCodeGuard.so','/lib/libImageDecoder.so','/classes.dex','/META-INF/MANIFEST.MF','/META-INF/CERT.SF')), second.der)
        expected = cg_auth_code(fallback_nonce_key('TQ=='), nonce_artifact_codes(materials, 'TQ==', is_mix=False, is_split=False))
        self.assertEqual(parse_qs(transcript.writes[-1][1].decode())['CODE_RESPONSE2'], [expected])
        self.assertEqual(package.calls('certificateFactory.generateCertificate'), [])
        self.assertEqual(second.calls('GetByteArrayElements'), [])
        self.assertEqual([row[0] for row in transcript.requests], [200, 300])


if __name__ == '__main__': unittest.main()
