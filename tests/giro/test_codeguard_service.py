import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from giro.codeguard_codec import RULE_KEY, RULE_IV, java_seed_encrypt, java_seed_decrypt, jni_modified_utf8
from giro.codeguard_effects import JavaFault, LinkFault
from giro.codeguard_flow import ChallengeState, JavaStageError, returned_token_key_iv
from giro.codeguard_service import generate_token_steps
from giro.codeguard_rule import AnalysisLimit
from cg_exchange_fixture import Transcript, fault

def service(t, *, encrypted=False):
    return generate_token_steps(t.main, t.runtime, t.agent, server_url='https://synthetic.invalid/', timeout=500, root_check=True, rooting_info=False, encrypted_token=encrypted)

def payload(t):
    if t.writes:
        return parse_qs(t.writes[-1][1].decode(), keep_blank_values=True)
    return parse_qs(urlsplit(t.requests[-1][1]).query, keep_blank_values=True)

def plain_response(t):
    value = payload(t)['CODE_RESPONSE'][0]
    if 'E101_ENGINE_LOAD_ERROR' in value or value.startswith('SYNTHETIC-LOCAL-ERROR:'):
        return value
    return java_seed_decrypt(base64.b64decode(value), RULE_KEY, RULE_IV).decode()

class ServiceTests(unittest.TestCase):

    def transcript(self, **kwargs):
        return Transcript([(200, {'CODE_CHALLENGE': 'c::r'}), (300, {'CODE_TOKEN': 'SYNTHETIC-TOKEN'})], **kwargs)

    def test_normal_sequence_connects_wire_and_existing_response_generator(self):
        t = self.transcript()
        self.assertEqual(t.run(service(t)), 'SYNTHETIC-TOKEN')
        self.assertEqual([x[0] for x in t.requests], [200, 300])
        self.assertIn('APP::1##synthetic-engine/', plain_response(t))
        self.assertEqual(payload(t)['CODE_RESPONSE2'], ['SYNTHETIC-NONCE-OBSERVATION'])
        self.assertNotIn('generate_encrypted_response', t.kinds())
        self.assertEqual(t.runtime.timeout, 500)

    def test_missing_cert_triggers_101_before_200_even_with_false_engine(self):
        t = Transcript([(101, {'CERT': 'c3ludGhldGlj', 'ENGINE_VERSION': 'new'}), (200, {'CODE_CHALLENGE': 'c::r'}), (300, {'CODE_TOKEN': 'fixture'})], cert='', overrides={'file_exists': False})
        self.assertEqual(t.run(service(t)), 'fixture')
        self.assertEqual([x[0] for x in t.requests], [101, 200, 300])
        self.assertEqual(t.runtime.status, 3)
        self.assertIn('##new/', plain_response(t))

    def test_101_exception_false_return_does_not_prevent_200(self):
        t = self.transcript(cert='')

        def opening(e):
            return fault('IOException') if 'CMD=101' in e.args[0] else t.default(e)
        t.overrides['http_open'] = opening
        self.assertEqual(t.run(service(t)), 'SYNTHETIC-TOKEN')
        self.assertEqual([x[0] for x in t.requests], [200, 300])
        self.assertEqual(parse_qs(urlsplit(t.requests[0][1]).query, keep_blank_values=True)['KEY'], [''])

    def test_cached_certificate_avoids_101_without_installation_success_assumption(self):
        t = self.transcript(cert='')
        t.preferences['CERT'] = 'c3ludGhldGlj'
        self.assertEqual(t.run(service(t)), 'SYNTHETIC-TOKEN')
        self.assertNotIn('application_info', t.kinds())

    def test_challenge_prefix_error_returns_before_os_native_and_300(self):
        t = self.transcript(overrides={'http_open': fault('IOException')})
        value = t.run(service(t))
        self.assertTrue(value.startswith('E101_NET_ERROR_001'))
        self.assertNotIn('oscheck_future', t.kinds())
        self.assertNotIn('native_get_nonce', t.kinds())

    def test_embedded_network_error_text_is_not_prefix_gate(self):
        t = Transcript([(200, {'CODE_CHALLENGE': 'abcE101_NET_ERROR_xyz::r'}), (300, {'CODE_TOKEN': 'fixture'})])
        self.assertEqual(t.run(service(t)), 'fixture')
        self.assertEqual([x[0] for x in t.requests], [200, 300])

    def test_nested_refresh_uses_same_updater_and_regenerates_key(self):
        t = Transcript([(200, {'CODE_CHALLENGE': 'only one part'}), (200, {'CODE_CHALLENGE': 'new::rule'}), (300, {'CODE_TOKEN': 'fixture'})])
        t.main.challenge = ChallengeState()
        self.assertEqual(t.run(service(t)), 'fixture')
        self.assertEqual([x[0] for x in t.requests], [200, 200, 300])
        self.assertEqual(t.runtime.data.key, b'\x02' * 16)
        self.assertEqual(t.agent.key, b'\x02' * 16)
        self.assertEqual(t.kinds().count('oscheck_future'), 1)
        nonce = next((e for e in t.effects if e.kind == 'native_get_nonce'))
        self.assertEqual(nonce.args[:2], (hashlib.sha256(b'new').hexdigest().upper(), 'new'))

    def test_post_os_refresh_preserves_old_os_result_but_uses_new_challenge_nonce(self):
        t = Transcript([(200, {'CODE_CHALLENGE': 'unchanged'}), (200, {'CODE_CHALLENGE': 'new::rule'}), (300, {'CODE_TOKEN': 'fixture'})])
        t.main.challenge = ChallengeState('old', '')
        self.assertEqual(t.run(service(t)), 'fixture')
        os_call = next((e for e in t.effects if e.kind == 'oscheck_future'))
        native = next((e for e in t.effects if e.kind == 'native_start'))
        self.assertEqual((os_call.args[0], native.args[0]), ('old', 'new'))
        self.assertEqual(t.runtime.data.key, b'\x02' * 16)

    def test_nested_fault_forwarded_to_response_catch_not_lost_by_router(self):
        t = self.transcript(overrides={'native_start': fault(message='native fault')})
        self.assertEqual(t.run(service(t)), 'SYNTHETIC-TOKEN')
        self.assertIn('E101_ENGINE_LOAD_ERROR2', payload(t)['CODE_RESPONSE'][0])
        self.assertIn('(native fault)', payload(t)['CODE_RESPONSE'][0])

    def test_native_null_engine_error_is_submitted_not_extra_cli_gate(self):
        t = self.transcript(overrides={'native_start': None})
        self.assertEqual(t.run(service(t)), 'SYNTHETIC-TOKEN')
        self.assertIn('E101_ENGINE_LOAD_ERROR4', payload(t)['CODE_RESPONSE'][0])
        self.assertIn('native_get_nonce', t.kinds())

    def test_nonce_exceptions_make_second_engine_error3_with_message(self):
        for error in (fault(message='nonce fault'), LinkFault(message='link fault')):
            t = self.transcript(overrides={'native_get_nonce': error})
            self.assertEqual(t.run(service(t)), 'SYNTHETIC-TOKEN')
            second = payload(t)['CODE_RESPONSE2'][0]
            self.assertIn('E101_ENGINE_LOAD_ERROR3', second)
            self.assertIn(error.message, second)

    def test_null_nonce_produces_updater_error7_before_cmd300_connection(self):
        t = self.transcript(overrides={'native_get_nonce': None})
        result = t.run(service(t))
        self.assertTrue(result.startswith('E101_NET_ERROR_007'))
        self.assertEqual([x[0] for x in t.requests], [200])

    def test_zip_failure_then_fingerprint_failure_overwrites_first_only(self):
        t = self.transcript(overrides={'check_zip_os14': False, 'check_fingerprint': False})
        self.assertEqual(t.run(service(t)), 'SYNTHETIC-TOKEN')
        formats = [e.args for e in t.effects if e.kind == 'format_local_error']
        self.assertEqual([f[1] for f in formats], ['unZip error : synthetic zip detail', 'FingerPrint error(synthetic fingerprint detail)'])
        self.assertEqual(payload(t)['CODE_RESPONSE'], ['SYNTHETIC-LOCAL-ERROR:FingerPrint error(synthetic fingerprint detail)'])
        self.assertEqual(payload(t)['CODE_RESPONSE2'], ['SYNTHETIC-NONCE-OBSERVATION'])

    def test_zip_formatter_exception_propagates_fp_formatter_exception_keeps_first(self):
        t = self.transcript(overrides={'check_zip_os14': False, 'format_local_error': fault()})
        with self.assertRaises(JavaFault):
            t.run(service(t))
        self.assertNotIn('native_get_nonce', t.kinds())
        t = self.transcript(overrides={'check_fingerprint': False, 'format_local_error': fault()})
        self.assertEqual(t.run(service(t)), 'SYNTHETIC-TOKEN')
        self.assertIn('SYNTHETIC-NATIVE-OBSERVATION', plain_response(t))

    def test_hash_key_and_mix_snapshots_precede_metadata_mutation(self):
        t = self.transcript()
        (t.runtime.data.hash_key, t.runtime.data.is_mix) = ('old key', True)

        def metadata(_):
            (t.runtime.data.hash_key, t.runtime.data.is_mix, t.runtime.data.is_split) = ('new key', False, True)
            return False
        t.overrides['split_metadata_boolean'] = metadata
        t.run(service(t))
        nonce = next((e for e in t.effects if e.kind == 'native_get_nonce'))
        self.assertEqual(nonce.args, ('old key', 'c', True, True))
        self.assertNotIn('CODE_RESPONSE2_VER', payload(t))

    def test_metadata_true_or_exception_follow_original_split_paths(self):
        for (metadata, updater, expected) in ((True, False, True), (fault(), True, True), (None, False, False)):
            t = self.transcript(overrides={'split_metadata_boolean': metadata})
            t.runtime.data.is_split = updater
            t.run(service(t))
            self.assertIs(next((e for e in t.effects if e.kind == 'native_get_nonce')).args[3], expected)

    def test_unknown_environment_not_accepted_or_converted_to_caught_fault(self):
        for kind in ('check_zip_os14', 'check_fingerprint', 'split_metadata_boolean'):
            t = self.transcript(overrides={kind: 'unknown'})
            with self.assertRaises(AnalysisLimit):
                t.run(service(t))
            self.assertEqual([x[0] for x in t.requests], [200])

    def test_returned_null_only_fails_when_encrypted_token_flag_is_on(self):
        for encrypted in (False, True):
            t = Transcript([(200, {'CODE_CHALLENGE': 'c::r'}), (300, {})])
            if encrypted:
                with self.assertRaises(JavaStageError):
                    t.run(service(t, encrypted=True))
            else:
                self.assertIsNone(t.run(service(t)))

    def test_encrypted_return_decryption_and_bad_cipher_error_formatter(self):
        (key, iv) = returned_token_key_iv('c')
        encoded = base64.b64encode(java_seed_encrypt(b'SYNTHETIC decoded value', key, iv)).decode()
        t = Transcript([(200, {'CODE_CHALLENGE': 'c::r'}), (300, {'CODE_TOKEN': '[ETOKEN]' + encoded})])
        self.assertEqual(t.run(service(t, encrypted=True)), 'SYNTHETIC decoded value')
        self.assertTrue(plain_response(t).startswith('[ETOKEN]'))
        t = Transcript([(200, {'CODE_CHALLENGE': 'c::r'}), (300, {'CODE_TOKEN': '[ETOKEN]a'})])
        self.assertEqual(t.run(service(t, encrypted=True)), 'SYNTHETIC-LOCAL-ERROR:token decryption fail')
        self.assertEqual(t.effects[-1].args, ('CG_RETRY01', 'token decryption fail', 'CG_RETRY(synthetic decrypt exception)'))

    def test_null_formatter_result_is_not_sent_after_fingerprint(self):
        t = self.transcript(overrides={'check_fingerprint': False, 'format_local_error': None})
        with self.assertRaises(JavaStageError):
            t.run(service(t))
        self.assertEqual([x[0] for x in t.requests], [200])

    def test_no_implicit_sdk_socket_file_and_no_private_value_in_repr(self):
        t = self.transcript()
        with patch('socket.socket', side_effect=AssertionError('no socket')), patch('ctypes.CDLL', side_effect=AssertionError('no SDK')), patch('builtins.open', side_effect=AssertionError('no files')):
            self.assertEqual(t.run(service(t)), 'SYNTHETIC-TOKEN')
        self.assertNotIn('SYNTHETIC-TOKEN', repr(t.effects) + repr(t.main) + repr(t.runtime))

@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto unavailable')
class FullSyntheticCryptoTests(unittest.TestCase):

    def test_generated_cert_rsa_key_wrap_hash_key_first_nonce_and_etoken_composition(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.x509.oid import NameOID
        from giro.codeguard_first import first_response_arithmetic
        from giro.codeguard_inputs import NonceArtifacts, nonce_artifact_codes
        from giro.codeguard_nonce import cg_auth_code
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'synthetic.invalid')])
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(123).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(private, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        challenge = base64.b64encode(b'synthetic challenge').decode()
        rule = base64.b64encode(java_seed_encrypt(b'HEADER00' + b'\x02' * 40, RULE_KEY, RULE_IV)).decode()
        nonce_key = bytes(range(32))
        hash_iv = bytes(range(16))
        encoded_hash = base64.b64encode(java_seed_encrypt(nonce_key, b'\x01' * 16, hash_iv)).decode() + '::' + base64.b64encode(hash_iv).decode()
        (out_key, out_iv) = returned_token_key_iv(challenge)
        returned = '[ETOKEN]' + base64.b64encode(java_seed_encrypt(b'SYNTHETIC server-issued-fixture', out_key, out_iv)).decode()
        t = Transcript([(101, {'CERT': base64.b64encode(cert).decode(), 'ENGINE_VERSION': 'synthetic-engine'}), (200, {'CODE_CHALLENGE': challenge + '::' + rule, 'HASH_KEY': encoded_hash, 'CODE_RESPONSE2_VER': 'isMix,isSplit'}), (300, {'CODE_TOKEN': returned})], cert='')
        public_keys = {}
        artifacts = NonceArtifacts(b'libCG', b'libID', b'dex', None, None, cert)
        t.overrides['android_parse_x509'] = lambda e: x509.load_der_x509_certificate(e.args[0])
        t.overrides['certificate_public_key'] = lambda e: e.args[0].public_key()

        def init(e):
            public_keys[e.args[0]] = e.args[2]
        t.overrides['rsa_cipher_init'] = init
        t.overrides['rsa_cipher_final'] = lambda e: public_keys[e.args[0]].encrypt(e.args[1], padding.PKCS1v15())
        t.overrides['native_start'] = lambda e: first_response_arithmetic(b'synthetic package', *e.args[:4]).decode()

        def nonce(e):
            (key, c, mix, split) = e.args
            return cg_auth_code(jni_modified_utf8(key), nonce_artifact_codes(artifacts, c, is_mix=mix, is_split=split))
        t.overrides['native_get_nonce'] = nonce
        with patch('socket.socket', side_effect=AssertionError('no network')), patch('ctypes.CDLL', side_effect=AssertionError('no SDK')):
            self.assertEqual(t.run(service(t, encrypted=True)), 'SYNTHETIC server-issued-fixture')
        cmd200 = parse_qs(urlsplit(t.requests[1][1]).query)
        self.assertEqual(private.decrypt(base64.b64decode(cmd200['KEY'][0]), padding.PKCS1v15()), t.agent.key)
        self.assertEqual(t.runtime.data.hash_key, nonce_key.hex().upper())
        frame = plain_response(t)
        self.assertTrue(frame.startswith('[ETOKEN]APP::1##'))
        expected = first_response_arithmetic(b'synthetic package', challenge, rule, 'APP', '1').decode()
        self.assertIn('##' + expected + '##', frame)
        self.assertEqual(len(payload(t)['CODE_RESPONSE2'][0]), 64)
        self.assertEqual(payload(t)['CODE_RESPONSE2_VER'], ['isMix'])
        self.assertEqual([r[0] for r in t.requests], [101, 200, 300])
