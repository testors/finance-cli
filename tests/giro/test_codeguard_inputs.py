import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch
from giro.codeguard_codec import jni_modified_utf8
from giro.codeguard_inputs import NonceArtifacts, fallback_nonce_key, nonce_artifact_codes, package_digest
from giro.codeguard_rule import AnalysisLimit

class ArtifactInputTests(unittest.TestCase):

    def inputs(self, manifest=b'manifest', sf=b'sf'):
        return NonceArtifacts(b'lib-codeguard', b'lib-image', b'dex', manifest, sf, b'synthetic-encoded-cert')

    def test_nonmix_exact_six_file_and_signer_hashes(self):
        expected = tuple((hashlib.sha256(v).hexdigest().upper().encode() for v in (b'lib-codeguard', b'lib-image', b'dex', b'manifest', b'sf', b'synthetic-encoded-cert')))
        self.assertEqual(nonce_artifact_codes(self.inputs(), None, is_mix=False, is_split=False), expected)

    def test_mix_uses_raw_digest_for_files_but_hex_digest_for_signer(self):
        challenge = 'challenge-A'
        out = nonce_artifact_codes(self.inputs(), challenge, is_mix=True, is_split=False)
        digest = hashlib.sha256(b'lib-codeguard').digest()
        self.assertEqual(out[0], hashlib.sha256(digest + challenge.encode()).hexdigest().upper().encode())
        cert_hex = hashlib.sha256(b'synthetic-encoded-cert').hexdigest().upper().encode()
        self.assertEqual(out[5], hashlib.sha256(cert_hex + challenge.encode()).hexdigest().upper().encode())

    def test_mix_uses_second_jni_challenge_not_first_key(self):
        challenge = '한\x00😀'
        out = nonce_artifact_codes(self.inputs(), challenge, is_mix=True, is_split=False)
        base = hashlib.sha256(b'dex').digest()
        expected = hashlib.sha256(base + jni_modified_utf8(challenge)).hexdigest().upper().encode()
        self.assertEqual(out[2], expected)
        self.assertNotEqual(out[2], hashlib.sha256(base + fallback_nonce_key(challenge)).hexdigest().upper().encode())

    def test_missing_optional_file_is_zeros_not_empty_file_hash(self):
        absent = nonce_artifact_codes(self.inputs(None, None), 'c', is_mix=False, is_split=False)
        empty = nonce_artifact_codes(self.inputs(b'', b''), 'c', is_mix=False, is_split=False)
        self.assertEqual(absent[3:5], (b'0' * 64,) * 2)
        self.assertNotEqual(empty[3:5], absent[3:5])

    def test_missing_optional_files_in_mix_hash_zero32_plus_challenge(self):
        out = nonce_artifact_codes(self.inputs(None, None), 'c', is_mix=True, is_split=False)
        self.assertEqual(out[3:5], (hashlib.sha256(bytes(32) + b'c').hexdigest().upper().encode(),) * 2)

    def test_split_does_not_use_manifest_and_sf_file_contents(self):
        for mix in (False, True):
            self.assertEqual(nonce_artifact_codes(self.inputs(), 'c', is_mix=mix, is_split=True), nonce_artifact_codes(self.inputs(None, None), 'c', is_mix=mix, is_split=True))

    def test_no_automatic_file_collection_or_network(self):
        with patch('builtins.open', side_effect=AssertionError('no files')), patch('socket.socket', side_effect=AssertionError('no network')):
            self.assertEqual(len(nonce_artifact_codes(self.inputs(), 'c', is_mix=True, is_split=False)), 6)

    def test_required_unknown_inputs_do_not_get_default_hashes(self):
        inp = NonceArtifacts(None, b'i', b'd', None, None, b'c')
        with self.assertRaises(AnalysisLimit):
            nonce_artifact_codes(inp, 'c', is_mix=False, is_split=False)
        with self.assertRaises(AnalysisLimit):
            nonce_artifact_codes(self.inputs(), None, is_mix=True, is_split=False)

    def test_fallback_key_uses_java_utf8_not_jni_modified_utf8(self):
        challenge = 'x\x00😀'
        self.assertEqual(fallback_nonce_key(challenge), hashlib.sha256(challenge.encode()).hexdigest().upper().encode())

    def test_dataclass_repr_does_not_disclose_bytes(self):
        self.assertNotIn('synthetic-encoded-cert', repr(self.inputs()))

    def test_package_digest_covers_entire_input(self):
        data = b'PK synthetic package container; synthetic embedded payload'
        self.assertEqual(package_digest(data), hashlib.sha256(data).digest())
        self.assertNotEqual(package_digest(data), hashlib.sha256(b'synthetic embedded payload').digest())
        with self.assertRaises(AnalysisLimit):
            package_digest(None)
