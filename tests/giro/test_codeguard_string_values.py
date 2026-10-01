"""Pure value equivalence and synthetic external environment observations."""
import base64
import hashlib
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from giro.codeguard_codec import jni_modified_utf8, RULE_KEY, RULE_IV, java_seed_decrypt
from giro.codeguard_effects import Effect
from giro.codeguard_native_jni import NativeStringValue, NativeUtfChars
from giro.codeguard_native_start import native_start_steps
from giro.codeguard_native_nonce import native_nonce_steps
from giro.codeguard_service import generate_token_steps
from giro.codeguard_string_values import (decode_modified_utf8, ModifiedUtfBoundary,
    StringValues, UNRESOLVED, project_string_values_steps, project_native_value_steps)
from giro.codeguard_rule import AnalysisLimit
from cg_exchange_fixture import Transcript, drive, fault
from test_codeguard_native_start import NativeObservations, rule
from test_codeguard_native_nonce import NonceObservations, KEY, CHALLENGE


def jni(name, *args): return Effect('native_jni', (name, *args))


def path_values(observer, effect):
    """A fixture explicitly resolving its synthetic path fields to contents."""
    result = observer.reply(effect)
    if effect.kind == 'native_jni' and effect.args[0] == 'GetObjectField':
        name = effect.args[2]
        if isinstance(observer, NativeObservations) and name in ('sourceDir', 'dataDir'):
            number = effect.args[1][1]
            return NativeStringValue('/installed/pkg/base-'+str(number) if name == 'sourceDir' else '/data/pkg')
        if isinstance(observer, NonceObservations) and name in ('nativeLibraryDir', 'dataDir'):
            return NativeStringValue(observer.paths[result].decode('ascii'))
    return result


class StringValueTests(unittest.TestCase):
    def test_canonical_roundtrip_including_nul_surrogates_and_supplementary(self):
        for text in ('', 'ASCII', '\x00', '한글', '\u007f\u0080\u07ff\u0800\uffff',
                     '\ud800', '\udfff', '\ud800A\udc00', '😀', 'A\x00😀'):
            encoded = jni_modified_utf8(text)
            decoded = decode_modified_utf8(encoded)
            self.assertEqual(decoded.encode('utf-16-be', 'surrogatepass'),
                             text.encode('utf-16-be', 'surrogatepass'))

    def test_c_nul_ends_input_but_encoded_nul_is_a_character(self):
        self.assertEqual(decode_modified_utf8(b'A\xc0\x80B\0\xff'), 'A\0B')
        self.assertEqual(decode_modified_utf8(b'\0\xf0\x9f\x98\x80'), '')

    def test_noncanonical_and_incomplete_inputs_are_not_replacement_decoded(self):
        for raw in (None, 'x', b'\x80', b'\xc0', b'\xc0\x81', b'\xc1\xbf',
                    b'\xc2A', b'\xe0\x80\x80', b'\xe1\x80', b'\xef\xff\xff',
                    b'\xf0\x9f\x98\x80', b'\xff'):
            with self.assertRaises(ModifiedUtfBoundary): decode_modified_utf8(raw)

    def test_jdk_vectors_and_all_utf16_code_units(self):
        java = shutil.which('java')
        if not java: self.skipTest('JDK unavailable for development comparison')
        result = subprocess.run([java, str(Path(__file__).parent/'java/JniStringValueVectors.java')],
                                capture_output=True, text=True, timeout=30, check=True)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 9)
        for line in lines[:-1]:
            units, encoded = line.split(':')
            text = bytes.fromhex(units).decode('utf-16-be', 'surrogatepass')
            self.assertEqual(jni_modified_utf8(text).hex(), encoded)
            self.assertEqual(decode_modified_utf8(bytes.fromhex(encoded)).encode('utf-16-be', 'surrogatepass').hex(), units)
        digest = hashlib.sha256()
        for unit in range(65536):
            text = chr(unit)
            encoded = jni_modified_utf8(text)
            self.assertEqual(decode_modified_utf8(encoded), text)
            digest.update(len(encoded).to_bytes(2, 'big') + encoded)
        self.assertEqual(lines[-1], 'all-units:' + digest.hexdigest())

    def test_owned_get_and_release_have_distinct_acquisition_identity(self):
        values, ref = StringValues(), NativeStringValue('A\0😀')
        first = values.resolve(jni('GetStringUTFChars', ref))
        second = values.resolve(jni('GetStringUTFChars', ref))
        self.assertIsNot(first.handle, second.handle)
        self.assertEqual(first.data, b'A\xc0\x80\xed\xa0\xbd\xed\xb8\x80\0')
        self.assertIsNone(values.resolve(jni('ReleaseStringUTFChars', ref, second.handle)))
        self.assertIsNone(values.resolve(jni('ReleaseStringUTFChars', ref, first.handle)))
        self.assertEqual((values.acquired_count, values.released_count), (2, 2))

    def test_equal_contents_do_not_authorize_release_of_other_reference(self):
        values, a, b = StringValues(), NativeStringValue('same'), NativeStringValue('same')
        utf = values.resolve(jni('GetStringUTFChars', a))
        with self.assertRaises(AnalysisLimit): values.resolve(jni('ReleaseStringUTFChars', b, utf.handle))
        with self.assertRaises(AnalysisLimit): StringValues().resolve(jni('ReleaseStringUTFChars', a, utf.handle))
        values.resolve(jni('ReleaseStringUTFChars', a, utf.handle))
        with self.assertRaises(AnalysisLimit): values.resolve(jni('ReleaseStringUTFChars', a, utf.handle))

    def test_deleted_owned_reference_is_not_reused(self):
        values, ref = StringValues(), NativeStringValue('value')
        values.resolve(jni('DeleteLocalRef', ref))
        with self.assertRaises(AnalysisLimit): values.resolve(jni('GetStringUTFChars', ref))
        with self.assertRaises(AnalysisLimit): values.resolve(jni('DeleteLocalRef', ref))

    def test_new_string_returns_owned_value_and_keeps_sensitive_contents_out_of_repr(self):
        values = StringValues()
        ref = values.resolve(jni('NewStringUTF', b'SYNTHETIC-PRIVATE'))
        self.assertEqual(ref.text, 'SYNTHETIC-PRIVATE')
        utf = values.resolve(jni('GetStringUTFChars', ref))
        self.assertNotIn('SYNTHETIC-PRIVATE', repr(ref)+repr(utf)+repr(utf.handle)+repr(values))

    def test_unowned_null_and_security_results_are_never_invented(self):
        values = StringValues()
        for effect in (jni('GetStringUTFChars', 'opaque-string-id'), jni('GetStringUTFChars', None),
                       jni('NewStringUTF', None), jni('NewStringUTF', b'\xff'),
                       jni('FindClass', 'android/app/ApplicationPackageManager'),
                       jni('CallBooleanMethod', 'expected', 'isInstance', 'manager'),
                       Effect('native_fopen', (b'/proc/self/status', b'r')),
                       jni('DeleteLocalRef', 'opaque-ref'), jni('ReleaseStringUTFChars', 's', 'h')):
            self.assertIs(values.resolve(effect), UNRESOLVED)
        with self.assertRaises(AnalysisLimit): NativeStringValue(None)

    def test_unsupported_encoding_and_external_fault_are_forwarded(self):
        seen = []
        def body():
            try: return (yield jni('NewStringUTF', b'\xff'))
            except type(fault()): return 'observed-catch'
        def reply(e):
            seen.append(e)
            return fault()
        self.assertEqual(drive(project_string_values_steps(body()), reply), 'observed-catch')
        self.assertEqual(seen[0].args, ('NewStringUTF', b'\xff'))

    def test_null_external_jni_result_suspends_normal_resolution(self):
        values, seen = StringValues(), []
        def body():
            yield jni('FindClass', 'missing')
            return (yield jni('NewStringUTF', b'known'))
        def reply(e):
            seen.append(e.args[0])
            return None if e.args[0] == 'FindClass' else 'explicit-exceptional-observation'
        result = drive(project_string_values_steps(body(), values=values), reply)
        self.assertEqual(result, 'explicit-exceptional-observation')
        self.assertEqual(seen, ['FindClass', 'NewStringUTF'])
        self.assertTrue(values.suspended)

    def test_external_void_release_does_not_suspend_normal_values(self):
        values = StringValues()
        def body():
            yield jni('DeleteLocalRef', 'external')
            return (yield jni('NewStringUTF', b'value'))
        result = drive(project_string_values_steps(body(), values=values), lambda e: None)
        self.assertEqual(result.text, 'value')
        self.assertFalse(values.suspended)

    def test_python_failure_is_not_translated_to_java_error_or_null(self):
        def body(): return (yield jni('NewStringUTF', b'value'))
        with patch('giro.codeguard_string_values.decode_modified_utf8', side_effect=MemoryError('synthetic')):
            with self.assertRaises(MemoryError): drive(project_string_values_steps(body()), lambda e: None)

    def test_native_start_computes_all_strings_without_string_observation_fixture(self):
        obs, values = NativeObservations(), StringValues()
        args = [NativeStringValue(x) for x in ('TQ==', rule(), 'APP', '1', '123')]
        expected = NativeObservations().run()
        gen = project_string_values_steps(native_start_steps('service', *args), values=values)
        result = drive(gen, lambda e: path_values(obs, e))
        self.assertEqual(result, expected)
        self.assertEqual((values.acquired_count, values.released_count), (8, 8))
        for method in ('GetStringUTFChars', 'ReleaseStringUTFChars', 'NewStringUTF'):
            self.assertEqual(obs.calls(method), [])
        self.assertEqual(obs.manager_count, 3)
        self.assertTrue(obs.calls('CallBooleanMethod'))

    def test_nonce_computes_strings_but_keeps_file_and_signer_provider_observations(self):
        obs, values = NonceObservations(), StringValues()
        gen = native_nonce_steps('service', NativeStringValue(KEY), NativeStringValue(CHALLENGE), False, False)
        result = drive(project_string_values_steps(gen, values=values), lambda e: path_values(obs, e))
        self.assertEqual(result, obs.expected())
        self.assertEqual((values.acquired_count, values.released_count), (7, 3))
        for method in ('GetStringUTFChars', 'ReleaseStringUTFChars', 'NewStringUTF'):
            self.assertEqual(obs.calls(method), [])
        self.assertTrue(obs.calls('GetByteArrayElements'))
        self.assertTrue(obs.calls('GetObjectArrayElement'))

    def test_two_responses_and_cmd300_use_pure_string_values(self):
        transcript = Transcript([(200, {'CODE_CHALLENGE':'TQ==::'+rule()}), (300, {'CODE_TOKEN':'SYNTHETIC'})])
        transcript.main.pid = '123'
        first, second = NativeObservations(), NonceObservations()
        stage = 'first'
        def reply(e):
            nonlocal stage
            if e.kind == 'check_zip_os14': stage = 'second'
            if e.kind.startswith('native_'): return path_values(first if stage == 'first' else second, e)
            return transcript.reply(e)
        gen = generate_token_steps(transcript.main, transcript.runtime, transcript.agent,
            server_url='https://synthetic.invalid/', timeout=1000, root_check=True,
            rooting_info=False, encrypted_token=False)
        self.assertEqual(drive(project_native_value_steps(gen, service='service'), reply), 'SYNTHETIC')
        self.assertEqual([r[0] for r in transcript.requests], [200, 300])
        form = parse_qs(transcript.writes[-1][1].decode())
        plain = java_seed_decrypt(base64.b64decode(form['CODE_RESPONSE'][0]), RULE_KEY, RULE_IV).decode()
        self.assertIn(NativeObservations().run(), plain)
        self.assertEqual(form['CODE_RESPONSE2'], [second.expected(challenge='TQ==', key=hashlib.sha256(b'TQ==').hexdigest().upper())])
        for obs in (first, second):
            self.assertEqual(obs.calls('NewStringUTF'), [])
            self.assertEqual(obs.calls('GetStringUTFChars'), [])


if __name__ == '__main__':
    unittest.main()
