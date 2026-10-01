"""Synthetic observations; no host, Android, institution or SDK executor."""
import base64
import hashlib
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from giro.codeguard_codec import jni_modified_utf8, java_seed_decrypt, RULE_KEY, RULE_IV
from giro.codeguard_effects import Effect, JavaFault
from giro.codeguard_inputs import NonceArtifacts, nonce_artifact_codes, fallback_nonce_key
from giro.codeguard_native_jni import NativeUtfChars
from giro.codeguard_native_io import FailedCmdlineRead
from giro.codeguard_native_nonce import (NativeNonceBoundary, native_nonce_steps,
    nonce_file_digest_steps, project_native_nonce_steps)
from giro.codeguard_native_start import project_native_start_steps
from giro.codeguard_nonce import cg_auth_code
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_service import generate_token_steps
from cg_exchange_fixture import Transcript, drive
from test_codeguard_native_start import NativeObservations, rule
from giro.codeguard_first import first_response_arithmetic


KEY = 'AB'*32
CHALLENGE = 'synthetic-challenge'


class NonceObservations:
    def __init__(self, *, override=None, returned='decode'):
        self.override, self.returned = override, returned
        self.effects, self.utf = [], []
        self.library_fields = 0
        self.streams = {}
        self.files = {b'/lib/a/libCodeGuard.so': b'guard'*211,
                      b'/lib/b/libImageDecoder.so': b'decoder'*200,
                      b'/data/pkg/files/classes.dex': b'dex'*800,
                      b'/data/pkg/files/META-INF/MANIFEST.MF': b'manifest',
                      b'/data/pkg/files/META-INF/CERT.SF': b'sf'}
        self.der = b'synthetic public certificate DER bytes'
        self.digest = hashlib.sha256(self.der).digest()
        self.paths = {'lib-one': b'/lib/a', 'lib-two': b'/lib/b', 'data': b'/data/pkg'}

    def reply(self, effect):
        self.effects.append(effect)
        if self.override:
            chosen, value = self.override(effect)
            if chosen: return value
        kind, args = effect.kind, effect.args
        if kind == 'native_fopen':
            path, mode = args
            if mode == b'r': return 'cmdline'
            if path not in self.files: return None
            stream = (path, len(self.streams))
            self.streams[stream] = [0, False]
            return stream
        if kind == 'native_fgets': return b'pkg:worker\0'
        if kind == 'native_fclose': return -1  # explicit ignored status
        if kind == 'native_feof': return int(self.streams[args[0]][1])
        if kind == 'native_fread':
            stream, size, count = args
            position, eof = self.streams[stream]
            data = self.files[stream[0]][position:position+count]
            self.streams[stream] = [position+len(data), len(data)<count]
            return data
        if kind != 'native_jni': raise AssertionError(kind)
        name, *args = args
        if name == 'GetObjectClass': return ('class', args[0])
        if name == 'FindClass': return args[0]
        if name in ('GetMethodID', 'GetStaticFieldID', 'GetFieldID'): return args[1]
        if name == 'GetStaticMethodID': return (args[1], args[0])
        if name == 'GetStaticIntField': return 34
        if name == 'CallStaticIntMethod': return 456
        if name == 'CallObjectMethod':
            return {'getPackageManager': 'manager', 'getApplicationInfo': 'app-info',
                    'getPackageInfo': 'pkg-info', 'toByteArray': 'signature-bytes',
                    'generateCertificate': 'certificate', 'getEncoded': 'DER-bytes',
                    'digest': 'digest-bytes'}[args[1]]
        if name == 'GetObjectField':
            if args[1] == 'nativeLibraryDir':
                self.library_fields += 1
                return 'lib-one' if self.library_fields == 1 else 'lib-two'
            return {'dataDir': 'data', 'signatures': 'signatures'}[args[1]]
        if name == 'GetObjectArrayElement': return 'signature'
        if name == 'NewObject': return 'input-stream'
        if name == 'CallStaticObjectMethod':
            return 'cert-factory' if args[0].endswith('CertificateFactory') else 'digest-object'
        if name == 'GetArrayLength': return len(self.digest)
        if name == 'GetByteArrayElements': return self.digest
        if name == 'GetStringUTFChars':
            data = self.paths[args[0]] if args[0] in self.paths else jni_modified_utf8(args[0])
            value = None if data is None else NativeUtfChars('utf-'+str(len(self.utf)+1), data)
            self.utf.append((args[0], value))
            return value
        if name in ('ReleaseStringUTFChars', 'DeleteLocalRef'): return None
        if name == 'NewStringUTF':
            if args[0] in (b'pkg', b'X.509', b'SHA-256'): return ('string', args[0])
            return args[0].decode('ascii') if self.returned == 'decode' else self.returned
        raise AssertionError(name)

    def run(self, **options):
        values = dict(service='service', key=KEY, challenge=CHALLENGE, is_mix=False, is_split=False)
        values.update(options)
        return drive(native_nonce_steps(**values), self.reply)

    def calls(self, name):
        return [e.args[1:] for e in self.effects if e.kind=='native_jni' and e.args[0]==name]

    def expected(self, *, mix=False, split=False, challenge=CHALLENGE, key=KEY):
        artifacts = NonceArtifacts(*(self.files.get(path) for path in (
            b'/lib/a/libCodeGuard.so', b'/lib/b/libImageDecoder.so', b'/data/pkg/files/classes.dex',
            b'/data/pkg/files/META-INF/MANIFEST.MF', b'/data/pkg/files/META-INF/CERT.SF')), self.der)
        return cg_auth_code(key.encode(), nonce_artifact_codes(artifacts, challenge, is_mix=mix, is_split=split))


class NonceFileReadTests(unittest.TestCase):
    def test_actual_short_reads_continue_until_observed_eof_without_padding(self):
        observed = iter([0, b'ab', 0, b'', 0, b'c', 1, -1])
        effects = []
        def reply(e):
            effects.append(e)
            return next(observed)
        result = drive(nonce_file_digest_steps('stream'), reply)
        self.assertEqual(result, hashlib.sha256(b'abc').digest())
        self.assertEqual([e.kind for e in effects], ['native_feof','native_fread']*3+['native_feof','native_fclose'])

    def test_initial_eof_hashes_empty_without_a_read(self):
        seen = []
        def reply(e):
            seen.append(e.kind)
            return -3
        self.assertEqual(drive(nonce_file_digest_steps('s'), reply), hashlib.sha256(b'').digest())
        self.assertEqual(seen, ['native_feof','native_fclose'])

    def test_missing_stream_and_unknown_reads_do_not_become_empty_digest(self):
        with self.assertRaises(NativeNonceBoundary) as caught:
            drive(nonce_file_digest_steps(None, null_code=82), lambda e: self.fail())
        self.assertEqual(caught.exception.native_code, 82)
        for unknown in (None, b'a'*1025, False):
            observed = iter([0, unknown])
            with self.assertRaises(AnalysisLimit):
                drive(nonce_file_digest_steps('s'), lambda e: next(observed))

    def test_zero_read_with_unset_eof_does_not_create_completion_or_ferror(self):
        gen = nonce_file_digest_steps('s')
        self.assertEqual(next(gen).kind, 'native_feof')
        for _ in range(3):
            self.assertEqual(gen.send(0).kind, 'native_fread')
            self.assertEqual(gen.send(b'').kind, 'native_feof')
        gen.close()  # caller suspends; no result, close effect or extra diagnosis


class NativeNonceTests(unittest.TestCase):
    def test_normal_path_matches_six_artifact_arithmetic_for_all_modes(self):
        for mix in (False, True):
            for split in (False, True):
                obs = NonceObservations()
                self.assertEqual(obs.run(is_mix=mix,is_split=split), obs.expected(mix=mix,split=split))
                kinds = [e.kind for e in obs.effects]
                self.assertNotIn('native_stat', kinds)
                self.assertNotIn('native_fseek', kinds)
                self.assertNotIn('native_ftell', kinds)
                self.assertFalse(any(args[1]=='isInstance' for args in obs.calls('GetMethodID')))
                self.assertEqual(obs.calls('GetObjectArrayElement'), [('signatures',0)])

    def test_duplicate_library_field_reads_and_utf_acquisitions_are_not_cached(self):
        obs = NonceObservations()
        obs.run()
        self.assertEqual(obs.calls('GetObjectField')[:3], [('app-info','nativeLibraryDir')]*2+[('app-info','dataDir')])
        opens = [e.args[0] for e in obs.effects if e.kind=='native_fopen']
        self.assertEqual(opens, [b'/proc/456/cmdline',*obs.files])
        self.assertEqual(obs.calls('GetStringUTFChars'), [(x,) for x in (CHALLENGE,'lib-one','lib-two','data','data','data',KEY)])

    def test_releases_keep_original_subset_and_order_before_final_string(self):
        obs = NonceObservations()
        obs.run()
        self.assertEqual(obs.calls('ReleaseStringUTFChars'), [('lib-one','utf-2'),(KEY,'utf-7'),(CHALLENGE,'utf-1')])
        self.assertEqual(obs.calls('DeleteLocalRef'), [(x,) for x in ('app-info',
            'android/app/ApplicationPackageManager','android/os/Process',('class','service'),
            'android/content/pm/ApplicationInfo','java/lang/Class','android/os/Build$VERSION',
            'manager',('class','manager'))])
        self.assertEqual(obs.effects[-1].args[0], 'NewStringUTF')
        self.assertEqual(obs.calls('ReleaseByteArrayElements'), [])

    def test_key_utf_is_not_acquired_before_all_files_and_signer(self):
        obs = NonceObservations()
        obs.run()
        get_key = next(i for i,e in enumerate(obs.effects) if e.args==('GetStringUTFChars',KEY))
        signer = next(i for i,e in enumerate(obs.effects) if e.args==('GetByteArrayElements','digest-bytes'))
        self.assertGreater(get_key, signer)
        self.assertEqual(obs.effects[0].args, ('GetStringUTFChars',CHALLENGE))

    def test_each_library_fallback_requires_an_observed_open_failure(self):
        obs = NonceObservations()
        expected = obs.expected()
        for name, base in ((b'libCodeGuard.so',b'/lib/a/'),(b'libImageDecoder.so',b'/lib/b/')):
            obs.files[b'/data/pkg/files/lib/'+name] = obs.files.pop(base+name)
        self.assertEqual(obs.run(), expected)
        opens = [e.args[0] for e in obs.effects if e.kind=='native_fopen']
        self.assertEqual(opens[1:5], [b'/lib/a/libCodeGuard.so',b'/data/pkg/files/lib/libCodeGuard.so',
                                     b'/lib/b/libImageDecoder.so',b'/data/pkg/files/lib/libImageDecoder.so'])

    def test_data_directory_is_reacquired_for_each_selected_file(self):
        obs = NonceObservations()
        expected = obs.expected()
        for i,name in enumerate((b'classes.dex',b'META-INF/MANIFEST.MF',b'META-INF/CERT.SF'),1):
            obs.files[b'/data/'+str(i).encode()+b'/files/'+name] = obs.files.pop(b'/data/pkg/files/'+name)
        count = 0
        def override(e):
            nonlocal count
            if e.args==('GetStringUTFChars','data'):
                count += 1
                return True, NativeUtfChars('data-'+str(count), b'/data/'+str(count).encode())
            return False, None
        obs.override = override
        self.assertEqual(obs.run(), expected)
        self.assertEqual(count, 3)

    def test_optional_open_failures_and_split_keep_zero_digest_not_empty_file(self):
        for mix in (False,True):
            obs = NonceObservations()
            del obs.files[b'/data/pkg/files/META-INF/MANIFEST.MF']
            del obs.files[b'/data/pkg/files/META-INF/CERT.SF']
            self.assertEqual(obs.run(is_mix=mix), obs.expected(mix=mix))
            split = NonceObservations()
            self.assertEqual(split.run(is_mix=mix,is_split=True), obs.expected(mix=mix))
            self.assertEqual(len([e for e in split.effects if e.kind=='native_fopen']),4)
            self.assertEqual(split.calls('GetStringUTFChars').count(('data',)),1)

    def test_required_open_failures_preserve_unsafe_native_boundaries(self):
        for path,code in ((b'/lib/a/libCodeGuard.so',None),(b'/lib/b/libImageDecoder.so',None),
                          (b'/data/pkg/files/classes.dex',82)):
            obs = NonceObservations()
            del obs.files[path]
            with self.assertRaises(NativeNonceBoundary) as caught: obs.run()
            self.assertEqual(caught.exception.native_code,code)
            self.assertEqual(obs.calls('ReleaseStringUTFChars'),[])
            self.assertNotIn((KEY,),obs.calls('GetStringUTFChars'))

    def test_cmdline_open_and_read_failure_are_not_safe_error_returns(self):
        for kind,code in (('native_fopen',15),('native_fgets',16)):
            obs = NonceObservations(override=lambda e: (e.kind==kind,None))
            with self.assertRaises(NativeNonceBoundary) as caught: obs.run()
            self.assertEqual(caught.exception.native_code,code)
            self.assertEqual(sum(e.kind=='native_fclose' for e in obs.effects),int(code==16))
            self.assertEqual(obs.calls('NewStringUTF'),[])
        obs=NonceObservations(override=lambda e: (e.kind=='native_fgets',FailedCmdlineRead(b'pkg\0')))
        with self.assertRaises(NativeNonceBoundary) as caught: obs.run()
        self.assertEqual(caught.exception.native_code,16)
        self.assertEqual(sum(e.kind=='native_fclose' for e in obs.effects),1)

    def test_pid_zero_sets_error_but_does_not_skip_subsequent_work(self):
        obs = NonceObservations(override=lambda e: (e.kind=='native_jni' and e.args[0]=='CallStaticIntMethod',0))
        self.assertEqual(obs.run(),'E101_ENGINE_LOAD_ERROR0_14_:lib2')
        self.assertIn(b'/proc/0/cmdline',[e.args[0] for e in obs.effects if e.kind=='native_fopen'])
        self.assertIn((KEY,),obs.calls('GetStringUTFChars'))
        self.assertEqual(len(obs.calls('ReleaseStringUTFChars')),3)

    def test_null_unused_lookup_classes_do_not_add_original_error_checks(self):
        names = ('android/app/ApplicationPackageManager','java/lang/Class')
        obs = NonceObservations(override=lambda e: (e.kind=='native_jni' and e.args[0]=='FindClass' and e.args[1] in names,None))
        self.assertEqual(obs.run(),obs.expected())
        self.assertEqual(len(obs.calls('DeleteLocalRef')),7)

    def test_late_signer_null_code_is_retained_through_explicit_later_jni_observations(self):
        obs = NonceObservations()
        def override(e):
            if e.args==('NewStringUTF',b'X.509'): return True,None
            return False,None
        obs.override=override
        self.assertEqual(obs.run(),'E101_ENGINE_LOAD_ERROR0_85_:lib2')
        self.assertIn(('java/security/cert/CertificateFactory',('getInstance','java/security/cert/CertificateFactory'),None),obs.calls('CallStaticObjectMethod'))
        self.assertEqual(len(obs.calls('ReleaseStringUTFChars')),3)

    def test_nonmix_null_challenge_is_not_turned_into_a_string(self):
        obs=NonceObservations()
        self.assertEqual(obs.run(challenge=None),obs.expected())
        self.assertEqual(len(obs.calls('ReleaseStringUTFChars')),2)
        mixed=NonceObservations()
        with self.assertRaises(NativeNonceBoundary): mixed.run(challenge=None,is_mix=True)
        self.assertEqual(sum(e.kind=='native_fclose' for e in mixed.effects),2)

    def test_jni_bytes_are_used_instead_of_reencoding_java_references(self):
        obs=NonceObservations()
        key,challenge=object(),object()
        def override(e):
            if e.kind=='native_jni' and e.args[0]=='GetStringUTFChars':
                if e.args[1] is key: return True,NativeUtfChars('key',KEY.encode())
                if e.args[1] is challenge: return True,NativeUtfChars('challenge',CHALLENGE.encode()+b'\0ignored')
            return False,None
        obs.override=override
        self.assertEqual(obs.run(key=key,challenge=challenge,is_mix=True),obs.expected(mix=True))

    def test_unresolved_digest_bytes_and_memory_boundaries_are_not_error_tokens(self):
        for length in (-1,64):
            obs=NonceObservations(override=lambda e: (e.kind=='native_jni' and e.args[0]=='GetArrayLength',length))
            with self.assertRaises(AnalysisLimit): obs.run()
            self.assertNotIn((KEY,),obs.calls('GetStringUTFChars'))
        obs=NonceObservations()
        obs.digest=b'\x01'*31
        with self.assertRaises(AnalysisLimit): obs.run(is_mix=True)

    def test_signer_uses_actual_array_bytes_and_nonmix_short_digest_is_zero_padded(self):
        for data in (b'',b'\x01\xff',bytes(range(32)),bytes(range(40))):
            with self.subTest(length=len(data)):
                actual=NonceObservations()
                actual.digest=data
                captured=[]
                from giro.codeguard_native_nonce import cg_auth_code as arithmetic
                def observe(key,codes):
                    captured.append(codes[-1])
                    return arithmetic(key,codes)
                with patch('giro.codeguard_native_nonce.cg_auth_code',side_effect=observe): actual.run()
                self.assertEqual(captured,[data.hex().upper().encode()[:64].ljust(64,b'\0')])

    def test_exact_block_file_needs_extra_read_and_paths_are_not_normalized(self):
        obs=NonceObservations()
        obs.paths['lib-one']=b'/lib//a/../a'
        path=b'/lib//a/../a/libCodeGuard.so'
        obs.files[path]=b'x'*1024
        obs.run()
        reads=[e for e in obs.effects if e.kind=='native_fread' and e.args[0][0]==path]
        self.assertEqual(len(reads),2)
        self.assertEqual([e.args[1:] for e in reads],[(1,1024)]*2)

    def test_final_null_is_preserved_and_unknown_java_string_is_not_decoded(self):
        self.assertIsNone(NonceObservations(returned=None).run())
        with self.assertRaises(AnalysisLimit): NonceObservations(returned=object()).run()

    def test_no_host_files_sdk_or_network_used(self):
        expected = NonceObservations().expected()  # preload pure package resources
        with patch('builtins.open',side_effect=AssertionError('host IO')), \
             patch('socket.socket',side_effect=AssertionError('network')):
            self.assertEqual(NonceObservations().run(),expected)


class NativeNonceProjectionTests(unittest.TestCase):
    def test_both_native_responses_reach_same_cmd300_without_response_placeholders(self):
        fixture=Transcript([(200,{'CODE_CHALLENGE':'TQ==::'+rule()}),
                            (300,{'CODE_TOKEN':'SYNTHETIC-TOKEN'})])
        fixture.main.pid='123'
        first,second=NativeObservations(),NonceObservations()
        stage='first'
        def reply(e):
            nonlocal stage
            if e.kind=='check_zip_os14': stage='second'
            if e.kind.startswith('native_'):
                return (first if stage=='first' else second).reply(e)
            return fixture.reply(e)
        gen=generate_token_steps(fixture.main,fixture.runtime,fixture.agent,
            server_url='https://synthetic.invalid/',timeout=1000,root_check=True,
            rooting_info=False,encrypted_token=False)
        gen=project_native_nonce_steps(project_native_start_steps(gen,service='service'),service='service')
        self.assertEqual(drive(gen,reply),'SYNTHETIC-TOKEN')
        self.assertTrue(second.calls('GetByteArrayElements'))
        self.assertTrue(first.calls('ReleaseStringUTFChars'))
        self.assertEqual([x[0] for x in fixture.requests],[200,300])
        form=parse_qs(fixture.writes[-1][1].decode())
        plain=java_seed_decrypt(base64.b64decode(form['CODE_RESPONSE'][0]),RULE_KEY,RULE_IV).decode()
        expected_first=first_response_arithmetic(first.package,'TQ==',rule(),'APP','1').decode()
        self.assertIn('##'+expected_first+'##',plain)
        self.assertEqual(form['CODE_RESPONSE2'],[second.expected(challenge='TQ==',key=fallback_nonce_key('TQ==').decode())])

    def test_projected_jni_fault_is_seen_by_original_catch_without_retry(self):
        observed=JavaFault('Exception',message='synthetic',java_string='synthetic')
        def parent():
            try: yield Effect('native_get_nonce',(KEY,CHALLENGE,False,False))
            except JavaFault as fault: return fault
        gen=project_native_nonce_steps(parent(),service='service')
        self.assertEqual(next(gen).args,('GetStringUTFChars',CHALLENGE))
        with self.assertRaises(StopIteration) as done: gen.throw(observed)
        self.assertIs(done.exception.value,observed)

    def test_unknown_inputs_remain_analysis_limits_not_parent_java_errors(self):
        def parent():
            try: yield Effect('native_get_nonce',(KEY,CHALLENGE,False,False))
            except JavaFault: self.fail('invented Java rejection')
        gen=project_native_nonce_steps(parent(),service='service')
        next(gen)
        with self.assertRaises(AnalysisLimit): gen.send(object())
