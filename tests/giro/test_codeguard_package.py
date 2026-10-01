"""Explicit synthetic Java/IO observations; no installed files or JCA proof."""
import base64
import hashlib
import unittest
from dataclasses import dataclass
from unittest.mock import patch
from urllib.parse import parse_qs

from giro.codeguard_effects import Effect, JavaFault, LinkFault
from giro.codeguard_package import (check_zip_steps, prepare_libraries_steps,
    library_entries_steps, prepare_metadata_steps, check_fingerprint_steps,
    fingerprint_certificate_steps, project_package_steps)
from giro.codeguard_platform import ReadOnce
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_service import generate_token_steps
from giro.codeguard_native_start import project_native_start_steps
from giro.codeguard_native_nonce import project_native_nonce_steps
from giro.codeguard_inputs import fallback_nonce_key
from cg_exchange_fixture import Transcript, drive
from test_codeguard_native_start import NativeObservations, rule
from test_codeguard_native_nonce import NonceObservations


def fault(kind='IOException', message='synthetic IO'):
    return JavaFault(kind, message=message, java_string='synthetic '+kind)


@dataclass(frozen=True)
class Entry:
    name: str
    data: bytes = b'synthetic bytes'
    directory: bool = False


class PackageObservations:
    """In-memory fixture. Every default below is a synthetic observation."""
    def __init__(self):
        self.source, self.destination = '/installed/base.apk', '/data/pkg/files'
        self.names = ['base.apk']
        self.archives = {self.source: [
            Entry('lib/arm64-v8a/libCodeGuard.so', b'guard'),
            Entry('lib/arm64-v8a/libImageDecoder.so', b'decoder'),
            Entry('classes.dex', b'dex'*800), Entry('META-INF/MANIFEST.MF', b'manifest'),
            Entry('META-INF/SIGNER.SF', b'sf'), Entry('META-INF/CERT.RSA', b'certificate')]}
        self.files = {self.source: b'container'}
        self.directories = {'/installed/', '/data/pkg/files/', '/data/pkg/files'}
        self.modified = {self.source: 5, self.destination+'/classes.dex': 8}
        self.preferences, self.errors = {}, {'UnZip': '', 'FingerPrint': ''}
        self.version, self.abi, self.debug, self.commit = 'v1', 'arm64-v8a', False, True
        self.effects, self.counts, self.overrides = [], {}, {}
        self.refs, self.counter = {}, 0

    @staticmethod
    def path(value):
        # Explicit fixture observation of File's duplicate-slash treatment.
        while '//' in value: value = value.replace('//', '/')
        return value

    def ref(self, kind, value):
        self.counter += 1
        ref = (kind, self.counter)
        self.refs[ref] = value
        return ref

    def calls(self, name):
        return [e.args[1:] for e in self.effects if e.kind=='package_java' and e.args[0]==name]

    def reply(self, e):
        self.effects.append(e)
        if e.kind=='java_runtime_fault': return fault(e.args[0])
        if e.kind!='package_java': raise AssertionError(e.kind)
        name, *args = e.args
        self.counts[name] = self.counts.get(name, 0)+1
        key = (name, self.counts[name])
        if key in self.overrides: return self.overrides[key]
        if name in ('monitor.enter','monitor.exit'): return None
        if name=='agent.getInstance': return 'agent'
        if name in ('agent.context','main.staticContext'): return 'context'
        if name=='agent.version': return self.version
        if name.startswith('agent.set'):
            self.errors[name[9:-8]] = args[1]
            return None
        if name.startswith('agent.get') and name.endswith('ErrorMsg'):
            return self.errors[name[9:-8]]
        if name=='context.getApplicationInfo': return 'app-info'
        if name=='applicationInfo.sourceDir': return self.source
        if name=='context.getFilesDir': return self.destination
        if name=='context.getSharedPreferences': return 'preferences'
        if name in ('preferences.getLong','preferences.getString'):
            return self.preferences.get(args[1],args[2])
        if name=='preferences.edit': return 'editor'
        if name.startswith('editor.'):
            if name=='editor.commit': return self.commit
            if name=='editor.remove': self.preferences.pop(args[1],None)
            else: self.preferences[args[1]] = args[2]
            return 'editor'
        if name=='log.DEBUG': return self.debug
        if name=='file.separator': return '/'
        if name=='file.new':
            return fault('NullPointerException') if args[0] is None else self.path(args[0])
        if name=='file.getPath': return args[0]
        if name=='file.exists': return args[0] in self.files or args[0] in self.directories
        if name=='file.isDirectory': return args[0] in self.directories
        if name=='file.mkdirs':
            self.directories.add(args[0])
            return True
        if name=='file.getParentFile': return args[0].rsplit('/',1)[0]
        if name=='file.list': return self.names
        if name=='file.lastModified': return self.modified[args[0]]
        if name=='build.CPU_ABI': return self.abi
        if name=='zip.new':
            path = self.path(args[0])
            return path if path in self.archives else fault()
        if name=='zip.size': return len(self.archives[args[0]])
        if name=='zip.entries': return self.ref('enumeration',[self.archives[args[0]],0])
        if name=='enumeration.hasMoreElements':
            values, index = self.refs[args[0]]
            return index<len(values)
        if name=='enumeration.nextElement':
            state = self.refs[args[0]]
            entry = state[0][state[1]]
            state[1] += 1
            return entry
        if name=='cast.ZipEntry': return args[0]
        if name=='zipEntry.getName': return args[0].name
        if name=='zipEntry.isDirectory': return args[0].directory
        if name=='zip.getInputStream': return self.ref('input', [args[1].data,0])
        if name=='fileOutput.new':
            self.files[args[0]] = b''
            return self.ref('output',args[0])
        if name in ('bufferedOutput.new','bufferedInput.new'): return args[0]
        if name=='fileInput.new': return args[0]
        if name=='zipInput.new': return self.ref('zip-stream',[self.archives[args[0]],0,None])
        if name=='zipInput.getNextEntry':
            state = self.refs[args[0]]
            if state[1]>=len(state[0]): return None
            entry = state[0][state[1]]
            state[1] += 1
            state[2] = [entry.data,0]
            return entry
        if name=='input.read':
            state = self.refs[args[0]]
            if args[0][0]=='zip-stream': state = state[2]
            data = state[0][state[1]:state[1]+args[2]]
            state[1] += len(data)
            return ReadOnce(len(data),data) if data else ReadOnce(-1,b'')
        if name=='bufferedOutput.write':
            self.files[self.refs[args[0]]] += args[1]
            return None
        if name in ('input.close','bufferedOutput.flush','bufferedOutput.close','zipInput.closeEntry'):
            return None
        if name=='certificateFactory.getInstance': return 'factory'
        if name=='certificateFactory.generateCertificate':
            return self.refs[args[1]][0]  # synthetic provider observation, not DER parsing
        if name in ('cast.X509Certificate','certificate.getEncoded'): return args[0]
        if name=='messageDigest.getInstance': return self.ref('digest',b'')
        if name=='messageDigest.update':
            self.refs[args[0]] += args[1]
            return None
        if name=='messageDigest.digest': return hashlib.sha256(self.refs[args[0]]).digest()
        raise AssertionError(name)

    def run(self, gen): return drive(gen,self.reply)
    def metadata(self): return self.run(prepare_metadata_steps(self.source,self.destination))
    def libraries(self): return self.run(library_entries_steps(self.source,self.destination))
    def fingerprint(self): return self.run(check_fingerprint_steps('context'))
    def check(self, *, os14=True): return self.run(check_zip_steps('agent',os14=os14))


class PackageCopyTests(unittest.TestCase):
    def test_primary_metadata_selects_whole_path_and_renames_sf(self):
        obs = PackageObservations()
        obs.archives[obs.source] += [Entry('classes.dex.backup',b'backup'),Entry('ignore',b'no')]
        self.assertTrue(obs.metadata())
        self.assertEqual(obs.files[obs.destination+'/META-INF/CERT.SF'],b'sf')
        self.assertEqual(obs.files[obs.destination+'/classes.dex.backup'],b'backup')
        self.assertNotIn(obs.destination+'/ignore',obs.files)
        self.assertFalse(obs.calls('fileInput.new'))
        self.assertEqual(obs.calls('enumeration.hasMoreElements')[:2], [(('enumeration',1),)]*2)

    def test_empty_inputs_return_true_without_io(self):
        for source,destination in ((None,'x'),('','x'),('x',None),('x','')):
            obs = PackageObservations()
            self.assertTrue(obs.run(prepare_metadata_steps(source,destination)))
            self.assertEqual(obs.effects,[])

    def test_library_null_destination_reads_separator_before_null_receiver_fault(self):
        obs = PackageObservations()
        self.assertFalse(obs.run(library_entries_steps(obs.source,None)))
        self.assertEqual(obs.effects[0].args,('file.separator',))
        self.assertEqual(obs.effects[1].kind,'java_runtime_fault')
        self.assertEqual(obs.calls('file.new'),[])

    def test_destination_append_reads_separator_again_only_when_needed(self):
        for suffix,expected in (('',2),('/',1)):
            obs = PackageObservations()
            obs.destination += suffix
            self.assertTrue(obs.libraries())
            self.assertEqual(len(obs.calls('file.separator')),expected)

    def test_early_false_does_not_enter_stream_fallback(self):
        for override in ({('file.exists',1):False},{('zip.size',1):0},
                         {('zip.entries',1):None},{('enumeration.hasMoreElements',1):False}):
            obs = PackageObservations()
            obs.overrides = override
            self.assertFalse(obs.metadata())
            self.assertFalse(obs.calls('fileInput.new'))

    def test_primary_exception_fallback_writes_original_names_but_stays_false(self):
        obs = PackageObservations()
        obs.overrides[('zip.new',1)] = fault()
        self.assertFalse(obs.metadata())
        self.assertEqual(obs.files[obs.destination+'/META-INF/SIGNER.SF'],b'sf')
        self.assertNotIn(obs.destination+'/META-INF/CERT.SF',obs.files)
        self.assertEqual(len(obs.calls('zipInput.closeEntry')),3)
        self.assertEqual(len(obs.calls('input.close')),1)
        self.assertEqual(obs.errors['UnZip'],'')  # primary outer catch only logs

    def test_primary_entry_failure_is_sticky_and_partial_files_are_not_rolled_back(self):
        obs = PackageObservations()
        obs.overrides[('input.read',2)] = fault(message='read interrupted')
        self.assertFalse(obs.metadata())
        self.assertEqual(obs.files[obs.destination+'/classes.dex'],b'dex'*800)
        self.assertEqual(obs.files[obs.destination+'/META-INF/CERT.SF'],b'sf')
        self.assertEqual(obs.files[obs.destination+'/META-INF/SIGNER.SF'],b'sf')
        self.assertEqual(obs.errors['UnZip'],'read interrupted')
        self.assertEqual(len(obs.calls('fileInput.new')),1)

    def test_zero_read_writes_zero_and_continues_to_observed_eof(self):
        obs = PackageObservations()
        obs.archives[obs.source] = [Entry('classes.dex',b'abc')]
        obs.overrides[('input.read',1)] = ReadOnce(0,b'')
        self.assertTrue(obs.metadata())
        self.assertEqual([args[1:] for args in obs.calls('bufferedOutput.write')],[(b'',0,0),(b'abc',0,3)])
        self.assertEqual(len(obs.calls('input.read')),3)

    def test_missing_read_is_analysis_limit_without_invented_cleanup_or_fallback(self):
        for value in (None,ReadOnce(3,b'xx'),ReadOnce(-2,b''),ReadOnce(True,b'x')):
            obs = PackageObservations()
            obs.overrides[('input.read',1)] = value
            with self.assertRaises(AnalysisLimit): obs.metadata()
            self.assertEqual(obs.calls('input.close'),[])
            self.assertEqual(obs.calls('bufferedOutput.close'),[])
            self.assertEqual(obs.calls('fileInput.new'),[])

    def test_primary_metadata_swallows_only_input_close_io_exception(self):
        obs = PackageObservations()
        obs.overrides[('input.close',1)] = fault('FileNotFoundException')
        obs.overrides[('input.close',1)].bases = ('IOException',)
        self.assertTrue(obs.metadata())
        self.assertEqual(obs.calls('fileInput.new'),[])
        other = PackageObservations()
        other.overrides[('input.close',1)] = fault('RuntimeException')
        self.assertFalse(other.metadata())
        self.assertEqual(len(other.calls('fileInput.new')),1)

    def test_libraries_do_not_swallow_input_close_io_exception(self):
        obs = PackageObservations()
        obs.overrides[('input.close',1)] = fault()
        self.assertFalse(obs.libraries())
        self.assertEqual(obs.calls('bufferedOutput.flush'),[])
        self.assertEqual(obs.errors['UnZip'],'synthetic IO')

    def test_library_open_failure_has_no_per_entry_cleanup_metadata_does(self):
        library = PackageObservations()
        library.overrides[('zip.getInputStream',1)] = fault()
        self.assertFalse(library.libraries())
        self.assertFalse(library.calls('bufferedOutput.close'))
        metadata = PackageObservations()
        metadata.overrides[('zip.getInputStream',1)] = fault()
        self.assertFalse(metadata.metadata())
        self.assertEqual(len(metadata.calls('bufferedOutput.close')),6)

    def test_stream_read_failure_skips_close_entry_and_continues(self):
        obs = PackageObservations()
        obs.overrides = {('zip.new',1):fault(),('input.read',1):fault()}
        self.assertFalse(obs.metadata())
        self.assertEqual(len(obs.calls('zipInput.closeEntry')),2)
        self.assertEqual(len(obs.calls('bufferedOutput.close')),3)
        self.assertEqual(obs.files[obs.destination+'/classes.dex'],b'')
        self.assertEqual(obs.files[obs.destination+'/META-INF/MANIFEST.MF'],b'manifest')

    def test_stream_close_entry_exception_keeps_written_bytes_and_continues(self):
        obs = PackageObservations()
        obs.overrides = {('zip.new',1):fault(),('zipInput.closeEntry',1):fault()}
        self.assertFalse(obs.metadata())
        self.assertEqual(obs.files[obs.destination+'/classes.dex'],b'dex'*800)
        self.assertEqual(len(obs.calls('zipInput.closeEntry')),3)
        self.assertEqual(len(obs.calls('bufferedOutput.close')),3)
        self.assertEqual(len(obs.calls('input.close')),1)

    def test_primary_nonempty_archive_without_selected_entries_returns_true(self):
        obs = PackageObservations()
        obs.archives[obs.source] = [Entry('unselected')]
        self.assertTrue(obs.metadata())
        self.assertEqual(obs.calls('fileOutput.new'),[])
        self.assertNotIn(obs.destination+'/classes.dex',obs.files)

    def test_link_fault_runs_known_finally_without_turning_into_java_failure(self):
        for method in ('metadata','libraries'):
            obs = PackageObservations()
            observed = LinkFault(message='synthetic link')
            obs.overrides[('input.read',1)] = observed
            with self.assertRaises(LinkFault) as caught: getattr(obs,method)()
            self.assertIs(caught.exception,observed)
            self.assertEqual(len(obs.calls('input.close')),1)
            self.assertEqual(len(obs.calls('bufferedOutput.close')),1)
            self.assertFalse(obs.calls('fileInput.new'))

    def test_error_setter_fault_still_closes_entry_then_outer_handler_receives_it(self):
        obs = PackageObservations()
        obs.overrides = {('input.read',1):fault(message='read'),
                         ('agent.setUnZipErrorMsg',1):fault(message='setter')}
        self.assertFalse(obs.libraries())
        self.assertEqual(len(obs.calls('bufferedOutput.close')),1)
        self.assertEqual(obs.errors['UnZip'],'setter')

    def test_fallback_constructor_failure_closes_only_constructed_zip_stream(self):
        for name in ('fileInput.new','bufferedInput.new','zipInput.new'):
            obs = PackageObservations()
            obs.overrides = {('zip.new',1):fault(),(name,1):fault()}
            self.assertFalse(obs.metadata())
            self.assertEqual(obs.calls('input.close'),[])

    def test_fallback_close_io_is_ignored_and_other_exception_reaches_outer_setter(self):
        for kind,expected in (('IOException',''),('RuntimeException','synthetic IO')):
            obs = PackageObservations()
            obs.overrides = {('zip.new',1):fault(),('input.close',1):fault(kind)}
            self.assertFalse(obs.metadata())
            self.assertEqual(obs.errors['UnZip'],expected)

    def test_directory_entries_and_null_metadata_entries_do_not_open_output(self):
        obs = PackageObservations()
        obs.archives[obs.source] = [None,Entry('classes.dex/',directory=True)]
        self.assertTrue(obs.metadata())
        self.assertEqual(obs.calls('fileOutput.new'),[])
        self.assertIn(obs.destination+'/classes.dex/',obs.directories)

    def test_library_abi_exception_uses_original_empty_string_branch(self):
        obs = PackageObservations()
        obs.archives[obs.source] = [Entry('lib/x86/libCodeGuard.so',b'x86')]
        self.assertTrue(obs.libraries())
        self.assertNotIn(obs.destination+'/lib/libCodeGuard.so',obs.files)
        obs.overrides[('build.CPU_ABI',2)] = fault()
        self.assertTrue(obs.libraries())
        self.assertEqual(obs.files[obs.destination+'/lib/libCodeGuard.so'],b'x86')

    def test_null_and_unobserved_abi_are_not_the_caught_exception_fallback(self):
        obs = PackageObservations()
        obs.abi = None
        self.assertFalse(obs.libraries())
        self.assertEqual(obs.calls('fileOutput.new'),[])
        unknown = PackageObservations()
        unknown.abi = object()
        with self.assertRaises(AnalysisLimit): unknown.libraries()
        self.assertEqual(unknown.calls('agent.setUnZipErrorMsg'),[])

    def test_library_whole_path_match_preserves_order_and_last_overwrite(self):
        obs = PackageObservations()
        obs.destination += '/arm64-v8a'
        obs.archives[obs.source] = [Entry('a/libCodeGuard.so',b'first'),Entry('b/libCodeGuard.so',b'last')]
        self.assertTrue(obs.libraries())
        self.assertEqual(obs.files[obs.destination+'/lib/libCodeGuard.so'],b'last')
        self.assertEqual(len(obs.calls('fileOutput.new')),2)

    def test_prepare_libraries_contains_apk_not_suffix_and_ignores_failures(self):
        obs = PackageObservations()
        obs.names = ['base.apk.extra','missing.apk','base.apk','base.apk']
        obs.archives['/installed/base.apk.extra'] = [Entry('lib/arm64-v8a/libCodeGuard.so',b'extra')]
        obs.overrides[('input.read',1)] = fault()
        self.assertIsNone(obs.run(prepare_libraries_steps('context',obs.destination)))
        self.assertEqual([args[0] for args in obs.calls('zip.new')],['/installed//'+name for name in obs.names])
        self.assertEqual(obs.files[obs.destination+'/lib/libCodeGuard.so'],b'guard')

    def test_library_prefix_empty_still_checks_directory_unlike_fingerprint(self):
        obs = PackageObservations()
        obs.source = 'base.apk'
        obs.run(prepare_libraries_steps('context',obs.destination))
        self.assertEqual(obs.calls('file.new'),[('',)])
        second = PackageObservations()
        second.source = 'base.apk'
        self.assertTrue(second.fingerprint())
        self.assertEqual(second.calls('file.new'),[])


class PackageCacheTests(unittest.TestCase):
    def cached(self):
        obs = PackageObservations()
        obs.files[obs.destination+'/classes.dex'] = b'existing'
        obs.preferences = {'apk_last':5,'app_version':'v1'}
        return obs

    def test_cache_hit_rechecks_exists_and_avoids_all_preparation(self):
        obs = self.cached()
        self.assertTrue(obs.check())
        self.assertEqual(len(obs.calls('file.exists')),2)
        self.assertEqual(len(obs.calls('agent.version')),2)
        self.assertEqual(obs.calls('zip.new'),[])
        self.assertEqual(obs.calls('preferences.edit'),[])
        self.assertEqual(obs.effects[-1].args,('monitor.exit','agent'))

    def test_null_context_exits_monitor_and_returns_false(self):
        obs = PackageObservations()
        obs.overrides[('agent.context',1)] = None
        self.assertFalse(obs.check())
        self.assertEqual([e.args[0] for e in obs.effects],['monitor.enter','agent.context','monitor.exit'])

    def test_debug_skips_second_exists_and_forces_preparation(self):
        obs = self.cached()
        obs.debug = True
        self.assertTrue(obs.check())
        # Remaining existence observations are directory preparation, not cache.
        dex = obs.destination+'/classes.dex'
        self.assertEqual(obs.calls('file.exists').count((dex,)),1)
        self.assertTrue(obs.calls('zip.new'))

    def test_cache_misses_when_source_newer_than_dex_or_version_differs(self):
        for key,value in (('dex',4),('version','v0'),('saved',4)):
            obs = self.cached()
            if key=='dex': obs.modified[obs.destination+'/classes.dex'] = value
            elif key=='version': obs.preferences['app_version'] = value
            else: obs.preferences['apk_last'] = value
            self.assertTrue(obs.check())
            self.assertTrue(obs.calls('preferences.edit'))

    def test_extraction_failure_can_return_true_after_removing_cache_keys(self):
        obs = PackageObservations()
        obs.preferences = {'apk_last':4,'app_version':'old'}
        obs.overrides[('zip.new',2)] = fault()  # library attempt precedes metadata
        self.assertTrue(obs.check())
        self.assertEqual(obs.preferences,{})
        self.assertEqual(obs.calls('editor.remove'),[('editor','apk_last'),('editor','app_version')])
        self.assertEqual(obs.files[obs.destination+'/classes.dex'],b'dex'*800)
        self.assertEqual(obs.calls('editor.putLong'),[])

    def test_successful_extraction_can_return_false_when_commit_false(self):
        obs = PackageObservations()
        obs.commit = False
        self.assertFalse(obs.check())
        self.assertEqual(obs.files[obs.destination+'/classes.dex'],b'dex'*800)
        self.assertEqual(obs.preferences,{'apk_last':5,'app_version':'v1'})

    def test_preparation_reacquires_context_and_uses_current_version_at_write(self):
        obs = PackageObservations()
        obs.overrides[('agent.version',2)] = 'v2'
        self.assertTrue(obs.check())
        self.assertEqual(len(obs.calls('agent.context')),6)
        self.assertEqual(len(obs.calls('context.getFilesDir')),3)
        self.assertEqual(obs.preferences['app_version'],'v2')

    def test_only_os14_inner_exception_is_false_both_release_monitor(self):
        for os14 in (True,False):
            obs = PackageObservations()
            observed = fault()
            obs.overrides[('preferences.edit',1)] = observed
            if os14: self.assertFalse(obs.check(os14=os14))
            else:
                with self.assertRaises(JavaFault) as caught: obs.check(os14=os14)
                self.assertIs(caught.exception,observed)
            self.assertEqual(obs.effects[-1].args,('monitor.exit','agent'))

    def test_precache_fault_propagates_even_for_os14(self):
        obs = self.cached()
        obs.preferences['app_version'] = None
        with self.assertRaises(JavaFault) as caught: obs.check()
        self.assertEqual(caught.exception.kind,'NullPointerException')
        self.assertEqual(obs.effects[-1].args,('monitor.exit','agent'))
        self.assertFalse(obs.calls('preferences.edit'))

    def test_unknown_boolean_does_not_become_false_or_invent_monitor_exit(self):
        obs = PackageObservations()
        obs.overrides[('log.DEBUG',1)] = None
        with self.assertRaises(AnalysisLimit): obs.check()
        self.assertEqual(obs.calls('monitor.exit'),[])


class PackageFingerprintTests(unittest.TestCase):
    def test_certificate_provider_order_and_no_wrap_padding(self):
        obs = PackageObservations()
        stream = obs.ref('input',[b'cert',0])
        result = obs.run(fingerprint_certificate_steps(stream))
        self.assertEqual(result,base64.b64encode(hashlib.sha256(b'cert').digest()).decode())
        self.assertEqual([e.args[0] for e in obs.effects],[
            'certificateFactory.getInstance','certificateFactory.generateCertificate',
            'cast.X509Certificate','messageDigest.getInstance','certificate.getEncoded',
            'messageDigest.update','messageDigest.digest'])
        self.assertTrue(result.endswith('='))

    def test_none_or_nonbytes_digest_is_not_invented_fingerprint(self):
        for value in (None,object()):
            obs = PackageObservations()
            obs.overrides[('messageDigest.digest',1)] = value
            stream = obs.ref('input',[b'cert',0])
            with self.assertRaises(JavaFault if value is None else AnalysisLimit):
                obs.run(fingerprint_certificate_steps(stream))

    def test_filter_uses_first_dot_case_insensitive_prefix_and_suffix(self):
        obs = PackageObservations()
        obs.archives[obs.source] = [Entry('meta-inf/one.rsa'),Entry('META-INF/a.b.RSA'),
                                    Entry('META-INF/x.EC'),Entry('OTHER/a.RSA')]
        self.assertTrue(obs.fingerprint())
        self.assertEqual(len(obs.calls('certificateFactory.generateCertificate')),1)
        self.assertEqual(len(obs.calls('zipEntry.getName')),10)
        self.assertEqual(obs.calls('input.close'),[])

    def test_filename_contains_and_suffix_both_required_without_is_directory(self):
        obs = PackageObservations()
        obs.names = ['base.apk.old','readme','base.apk']
        self.assertTrue(obs.fingerprint())
        self.assertEqual(obs.calls('zip.new'),[('/installed//base.apk',)])
        self.assertEqual(obs.calls('file.isDirectory'),[])

    def test_matching_certificates_across_archives_pass_mismatch_sets_second_value(self):
        for second,expected in ((b'certificate',True),(b'different',False)):
            obs = PackageObservations()
            obs.names += ['split.apk']
            obs.archives['/installed/split.apk'] = [Entry('META-INF/CERT.RSA',second)]
            self.assertEqual(obs.fingerprint(),expected)
            if not expected:
                self.assertEqual(obs.errors['FingerPrint'],base64.b64encode(hashlib.sha256(second).digest()).decode())

    def test_certificate_exception_sets_empty_baseline_not_archive_skip(self):
        obs = PackageObservations()
        obs.archives[obs.source] = [Entry('META-INF/A.RSA'),Entry('META-INF/B.RSA')]
        obs.overrides[('certificateFactory.getInstance',1)] = fault('CertificateException')
        self.assertFalse(obs.fingerprint())
        self.assertEqual(len(obs.calls('certificateFactory.getInstance')),2)
        both = PackageObservations()
        both.archives[both.source] = obs.archives[obs.source]
        both.overrides = {('certificateFactory.getInstance',1):fault(),('certificateFactory.getInstance',2):fault()}
        self.assertTrue(both.fingerprint())

    def test_stream_open_exception_skips_remaining_archive_without_empty_baseline(self):
        obs = PackageObservations()
        obs.archives[obs.source] = [Entry('META-INF/A.RSA'),Entry('META-INF/B.RSA')]
        obs.names += ['split.apk']
        obs.archives['/installed/split.apk'] = [Entry('META-INF/C.RSA')]
        obs.overrides[('zip.getInputStream',1)] = fault()
        self.assertTrue(obs.fingerprint())
        self.assertEqual(len(obs.calls('zip.getInputStream')),2)
        self.assertEqual(len(obs.calls('certificateFactory.getInstance')),1)

    def test_mismatch_setter_exception_is_archive_exception_and_preserves_baseline(self):
        obs = PackageObservations()
        obs.archives[obs.source] = [Entry('META-INF/A.RSA',b'a'),Entry('META-INF/B.RSA',b'b')]
        obs.names += ['split.apk']
        obs.archives['/installed/split.apk'] = [Entry('META-INF/C.RSA',b'a')]
        obs.overrides[('agent.setFingerPrintErrorMsg',1)] = fault()
        self.assertTrue(obs.fingerprint())
        self.assertEqual(len(obs.calls('certificateFactory.getInstance')),3)

    def test_empty_missing_or_unselected_archives_do_not_invent_cert_requirement(self):
        for names in (None,[],['missing.apk'],['readme']):
            obs = PackageObservations()
            obs.names = names
            self.assertTrue(obs.fingerprint())
            self.assertEqual(obs.calls('certificateFactory.getInstance'),[])

    def test_null_filename_is_outside_archive_catch(self):
        obs = PackageObservations()
        obs.names = [None]
        with self.assertRaises(JavaFault) as caught: obs.fingerprint()
        self.assertEqual(caught.exception.kind,'NullPointerException')

    def test_name_is_read_three_times_and_substring_uses_third_first_dot(self):
        obs = PackageObservations()
        obs.archives[obs.source] = [Entry('META-INF/A.RSA')]
        obs.overrides = {('zipEntry.getName',2):'xRSA',('zipEntry.getName',3):'.'}
        self.assertTrue(obs.fingerprint())
        self.assertEqual(len(obs.calls('certificateFactory.getInstance')),1)

    def test_bad_substring_and_empty_split_are_archive_exceptions(self):
        for name,overrides in (('/',{}),('META-INF/A.RSA',{
                ('zipEntry.getName',2):'x',('zipEntry.getName',3):'long.'})):
            obs = PackageObservations()
            obs.archives[obs.source] = [Entry(name)]
            obs.overrides = overrides
            self.assertTrue(obs.fingerprint())
            self.assertTrue(any(e.kind=='java_runtime_fault' for e in obs.effects))
            self.assertEqual(obs.calls('certificateFactory.getInstance'),[])

    def test_nonascii_case_comparison_requires_explicit_java_result(self):
        obs = PackageObservations()
        obs.archives[obs.source] = [Entry('META-İNF/A.RSA')]
        obs.overrides[('string.equalsIgnoreCase',1)] = True
        self.assertTrue(obs.fingerprint())
        self.assertEqual(len(obs.calls('certificateFactory.getInstance')),1)
        obs.overrides[('string.equalsIgnoreCase',2)] = None
        with self.assertRaises(AnalysisLimit): obs.fingerprint()


class PackageProjectionTests(unittest.TestCase):
    def package_exchange(self, package):
        transcript = Transcript([(200,{'CODE_CHALLENGE':'c::r'}),
                                 (300,{'CODE_TOKEN':'SYNTHETIC-TOKEN'})])
        gen = generate_token_steps(transcript.main,transcript.runtime,transcript.agent,
            server_url='https://synthetic.invalid/',timeout=1000,root_check=True,
            rooting_info=False,encrypted_token=False)
        def reply(e):
            return package.reply(e) if e.kind in ('package_java','java_runtime_fault') else transcript.reply(e)
        self.assertEqual(drive(project_package_steps(gen),reply),'SYNTHETIC-TOKEN')
        return transcript

    def test_failed_extraction_with_commit_true_does_not_invent_zip_error(self):
        package = PackageObservations()
        package.overrides[('zip.new',2)] = fault()
        transcript = self.package_exchange(package)
        self.assertEqual(package.preferences,{})
        self.assertNotIn('format_local_error',transcript.kinds())
        self.assertEqual([x[0] for x in transcript.requests],[200,300])

    def test_false_commit_then_fingerprint_mismatch_preserves_original_error_order(self):
        package = PackageObservations()
        package.commit = False
        package.archives[package.source].append(Entry('META-INF/SECOND.RSA',b'other'))
        transcript = self.package_exchange(package)
        formats = [e.args[1] for e in transcript.effects if e.kind=='format_local_error']
        self.assertEqual(formats,['unZip error : ',
            'FingerPrint error('+package.errors['FingerPrint']+')'])
        self.assertEqual([x[0] for x in transcript.requests],[200,300])

    def test_packages_and_both_native_responses_compose_into_same_cmd300(self):
        transcript = Transcript([(200,{'CODE_CHALLENGE':'TQ==::'+rule()}),
                                 (300,{'CODE_TOKEN':'SYNTHETIC-TOKEN'})])
        transcript.main.pid = '123'
        first, second, package = NativeObservations(), NonceObservations(), PackageObservations()
        second.files = {}  # receive synthetic preparation output, not ready-made files
        stage = 'first'
        def reply(e):
            nonlocal stage
            if e.kind=='package_java':
                stage = 'second'
                result = package.reply(e)
                second.files = {key.encode():value for key,value in package.files.items()}
                return result
            if e.kind.startswith('native_'): return (first if stage=='first' else second).reply(e)
            return transcript.reply(e)
        gen = generate_token_steps(transcript.main,transcript.runtime,transcript.agent,
            server_url='https://synthetic.invalid/',timeout=1000,root_check=True,
            rooting_info=False,encrypted_token=False)
        gen = project_package_steps(project_native_nonce_steps(
            project_native_start_steps(gen,service='service'),service='service'))
        self.assertEqual(drive(gen,reply),'SYNTHETIC-TOKEN')
        self.assertEqual([x[0] for x in transcript.requests],[200,300])
        self.assertNotIn('check_zip_os14',transcript.kinds())
        self.assertNotIn('check_fingerprint',transcript.kinds())
        self.assertTrue(package.calls('certificateFactory.generateCertificate'))
        self.assertEqual(second.files[b'/data/pkg/files/classes.dex'],b'dex'*800)
        # Nonce's preferred library opens fail; prepared /files/lib paths are used.
        from giro.codeguard_inputs import NonceArtifacts, nonce_artifact_codes
        from giro.codeguard_nonce import cg_auth_code
        materials = NonceArtifacts(*(package.files[package.destination+suffix] for suffix in (
            '/lib/libCodeGuard.so','/lib/libImageDecoder.so','/classes.dex',
            '/META-INF/MANIFEST.MF','/META-INF/CERT.SF')),second.der)
        expected = cg_auth_code(fallback_nonce_key('TQ=='),nonce_artifact_codes(materials,'TQ==',is_mix=False,is_split=False))
        form = parse_qs(transcript.writes[-1][1].decode())
        self.assertEqual(form['CODE_RESPONSE2'],[expected])

    def test_projection_forwards_fault_to_parent_and_getter_is_not_placeholder(self):
        obs = PackageObservations()
        observed = fault()
        obs.overrides[('main.staticContext',1)] = observed
        def parent():
            try: yield Effect('check_fingerprint')
            except JavaFault as actual: return actual
        self.assertIs(obs.run(project_package_steps(parent())),observed)
        obs.errors['UnZip'] = 'synthetic persisted detail'
        def getter(): return (yield Effect('zip_error_message'))
        self.assertEqual(obs.run(project_package_steps(getter())),'synthetic persisted detail')

    def test_no_host_files_provider_or_network_are_opened(self):
        with patch('builtins.open',side_effect=AssertionError('host IO')), \
             patch('socket.socket',side_effect=AssertionError('network')):
            obs = PackageObservations()
            self.assertTrue(obs.check())
            self.assertTrue(obs.fingerprint())


if __name__=='__main__': unittest.main()
