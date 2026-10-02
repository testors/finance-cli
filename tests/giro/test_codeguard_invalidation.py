"""Synthetic cleanup effects and memory-only file operations."""
import unittest

from giro.codeguard_effects import Effect, JavaFault, LinkFault
from giro.codeguard_package import invalidate_engine_steps, project_package_steps
from giro.codeguard_lifecycle import GuardProcess
from giro.codeguard_rule import AnalysisLimit
from cg_exchange_fixture import drive
from test_codeguard_runtime import memory_platform


class CleanupObservations:
    def __init__(self):
        self.listings = {'/files':[None, '/files/one.dex.backup', '/files/keep.MF', '/files/meta', '/files/lib'],
            '/files/meta':[None, '/files/meta/manifest.MF', '/files/meta/signer.SF', '/files/meta/keep.dex',
                           '/files/meta/deep'],
            '/files/lib':['/files/lib/libCodeGuard.so.old', '/files/lib/libImageDecoder.so', '/files/lib/keep']}
        self.calls, self.overrides = [], {}

    def reply(self, effect):
        name, *args = effect.args
        self.calls.append((name, *args))
        key = (name, *args)
        if key in self.overrides: return self.overrides[key]
        if name == 'context.getFilesDir': return '/files'
        if name == 'file.listFiles': return self.listings.get(args[0])
        if name == 'file.isDirectory': return args[0] in self.listings
        if name in ('file.getPath', 'file.getAbsolutePath'): return args[0]
        if name == 'file.delete': return True
        raise AssertionError(name)

    def deleted(self): return [row[1] for row in self.calls if row[0] == 'file.delete']


class CleanupTests(unittest.TestCase):
    def test_exact_two_levels_full_path_substrings_and_nullable_entries(self):
        obs = CleanupObservations()
        drive(invalidate_engine_steps('context'), obs.reply)
        self.assertEqual(obs.deleted(), ['/files/one.dex.backup', '/files/meta/manifest.MF',
            '/files/meta/signer.SF', '/files/lib/libCodeGuard.so.old', '/files/lib/libImageDecoder.so'])
        self.assertNotIn(('file.listFiles', '/files/meta/deep'), obs.calls)
        self.assertNotIn(('file.delete', '/files/keep.MF'), obs.calls)
        self.assertNotIn(('file.delete', '/files/meta/keep.dex'), obs.calls)

    def test_full_path_match_includes_directory_component(self):
        obs = CleanupObservations()
        obs.listings = {'/files':['/files/some.MF'], '/files/some.MF':['/files/some.MF/ordinary']}
        drive(invalidate_engine_steps('context'), obs.reply)
        self.assertEqual(obs.deleted(), ['/files/some.MF/ordinary'])

    def test_null_root_listing_returns_and_null_child_listing_skips_only_that_child(self):
        obs = CleanupObservations()
        obs.listings['/files'] = None
        drive(invalidate_engine_steps('context'), obs.reply)
        self.assertEqual(obs.deleted(), [])
        obs = CleanupObservations()
        obs.listings['/files/meta'] = None
        drive(invalidate_engine_steps('context'), obs.reply)
        self.assertEqual(obs.deleted(), ['/files/one.dex.backup', '/files/lib/libCodeGuard.so.old',
                                        '/files/lib/libImageDecoder.so'])

    def test_false_delete_is_not_failure_and_skips_only_post_delete_path_read(self):
        obs = CleanupObservations()
        obs.overrides[('file.delete', '/files/one.dex.backup')] = False
        drive(invalidate_engine_steps('context'), obs.reply)
        self.assertEqual(obs.calls.count(('file.getAbsolutePath', '/files/one.dex.backup')), 1)
        self.assertEqual(len(obs.deleted()), 5)

    def test_java_exception_ends_entire_scan_without_undo_or_retry(self):
        obs = CleanupObservations()
        obs.overrides[('file.delete', '/files/meta/manifest.MF')] = JavaFault(
            'SecurityException', message='synthetic', java_string='synthetic')
        drive(invalidate_engine_steps('context'), obs.reply)
        self.assertEqual(obs.deleted(), ['/files/one.dex.backup', '/files/meta/manifest.MF'])
        self.assertNotIn(('file.getAbsolutePath', '/files/meta/manifest.MF'), obs.calls)

    def test_error_and_missing_provider_are_not_swallowed_as_java_exceptions(self):
        for fault in (LinkFault(message='synthetic'), AnalysisLimit('unknown provider')):
            obs = CleanupObservations()
            def reply(effect):
                if effect.args[0] == 'file.delete': raise fault
                return obs.reply(effect)
            with self.subTest(kind=type(fault).__name__), self.assertRaises(type(fault)):
                drive(invalidate_engine_steps('context'), reply)

    def test_projection_expands_cleanup_without_creating_host_io(self):
        obs = CleanupObservations()
        def steps():
            return (yield Effect('invalidate_engine_artifacts', ('context',)))
        self.assertIsNone(drive(project_package_steps(steps()), obs.reply))
        self.assertEqual(len(obs.deleted()), 5)

    def test_memory_delete_retains_nonempty_directories_and_other_namespaces(self):
        platform = memory_platform(b'synthetic signer')
        platform.bind(GuardProcess())
        platform.directories.update({'/cache':['gone.dex', 'keep'], '/cache/keep':['inside']})
        platform.environment.files.update({b'/cache/gone.dex':b'one', b'/cache/keep/inside':b'two',
                                           b'/external/untouched':b'three'})
        platform.modified['/cache/gone.dex'] = 1
        self.assertFalse(platform._package('file.delete', '/cache/keep'))
        self.assertTrue(platform._package('file.delete', '/cache/gone.dex'))
        self.assertFalse(platform._package('file.delete', '/cache/gone.dex'))
        self.assertEqual(platform._package('file.listFiles', '/cache'), ['/cache/keep'])
        self.assertNotIn('/cache/gone.dex', platform.modified)
        self.assertEqual(platform.environment.files[b'/external/untouched'], b'three')
        self.assertTrue(platform._package('file.delete', '/cache/keep/inside'))
        self.assertTrue(platform._package('file.delete', '/cache/keep'))
        self.assertIsNone(platform._package('file.listFiles', '/absent'))


if __name__ == '__main__': unittest.main()
