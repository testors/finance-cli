"""Synthetic constructor/loader/Agent observations; no native library execution."""
import unittest

from giro.codeguard_effects import Effect, LinkFault
from giro.codeguard_main import (MainServiceProcess, main_instance_steps,
                                 project_main_service_steps)
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_worker import AgentCallState, agent_call_steps
from cg_exchange_fixture import Transcript, drive, fault


BOOT_LOG = 'E0,E19.101,E19.10,E20.20,E19.11.1,E20.21'


class MainObservations(Transcript):
    def __init__(self, documents=()):
        super().__init__(documents)
        self.process = MainServiceProcess()
        self.call = AgentCallState('APP', '1', None, None, None,
                                   True, False, True, False, 'AGENT', 'pending')
        self.build = dict(MODEL='model#1', ID='build', RELEASE='release')

    def default(self, e):
        if e.kind == 'build_string_field': return self.build[e.args[0]]
        if e.kind in ('main_monitor_enter', 'main_monitor_exit', 'main_load_library',
                      'main_load_log', 'main_app_info_log', 'set_agent_context',
                      'build_exception_log'): return None
        if e.kind == 'main_link_to_string': return 'java.synthetic.UnsatisfiedLinkError: library'
        if e.kind == 'process_pid': return 123
        return super().default(e)

    def instance(self, context='context-one'):
        return self.run(main_instance_steps(self.process, context))

    def routed(self, generator):
        return self.run(project_main_service_steps(generator, process=self.process, agent=self.agent))

    def token(self, context='context-one'):
        return self.routed(agent_call_steps(self.call, context=context,
                          server_url='https://synthetic.invalid/', timeout=4321))


class MainServiceTests(unittest.TestCase):
    def test_constructor_defaults_and_only_two_load_calls(self):
        obs = MainObservations()
        instance = obs.instance()
        self.assertIs(obs.process.instance, instance)
        self.assertEqual(obs.process.status_log, BOOT_LOG)
        self.assertEqual(instance.response.build_string, 'model#1/build/release')
        self.assertIsNone(instance.response.challenge)
        self.assertIsNone(instance.response.etc_data)
        self.assertIsNone(instance.response.native_error_detail)
        self.assertFalse(instance.response.detail_enabled)
        self.assertFalse(instance.encrypted_token)
        self.assertEqual(instance.updater.context, 'context-one')
        self.assertEqual(instance.updater.timeout, 10000)
        self.assertEqual(instance.updater.data.cookie, '')
        self.assertIsNone(instance.updater.url)
        self.assertIsNone(instance.updater.data.key)
        self.assertIsNone(instance.updater.data.rcl)
        self.assertEqual([e.args for e in obs.effects if e.kind == 'main_load_library'],
                         [('CodeGuard',), ('ImageDecoder',)])
        self.assertEqual(obs.kinds()[:4], ['main_monitor_enter'] + ['build_string_field'] * 3)
        self.assertEqual(obs.kinds()[-1], 'main_monitor_exit')

    def test_context_is_published_after_constructor_and_reused_updater_stays_old(self):
        obs = MainObservations()
        contexts = []
        obs.overrides['main_load_library'] = lambda _: contexts.append(obs.process.context)
        first = obs.instance()
        first.updater.data.key = b'synthetic-key'
        obs.build['MODEL'] = 'later-model'
        second = obs.instance('context-two')
        self.assertIs(first, second)
        self.assertEqual(contexts, [None, None])
        self.assertEqual(obs.process.context, 'context-two')
        self.assertEqual(second.updater.context, 'context-one')
        self.assertEqual(second.updater.data.key, b'synthetic-key')
        self.assertEqual(second.response.build_string, 'model#1/build/release')
        self.assertEqual(obs.kinds().count('build_string_field'), 3)
        self.assertEqual(obs.process.status_log, BOOT_LOG)

    def test_load_failure_continues_to_second_library_and_publishes_instance(self):
        for failure, suffix in ((fault('SecurityException'), ',E21.11'),
                                (LinkFault(message='message differs'),
                                 ',E21:java.synthetic.UnsatisfiedLinkError: library')):
            obs = MainObservations()
            obs.overrides['main_load_library'] = lambda e: failure if e.args[0] == 'CodeGuard' else None
            self.assertIsNotNone(obs.instance())
            self.assertEqual(obs.process.status_log,
                             'E0,E19.101,E19.10' + suffix + ',E19.11.1,E20.21')
            self.assertEqual(obs.kinds().count('main_load_library'), 2)
            obs.instance()
            self.assertEqual(obs.kinds().count('main_load_library'), 2)

    def test_success_log_failure_keeps_success_marker_and_adds_failure_marker(self):
        obs = MainObservations()
        obs.overrides['main_load_log'] = lambda e: fault() if e.args == ('success', 'CodeGuard') else None
        obs.instance()
        self.assertEqual(obs.process.status_log,
                         'E0,E19.101,E19.10,E20.20,E21.11,E19.11.1,E20.21')

    def test_first_log_only_stage_has_its_own_link_catch(self):
        obs = MainObservations()
        obs.overrides['main_load_log'] = lambda e: LinkFault() if e.args == ('success', None) else None
        obs.instance()
        self.assertEqual(obs.process.status_log,
            'E0,E19.101,E19.102:java.synthetic.UnsatisfiedLinkError: library,E19.10,E20.20,E19.11.1,E20.21')

    def test_failed_constructor_retains_static_log_but_publishes_neither_context_nor_instance(self):
        obs = MainObservations()
        obs.overrides['main_load_library'] = fault()
        obs.overrides['main_load_log'] = lambda e: fault('SecurityException') if e.args[0] == 'failure' else None
        with self.assertRaises(type(fault())): obs.instance()
        self.assertIsNone(obs.process.instance)
        self.assertIsNone(obs.process.context)
        self.assertEqual(obs.process.status_log, 'E0,E19.101,E19.10,E21.11')
        self.assertEqual(obs.kinds()[-1], 'main_monitor_exit')
        obs.overrides.clear()
        obs.instance('retry-context')  # explicit second call, not an automatic retry
        self.assertEqual(obs.process.status_log, 'E0,E19.101,E19.10,E21.11' + BOOT_LOG[2:])
        self.assertEqual(obs.process.instance.updater.context, 'retry-context')
        self.assertEqual(obs.kinds().count('build_string_field'), 6)

    def test_unresolved_loader_does_not_become_java_failure_or_cleanup(self):
        obs = MainObservations()
        obs.overrides['main_load_library'] = AnalysisLimit('unobserved load')
        with self.assertRaises(AnalysisLimit): obs.instance()
        self.assertEqual(obs.process.status_log, 'E0,E19.101,E19.10')
        self.assertIsNone(obs.process.instance)
        self.assertNotIn('main_monitor_exit', obs.kinds())

    def test_missing_link_tostring_is_not_replaced_by_exception_message(self):
        obs = MainObservations()
        obs.overrides['main_load_library'] = LinkFault(message='must-not-substitute')
        obs.overrides['main_link_to_string'] = None
        with self.assertRaises(AnalysisLimit): obs.instance()
        self.assertEqual(obs.process.status_log, 'E0,E19.101,E19.10')
        self.assertNotIn('must-not-substitute', repr(obs.process))

    def test_build_exception_fallback_is_source_behavior_not_missing_input_default(self):
        obs = MainObservations()
        obs.overrides['build_string_field'] = fault()
        self.assertEqual(obs.instance().response.build_string, '')
        self.assertEqual(obs.kinds().count('build_exception_log'), 1)
        self.assertEqual(obs.process.status_log, BOOT_LOG)

    def test_agent_call_reaches_cmd300_without_preconstructed_main_and_keeps_state(self):
        obs = MainObservations(((200, {'CODE_CHALLENGE': 'first::rule'}),
                                (300, {'CODE_TOKEN': 'synthetic-first'}),
                                (200, {'CODE_CHALLENGE': 'second::rule'}),
                                (300, {'CODE_TOKEN': 'synthetic-second'})))
        obs.call.etc_data = 'synthetic-extra'
        self.assertEqual(obs.token(), 'synthetic-first')
        instance = obs.process.instance
        challenge = instance.response.challenge
        etc_data = instance.response.etc_data
        self.assertEqual(instance.response.pid, '123')
        self.assertIsNone(obs.call.pending_value)
        obs.call.etc_data = None
        self.assertEqual(obs.token('context-two'), 'synthetic-second')
        self.assertIs(instance.response.challenge, challenge)
        self.assertEqual(challenge.challenge, 'second')
        self.assertEqual(instance.response.etc_data, etc_data)
        self.assertEqual(instance.updater.context, 'context-one')
        self.assertEqual(instance.updater.timeout, 4321)
        self.assertEqual(obs.process.context, 'context-two')
        self.assertEqual(obs.kinds().count('main_load_library'), 2)
        self.assertEqual([r[0] for r in obs.requests], [200, 300, 200, 300])
        self.assertEqual(obs.process.status_log.count(',E30,E30.1,E30.5,E32'), 2)

    def test_set_updater_only_constructs_when_missing(self):
        obs = MainObservations()
        first = obs.instance()
        old = first.updater
        def setters():
            yield Effect('main_set_updater', ('context-two',))
            yield Effect('main_set_server', ('synthetic-url',))
        obs.routed(setters())
        self.assertIs(first.updater, old)
        self.assertEqual(old.context, 'context-one')
        self.assertEqual(old.url, 'synthetic-url')
        first.updater = None
        obs.routed(setters())
        self.assertEqual(first.updater.context, 'context-two')
        self.assertIsNot(first.updater, old)

    def test_app_info_log_failure_leaves_challenge_and_pending_value_unassigned(self):
        obs = MainObservations()
        obs.overrides['main_app_info_log'] = fault()
        with self.assertRaises(type(fault())): obs.token()
        self.assertIsNone(obs.process.instance.response.challenge)
        self.assertEqual(obs.process.status_log, BOOT_LOG + ',E30')
        self.assertEqual(obs.call.pending_value, 'pending')
        self.assertEqual(obs.requests, [])

    def test_context_can_be_explicit_null_without_changing_old_updater(self):
        obs = MainObservations()
        instance = obs.instance()
        self.assertIs(obs.instance(None), instance)
        self.assertIsNone(obs.process.context)
        self.assertEqual(instance.updater.context, 'context-one')

    def test_calls_before_construction_remain_unresolved(self):
        obs = MainObservations()
        def setter(): yield Effect('main_set_updater', ('context',))
        with self.assertRaises(AnalysisLimit): obs.routed(setter())


if __name__ == '__main__':
    unittest.main()
