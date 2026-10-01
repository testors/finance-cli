"""Synthetic Agent schedules/IO. No institution or original runtime execution."""
import base64
import unittest
from urllib.parse import parse_qs, urlsplit

from giro.codeguard_agent import AgentRuntime, agent_init_steps, project_agent_worker_steps
from giro.codeguard_app import giro_task_settings, giro_task_checks
from giro.codeguard_effects import LinkFault
from giro.codeguard_codec import RULE_KEY, RULE_IV, java_seed_decrypt
from giro.codeguard_native_start import project_native_start_steps
from giro.codeguard_native_nonce import project_native_nonce_steps
from giro.codeguard_oscheck import oscheck_future_steps
from giro.codeguard_package import project_package_steps
from giro.codeguard_response import os_status_digest
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_task import TaskTokenState, manager_message, post_execute
from giro.codeguard_worker import worker_steps
from cg_exchange_fixture import drive, fault
from test_codeguard_main import MainObservations
from test_codeguard_package import PackageObservations
from test_codeguard_native_start import NativeObservations, rule
from test_codeguard_native_nonce import NonceObservations
from test_codeguard_oscheck import OSObservations


class AgentObservations(MainObservations):
    def __init__(self, documents=()):
        super().__init__(documents)
        self.runtime = AgentRuntime()
        self.process, self.agent = self.runtime.main, self.runtime.material
        self.jobs, self.notifications = [], []
        self.package = PackageObservations()

    def default(self, e):
        if e.kind == 'package_java':
            if e.args[0] == 'agent.context': return self.runtime.context
            if e.args[0] == 'agent.version': return self.runtime.call.version
            return self.package.reply(e)
        if e.kind in ('agent_app_info_log', 'agent_init_context_log', 'invalidate_engine_artifacts'):
            return None
        if e.kind == 'agent_thread_new': return ('thread', e.args[0].kind)
        if e.kind == 'agent_thread_start':
            self.jobs.append(e.args[1])
            return None
        if e.kind in ('update_send_empty_message', 'update_listener'):
            self.notifications.append((e.kind, e.args))
            return False  # send's false return does not block callback/field clearing
        return super().default(e)

    def init(self, **changes):
        options = dict(context='initial-context', app_info='APP', version='1',
            update_url='https://update.synthetic.invalid/', handler='handler', message_what=100, timeout=5000)
        options.update(changes)
        self.run(agent_init_steps(self.runtime, **options))

    def update(self): return self.run(next(j for j in self.jobs if j.kind == 'update').steps())
    def zip(self): return self.run(next(j for j in self.jobs if j.kind == 'zip').steps())

    def worker(self, *, context='token-context', etc_data=None):
        state = TaskTokenState(None, -1, '', None, '', None, None, 'https://token.synthetic.invalid/')
        result = self.run(project_agent_worker_steps(worker_steps(
            state, giro_task_settings(etc_data=etc_data), context=context), runtime=self.runtime))
        return result, state


class AgentCompositionTests(unittest.TestCase):
    def test_init_starts_two_jobs_without_running_or_joining_them(self):
        obs = AgentObservations()
        obs.init()
        self.assertEqual([j.kind for j in obs.jobs], ['zip', 'update'])
        self.assertEqual([j.phase for j in obs.jobs], ['created', 'created'])
        self.assertEqual(obs.runtime.call.status_log, '0,1')
        self.assertFalse(obs.runtime.update_status)
        self.assertIsNone(obs.runtime.main.instance)
        self.assertEqual(obs.runtime.updater.timeout, 10000)
        self.assertIsNone(obs.runtime.updater.url)
        self.assertEqual(obs.requests, [])
        self.assertEqual(obs.notifications, [])

    def test_update_uses_own_updater_and_shared_material_before_main_exists(self):
        obs = AgentObservations(((101, {'CERT':'Y2VydA==', 'ENGINE_VERSION':'new-engine'}),))
        obs.init()
        updater = obs.runtime.updater
        obs.update()
        self.assertIsNone(obs.runtime.main.instance)
        self.assertEqual(updater.timeout, 50000)
        self.assertEqual(obs.runtime.material.certificate_text, 'Y2VydA==')
        self.assertEqual(obs.runtime.material.engine_version, 'new-engine')
        self.assertEqual(updater.status, 3)
        self.assertIsNone(updater.data.key)
        self.assertEqual(updater.data.cookie, '')
        self.assertTrue(obs.runtime.main.status_log.startswith('E0,E11.1'))
        self.assertEqual(obs.notifications, [('update_send_empty_message', ('handler', 100))])
        self.assertIsNone(obs.runtime.handler)
        self.assertFalse(obs.runtime.update_status)
        self.assertEqual(obs.jobs[0].phase, 'created')  # callback is not ZIP completion

    def test_update_reads_late_context_app_url_but_keeps_captured_timeout(self):
        obs = AgentObservations(((101, {}),))
        obs.init()
        obs.runtime.context = 'late-context'
        obs.runtime.call.set_app_info('LATE', '2')
        obs.runtime.update_url = 'https://late.synthetic.invalid/'
        obs.runtime.set_max_timeout(900)
        obs.update()
        updater = obs.runtime.updater
        self.assertEqual(updater.context, 'late-context')
        self.assertEqual(updater.timeout, 50000)
        self.assertTrue(obs.requests[0][1].startswith('https://late.synthetic.invalid/'))
        self.assertEqual(parse_qs(urlsplit(obs.requests[0][1]).query)['CODE_APP_INFO'], ['LATE21'])
        self.assertEqual(obs.runtime.max_timeout, 9000)

    def test_false_update_result_still_notifies_without_inventing_success(self):
        obs = AgentObservations()
        obs.init()
        obs.overrides['http_open'] = fault('IOException')
        obs.update()
        self.assertEqual(obs.runtime.updater.status, 3)  # overwritten by source catch
        self.assertEqual(len(obs.notifications), 1)
        self.assertIsNone(obs.runtime.material.certificate_text)
        self.assertFalse(obs.runtime.update_status)
        self.assertEqual(obs.jobs[1].phase, 'returned')

    def test_null_late_context_returns_false_then_notifies_without_http(self):
        obs = AgentObservations()
        obs.init()
        obs.runtime.context = None
        obs.update()
        self.assertEqual(obs.requests, [])
        self.assertEqual(obs.runtime.updater.status, 0)
        self.assertEqual(len(obs.notifications), 1)

    def test_callback_failure_repeats_listener_but_not_cleared_handler(self):
        obs = AgentObservations(((101, {}),))
        obs.init()
        obs.runtime.listener = 'listener'
        calls = []
        def callback(e):
            calls.append(e.args)
            return fault() if len(calls) == 1 else None
        obs.overrides['update_listener'] = callback
        obs.update()
        self.assertEqual(calls, [('listener', 0), ('listener', 0)])
        self.assertEqual(len(obs.notifications), 1)
        self.assertIsNone(obs.runtime.handler)

    def test_second_init_during_http_replaces_updater_but_not_inflight_receiver(self):
        obs = AgentObservations(((101, {'CERT':'b2xk', 'ENGINE_VERSION':'old-job-result'}),))
        obs.init()
        old = obs.runtime.updater
        def open_request(e):
            obs.init(context='new-context', handler='new-handler', message_what=222, timeout=700)
            return obs.default(e)
        obs.overrides['http_open'] = open_request
        obs.update()
        self.assertIsNot(obs.runtime.updater, old)
        self.assertEqual(old.status, 3)
        self.assertEqual(old.context, 'initial-context')
        self.assertEqual(obs.runtime.updater.status, 0)
        self.assertEqual(obs.runtime.updater.context, 'new-context')
        self.assertEqual(obs.notifications, [('update_send_empty_message', ('new-handler', 222))])
        self.assertEqual(obs.runtime.material.engine_version, 'old-job-result')
        self.assertEqual(len(obs.jobs), 4)
        self.assertEqual(obs.runtime.call.status_log, '0,1,1')

    def test_pending_initial_update_does_not_prevent_main_own_certificate_fetch(self):
        obs = AgentObservations(((101, {'CERT':'bWFpbg==', 'ENGINE_VERSION':'main-version'}),
            (200, {'CODE_CHALLENGE':'c::r'}), (300, {'CODE_TOKEN':'synthetic-token'}),
            (101, {'CERT':'bGF0ZQ==', 'ENGINE_VERSION':'late-version'})))
        obs.preferences['CERT'] = ''
        obs.init()
        initial = obs.runtime.updater
        job = obs.jobs[1].steps()
        effect = next(job)
        while effect.kind != 'http_open':
            reply = obs.reply(effect)
            effect = job.throw(reply) if isinstance(reply, BaseException) else job.send(reply)
        # Initial CMD101 has reached an uncompleted open; its caller does not
        # join it before starting a token task with still-missing material.
        result, task = obs.worker()
        self.assertTrue(result)
        self.assertEqual(task.token, 'synthetic-token')
        self.assertEqual(obs.runtime.material.certificate_text, 'bWFpbg==')
        key = obs.runtime.material.key
        while True:
            reply = obs.reply(effect)
            try:
                effect = job.throw(reply) if isinstance(reply, BaseException) else job.send(reply)
            except StopIteration:
                break
        self.assertEqual([r[0] for r in obs.requests], [101, 200, 300, 101])
        self.assertEqual(obs.runtime.material.certificate_text, 'bGF0ZQ==')
        self.assertEqual(obs.runtime.material.engine_version, 'late-version')
        self.assertEqual(obs.runtime.material.key, key)
        self.assertIsNone(initial.data.key)
        self.assertEqual(initial.context, 'initial-context')
        self.assertEqual(obs.runtime.main.instance.updater.context, 'token-context')

    def test_missing_update_updater_is_created_with_current_context(self):
        obs = AgentObservations(((101, {}),))
        obs.init()
        obs.runtime.updater = None
        obs.runtime.context = 'current-context'
        obs.update()
        self.assertEqual(obs.runtime.updater.context, 'current-context')
        self.assertEqual(obs.runtime.updater.timeout, 50000)

    def test_link_failure_and_unresolved_io_do_not_become_update_callbacks(self):
        for failure, phase in ((LinkFault(), 'threw'), (AnalysisLimit('unobserved IO'), 'unresolved')):
            obs = AgentObservations()
            obs.init()
            obs.overrides['http_open'] = failure
            with self.assertRaises(type(failure)): obs.update()
            self.assertEqual(obs.notifications, [])
            self.assertEqual(obs.jobs[1].phase, phase)

    def test_zip_job_expands_package_preparation_and_runs_once(self):
        obs = AgentObservations()
        obs.init()
        obs.zip()
        self.assertEqual(obs.jobs[0].phase, 'returned')
        self.assertTrue(any(e.kind == 'package_java' for e in obs.effects))
        self.assertTrue(obs.package.calls('zip.new'))
        self.assertNotIn('invalidate_engine_artifacts', obs.kinds())
        with self.assertRaises(AnalysisLimit): obs.zip()

    def test_zip_cleanup_exception_runs_catch_cleanup_with_new_context(self):
        obs = AgentObservations()
        obs.init()
        obs.package.commit = False
        contexts = []
        def invalidate(e):
            contexts.append(e.args[0])
            obs.runtime.context = 'later-context'
            return fault() if len(contexts) == 1 else None
        obs.overrides['invalidate_engine_artifacts'] = invalidate
        obs.zip()
        self.assertEqual(contexts, ['initial-context', 'later-context'])
        self.assertEqual(obs.jobs[0].phase, 'returned')

    def test_zip_unresolved_observation_does_not_trigger_destructive_fallback(self):
        obs = AgentObservations()
        obs.init()
        obs.overrides['package_java'] = AnalysisLimit('unobserved package')
        with self.assertRaises(AnalysisLimit): obs.zip()
        self.assertNotIn('invalidate_engine_artifacts', obs.kinds())
        self.assertEqual(obs.jobs[0].phase, 'unresolved')

    def test_worker_connects_initial_update_main_and_two_token_exchanges(self):
        obs = AgentObservations(((101, {'CERT':'Y2VydA==', 'ENGINE_VERSION':'engine'}),
            (200, {'CODE_CHALLENGE':'first::rule'}), (300, {'CODE_TOKEN':'synthetic-first'}),
            (200, {'CODE_CHALLENGE':'second::rule'}), (300, {'CODE_TOKEN':'synthetic-second'})))
        obs.init()
        obs.update()
        initial_updater = obs.runtime.updater
        obs.runtime.set_max_timeout(10000)
        result, first = obs.worker(etc_data='synthetic-extra')
        self.assertTrue(result)
        self.assertEqual((first.status_code, first.token), (0, 'synthetic-first'))
        main = obs.runtime.main.instance
        first_key = main.updater.data.key
        challenge = main.response.challenge
        self.assertIsNot(main.updater, initial_updater)
        self.assertIsNone(initial_updater.data.key)
        self.assertEqual(initial_updater.timeout, 50000)
        self.assertEqual(main.updater.timeout, 100000)
        self.assertTrue(obs.runtime.main.status_log.startswith('E0,E11.1'))
        result, second = obs.worker(context='second-context', etc_data='')
        self.assertEqual(second.token, 'synthetic-second')
        self.assertIs(main.response.challenge, challenge)
        self.assertNotEqual(main.updater.data.key, first_key)
        self.assertEqual(main.updater.data.key, obs.runtime.material.key)
        self.assertEqual(main.updater.context, 'token-context')
        self.assertEqual(obs.runtime.context, 'second-context')
        self.assertEqual(obs.runtime.call.etc_data, 'synthetic-extra')
        self.assertEqual([r[0] for r in obs.requests], [101, 200, 300, 200, 300])
        self.assertEqual(obs.kinds().count('main_load_library'), 2)
        self.assertEqual(obs.jobs[0].phase, 'created')
        messages, delivered = [], []
        adapters = dict(check_flags=giro_task_checks(), observed_check=lambda _: self.fail('unexpected check'),
                        format_error=lambda *a: self.fail('unexpected error formatter'))
        post_execute(second, result, send_message=messages.append, callback_listener=None, **adapters)
        delivered.append(manager_message(second, messages[0], **adapters))
        self.assertEqual(delivered, ['synthetic-second'])
        self.assertIsNone(second.token)

    def test_timeout_is_read_after_main_configuration_not_at_worker_entry(self):
        obs = AgentObservations(((200, {'CODE_CHALLENGE':'c::r'}), (300, {'CODE_TOKEN':'synthetic'})))
        obs.init()
        obs.runtime.set_max_timeout(100)
        def read_pid(_):
            obs.runtime.set_max_timeout(999)
            return 42
        obs.overrides['process_pid'] = read_pid
        obs.worker()
        self.assertEqual(obs.runtime.main.instance.updater.timeout, 9990)

    def test_initial_jobs_worker_os_package_and_both_native_calculations_compose(self):
        obs = AgentObservations(((101, {'CERT':'Y2VydA==', 'ENGINE_VERSION':'engine'}),
            (200, {'CODE_CHALLENGE':'TQ==::'+rule()}), (300, {'CODE_TOKEN':'synthetic-token'})))
        obs.init()
        obs.update()
        obs.zip()
        first, second = NativeObservations(), NonceObservations()
        os = None
        stage = 'first'
        def reply(e):
            nonlocal os, stage
            if e.kind == 'oscheck_future':
                owner = obs.runtime.main.instance.response
                os = OSObservations(owner)
                os.context = obs.runtime.main.context
                _, root, rooting, _, _, timeout = e.args
                return drive(oscheck_future_steps(owner, root_check=root, rooting_info=rooting,
                    timeout=timeout, extended_state=os.extended, standard_state=os.standard), os.reply)
            if e.kind == 'package_java':
                stage = 'second'
                result = obs.reply(e)
                second.files = {path.encode():data for path,data in obs.package.files.items()}
                return result
            if e.kind.startswith('native_'):
                return (first if stage == 'first' else second).reply(e)
            return obs.reply(e)
        task = TaskTokenState(None, -1, '', None, '', None, None, 'https://token.synthetic.invalid/')
        obs.runtime.set_max_timeout(10000)
        gen = project_agent_worker_steps(worker_steps(task, giro_task_settings(etc_data=None),
            context='token-context'), runtime=obs.runtime)
        gen = project_package_steps(project_native_nonce_steps(
            project_native_start_steps(gen, service='service'), service='service'))
        self.assertTrue(drive(gen, reply))
        self.assertEqual(task.token, 'synthetic-token')
        self.assertEqual([r[0] for r in obs.requests], [101, 200, 300])
        self.assertEqual([j.phase for j in obs.jobs], ['returned', 'returned'])
        self.assertEqual(os.works[0].phase, 'returned')
        for coarse in ('oscheck_future', 'native_start', 'native_get_nonce', 'check_zip_os14', 'check_fingerprint'):
            self.assertNotIn(coarse, obs.kinds())
        form = parse_qs(obs.writes[-1][1].decode())
        plain = java_seed_decrypt(base64.b64decode(form['CODE_RESPONSE'][0]), RULE_KEY, RULE_IV).decode()
        self.assertIn('*' + os_status_digest('TQ==') + '##', plain)
        self.assertNotIn('SYNTHETIC-NATIVE-OBSERVATION', plain)
        self.assertNotEqual(form['CODE_RESPONSE2'], ['SYNTHETIC-NONCE-OBSERVATION'])

    def test_worker_java_failure_is_not_boolean_completion(self):
        obs = AgentObservations()
        obs.init()
        obs.runtime.call.pending_value = 'pending'
        obs.overrides['process_pid'] = fault()
        with self.assertRaises(type(fault())): obs.worker()
        self.assertEqual(obs.runtime.call.pending_value, 'pending')
        self.assertEqual(obs.requests, [])

    def test_null_init_context_fails_after_app_and_handler_but_before_jobs(self):
        obs = AgentObservations()
        with self.assertRaises(type(fault())): obs.init(context=None)
        self.assertEqual(obs.runtime.call.app_info, 'APP')
        self.assertEqual(obs.runtime.handler, 'handler')
        self.assertIsNone(obs.runtime.updater)
        self.assertEqual(obs.jobs, [])
        self.assertEqual(obs.runtime.call.status_log, '0')

    def test_failed_second_thread_start_leaves_first_job_and_partial_init(self):
        obs = AgentObservations()
        def start(e):
            return fault() if e.args[1].kind == 'update' else obs.default(e)
        obs.overrides['agent_thread_start'] = start
        with self.assertRaises(type(fault())): obs.init()
        self.assertEqual([j.kind for j in obs.jobs], ['zip'])
        self.assertIsNotNone(obs.runtime.updater)
        self.assertEqual(obs.runtime.call.status_log, '0,1')

    def test_timeout_multiplication_uses_signed_java_int(self):
        runtime = AgentRuntime()
        runtime.set_max_timeout(2**30)
        self.assertEqual(runtime.max_timeout, -2**31)
        for invalid in (None, True, 2**31):
            with self.assertRaises(AnalysisLimit): runtime.set_max_timeout(invalid)


if __name__ == '__main__':
    unittest.main()
