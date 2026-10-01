"""Synthetic dispatch schedules; no real workers, institution IO or device."""
import base64
import hashlib
import unittest
from urllib.parse import parse_qs

from giro.codeguard_effects import LinkFault
from giro.codeguard_lifecycle import GuardProcess, ManagerConfig
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_certificate_values import NativeByteArrayValue
from giro.codeguard_fingerprint_values import KnownCertificateStream
from giro.codeguard_oscheck import oscheck_future_steps
from giro.codeguard_package import project_package_steps
from giro.codeguard_string_values import project_native_value_steps
from giro.codeguard_codec import RULE_KEY, RULE_IV, java_seed_decrypt
from giro.codeguard_response import os_status_digest
from cg_exchange_fixture import drive, fault
from test_codeguard_agent import AgentObservations
from test_codeguard_certificate_values import synthetic_certificates
from test_codeguard_fingerprint_values import bag
from test_codeguard_native_nonce import NonceObservations
from test_codeguard_native_start import NativeObservations, rule
from test_codeguard_oscheck import OSObservations
from test_codeguard_package import Entry
from test_codeguard_string_values import path_values


class LifecycleObservations(AgentObservations):
    def __init__(self, documents=()):
        super().__init__(documents)
        self.guard = GuardProcess(agent=self.runtime)
        self.manager = self.guard.manager_instance(ManagerConfig('init-context', 'APP', '1',
            'https://token.synthetic.invalid/', 'https://update.synthetic.invalid/'))
        self.works, self.messages, self.delivered, self.callbacks = [], [], [], []

    def default(self, e):
        if e.kind in ('task_constructor', 'task_monitor_enter', 'task_monitor_exit', 'task_log', 'manager_handler_new',
                      'manager_exception_trace', 'manager_exception_log', 'phone_security_log'):
            return None
        if e.kind == 'telephony_service': return 'synthetic-telephony'
        if e.kind == 'telephony_line1_number': return 'synthetic-phone'
        if e.kind == 'task_executor_execute':
            self.works.append(e.args[0])
            return None
        if e.kind == 'task_send_message':
            self.messages.append(e.args)
            return True
        if e.kind == 'manager_token_listener':
            self.delivered.append(e.args)
            return None
        if e.kind in ('manager_update_listener', 'task_listener'):
            self.callbacks.append(e.args)
            return None
        return super().default(e)

    def submit(self, listener='listener', context='task-context'):
        self.run(self.manager.get_token_steps(context=context, listener=listener))
        return self.manager.task

    def finish(self, task, result=True, cancelled=False):
        self.run(task.finish_steps(result, cancelled=cancelled))

    def deliver(self, index=0):
        handler, what, payload = self.messages[index]
        self.run(handler.message_steps(what, payload))


class LifecycleTests(unittest.TestCase):
    def test_first_builder_only_and_initialization_does_not_join_jobs(self):
        obs = LifecycleObservations()
        same = obs.guard.manager_instance(ManagerConfig('ignored'))
        self.assertIs(same, obs.manager)
        obs.run(obs.manager.init_steps())
        self.assertTrue(obs.guard.is_init)
        self.assertFalse(obs.guard.log_debug)
        self.assertEqual([j.phase for j in obs.jobs], ['created', 'created'])
        self.assertEqual(obs.requests, [])
        self.assertIsNone(obs.runtime.main.instance)
        self.assertEqual(obs.runtime.context, 'init-context')
        binding = obs.runtime.handler
        obs.manager.update_listener = 'new-listener'
        obs.run(binding.message_steps(999, 'ignored'))
        self.assertEqual(obs.callbacks, [('new-listener',)])

    def test_null_init_and_second_thread_failure_do_not_invent_initialized_state(self):
        obs = LifecycleObservations()
        obs.manager.config.context = None
        with self.assertRaises(type(fault())): obs.run(obs.manager.init_steps())
        self.assertFalse(obs.guard.is_init)
        self.assertEqual(obs.jobs, [])
        obs.manager.config.context = 'context'
        obs.overrides['agent_thread_start'] = lambda e: fault() if e.args[1].kind == 'update' else obs.default(e)
        with self.assertRaises(type(fault())): obs.run(obs.manager.init_steps())
        self.assertFalse(obs.guard.is_init)
        self.assertEqual([j.kind for j in obs.jobs], ['zip'])
        obs.guard.is_init = True
        with self.assertRaises(type(fault())): obs.run(obs.manager.init_steps())
        self.assertTrue(obs.guard.is_init)  # a later init failure never writes false

    def test_close_does_not_cancel_or_clear_agent_and_late_work_repopulates_task(self):
        obs = LifecycleObservations(((200, {'CODE_CHALLENGE':'c::r'}), (300, {'CODE_TOKEN':'synthetic'})))
        task = obs.submit()
        obs.runtime.call.etc_data = 'retained'
        obs.run(obs.manager.close_steps())
        self.assertIs(obs.manager.task, task)
        self.assertIsNone(obs.guard.task)
        self.assertEqual(obs.runtime.call.etc_data, 'retained')
        self.assertEqual(task.status, 'RUNNING')
        self.assertEqual(obs.works[0].phase, 'created')
        self.assertTrue(obs.run(obs.works[0].steps()))
        self.assertEqual(task.state.token, 'synthetic')
        self.assertEqual(task.status, 'RUNNING')
        obs.finish(task)
        obs.deliver()
        self.assertEqual(obs.delivered, [('listener', 'synthetic')])

    def test_init_and_two_requests_reuse_main_but_have_distinct_tasks(self):
        obs = LifecycleObservations(((101, {'CERT':'Y2VydA=='}),
            (200, {'CODE_CHALLENGE':'first::rule'}), (300, {'CODE_TOKEN':'first-token'}),
            (200, {'CODE_CHALLENGE':'second::rule'}), (300, {'CODE_TOKEN':'second-token'})))
        obs.run(obs.manager.init_steps())
        obs.update()
        first = obs.submit('first')
        self.assertEqual(obs.runtime.max_timeout, 100000)
        self.assertTrue(obs.run(obs.works[0].steps()))
        main = obs.runtime.main.instance
        obs.finish(first)
        self.assertEqual(first.state.token, 'first-token')  # post does not consume
        obs.deliver()
        self.assertIsNone(first.state.token)
        second = obs.submit('second', 'later-context')
        self.assertIsNot(first, second)
        self.assertTrue(obs.run(obs.works[1].steps()))
        obs.finish(second)
        obs.deliver(1)
        self.assertEqual(obs.delivered, [('first', 'first-token'), ('second', 'second-token')])
        self.assertIs(obs.runtime.main.instance, main)
        self.assertEqual(main.updater.context, 'task-context')
        self.assertEqual(obs.runtime.context, 'later-context')
        self.assertEqual(obs.kinds().count('main_load_library'), 2)
        self.assertEqual([r[0] for r in obs.requests], [101, 200, 300, 200, 300])

    def test_old_queued_message_consumes_current_token_and_calls_captured_listener(self):
        obs = LifecycleObservations()
        old = obs.submit('old-listener')
        old.state.token = 'old-token'
        obs.finish(old)
        new = obs.submit('new-listener')
        new.state.token = 'new-token'
        obs.manager.task_listener = 'unused-field-listener'
        obs.deliver()
        self.assertEqual(obs.delivered, [('old-listener', 'new-token')])
        self.assertIsNone(new.state.token)
        self.assertIsNone(obs.guard.task)
        self.assertIs(obs.manager.task, new)
        self.assertEqual(obs.messages[0][2], 'old-token')

    def test_old_clear_or_cancel_unpublishes_new_singleton_without_clearing_new_token(self):
        for cancel in (False, True):
            obs = LifecycleObservations()
            old = obs.submit('old')
            new = obs.submit('new')
            new.state.token = 'keep'
            if cancel:
                obs.finish(old, cancelled=True)
            else:
                obs.run(old.clear_steps())
            self.assertIsNone(obs.guard.task)
            self.assertIs(obs.manager.task, new)
            self.assertEqual(new.state.token, 'keep')
            self.assertEqual(obs.messages, [])

    def test_clear_failure_does_not_clear_and_is_outside_manager_catch(self):
        obs = LifecycleObservations()
        task = obs.submit()
        task.state.token = 'keep'
        obs.overrides['task_log'] = lambda e: fault() if e.args == ('clear',) else None
        with self.assertRaises(type(fault())): obs.submit('next')
        self.assertEqual(task.state.token, 'keep')
        self.assertIs(obs.guard.task, task)
        self.assertEqual(obs.delivered, [])
        self.assertNotIn('manager_exception_trace', obs.kinds())

    def test_security_exception_phone_fallback_and_other_phone_failure_partial_state(self):
        obs = LifecycleObservations()
        obs.overrides['telephony_line1_number'] = fault('SecurityException')
        task = obs.submit()
        self.assertEqual(task.settings.etc_data, '')
        self.assertEqual(task.status, 'RUNNING')
        obs.overrides['telephony_line1_number'] = fault('NullPointerException')
        failed = obs.submit('failure')
        self.assertIsNot(task, failed)
        self.assertIs(obs.guard.task, failed)
        self.assertEqual(failed.settings.app_info, 'APP')
        self.assertEqual(failed.state.server_url, obs.manager.config.token_url)
        self.assertEqual(obs.runtime.max_timeout, 100000)
        self.assertEqual(failed.status, 'PENDING')
        self.assertEqual(obs.delivered, [('failure', '')])
        self.assertEqual(len(obs.works), 1)

    def test_executor_rejection_leaves_running_task_and_logger_can_prevent_failure_callback(self):
        obs = LifecycleObservations()
        obs.overrides['task_executor_execute'] = fault('RejectedExecutionException')
        task = obs.submit()
        self.assertEqual(task.status, 'RUNNING')
        self.assertIsNone(task.state.token)
        self.assertEqual(obs.delivered, [('listener', '')])
        obs.delivered.clear()
        obs.overrides['manager_exception_log'] = fault()
        with self.assertRaises(type(fault())): obs.submit()
        self.assertEqual(obs.delivered, [])

    def test_analysis_and_link_errors_are_not_manager_failure_callbacks(self):
        for error in (AnalysisLimit('missing phone observation'), LinkFault(), ValueError('Python failure')):
            obs = LifecycleObservations()
            obs.overrides['telephony_service'] = error
            with self.assertRaises(type(error)): obs.submit()
            self.assertEqual(obs.delivered, [])
            self.assertNotIn('manager_exception_log', obs.kinds())

    def test_constructor_failure_never_publishes_and_only_java_failure_exits_monitor(self):
        for error, released in ((fault(), True), (LinkFault(), True), (AnalysisLimit('constructor'), False)):
            obs = LifecycleObservations()
            obs.overrides['task_constructor'] = error
            with self.assertRaises(type(error)): obs.run(obs.guard.task_instance_steps())
            self.assertIsNone(obs.guard.task)
            self.assertEqual('task_monitor_exit' in obs.kinds(), released)

    def test_set_app_info_keeps_captured_arguments_when_agent_fields_change(self):
        obs = LifecycleObservations()
        def log(e):
            obs.runtime.call.set_app_info('changed', '2')
        obs.overrides['agent_app_info_log'] = log
        task = obs.submit()
        self.assertEqual((task.settings.app_info, task.settings.version), ('APP', '1'))
        self.assertEqual(obs.runtime.call.app_info, 'changed')

    def test_false_send_and_null_result_still_reach_listener_without_consuming_token(self):
        obs = LifecycleObservations()
        task = obs.submit()
        task.state.token, task.listener = 'keep', 'callback'
        obs.overrides['task_send_message'] = False
        obs.finish(task, result=None)
        self.assertEqual(obs.callbacks, [('callback', 1)])
        self.assertEqual(task.state.token, 'keep')
        self.assertEqual(task.status, 'FINISHED')
        self.assertEqual(obs.messages, [])

    def test_post_formatting_failure_prevents_callback_and_finished_status(self):
        obs = LifecycleObservations()
        task = obs.submit()
        task.listener = 'callback'
        obs.overrides['format_local_error'] = fault()
        with self.assertRaises(type(fault())): obs.finish(task)
        self.assertEqual(task.status, 'RUNNING')
        self.assertEqual(obs.callbacks, [])
        self.assertEqual(obs.messages, [])

    def test_render_failure_during_delivery_clears_manager_value_but_not_task(self):
        obs = LifecycleObservations()
        task = obs.submit()
        task.state.token = 'keep'
        task.checks['debugging'] = True
        obs.overrides['task_environment_check'] = fault()
        obs.manager.token = 'old-manager-value'
        with self.assertRaises(type(fault())): obs.run(task.handler.message_steps())
        self.assertEqual(obs.manager.token, '')
        self.assertEqual(task.state.token, 'keep')
        self.assertIs(obs.guard.task, task)
        self.assertEqual(obs.delivered, [])

    def test_render_reads_agent_log_again_at_delivery_and_build_only_for_connection_errors(self):
        obs = LifecycleObservations()
        task = obs.submit()
        task.state.status_code, task.state.task_log = 102, 'task-detail'
        obs.runtime.call.status_log = 'first-log'
        obs.overrides['format_local_error'] = lambda e: e.args[2]
        obs.finish(task)
        obs.runtime.call.status_log = 'later-log'
        obs.deliver()
        self.assertIn('agent:first-log&&task-detail', obs.messages[0][2])
        self.assertIn('agent:later-log&&task-detail', obs.delivered[0][1])
        self.assertEqual(obs.kinds().count('build_string_field'), 4)

    def test_send_rereads_handler_after_render_but_keeps_message_what(self):
        obs = LifecycleObservations()
        task = obs.submit()
        def format_error(e):
            task.handler, task.message_what = 'replacement-handler', 999
            return 'formatted'
        obs.overrides['format_local_error'] = format_error
        obs.finish(task)
        self.assertEqual(obs.messages, [('replacement-handler', 200, 'formatted')])

    def test_execute_once_and_worker_resume_guard(self):
        obs = LifecycleObservations(((200, {'CODE_CHALLENGE':'c::r'}), (300, {'CODE_TOKEN':'token'})))
        task = obs.submit()
        with self.assertRaises(type(fault())): obs.run(task.execute_steps('again'))
        work = obs.works[0]
        self.assertTrue(obs.run(work.steps()))
        with self.assertRaises(AnalysisLimit): obs.run(work.steps())
        self.assertEqual(work.phase, 'returned')
        self.assertEqual(len(obs.works), 1)

    def test_worker_fault_has_no_invented_finish_or_message(self):
        for failure, phase in ((fault(), 'threw'), (AnalysisLimit('missing PID'), 'unresolved')):
            obs = LifecycleObservations()
            task = obs.submit()
            obs.overrides['process_pid'] = failure
            with self.assertRaises(type(failure)): obs.run(obs.works[0].steps())
            self.assertEqual(obs.works[0].phase, phase)
            self.assertEqual(task.status, 'RUNNING')
            self.assertEqual(obs.messages, [])

    def test_manager_to_initial_jobs_native_value_calculations_and_final_listener(self):
        obs = LifecycleObservations(((101, {'CERT':'Y2VydA=='}),
            (200, {'CODE_CHALLENGE':'TQ==::'+rule()}), (300, {'CODE_TOKEN':'synthetic-issued'})))
        obs.run(obs.manager.init_steps())
        obs.update()
        obs.zip()
        task = obs.submit()
        first, second = NativeObservations(), NonceObservations()
        second.der = synthetic_certificates()[0]
        second.digest = hashlib.sha256(second.der).digest()
        def signature(e):
            if e.kind == 'native_jni' and e.args[:3] == ('CallObjectMethod', 'signature', 'toByteArray'):
                return True, NativeByteArrayValue(second.der)
            return False, None
        second.override = signature
        package = obs.package
        package.archives[package.source] = [Entry(e.name, bag([second.der]) if e.name.endswith('.RSA') else e.data)
                                            for e in package.archives[package.source]]
        stage, os = 'first', None
        def reply(e):
            nonlocal stage, os
            if e.kind == 'oscheck_future':
                owner = obs.runtime.main.instance.response
                os = OSObservations(owner)
                os.context = obs.runtime.main.context
                _, root, rooting, _, _, timeout = e.args
                return drive(oscheck_future_steps(owner, root_check=root, rooting_info=rooting,
                    timeout=timeout, extended_state=os.extended, standard_state=os.standard), os.reply)
            if e.kind == 'package_java':
                stage = 'second'
                if e.args[0] == 'zip.getInputStream' and e.args[2].name.endswith('.RSA'):
                    result = KnownCertificateStream(e.args[2].data)
                else:
                    result = obs.reply(e)
                second.files = {key.encode(): value for key, value in package.files.items()}
                return result
            if e.kind.startswith('native_'): return path_values(first if stage == 'first' else second, e)
            return obs.reply(e)
        work = project_package_steps(project_native_value_steps(obs.works[0].steps(),
            service='service', certificate_values=True), certificate_values=True)
        self.assertTrue(drive(work, reply))
        obs.finish(task)
        obs.deliver()
        self.assertEqual(obs.delivered, [('listener', 'synthetic-issued')])
        self.assertIsNone(obs.guard.task)
        self.assertEqual([r[0] for r in obs.requests], [101, 200, 300])
        self.assertEqual([j.phase for j in obs.jobs], ['returned', 'returned'])
        self.assertEqual(os.works[0].phase, 'returned')
        self.assertEqual(package.calls('certificateFactory.generateCertificate'), [])
        self.assertEqual(second.calls('GetByteArrayElements'), [])
        for coarse in ('oscheck_future', 'native_start', 'native_get_nonce', 'check_zip_os14', 'check_fingerprint'):
            self.assertNotIn(coarse, obs.kinds())
        form = parse_qs(obs.writes[-1][1].decode())
        plain = java_seed_decrypt(base64.b64decode(form['CODE_RESPONSE'][0]), RULE_KEY, RULE_IV).decode()
        self.assertIn('*' + os_status_digest('TQ==') + '##', plain)
        self.assertNotIn('SYNTHETIC-NATIVE-OBSERVATION', plain)
        self.assertNotEqual(form['CODE_RESPONSE2'], ['SYNTHETIC-NONCE-OBSERVATION'])


if __name__ == '__main__':
    unittest.main()
