"""Synthetic scheduling/device observations, plus development-only JDK checks."""
import base64
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from giro.codeguard_codec import RULE_KEY, RULE_IV, java_seed_decrypt
from giro.codeguard_device import ExtendedDeviceState
from giro.codeguard_effects import JavaFault, LinkFault
from giro.codeguard_flow import ChallengeState
from giro.codeguard_oscheck import (OSCheckWork, CompletedOSCheck,
    oscheck_future_steps, project_oscheck_steps)
from giro.codeguard_response import response_steps, os_status_digest
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_standard_device import StandardDeviceState
from giro.codeguard_service import generate_token_steps
from giro.codeguard_native_start import project_native_start_steps
from giro.codeguard_native_nonce import project_native_nonce_steps
from giro.codeguard_package import project_package_steps
from cg_exchange_fixture import Transcript, drive, fault, sample_state
from test_codeguard_native_start import NativeObservations, rule
from test_codeguard_native_nonce import NonceObservations
from test_codeguard_package import PackageObservations


def rcl(*entries):
    return json.dumps([dict(policy=p,description=d,enabled=True,osType=1) for p,d in entries])


class OSObservations:
    def __init__(self, owner=None):
        self.owner = owner or sample_state(challenge=ChallengeState('challenge','rule',rcl_suffix=rcl((12,'synthetic-path'))))
        self.extended, self.standard = ExtendedDeviceState('old-ex'), StandardDeviceState('old-standard')
        self.effects, self.works, self.counts, self.overrides = [], [], {}, {}
        self.context = 'synthetic-context-at-execution'
        self.device = {'device_log':None,'device_file': 'synthetic-file','device_file_exists':False,
            'device_log_debug_enabled':False,'device_runtime':'synthetic-runtime',
            'device_runtime_exec':fault(),'device_runtime_exec_array':fault(),
            'device_package_manager':'synthetic-manager',
            'device_application_info':fault('NameNotFoundException'),
            'device_build_field':'synthetic-release-tags','device_context_present':True,
            'device_package_info':fault('NameNotFoundException')}

    def calls(self,name):
        return [e.args[1:] for e in self.effects if e.kind=='oscheck_java' and e.args[0]==name]

    def reply(self,e):
        self.effects.append(e)
        if e.kind=='oscheck_device':
            work,context,inner = e.args
            value = self.device[inner.kind]
            return value(e) if callable(value) else value
        if e.kind!='oscheck_java': raise AssertionError(e.kind)
        name,*args=e.args
        self.counts[name]=self.counts.get(name,0)+1
        key=(name,self.counts[name])
        if key in self.overrides:
            value=self.overrides[key]
            return value(e) if callable(value) else value
        if name=='executors.newSingleThreadExecutor': return ('executor',self.counts[name])
        if name=='challenge.field': return getattr(args[0].challenge,args[1])
        if name=='callable.new':
            self.works.append(args[0])
            return ('callable',len(self.works))
        if name=='executor.submit': return ('future',len(self.works))
        if name=='future.get':
            work=args[3]
            try: drive(work.steps(),self.reply)
            except (JavaFault,LinkFault): return fault('ExecutionException')
            return CompletedOSCheck(work)
        if name=='main.staticContext': return self.context
        if name=='main.detailEnabled': return args[0].detail_enabled
        if name=='device.detail': return args[1].detail
        raise AssertionError(name)

    def future(self, **options):
        values=dict(root_check=True,rooting_info=False,timeout=5000,
                    extended_state=self.extended,standard_state=self.standard)
        values.update(options)
        return drive(oscheck_future_steps(self.owner,**values),self.reply)

    def project(self,gen):
        return project_oscheck_steps(gen,owner=self.owner,extended_state=self.extended,standard_state=self.standard)

    def response(self, **options):
        args=dict(root_check=True,rooting_info=False)
        args.update(options)
        ticks=iter([10,20])
        def reply(e):
            if e.kind.startswith('oscheck_'): return self.reply(e)
            if e.kind=='clock_ms': return next(ticks)
            return {'native_start':'synthetic-native','engine_version':'engine','location_text':''}[e.kind]
        return drive(self.project(response_steps(self.owner,**args)),reply)


class OSCheckFutureTests(unittest.TestCase):
    def test_normal_composition_computes_digest_from_explicit_file_result(self):
        for present,source in ((False,'challenge'),(True,'synthetic-path')):
            obs=OSObservations()
            obs.device['device_file_exists']=present
            self.assertEqual(obs.future(),os_status_digest(source))
            work=obs.works[0]
            self.assertEqual(work.phase,'returned')
            self.assertIsNone(work.failure)
            names=[e.args[0] for e in obs.effects if e.kind=='oscheck_java']
            self.assertEqual(names[:7],['executors.newSingleThreadExecutor',
                'challenge.field','challenge.field','challenge.field','callable.new',
                'executor.submit','future.get'])
            self.assertEqual(obs.calls('future.get')[0][1:3],(5000,'MILLISECONDS'))
            self.assertEqual(obs.owner.detail_enabled,present)

    def test_field_capture_is_after_executor_creation_and_before_submission(self):
        obs=OSObservations()
        def create(_):
            obs.owner.challenge=ChallengeState('new','rule',fourth='4',rcl_suffix='')
            return 'executor'
        obs.overrides[('executors.newSingleThreadExecutor',1)]=create
        self.assertEqual(obs.future(root_check=False),os_status_digest('new'))
        work=obs.works[0]
        self.assertEqual((work.challenge,work.fourth,work.rcl),('new','4',''))
        self.assertEqual([a[1] for a in obs.calls('challenge.field')],['challenge','fourth','rcl_suffix'])

    def test_constructor_strings_remain_captured_while_worker_context_is_late(self):
        obs=OSObservations()
        obs.device['device_file_exists']=True
        def submit(e):
            obs.owner.challenge.challenge='later'
            obs.owner.challenge.rcl_suffix=rcl((12,'later-path'))
            obs.context='later-context'
            return 'future'
        obs.overrides[('executor.submit',1)]=submit
        self.assertEqual(obs.future(),os_status_digest('synthetic-path'))
        scoped=[e for e in obs.effects if e.kind=='oscheck_device']
        self.assertTrue(scoped)
        self.assertEqual({e.args[1] for e in scoped},{'later-context'})
        file_call=next(e for e in scoped if e.args[2].kind=='device_file')
        self.assertEqual(file_call.args[2].args,('synthetic-path',))

    def test_work_can_start_during_submit_before_timed_get(self):
        obs=OSObservations()
        def submit(e):
            drive(e.args[3].steps(),obs.reply)
            return 'future'
        obs.overrides[('executor.submit',1)]=submit
        obs.overrides[('future.get',1)]=lambda e:CompletedOSCheck(e.args[4])
        self.assertEqual(obs.future(),os_status_digest('challenge'))
        self.assertEqual(len(obs.calls('main.staticContext')),1)

    def test_standard_check_still_runs_mandatory_prefix_with_empty_options(self):
        obs=OSObservations(sample_state(challenge=ChallengeState('c','r',fourth='',rcl_suffix='')))
        self.assertEqual(obs.future(),os_status_digest('c'))
        inner=[e.args[2] for e in obs.effects if e.kind=='oscheck_device']
        self.assertEqual(sum(e.kind=='device_runtime_exec' for e in inner),1)
        self.assertEqual(sum(e.kind=='device_application_info' for e in inner),5)
        self.assertFalse(any(e.kind=='device_file' for e in inner))

    def test_owning_flags_skip_checks_only_when_explicitly_selected(self):
        for options,expected in (({'root_check':False},'challenge'),
                                  ({'root_check':False,'rooting_info':True},'OS_modification_by_rooting_info')):
            obs=OSObservations()
            self.assertEqual(obs.future(**options),os_status_digest(expected))
            self.assertEqual(obs.calls('main.staticContext'),[])
            self.assertEqual(obs.owner.detail_enabled,False)
        with self.assertRaises(AnalysisLimit): OSObservations().future(root_check=None)

    def test_job_may_write_true_but_observe_false_before_source_selection(self):
        obs=OSObservations()
        obs.device['device_file_exists']=True
        obs.overrides[('main.detailEnabled',1)]=False  # explicit overlapping-field observation
        self.assertEqual(obs.future(),os_status_digest('challenge'))
        self.assertTrue(obs.owner.detail_enabled)
        self.assertEqual(obs.extended.detail,'synthetic-path')
        self.assertEqual(obs.calls('device.detail'),[])

    def test_false_check_can_read_later_true_and_use_shared_detail(self):
        obs=OSObservations()
        obs.overrides[('main.detailEnabled',1)]=True
        self.assertEqual(obs.future(),os_status_digest('old-ex'))
        self.assertFalse(obs.owner.detail_enabled)  # a read is not another write

    def test_java_context_fault_is_worker_catch_and_successful_digest_return(self):
        obs=OSObservations()
        obs.overrides[('main.staticContext',1)]=fault('SecurityException')
        self.assertEqual(obs.future(),os_status_digest('challenge'))
        self.assertEqual(obs.owner.status_log,'E0,E32.4')
        self.assertEqual(obs.works[0].phase,'returned')

    def test_worker_link_fault_and_executor_link_fault_have_different_outcomes(self):
        obs=OSObservations()
        link=LinkFault(message='synthetic')
        obs.overrides[('main.staticContext',1)]=link
        result=obs.response()
        self.assertIn('*'+os_status_digest('challenge')+'##',result)
        self.assertIs(obs.works[0].failure,link)
        self.assertEqual(obs.works[0].phase,'threw')
        direct=OSObservations()
        direct.overrides[('executors.newSingleThreadExecutor',1)]=link
        with self.assertRaises(LinkFault): direct.response()

    def test_missing_observations_and_python_failures_never_become_execution_exception(self):
        for result in (None,AnalysisLimit('unknown'),ValueError('bug')):
            obs=OSObservations()
            obs.device['device_file_exists']=result
            with self.assertRaises(ValueError if isinstance(result,ValueError) else AnalysisLimit):
                obs.response()
            self.assertEqual(obs.works[0].phase,'unresolved')
            self.assertIsNone(obs.owner.os_status)

    def test_pending_or_foreign_completion_marker_cannot_fabricate_success(self):
        for result in (None,'fake-string','pending','foreign'):
            obs=OSObservations()
            def get(e):
                work=e.args[4]
                if result=='pending': return CompletedOSCheck(work)
                if result=='foreign':
                    other=OSCheckWork(obs.owner,'other',False,False,None,None,obs.extended,obs.standard)
                    drive(other.steps(),obs.reply)
                    return CompletedOSCheck(other)
                return result
            obs.overrides[('future.get',1)]=get
            with self.assertRaises(AnalysisLimit): obs.future()
            self.assertEqual(obs.works[0].phase,'created')

    def test_successful_callable_cannot_be_reexecuted_by_another_generator(self):
        obs=OSObservations()
        obs.future()
        with self.assertRaises(AnalysisLimit): drive(obs.works[0].steps(),obs.reply)

    def test_repeated_responses_create_distinct_executor_and_callable(self):
        obs=OSObservations()
        obs.response()
        obs.response()
        self.assertEqual(len(obs.calls('executors.newSingleThreadExecutor')),2)
        self.assertIsNot(obs.works[0],obs.works[1])
        self.assertTrue(all(w.phase=='returned' for w in obs.works))
        self.assertFalse(any('cancel' in e.args[0] or 'shutdown' in e.args[0]
                             for e in obs.effects if e.kind=='oscheck_java'))

    def test_submit_failure_keeps_callable_unstarted_and_preserves_outer_error(self):
        obs=OSObservations()
        obs.overrides[('executor.submit',1)]=fault('RejectedExecutionException')
        result=obs.response()
        self.assertIn('OS_CHECK_ERR001(java.synthetic.RejectedExecutionException:',result)
        self.assertEqual(obs.works[0].phase,'created')
        self.assertEqual(obs.calls('future.get'),[])

    def test_cancellation_exception_is_outer_error_not_timeout_fallback(self):
        obs=OSObservations()
        obs.overrides[('future.get',1)]=fault('CancellationException')
        self.assertIn('OS_CHECK_ERR001(java.synthetic.CancellationException:',obs.response())
        self.assertEqual(obs.works[0].phase,'created')

    def test_future_exception_subclass_follows_typed_java_catch(self):
        obs=OSObservations()
        timeout=fault('SyntheticTimeoutSubclass')
        timeout.bases=('TimeoutException',)
        obs.overrides[('future.get',1)]=timeout
        self.assertIn('*'+os_status_digest('challenge')+'##',obs.response())
        self.assertNotIn('E32.5(',obs.owner.status_log)

    def test_timeout_uses_current_challenge_without_altering_captured_work(self):
        obs=OSObservations()
        def get(_):
            obs.owner.challenge.challenge='changed-while-waiting'
            return fault('TimeoutException')
        obs.overrides[('future.get',1)]=get
        result=obs.response()
        self.assertIn('*'+os_status_digest('changed-while-waiting')+'##',result)
        self.assertEqual(obs.works[0].challenge,'challenge')
        self.assertEqual(obs.works[0].phase,'created')

    def test_timeout_then_late_worker_completion_changes_detail_not_stored_os_status(self):
        obs=OSObservations()
        obs.device['device_file_exists']=True
        obs.overrides[('future.get',1)]=fault('TimeoutException')
        gen=obs.project(response_steps(obs.owner,root_check=True,rooting_info=False))
        seen=[]
        def reply(e):
            seen.append(e.kind)
            if e.kind.startswith('oscheck_'): return obs.reply(e)
            if e.kind=='native_start':
                self.assertEqual(obs.owner.os_status,os_status_digest('challenge'))
                self.assertEqual(drive(obs.works[0].steps(),obs.reply),os_status_digest('synthetic-path'))
                return 'native'
            return {'clock_ms':10,'engine_version':'engine','location_text':''}[e.kind]
        result=drive(gen,reply)
        self.assertIn('!'+base64.b64encode(b'synthetic-path').decode()+'*'+os_status_digest('challenge')+'##',result)
        self.assertEqual(obs.owner.os_status,os_status_digest('challenge'))
        self.assertEqual(obs.works[0].phase,'returned')

    def test_suspended_worker_is_resumed_after_timeout_without_second_device_execution(self):
        obs=OSObservations()
        suspended=[]
        def get(e):
            work=e.args[4]
            worker=work.steps()
            effect=next(worker)
            while not (effect.kind=='oscheck_device' and effect.args[2].kind=='device_file_exists'):
                answer=obs.reply(effect)
                effect=worker.throw(answer) if isinstance(answer,BaseException) else worker.send(answer)
            suspended.append((worker,effect))
            return fault('TimeoutException')
        obs.overrides[('future.get',1)]=get
        obs.response()
        self.assertEqual(obs.works[0].phase,'running')
        worker,effect=suspended[0]
        with self.assertRaises(AnalysisLimit): next(obs.works[0].steps())
        next_effect=worker.send(True)
        self.assertEqual(next_effect.args[0],'main.detailEnabled')
        detail_effect=worker.send(obs.reply(next_effect))
        with self.assertRaises(StopIteration) as done: worker.send(obs.reply(detail_effect))
        self.assertEqual(done.exception.value,os_status_digest('synthetic-path'))
        self.assertEqual(sum(e.kind=='oscheck_device' and e.args[2].kind=='device_file' for e in obs.effects),1)

    def test_older_worker_can_finish_after_next_response_reset(self):
        obs=OSObservations()
        obs.device['device_file_exists']=True
        obs.overrides[('future.get',1)]=fault('TimeoutException')
        obs.response()
        old=obs.works[0]
        obs.owner.challenge.challenge='new-challenge'
        def new_get(_):
            self.assertFalse(obs.owner.detail_enabled)  # reset by second response
            drive(old.steps(),obs.reply)
            return fault('TimeoutException')
        obs.overrides[('future.get',2)]=new_get
        result=obs.response()
        self.assertIn('!'+base64.b64encode(b'synthetic-path').decode()+'*'+os_status_digest('new-challenge')+'##',result)
        self.assertEqual(old.value,os_status_digest('synthetic-path'))
        self.assertEqual(obs.works[1].phase,'created')

    def test_unknown_shared_field_visibility_is_not_read_from_local_state_as_default(self):
        obs=OSObservations()
        obs.overrides[('main.detailEnabled',1)]=None
        with self.assertRaises(AnalysisLimit): obs.future()

    def test_private_work_state_and_effect_repr_do_not_contain_inputs(self):
        obs=OSObservations()
        obs.owner.challenge.challenge='PRIVATE-SYNTHETIC'
        obs.future()
        self.assertNotIn('PRIVATE-SYNTHETIC',repr(obs.works[0])+repr(CompletedOSCheck(obs.works[0]))+repr(obs.effects))

    def test_no_host_threads_environment_or_network_used(self):
        os_status_digest('challenge')  # preload pure crypto resources
        with patch('builtins.open',side_effect=AssertionError('host IO')), \
             patch('socket.socket',side_effect=AssertionError('network')), \
             patch('threading.Thread.start',side_effect=AssertionError('thread')):
            self.assertEqual(OSObservations().future(),os_status_digest('challenge'))


class OSCheckIntegrationTests(unittest.TestCase):
    def test_oscheck_package_and_both_native_responses_share_one_exchange(self):
        transcript=Transcript([(200,{'CODE_CHALLENGE':'TQ==::'+rule()}),
                               (300,{'CODE_TOKEN':'SYNTHETIC-TOKEN'})])
        transcript.main.pid='123'
        obs=OSObservations(transcript.main)
        first,second,package=NativeObservations(),NonceObservations(),PackageObservations()
        stage='first'
        def reply(e):
            nonlocal stage
            if e.kind.startswith('oscheck_'): return obs.reply(e)
            if e.kind=='package_java':
                stage='second'
                value=package.reply(e)
                second.files={key.encode():data for key,data in package.files.items()}
                return value
            if e.kind.startswith('native_'): return (first if stage=='first' else second).reply(e)
            return transcript.reply(e)
        gen=generate_token_steps(transcript.main,transcript.runtime,transcript.agent,
            server_url='https://synthetic.invalid/',timeout=1000,root_check=True,
            rooting_info=False,encrypted_token=False)
        gen=obs.project(project_package_steps(project_native_nonce_steps(
            project_native_start_steps(gen,service='service'),service='service')))
        self.assertEqual(drive(gen,reply),'SYNTHETIC-TOKEN')
        self.assertEqual([x[0] for x in transcript.requests],[200,300])
        self.assertNotIn('oscheck_future',transcript.kinds())
        self.assertNotIn('check_zip_os14',transcript.kinds())
        self.assertNotIn('check_fingerprint',transcript.kinds())
        self.assertNotIn('native_start',transcript.kinds())
        self.assertNotIn('native_get_nonce',transcript.kinds())
        form=parse_qs(transcript.writes[-1][1].decode())
        plain=java_seed_decrypt(base64.b64decode(form['CODE_RESPONSE'][0]),RULE_KEY,RULE_IV).decode()
        self.assertIn('*'+os_status_digest('TQ==')+'##',plain)
        self.assertEqual(obs.works[0].phase,'returned')
        self.assertTrue(any(e.kind=='oscheck_device' for e in obs.effects))

    def test_jdk_future_timeout_interrupt_and_worker_error_are_distinct(self):
        java=shutil.which('java')
        if not java: self.skipTest('JDK unavailable for development-only comparison')
        result=subprocess.run([java,str(Path(__file__).parent/'java/OSCheckFutureVectors.java')],
                              capture_output=True,text=True,timeout=30,check=True)
        self.assertEqual(result.stdout.splitlines(),[
            'timeout:done=false:cancelled=false','late:detail=true:result=worker-value',
            'worker:ExecutionException:UnsatisfiedLinkError',
            'interrupted:InterruptedException:cleared=true',
            'after-interrupt:done=false:cancelled=false','resume:worker-value'])


if __name__=='__main__': unittest.main()
