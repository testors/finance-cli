"""Capability listing, setup gating and login separation contracts. Synthetic only."""
import json
import unittest
from unittest.mock import patch

from support import ServerCase, synthetic_certificate

from finance_cli.server import adapters, capabilities


class CapabilityTests(ServerCase):
    def test_feature_list_and_registered_jobs_match(self):
        listed = {name for feature in capabilities.FEATURES for name in feature[4]}
        self.assertEqual(listed, set(adapters.names()))
        for area, feature_id, title, placement, jobs in capabilities.FEATURES:
            if placement in ('planned', 'local'):
                self.assertEqual(jobs, (), feature_id)
        self.enroll()
        states = {f['id']: f for f in self.get('/capabilities').json()['features']}
        self.assertEqual(states['giro-live']['status'], 'planned')
        self.assertEqual(states['hana-issuance']['status'], 'available')
        self.assertEqual(states['hometax-tax']['verification'], 'live_untested')
        self.assertEqual(states['giro-bills']['verification'], 'offline')
        unknown = self.post('/jobs', {'name': 'giro.live.pay'})
        self.assertEqual((unknown.status_code, unknown.json()['error']), (404, 'job_name_not_registered'))

    def test_setup_required_blocks_submission(self):
        self.enroll()
        synthetic_certificate()
        login = self.post('/logins', {'institution': 'hometax', 'method': 'joint_certificate', 'name': 'h',
                                      'credential': 'synthetic'}).json()
        with patch.object(capabilities, 'setup_reasons', return_value=['hometax_runtime_not_installed']):
            feature = {f['id']: f for f in self.get('/capabilities').json()['features']}['hometax-login']
            self.assertEqual((feature['status'], feature['reasons']), ('setup_required', ['hometax_runtime_not_installed']))
            refused = self.post('/jobs', {'name': 'hometax.login', 'login_id': login['id'],
                                          'secrets': {'certificate_password': 'x'}})
        self.assertEqual((refused.status_code, refused.json()['error']), (409, 'capability_unavailable'))
        self.assertEqual(self.get('/jobs').json()['jobs'], [])

    def test_reviewed_banking_evidence_is_scoped_and_does_not_change_readiness(self):
        from finance_cli.cli.main import capabilities as cli_capabilities
        self.enroll()
        value = self.get('/capabilities').json()
        states = {f['id']: f for f in value['features']}
        jobs = {j['name']: j for f in value['features'] for j in f['jobs']}
        self.assertEqual(value['verification']['hana'], 'live_partial')
        self.assertEqual(states['hana-accounts']['verification'], 'live_partial')
        self.assertEqual(states['hana-issuance']['verification'], 'live_verified')
        self.assertEqual(states['hana-extend']['verification'], 'live_untested')
        self.assertEqual(jobs['hana.onesign.accounts']['verification'], 'live_verified')
        self.assertEqual(jobs['hana.accounts.list']['verification'], 'live_untested')
        self.assertEqual(jobs['hana.onesign.history.more']['verification'], 'live_untested')
        self.assertEqual(jobs['hana.onesign.history.export']['verification'], 'live_untested')
        self.assertEqual(jobs['hana.onesign.inquiry.detail']['verification'], 'live_untested')
        self.assertEqual(jobs['hana.onesign.history.list']['verification'], 'live_partial')
        self.assertEqual(jobs['hana.onesign.security.query']['verification'], 'live_partial')
        self.assertIn('이체한도 조회 성공 확인', jobs['hana.onesign.security.query']['verification_note'])
        self.assertEqual(jobs['hana.transfer.prepare']['verification'], 'live_partial')
        self.assertIn('최종 이체 확정은 미확인', jobs['hana.transfer.reconcile']['verification_note'])
        self.assertEqual(jobs['hana.onesign.issue.prepare-id']['verification'], 'offline')
        report = cli_capabilities()['services']['hana']['live_verification']
        for name, evidence in report['jobs'].items():
            self.assertEqual(jobs[name]['verification'], evidence['verification'])
            self.assertEqual(adapters.get(name).verification, evidence['verification'])
        self.assertFalse(cli_capabilities()['services']['hana']['live_tested'])
        self.assertEqual(states['hometax-login']['verification'], 'live_untested')
        for feature in ('giro-live', 'joint-issuance', 'financial-issuance', 'hana-otp-limit'):
            self.assertEqual(states[feature]['status'], 'planned')
        self.assertEqual(self.get('/jobs').json()['jobs'], [])

    def test_credential_usage_is_reported_and_blocks_removal(self):
        from finance_cli.core import credential_refs
        self.enroll()
        synthetic_certificate()
        self.assertEqual(self.get('/credentials').json()['credentials'][0]['in_use'], [])
        self.assertEqual(credential_refs.references('joint', 'synthetic'), [])
        login = self.post('/logins', {'institution': 'hometax', 'method': 'joint_certificate', 'name': '개인',
                                      'credential': 'synthetic', 'signing': {'invoice_sign': {'method': 'joint_certificate', 'credential': 'synthetic'}}}).json()
        usage = self.get('/credentials').json()['credentials'][0]['in_use']
        self.assertEqual(usage, [{'source': 'login', 'login_id': login['id'], 'name': '개인'},
                                 {'source': 'login_signing', 'login_id': login['id'], 'name': '개인', 'purpose': 'invoice_sign'}])
        self.assertEqual(credential_refs.references('joint', 'synthetic'), usage)
        with self.assertRaises(credential_refs.CredentialInUse) as caught:
            credential_refs.guard('joint', 'synthetic')
        self.assertEqual(caught.exception.references, usage)
        self.assertEqual(credential_refs.references('joint', 'absent'), [])

    def test_two_logins_sharing_a_certificate_stay_separate(self):
        self.enroll()
        synthetic_certificate()
        first = self.post('/logins', {'institution': 'hometax', 'method': 'joint_certificate', 'name': '개인',
                                      'credential': 'synthetic'}).json()
        second = self.post('/logins', {'institution': 'hometax', 'method': 'joint_certificate', 'name': '세무 대리',
                                       'credential': 'synthetic'}).json()
        self.assertEqual(first['credential']['fingerprint'], second['credential']['fingerprint'])
        self.assertEqual(len(self.get('/credentials').json()['credentials']), 1)  # One vault entry.
        from finance_cli.server import model
        with self.db.write() as con:
            session = model.add_session(con, login_id=first['id'], location='server/sessions/hometax/x.json',
                                        revision=1, job_id='jb_x')
            model.set_pointer(con, first['id'], session)
        self.assertEqual(self.get(f"/logins/{second['id']}/sessions").json()['sessions'], [])
        readiness = {row['id']: row['readiness'] for row in self.get('/logins').json()['logins']}
        self.assertEqual((readiness[first['id']], readiness[second['id']]), ('ready', 'login_required'))
        with patch.object(capabilities, 'setup_reasons', return_value=[]):
            refused = self.post('/jobs', {'name': 'hometax.session.refresh', 'login_id': second['id']})
        self.assertEqual(refused.json()['error'], 'login_required')

    def test_browser_cannot_register_its_own_identity(self):
        self.enroll()
        synthetic_certificate()
        login = self.post('/logins', {'institution': 'hometax', 'method': 'joint_certificate', 'name': 'h',
                                      'credential': 'synthetic'}).json()
        forged = self.post(f"/logins/{login['id']}/targets", {'candidate': 'x', 'identity': {'tin': 'forged'}})
        self.assertEqual(forged.json()['error'], 'input_fields_not_accepted')
        missing = self.post(f"/logins/{login['id']}/targets", {'job_id': 'jb_0000000000000000', 'candidate': 'x'})
        self.assertEqual(missing.status_code, 404)
        self.assertNotIn('forged', json.dumps(self.get('/targets').json()))



class SecretHandoffTests(ServerCase):
    """POST /jobs with secrets through a real worker process; nothing reaches a bank."""

    def setUp(self):
        super().setUp()
        from finance_cli.core import storage
        path = storage.directory(self.home)
        for part in ('hana', 'identities', 'synthetic'):
            path = storage.directory(path / part)
        self.lock = path / 'operation.lock'
        self.enroll()
        self.login = self.post('/logins', {'institution': 'hana', 'method': 'onesign', 'name': '하나인증서',
                                           'credential': 'synthetic'}).json()
        self.secrets = {'vault_passphrase': 'SECRET-PASSPHRASE-VALUE', 'pin': '604928'}

    def wait(self, job_id):
        import time
        for _ in range(200):
            job = self.get(f'/jobs/{job_id}').json()
            if job['status'] in ('finished', 'cancelled', 'expired'):
                return job
            time.sleep(0.1)
        self.fail('worker did not finish')

    def leaked(self):
        text = ''
        for path in self.home.rglob('*'):
            if path.is_file():
                text += path.read_bytes().decode('utf-8', 'replace')
        return 'SECRET-PASSPHRASE-VALUE' in text or '604928' in text

    def test_secrets_reach_only_a_worker_that_holds_the_lock(self):
        from finance_cli.core import storage
        with storage.lock(self.lock):
            refused = self.post('/jobs', {'name': 'hana.onesign.login', 'login_id': self.login['id'],
                                          'secrets': self.secrets})
        self.assertEqual((refused.status_code, refused.json()['error']), (409, 'resource_busy'))
        job = self.get('/jobs').json()['jobs'][0]
        self.assertEqual((job['status'], job['local']['cancelled_reason']), ('cancelled', 'resource_busy_secrets_not_sent'))
        accepted = self.post('/jobs', {'name': 'hana.onesign.login', 'login_id': self.login['id'],
                                       'secrets': self.secrets})
        self.assertEqual(accepted.status_code, 202, accepted.text)
        finished = self.wait(accepted.json()['id'])
        # The worker got the secrets, then stopped locally: there is no vault to open.
        self.assertEqual((finished['outcome'], finished['local']['stopped']), ('not_started', 'onesign_store_not_opened'))
        self.assertIn('step_started', [e['kind'] for e in finished['events']])
        self.assertFalse(self.leaked())



class RemovalTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.enroll()
        synthetic_certificate('login-cert')

    def hometax_login(self):
        return self.post('/logins', {'institution': 'hometax', 'method': 'joint_certificate', 'name': '홈택스',
                                     'credential': 'login-cert'}).json()

    def test_credential_removal_needs_the_name_and_no_references(self):
        login = self.hometax_login()
        mismatch = self.post('/credentials/joint/login-cert/remove', {'confirm': 'login'})
        self.assertEqual(mismatch.json()['error'], 'removal_confirmation_mismatch')
        in_use = self.post('/credentials/joint/login-cert/remove', {'confirm': 'login-cert'})
        self.assertEqual((in_use.status_code, in_use.json()['error']), (409, 'credential_in_use'))
        self.assertEqual(in_use.json()['references'][0]['login_id'], login['id'])
        self.assertEqual(self.post(f"/logins/{login['id']}/remove", {'expected_revision': 1}).status_code, 200)
        removed = self.post('/credentials/joint/login-cert/remove', {'confirm': 'login-cert'})
        self.assertEqual(removed.status_code, 200, removed.text)
        self.assertEqual(self.get('/credentials').json()['credentials'], [])

    def test_credential_rename_keeps_the_key_and_refuses_while_referenced(self):
        from finance_cli.credentials.registry import Registry
        fingerprint = Registry().entry('login-cert')['certificate_id']
        login = self.hometax_login()
        in_use = self.post('/credentials/joint/login-cert/rename', {'new_name': 'renamed'})
        self.assertEqual((in_use.status_code, in_use.json()['error']), (409, 'credential_in_use'))
        self.post(f"/logins/{login['id']}/remove", {'expected_revision': 1})
        bad = self.post('/credentials/joint/login-cert/rename', {'new_name': '../escape'})
        self.assertEqual(bad.json()['error'], 'invalid_name')
        renamed = self.post('/credentials/joint/login-cert/rename', {'new_name': 'renamed'})
        self.assertEqual(renamed.status_code, 200, renamed.text)
        self.assertEqual(Registry().entry('renamed')['certificate_id'], fingerprint)
        self.assertEqual([c['ref'] for c in self.get('/credentials').json()['credentials']], ['renamed'])
        missing = self.post('/credentials/joint/login-cert/rename', {'new_name': 'again'})
        self.assertEqual((missing.status_code, missing.json()['error']), (404, 'credential_not_found'))

    def test_connection_removal_keeps_history_and_deletes_session_files(self):
        from finance_cli.server import model
        from finance_cli.server.config import private_directory
        from test_foundation import insert_job
        login = self.hometax_login()
        session_file = private_directory('sessions', 'hometax') / 'sf_test.json'
        session_file.write_text('{"cookie_jar": "SYNTHETIC-COOKIE"}')
        with self.db.write() as con:
            session = model.add_session(con, login_id=login['id'], location='server/sessions/hometax/sf_test.json',
                                        revision=1, job_id='jb_x')
            model.set_pointer(con, login['id'], session)
        finished = insert_job(self.db, login_id=login['id'], name='hometax.tax.dues')
        waiting = insert_job(self.db, login_id=login['id'], name='hometax.invoice.prepare', status='awaiting_input')
        running = insert_job(self.db, login_id=login['id'], name='hometax.tax.dues', status='running')
        busy = self.post(f"/logins/{login['id']}/remove", {'expected_revision': 1})
        self.assertEqual((busy.status_code, busy.json()['error']), (409, 'login_has_active_jobs'))
        with self.db.write() as con:
            con.execute("UPDATE jobs SET status='finished' WHERE id=?", (running,))
        stale = self.post(f"/logins/{login['id']}/remove", {'expected_revision': 0})
        self.assertEqual(stale.json()['error'], 'revision_conflict')
        result = self.post(f"/logins/{login['id']}/remove", {'expected_revision': 1}).json()
        self.assertEqual((result['removed'], result['session_files_removed'], result['institution_logout']),
                         (True, 1, False))
        self.assertFalse(session_file.exists())
        self.assertEqual(self.get('/logins').json()['logins'], [])
        self.assertEqual(self.get(f'/jobs/{finished}').json()['status'], 'finished')
        self.assertEqual(self.get(f'/jobs/{waiting}').json()['status'], 'cancelled')
        self.assertEqual(len(self.get('/credentials').json()['credentials']), 1)  # Certificates stay.

    def test_onesign_connection_removal_never_touches_the_store(self):
        from finance_cli.core import storage
        from finance_cli.server import model
        path = storage.directory(self.home)
        for part in ('hana', 'identities', 'synthetic'):
            path = storage.directory(path / part)
        login = self.post('/logins', {'institution': 'hana', 'method': 'onesign', 'name': '하나인증서',
                                      'credential': 'synthetic'}).json()
        with self.db.write() as con:
            model.add_session(con, login_id=login['id'], location='hana/identities/synthetic', revision=1,
                              job_id='jb_x', name='websession')
        result = self.post(f"/logins/{login['id']}/remove", {'expected_revision': 1}).json()
        self.assertEqual(result['session_files_removed'], 0)
        self.assertTrue(path.is_dir())
        self.app.state.vaults._items['synthetic'] = 'remembered'  # As if unlocked earlier.
        self.assertEqual(self.post('/credentials/onesign/synthetic/rename', {'new_name': 'main2'}).status_code, 200)
        self.assertFalse(path.exists())
        path = path.with_name('main2')
        self.assertTrue(path.is_dir())
        self.assertEqual(self.app.state.vaults.get('main2'), 'remembered')
        self.assertEqual([c['ref'] for c in self.get('/credentials').json()['credentials'] if c['type'] == 'onesign'],
                         ['main2'])
        busy_lock = path / 'operation.lock'
        with storage.lock(busy_lock):
            refused = self.post('/credentials/onesign/main2/remove', {'confirm': 'main2'})
        self.assertEqual(refused.json()['error'], 'resource_busy')
        self.assertEqual(self.post('/credentials/onesign/main2/remove', {'confirm': 'main2'}).status_code, 200)
        self.assertIsNone(self.app.state.vaults.get('main2'))
        self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
