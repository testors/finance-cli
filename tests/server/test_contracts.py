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
        self.assertEqual(states['hana-issuance']['status'], 'local_only')
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


if __name__ == '__main__':
    unittest.main()
