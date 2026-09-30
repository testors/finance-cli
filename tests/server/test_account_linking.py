"""Automatic banking setup from stored synthetic responses; no institution I/O."""
import io
import sqlite3
from unittest.mock import patch

from fastapi.testclient import TestClient

from support import ORIGIN, ServerCase
from test_foundation import insert_job
from finance_cli.server import jobs, model, worker
from finance_cli.server.app import create_app
from finance_cli.server.adapters.base import StepResult
from finance_cli.server.db import dumps


class AccountLinkingTests(ServerCase):
    def setUp(self):
        super().setUp()
        with self.db.write() as con:
            self.login = model.create_login(con, institution_name='hana', method='joint_certificate', name='합성')

    def query(self, number='12345678901234', **changes):
        candidate = {'ref': 'account-1', 'kind': 'account', 'identity_key': 'account:' + number,
                     'label': '합성 계좌', 'identity': {'account_number': number}}
        job_id = insert_job(self.db, name='hana.accounts.list', login_id=self.login['id'],
                            result={'accounts': [{'ref': 'account-1'}]}, attempt={'target_candidates': [candidate]})
        values = {'login_revision': 1, 'service_verdict': dumps({'accepted': True}), **changes}
        with self.db.write() as con:
            con.execute('UPDATE jobs SET ' + ','.join(f'{key}=?' for key in values) + ' WHERE id=?',
                        (*values.values(), job_id))
        return job_id

    def test_success_links_accounts_and_preserves_user_settings_without_duplicates(self):
        job_id = self.query()
        with self.db.write() as con:
            self.assertTrue(model.link_hana_accounts(con, jobs.get(con, job_id)))
            target = model.list_targets(con)[0]
            model.update_target(con, target['id'], name='사용자 이름', disabled=True)
            profile = model.create_profile(con, name='선택 그룹', target_ids=[target['id']])
            self.assertTrue(model.link_hana_accounts(con, jobs.get(con, job_id)))
            self.assertEqual(len(model.list_targets(con)), 1)
            kept = model.get_target(con, target['id'])
            self.assertEqual((kept['display_name'], kept['disabled']), ('사용자 이름', True))
            self.assertEqual(model.get_profile(con, profile['id'])['target_ids'], [target['id']])
            # A later empty response does not erase existing accounts or change their use flag.
            con.execute('UPDATE jobs SET attempt=? WHERE id=?', (dumps({'target_candidates': []}), job_id))
            model.link_hana_accounts(con, jobs.get(con, job_id))
            self.assertEqual(model.list_targets(con), [kept])

    def test_unconfirmed_old_revision_and_other_jobs_do_not_add_accounts(self):
        for changes in ({'outcome': 'unknown'}, {'outcome': 'rejected'}, {'status': 'running'},
                        {'service_verdict': dumps({'accepted': False})}, {'service_verdict': '{}'},
                        {'login_revision': 0}, {'name': 'hometax.targets.discover'}):
            with self.subTest(changes=changes):
                job_id = self.query(**changes)
                with self.db.write() as con:
                    model.link_hana_accounts(con, jobs.get(con, job_id))
                    self.assertEqual(model.list_targets(con), [])

    def test_restart_uses_latest_success_without_rewriting_jobs_or_creating_a_profile(self):
        self.query('11111111111111')
        latest = self.query('22222222222222')
        self.query('33333333333333', outcome='rejected')
        with self.db.read() as con:
            before = [dict(row) for row in con.execute('SELECT * FROM jobs ORDER BY id')]
        for _ in range(2):
            with TestClient(create_app(self.config, db=self.db, dispatcher=False), base_url=ORIGIN):
                pass
        with self.db.read() as con:
            targets = model.list_targets(con)
            self.assertEqual([t['identity']['account_number'] for t in targets], ['22222222222222'])
            self.assertEqual(targets[0]['source_job_id'], latest)
            self.assertEqual(model.list_profiles(con), [])
            self.assertEqual([dict(row) for row in con.execute('SELECT * FROM jobs ORDER BY id')], before)

    def test_linking_failure_keeps_the_bank_success_and_does_not_send_again(self):
        job_id = self.query(status='running')
        with self.db.read() as con:
            job = jobs.get(con, job_id)
        with patch.object(model, 'register_target', side_effect=sqlite3.OperationalError('synthetic failure')):
            status = worker.persist(self.db, None, StepResult(service_verdict={'accepted': True}, outcome='success'),
                                    job=job, step='run', adapter=jobs.registry.get('hana.accounts.list'))
        self.assertEqual(status, 'finished')
        with self.db.read() as con:
            shown = jobs.public(con, jobs.get(con, job_id))
            self.assertEqual((shown['outcome'], shown['service_verdict']), ('success', {'accepted': True}))
            self.assertTrue(shown['local']['account_linking_failed'])
            self.assertEqual(model.list_targets(con), [])

    def test_onesign_transfer_inherits_login_but_explicit_signers_and_invoice_rules_stay(self):
        credential = {'type': 'onesign', 'ref': 'synthetic', 'fingerprint': None}
        login = {'institution': 'hana', 'method': 'onesign', 'credential': dumps(credential), 'signing': '{}'}
        with self.db.read() as con:
            self.assertEqual(model.signing_for(con, login, None, 'transfer_sign'), {'method': 'onesign', **credential})
            explicit = {'method': 'onesign', 'type': 'onesign', 'ref': 'explicit', 'fingerprint': None}
            login['signing'] = dumps({'transfer_sign': explicit})
            self.assertEqual(model.signing_for(con, login, None, 'transfer_sign'), explicit)
            login.update(institution='hometax', method='joint_certificate', signing='{}')
            self.assertIsNone(model.signing_for(con, login, None, 'invoice_sign'))
            login.update(institution='hana')
            self.assertIsNone(model.signing_for(con, login, None, 'transfer_sign'))

    def test_account_link_transaction_failure_cannot_roll_back_the_committed_verdict(self):
        job_id = self.query(status='running')
        with self.db.read() as con:
            job = jobs.get(con, job_id)
        log = io.StringIO()
        with patch.object(model, 'link_hana_accounts', side_effect=sqlite3.OperationalError('synthetic failure')), \
                patch('sys.stderr', log):
            worker.persist(self.db, None, StepResult(service_verdict={'accepted': True}, outcome='success'),
                           job=job, step='run', adapter=jobs.registry.get('hana.accounts.list'))
        with self.db.read() as con:
            shown = jobs.public(con, jobs.get(con, job_id))
        self.assertEqual((shown['status'], shown['outcome'], shown['service_verdict']),
                         ('finished', 'success', {'accepted': True}))
        self.assertIn('result was saved', log.getvalue())
        self.assertNotIn('synthetic failure', log.getvalue())
