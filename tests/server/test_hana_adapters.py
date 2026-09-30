"""Hana adapters against the synthetic bank fixtures of the CLI tests; no sockets."""
import copy
import functools
import io
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

from support import ROOT, ServerCase, synthetic_certificate

sys.path.insert(0, str(ROOT / 'tests'))
import test_hana_onesign as onesign_fixture  # noqa: E402
import test_hana_sessions as joint_fixture  # noqa: E402

from Crypto.PublicKey import ECC  # noqa: E402

from finance_cli.server import jobs, worker  # noqa: E402
from finance_cli.server.db import loads  # noqa: E402
from finance_cli.services.hana import onesign, onesign_transfer, transport  # noqa: E402
from finance_cli.services.hana.onesign_state import State  # noqa: E402


class HanaCase(ServerCase):
    def run_job(self, job_id, secrets=None):
        with self.db.read() as con:
            job = jobs.get(con, job_id)
        stdin = io.StringIO(json.dumps(secrets) + '\n' if secrets is not None else '')
        worker.run(self.db, job_id, job['step'], control=io.StringIO(), stdin=stdin)
        return self.get(f'/jobs/{job_id}').json()

    def submit(self, name, **fields):
        job, created = jobs.submit(self.db, name=name, origin='web:test', **fields)
        self.assertTrue(created)
        return job

    def assertNoLeak(self, value, *needles):
        text = json.dumps(value, ensure_ascii=False)
        for needle in needles:
            self.assertNotIn(needle, text)

    def register_account(self, login_id, job):
        ref = job['result']['accounts'][0]['ref']
        response = self.post(f'/logins/{login_id}/targets', {'job_id': job['id'], 'candidate': ref})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()


class JointPathTests(HanaCase):
    def setUp(self):
        super().setUp()
        self.bank = joint_fixture.FakeBank()
        self.enterContext(patch.object(transport, 'opener', self.bank.opener))
        self.enroll()
        synthetic_certificate('personal')
        (self.root / 'profile.json').write_text(json.dumps({
            'system_header': {'CHNL_SYS_HDPT': {'TRMS_SYS_CD': 'OQF'}}, 'channel_header': {'CNL_HDPT': {'MBLE_OS': 'AOS'}},
            'secure_token': 'SYNTHETIC-TOKEN', 'profile_provenance': {'source': 'synthetic'}}))
        (self.root / 'login-input.json').write_text(json.dumps({
            'push_token': 'push', 'fakefinder_install_id': 'install', 'input_provenance': {'source': 'synthetic'}}))
        self.login = self.post('/logins', {'institution': 'hana', 'method': 'joint_certificate', 'name': '하나 개인',
                                           'credential': 'personal'}).json()

    def link_registration(self):
        from finance_cli.server.registration import link
        with self.db.write() as con:
            linked = link(con, self.login['id'], expected_revision=1, app_profile=self.root / 'profile.json',
                          login_input=self.root / 'login-input.json')
        self.assertFalse(linked['contents_stored_in_database'])
        with self.db.read() as con:
            self.assertNotIn('SYNTHETIC-TOKEN', json.dumps([dict(r) for r in con.execute('SELECT * FROM logins')]))

    def test_login_requires_linked_registration(self):
        refused = self.post('/jobs', {'name': 'hana.login', 'login_id': self.login['id'],
                                      'secrets': {'certificate_password': 'x'}})
        self.assertEqual(refused.json()['error'], 'registration_required:app_profile,login_input')

    def test_login_accounts_history_export_inquiry_security_extend(self):
        self.link_registration()
        wrong = self.run_job(self.submit('hana.login', login_id=self.login['id'])['id'],
                             {'certificate_password': 'wrong'})
        self.assertEqual((wrong['outcome'], wrong['local']['stopped']),
                         ('not_started', 'incorrect_password_or_damaged_credential'))
        self.assertEqual(self.bank.requests, [])  # A wrong password costs no bank request.
        login = self.run_job(self.submit('hana.login', login_id=self.login['id'])['id'],
                             {'certificate_password': 'Synthetic-Password!'})
        self.assertEqual(login['outcome'], 'success', login)
        self.assertNoLeak(login, 'USER-TOKEN', 'ACCESS-TOKEN', 'SERVER-NONCE')
        accounts = self.run_job(self.submit('hana.accounts.list', login_id=self.login['id'])['id'])
        self.assertEqual(accounts['outcome'], 'success', accounts)
        self.assertEqual(accounts['result']['accounts'][0]['account_number'], '••••••••••1234')
        self.assertNoLeak(accounts, joint_fixture.ACCOUNT)
        again = self.run_job(self.submit('hana.accounts.list', login_id=self.login['id'])['id'])
        self.assertNotEqual(again['outcome'], 'success')  # One-shot per session, as in the CLI.
        self.assertIn('stopped', again['local'])
        target = self.register_account(self.login['id'], accounts)
        self.assertEqual(target['identity']['account_number'], '••••••••••1234')
        today = time.strftime('%Y-%m-%d')
        history = self.run_job(self.submit('hana.history.list', login_id=self.login['id'], target_id=target['id'],
                                           input={'start_date': today, 'end_date': today})['id'])
        self.assertEqual(history['outcome'], 'success', history)
        self.assertEqual(history['result']['rows'][0]['amount'], 10)
        self.assertFalse(history['result']['more_available'])
        self.assertEqual([s['stage'] for s in history['service_verdict']['stages']], ['clock', 'account', 'page'])
        export = self.run_job(self.submit('hana.history.export', login_id=self.login['id'], target_id=target['id'],
                                          parent_job_id=history['id'])['id'])
        self.assertEqual(export['outcome'], 'success', export)
        document = self.get(f"/artifacts/{export['artifacts'][0]['id']}").json()
        self.assertNotIn('raw', document['rows'][0])
        self.assertNotIn('scope', document)
        csv = self.get(f"/artifacts/{export['artifacts'][1]['id']}")
        self.assertTrue(csv.headers['content-disposition'].startswith('attachment'))
        inquiry = self.run_job(self.submit('hana.inquiry.history', login_id=self.login['id'], target_id=target['id'],
                                           input={'start_date': today, 'end_date': today})['id'])
        self.assertEqual(inquiry['outcome'], 'success', inquiry)
        self.assertEqual(inquiry['result']['rows'][0]['eChnlTrscAcpnNo'], 'A1')
        security = self.run_job(self.submit('hana.security.query', login_id=self.login['id'],
                                            input={'kind': 'limits'})['id'])
        self.assertEqual(security['outcome'], 'success', security)
        self.assertFalse(security['result']['state_change_requested'])
        self.assertNotIn('raw_value', json.dumps(security))
        extend = self.run_job(self.submit('hana.session.extend', login_id=self.login['id'])['id'])
        self.assertEqual(extend['outcome'], 'success', extend)
        self.assertEqual(extend['result']['login_extension_accepted'], True)


class OneSignPathTests(HanaCase):
    @classmethod
    def setUpClass(cls):
        onesign_fixture.FlowTests.setUpClass()
        cls.flow = onesign_fixture.FlowTests

    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(ECC, 'generate', return_value=self.flow.signing_key))
        state = State('synthetic', onesign_fixture.PASSWORD, copy.deepcopy(self.flow.template)).__enter__()
        try:
            self.services = onesign_fixture.Services(state, self.flow.cert, self.flow.public)
            inputs = {'phone': lambda: {'name': '합성 이름', 'birth7': '9001011', 'phone': '01000000000', 'carrier': '4'},
                      'agree': lambda *a: True, 'sms': lambda: '012345', 'account': lambda rows: rows[0]['acctNo'],
                      'account_password': lambda *a: '6049', 'new_pin': lambda: (onesign_fixture.PIN,) * 2,
                      'confirm_issue': lambda: True}
            serial = iter(range(1000))

            def op(action):
                result = onesign.operate(state, action, f'enroll-{next(serial)}', session='signup', send=True,
                                         inputs=inputs, exchange=self.services)
                self.assertEqual(result['processing_status'], 'completed', (action, result))
            for action in (*onesign.PHONE, 'begin-id'):
                op(action)
            onesign.prepare_identity(state, 'resident', b'\xff\xd8\xff\xc0\x00\x11\x08\x01\x00\x02\x00' + bytes(10),
                                     {'name': '합성 이름', 'issueDate': '2020.02.29', 'birthDate': '900101',
                                      'resident': '1000000'})
            for action in ('identity', 'account', 'issue', 'complete'):
                op(action)
        finally:
            state.__exit__(None, None, None)
        self.enterContext(patch.object(onesign, 'operate', functools.partial(onesign.operate, exchange=self.services)))
        self.enterContext(patch.object(onesign_transfer, 'operate',
                                       functools.partial(onesign_transfer.operate, exchange=self.services)))
        self.enroll()
        self.login = self.post('/logins', {'institution': 'hana', 'method': 'onesign', 'name': '하나 하나인증서',
                                           'credential': 'synthetic', 'signing': {
                                               'transfer_sign': {'method': 'onesign', 'credential': 'synthetic'}}}).json()
        self.vault = {'vault_passphrase': onesign_fixture.PASSWORD}

    def signed_in(self):
        job = self.run_job(self.submit('hana.onesign.login', login_id=self.login['id'])['id'],
                           {**self.vault, 'pin': onesign_fixture.PIN})
        self.assertEqual(job['outcome'], 'success', job)
        return job

    def account_target(self):
        accounts = self.run_job(self.submit('hana.onesign.accounts', login_id=self.login['id'])['id'], self.vault)
        self.assertEqual(accounts['outcome'], 'success', accounts)
        return self.register_account(self.login['id'], accounts)

    def prepare(self, target):
        job = self.submit('hana.transfer.prepare', login_id=self.login['id'], target_id=target['id'], input={
            'recipient_bank_code': '004', 'recipient_account_number': onesign_fixture.RECIPIENT, 'amount_krw': 100})
        return self.run_job(job['id'], {**self.vault, 'account_password': '6049'})

    def confirm(self, job, secrets):
        with patch('finance_cli.server.app.start_with_secrets', return_value='started'):
            response = self.post(f"/jobs/{job['id']}/confirm", {'confirmation': job['awaiting']['digest'],
                                                                'secrets': secrets})
        self.assertEqual(response.status_code, 200, response.text)
        return self.run_job(job['id'], secrets)

    def test_wrong_passphrase_and_pin_stop_before_requests(self):
        before = len(self.services.calls)
        wrong = self.run_job(self.submit('hana.onesign.login', login_id=self.login['id'])['id'],
                             {'vault_passphrase': 'wrong passphrase!', 'pin': onesign_fixture.PIN})
        self.assertEqual((wrong['outcome'], wrong['local']['stopped']), ('not_started', 'store_authentication_failed'))
        short = self.run_job(self.submit('hana.onesign.login', login_id=self.login['id'])['id'],
                             {**self.vault, 'pin': '12'})
        self.assertEqual(short['local']['stopped'], 'pin_six_digits_required')
        self.assertEqual(len(self.services.calls), before)

    def test_transfer_prepare_confirm_execute_once_and_reconcile_separately(self):
        self.signed_in()
        target = self.account_target()
        prepared = self.prepare(target)
        self.assertEqual(prepared['status'], 'awaiting_input', prepared)
        awaiting = prepared['awaiting']
        self.assertEqual((awaiting['next_step'], awaiting['requires']), ('execute', ['vault_passphrase']))
        self.assertEqual(awaiting['preview']['recipient_name'], '합성 수취인')
        self.assertEqual(awaiting['preview']['source_account'], '••••••••••1234')
        self.assertEqual(awaiting['verification'], 'live_untested')
        self.assertLessEqual(awaiting['expires_at'] - time.time(), 600)
        self.assertNoLeak(prepared, '6049', onesign_fixture.PASSWORD)
        sessions = self.get(f"/logins/{self.login['id']}/sessions").json()['sessions']
        self.assertEqual(sessions[0]['state'], 'consumed')  # One login session per transfer.
        refused = self.post('/jobs', {'name': 'hana.transfer.prepare', 'login_id': self.login['id'],
                                      'target_id': target['id'], 'input': {'recipient_bank_code': '004',
                                                                           'recipient_account_number': onesign_fixture.RECIPIENT,
                                                                           'amount_krw': 100},
                                      'secrets': {**self.vault, 'account_password': '6049'}})
        self.assertEqual(refused.json()['error'], 'session_consumed')
        executed = self.confirm(prepared, self.vault)
        self.assertEqual(executed['outcome'], 'success', executed)
        self.assertTrue(executed['service_verdict']['execution_result']['accepted'])
        self.assertFalse(executed['service_verdict']['execution_result']['transfer_confirmed'])
        calls = len(self.services.calls)
        again = self.post(f"/jobs/{prepared['id']}/confirm", {'confirmation': awaiting['digest'], 'secrets': self.vault})
        self.assertEqual(again.json()['status'], 'finished')
        self.assertEqual(len(self.services.calls), calls)
        reconcile = self.run_job(self.submit('hana.transfer.reconcile', login_id=self.login['id'],
                                             target_id=target['id'], parent_job_id=prepared['id'])['id'], self.vault)
        self.assertTrue(reconcile['reconciliation']['candidate_complete'], reconcile)
        self.assertFalse(reconcile['reconciliation']['transfer_confirmed'])
        parent = self.get(f"/jobs/{prepared['id']}").json()
        self.assertEqual(parent['outcome'], 'success')  # Reconciliation never rewrites the execution verdict.
        self.assertTrue(parent['reconciliation']['candidate_complete'])

    def test_pin_route_requires_pin_at_confirmation(self):
        self.services.auth['pinCertYn'] = 'Y'
        self.signed_in()
        target = self.account_target()
        prepared = self.prepare(target)
        self.assertEqual((prepared['awaiting']['next_step'], prepared['awaiting']['requires']),
                         ('execute_pin', ['vault_passphrase', 'pin']))
        missing = self.post(f"/jobs/{prepared['id']}/confirm", {'confirmation': prepared['awaiting']['digest'],
                                                                'secrets': self.vault})
        self.assertEqual(missing.json()['error'], 'step_secrets_required')
        calls = len(self.services.calls)
        bad = self.confirm(prepared, {**self.vault, 'pin': '12'})
        # Refused before anything left: the prepared transfer stays confirmable.
        self.assertEqual((bad['status'], bad['local']['last_confirmation_refused']),
                         ('awaiting_input', 'pin_six_digits_required'))
        self.assertEqual(len(self.services.calls), calls)
        wrong_vault = self.confirm(bad, {'vault_passphrase': 'wrong passphrase!', 'pin': onesign_fixture.PIN})
        self.assertEqual(wrong_vault['local']['last_confirmation_refused'], 'store_authentication_failed')
        executed = self.confirm(wrong_vault, {**self.vault, 'pin': onesign_fixture.PIN})
        self.assertEqual(executed['outcome'], 'success', executed)
        self.assertEqual(executed['local']['previous_steps'][-1]['step'], 'prepare')
        self.assertIn('/requestSecretE', ' '.join(c[1] for c in self.services.calls[calls:]))

    def test_execution_verdict_survives_a_later_local_error(self):
        self.signed_in()
        target = self.account_target()
        prepared = self.prepare(target)
        real = onesign_transfer.operate

        def show_fails(state, action, *args, **kwargs):
            if action == 'show':
                raise RuntimeError('state read failed after execution')
            return real(state, action, *args, **kwargs)
        with patch.object(onesign_transfer, 'operate', show_fails):
            executed = self.confirm(prepared, self.vault)
        self.assertEqual(executed['outcome'], 'success', executed)
        self.assertTrue(executed['service_verdict']['execution_result']['accepted'])

    def test_cancel_prepared_transfer_and_reject_foreign_parent_target(self):
        self.signed_in()
        target = self.account_target()
        prepared = self.prepare(target)
        cancelled = self.post(f"/jobs/{prepared['id']}/cancel")
        self.assertEqual(cancelled.json()['status'], 'cancelled')
        other = self.post('/jobs', {'name': 'hana.transfer.reconcile', 'login_id': self.login['id'],
                                    'target_id': 'tg_0000000000000000', 'parent_job_id': prepared['id'],
                                    'secrets': self.vault})
        self.assertEqual(other.json()['error'], 'parent_target_mismatch')

    def test_unlocked_store_needs_no_passphrase_from_the_browser(self):
        wrong = self.post('/vaults/synthetic/unlock', {'passphrase': 'wrong passphrase!'})
        self.assertEqual((wrong.status_code, wrong.json()['error']), (400, 'store_authentication_failed'))
        locked = self.post('/jobs', {'name': 'hana.onesign.login', 'login_id': self.login['id'],
                                     'secrets': {'pin': onesign_fixture.PIN}})
        self.assertEqual(locked.json()['error'], 'step_secrets_required')
        self.assertEqual(self.post('/vaults/synthetic/unlock', {'passphrase': onesign_fixture.PASSWORD}).status_code, 200)
        self.assertEqual(self.get('/vaults').json()['vaults'], [{'name': 'synthetic', 'unlocked': True}])
        captured = []

        def start(job_id, step, secrets):
            captured.append(dict(secrets))
            return 'started'
        with patch('finance_cli.server.app.start_with_secrets', start):
            login = self.post('/jobs', {'name': 'hana.onesign.login', 'login_id': self.login['id'],
                                        'secrets': {'pin': onesign_fixture.PIN}}).json()
        self.assertEqual(captured[-1], {'vault_passphrase': onesign_fixture.PASSWORD, 'pin': onesign_fixture.PIN})
        self.assertEqual(self.run_job(login['id'], captured[-1])['outcome'], 'success')
        with patch('finance_cli.server.app.start_with_secrets', start):
            accounts = self.post('/jobs', {'name': 'hana.onesign.accounts', 'login_id': self.login['id']}).json()
        accounts = self.run_job(accounts['id'], captured[-1])
        target = self.register_account(self.login['id'], accounts)
        with patch('finance_cli.server.app.start_with_secrets', start):
            prepared = self.post('/jobs', {'name': 'hana.transfer.prepare', 'login_id': self.login['id'],
                                           'target_id': target['id'], 'secrets': {'account_password': '6049'},
                                           'input': {'recipient_bank_code': '004', 'amount_krw': 100,
                                                     'recipient_account_number': onesign_fixture.RECIPIENT}}).json()
        self.assertEqual(captured[-1], {'vault_passphrase': onesign_fixture.PASSWORD, 'account_password': '6049'})
        prepared = self.run_job(prepared['id'], captured[-1])
        with patch('finance_cli.server.app.start_with_secrets', start):
            self.post(f"/jobs/{prepared['id']}/confirm", {'confirmation': prepared['awaiting']['digest']})
        self.assertEqual(captured[-1], {'vault_passphrase': onesign_fixture.PASSWORD})
        self.assertEqual(self.run_job(prepared['id'], captured[-1])['outcome'], 'success')
        with self.db.read() as con:
            dump = json.dumps([dict(r) for table in ('jobs', 'job_events', 'logins', 'sessions')
                               for r in con.execute(f'SELECT * FROM {table}')])
        self.assertNotIn(onesign_fixture.PASSWORD, dump)
        self.assertEqual(self.post('/vaults/synthetic/lock').status_code, 200)
        again = self.post('/jobs', {'name': 'hana.onesign.accounts', 'login_id': self.login['id']})
        self.assertEqual(again.json()['error'], 'step_secrets_required')

    def test_server_start_can_unlock_a_store_in_memory(self):
        from finance_cli.server import cli
        seen = {}
        with patch('getpass.getpass', return_value=onesign_fixture.PASSWORD), \
                patch('uvicorn.run', side_effect=lambda app, **kw: seen.update(app=app)):
            self.assertEqual(cli.main(['start', '--unlock', 'synthetic']), 0)
        self.assertTrue(seen['app'].state.vaults.unlocked('synthetic'))
        output = io.StringIO()
        with patch('getpass.getpass', return_value='wrong passphrase!'), patch('sys.stdout', output), \
                patch('uvicorn.run', side_effect=AssertionError('must not start')):
            self.assertEqual(cli.main(['start', '--unlock', 'synthetic']), 2)
        self.assertEqual(json.loads(output.getvalue())['error'], 'store_authentication_failed')

    def test_expired_confirmation_is_refused(self):
        self.signed_in()
        target = self.account_target()
        prepared = self.prepare(target)
        with self.db.write() as con:
            con.execute('UPDATE jobs SET expires_at=? WHERE id=?', (time.time() - 1, prepared['id']))
        refused = self.post(f"/jobs/{prepared['id']}/confirm", {'confirmation': prepared['awaiting']['digest'],
                                                                'secrets': self.vault})
        self.assertEqual((refused.status_code, refused.json()['error']), (409, 'job_expired'))
        self.assertEqual(self.get(f"/jobs/{prepared['id']}").json()['status'], 'expired')


if __name__ == '__main__':
    unittest.main()
