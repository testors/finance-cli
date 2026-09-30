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

    def query_setup(self):
        from finance_cli.services.hana import ledger_protocol as lp, onesign_queries
        self.enterContext(patch.object(onesign_queries, 'send_http', self.services))
        self.services.override[onesign.ACCOUNTS] = {'mainAcctList': [
            {'acctNo': onesign_fixture.SOURCE, 'curCd': 'KRW', 'acctBal': 1000, 'acctSeqNo': ''}]}
        self.services.override[lp.PATHS['account']] = {'acctInfo': {
            'acctNo': onesign_fixture.SOURCE, 'curCd': 'KRW', 'tailNo': '01'}}
        self.services.override[lp.PATHS['recent']] = {'grid1': [{'trscDt': time.strftime('%Y%m%d'), 'trscAmt': 10,
                                                               'trscSrno': 'PRIVATE-SYNTHETIC-ROW'}],
                                                    'recNcnt1': 1, 'nextTrscYn1': 'N'}
        self.signed_in()
        return self.account_target()

    def query_job(self, target, suffix, parent=None, **input):
        if parent is None:
            input = {'start_date': time.strftime('%Y-%m-%d'), 'end_date': time.strftime('%Y-%m-%d'), **input}
        return self.run_job(self.submit('hana.onesign.' + suffix, login_id=self.login['id'], target_id=target['id'],
                                        input=input, parent_job_id=parent)['id'], self.vault)

    def test_same_login_queries_before_and_after_transfer_and_sealed_receipts(self):
        from finance_cli.services.hana import ledger_protocol as lp
        target = self.query_setup()
        session = self.get('/logins').json()['logins'][0]['current_session_id']
        history = self.query_job(target, 'history.list')
        self.assertEqual(history['outcome'], 'success', history)
        self.assertEqual(history['result']['rows'][0]['amount'], 10)
        self.assertFalse(history['result']['more_available'])
        count = len(self.services.calls)
        detail = self.query_job(target, 'history.detail', history['id'], row=1)
        self.assertEqual(detail['outcome'], 'success', detail)
        self.assertFalse(detail['result']['network_used'])
        exported = self.query_job(target, 'history.export', history['id'])
        self.assertEqual(exported['outcome'], 'success', exported)
        self.assertEqual(count, len(self.services.calls))
        artifact = self.get('/artifacts/' + exported['artifacts'][0]['id']).json()
        self.assertNotIn('scope', artifact)
        self.assertNotIn('raw', artifact['rows'][0])
        self.assertNoLeak(artifact, onesign_fixture.SOURCE, 'PRIVATE-SYNTHETIC-ROW', 'SYNTHETIC-OAT')
        prepared = self.prepare(target)
        self.assertEqual(prepared['status'], 'awaiting_input', prepared)
        executed = self.confirm(prepared, self.vault)
        self.assertEqual(executed['outcome'], 'success', executed)
        row = self.get('/logins').json()['logins'][0]
        self.assertEqual((row['current_session_id'], row['readiness']), (session, 'query_only'))
        count = len(self.services.calls)
        accounts = self.run_job(self.submit('hana.onesign.accounts', login_id=self.login['id'])['id'], self.vault)
        self.assertEqual(accounts['outcome'], 'success', accounts)
        history2 = self.query_job(target, 'history.list')
        inquiry = self.query_job(target, 'inquiry.history')
        inquiry_detail = self.query_job(target, 'inquiry.detail', inquiry['id'], row=1)
        for job in (accounts, history2, inquiry, inquiry_detail):
            self.assertEqual(job['outcome'], 'success', job)
            self.assertEqual(job['session_id'], session)
            self.assertNoLeak(job, onesign_fixture.SOURCE, onesign_fixture.PASSWORD, 'SYNTHETIC-OAT',
                              'PRIVATE-SYNTHETIC-ROW')
        paths = [c[1] for c in self.services.calls[count:]]
        self.assertEqual(paths, [onesign.ACCOUNTS, lp.PATHS['clock'], lp.PATHS['account'], lp.PATHS['recent'],
                                 onesign_transfer.PATHS['history'], onesign_transfer.PATHS['detail']])
        for _, path, headers, _ in self.services.calls[count:]:
            self.assertTrue(headers.get('one-access-token'), path)
        # No plaintext receipts in job files or OneSign storage.
        for path in self.root.rglob('*'):
            if path.is_file() and path.suffix in ('.json', '.bin', '.csv'):
                self.assertNotIn(b'PRIVATE-SYNTHETIC-ROW', path.read_bytes(), str(path))
        with State('synthetic', onesign_fixture.PASSWORD) as state:
            self.assertTrue(any(s.get('transfer_attempted') for s in state.snapshot()['sessions'].values()))

    def test_query_pagination_continues_once_and_export_keeps_duplicates(self):
        from finance_cli.services.hana import ledger_protocol as lp
        target = self.query_setup()
        first = self.services.override[lp.PATHS['recent']]
        first.update(recNcnt1=20, nextTrscYn1='Y', dtlsSeqNo1=2, trscSeqNo1=3, nextTrscDt1='20260930')
        history = self.query_job(target, 'history.list')
        self.assertEqual(history['outcome'], 'success', history)
        self.assertTrue(history['result']['more_available'], history)
        first.update(nextTrscYn1='N', recNcnt1=1)
        count = len(self.services.calls)
        more = self.query_job(target, 'history.more', history['id'])
        self.assertEqual(more['outcome'], 'success', more)
        self.assertTrue(more['result']['pagination_complete'])
        sent = json.loads(self.services.calls[-1][3])
        self.assertEqual((sent['dtlsSeqNo'], sent['trscSeqNo']), (2, 3))
        again = self.query_job(target, 'history.more', history['id'])
        self.assertNotEqual(again['outcome'], 'success', again)
        self.assertEqual(len(self.services.calls), count + 1)
        exported = self.query_job(target, 'history.export', more['id'])
        self.assertEqual(exported['result']['row_count'], 2)
        document = self.get('/artifacts/' + exported['artifacts'][0]['id']).json()
        self.assertFalse(document['duplicates_removed'])
        self.assertEqual(document['issues'][-1]['issue'], 'identical_row_preserved')

    def test_query_bad_cursor_preserves_page_and_detail_uses_saved_identifiers(self):
        from finance_cli.services.hana import ledger_protocol as lp
        target = self.query_setup()
        value = self.services.override[lp.PATHS['recent']]
        value.update(recNcnt1=20, nextTrscYn1='Y')  # Missing trscSeqNo1: do not infer a next page.
        value['grid1'][0].update(atfMgntNo='SYNTHETIC-DETAIL', balFlctDvCd='2', atfPrfRankCd='314')
        self.services.override[lp.PATHS['automatic']] = {'trnsAmt': 10, 'wdrwAcctNo': onesign_fixture.SOURCE,
                                                        'cookie': 'SYNTHETIC-COOKIE'}
        history = self.query_job(target, 'history.list')
        self.assertEqual(history['outcome'], 'success', history)
        self.assertFalse(history['result']['more_available'])
        self.assertFalse(history['result']['pagination_complete'])
        count = len(self.services.calls)
        more = self.query_job(target, 'history.more', history['id'])
        self.assertNotEqual(more['outcome'], 'success', more)
        self.assertEqual(len(self.services.calls), count)
        detail = self.query_job(target, 'history.detail', history['id'], row=1)
        self.assertEqual(detail['outcome'], 'success', detail)
        self.assertEqual(detail['result']['source'], 'bank_detail')
        self.assertEqual(self.services.calls[-1][1], lp.PATHS['automatic'])
        self.assertEqual(json.loads(self.services.calls[-1][3])['atfMgntNo'], 'SYNTHETIC-DETAIL')
        self.assertNoLeak(detail, onesign_fixture.SOURCE, 'SYNTHETIC-COOKIE')

    def test_query_acceptance_survives_bad_data_and_response_storage_failure(self):
        from finance_cli.services.hana import ledger_protocol as lp
        target = self.query_setup()
        self.services.override[lp.PATHS['recent']] = b'not JSON'
        malformed = self.query_job(target, 'history.list')
        self.assertEqual(malformed['outcome'], 'success', malformed)
        self.assertIsNone(malformed['result']['rows'])
        self.assertTrue(malformed['local']['saved_rows_unreadable'])
        real_record = State.record

        def fail_receipt(state, run, name, value):
            if run.startswith('query-') and name == 'http-0001-response':
                raise OSError('synthetic disk failure')
            return real_record(state, run, name, value)
        count = len(self.services.calls)
        with patch.object(State, 'record', fail_receipt):
            failed = self.query_job(target, 'inquiry.history')
        self.assertEqual(failed['outcome'], 'success', failed)
        self.assertTrue(failed['service_verdict']['accepted'])
        self.assertEqual(failed['service_verdict']['processing_status'], 'response_storage_failed')
        self.assertIsNone(failed['result']['rows'])
        self.assertEqual(len(self.services.calls), count + 1)

    def test_query_rejection_or_transport_loss_does_not_refresh_retry_or_continue(self):
        from finance_cli.services.hana import ledger_protocol as lp, onesign_queries
        target = self.query_setup()
        count = len(self.services.calls)
        self.services.override[lp.PATHS['account']] = OSError('synthetic response lost')
        lost = self.query_job(target, 'history.list')
        self.assertEqual(lost['outcome'], 'unknown', lost)
        self.assertEqual([c[1] for c in self.services.calls[count:]], [lp.PATHS['clock'], lp.PATHS['account']])
        count = len(self.services.calls)

        def rejected(*args):
            status, headers, raw, cookies = self.services(*args)
            return 403, headers, raw, cookies
        with patch.object(onesign_queries, 'send_http', rejected):
            refused = self.query_job(target, 'inquiry.history')
        self.assertEqual(refused['outcome'], 'rejected', refused)
        self.assertEqual(len(self.services.calls), count + 1)

    def test_queries_refuse_expired_stale_superseded_sessions_and_recheck_queued_jobs(self):
        from finance_cli.server import model
        target = self.query_setup()
        prepared = self.prepare(target)
        self.assertEqual(prepared['status'], 'awaiting_input', prepared)
        with self.db.read() as con:
            session = model.current_session(con, self.login['id'])['id']
        count = len(self.services.calls)
        for state, note in (('expired', 'transfer_prepared'), ('stale', 'transfer_prepared'),
                            ('consumed', 'superseded_by_synthetic'), ('consumed', None)):
            with self.db.write() as con:
                model.mark_session(con, session, state, note)
            for name in ('accounts', 'history.list', 'inquiry.history'):
                response = self.post('/jobs', {'name': 'hana.onesign.' + name, 'login_id': self.login['id'],
                    'target_id': target['id'], 'secrets': self.vault,
                    'input': {} if name == 'accounts' else {'start_date': '2026-10-01', 'end_date': '2026-10-01'}})
                self.assertEqual(response.json()['error'], 'session_' + state)
            self.assertEqual(self.get('/logins').json()['logins'][0]['readiness'], 'login_required')
        with self.db.write() as con:
            model.mark_session(con, session, 'consumed', 'transfer_prepared')
        queued = self.submit('hana.onesign.accounts', login_id=self.login['id'])
        with self.db.write() as con:
            model.mark_session(con, session, 'consumed', 'superseded_by_synthetic')
        checked = self.run_job(queued['id'], self.vault)
        self.assertEqual(checked['local']['stopped'], 'fixed_session_not_usable')
        self.assertEqual(len(self.services.calls), count)

    def test_query_requires_current_session_accounts_and_cannot_mix_receipts(self):
        from finance_cli.services.hana import onesign_queries
        target = self.query_setup()
        history = self.query_job(target, 'history.list')
        self.assertEqual(history['outcome'], 'success', history)
        with self.db.read() as con:
            saved = json.loads(jobs.get(con, history['id'])['attempt'])['history']['receipts']['page']
        self.signed_in()
        count = len(self.services.calls)
        missing = self.query_job(target, 'history.list')
        self.assertEqual(missing['local']['stopped'], 'accounts_query_required_in_session')
        self.assertEqual(len(self.services.calls), count)
        with State('synthetic', onesign_fixture.PASSWORD) as state:
            current = list(state.snapshot()['sessions'])[-1]
            source = onesign_queries.Queries(state, current)
            with self.assertRaisesRegex(ValueError, 'query_login_identity_changed'):
                source.read_receipt(saved)
        foreign = self.post('/jobs', {'name': 'hana.onesign.history.export', 'login_id': self.login['id'],
                                      'target_id': target['id'], 'parent_job_id': history['id'], 'secrets': self.vault})
        self.assertEqual(foreign.json()['error'], 'session_consumed')

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
