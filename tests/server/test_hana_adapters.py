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

from finance_cli.server import jobs, worker, session_activity  # noqa: E402
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
        self.assertAbsent(json.dumps(value, ensure_ascii=False), *needles)

    def register_account(self, login_id, job):
        ref = job['result']['accounts'][0]['ref']
        target_id = job['result']['candidate_targets'][ref]
        targets = self.get(f'/logins/{login_id}/targets').json()['targets']
        return next(target for target in targets if target['id'] == target_id)


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

    def test_joint_idle_clock_tracks_http_and_blocks_expired_query(self):
        self.link_registration()
        at = time.time()
        with patch.object(session_activity, 'now', return_value=at):
            self.run_job(self.submit('hana.login', login_id=self.login['id'])['id'],
                         {'certificate_password': 'Synthetic-Password!'})
        with patch.object(session_activity, 'now', return_value=at + 589):
            self.run_job(self.submit('hana.accounts.list', login_id=self.login['id'])['id'])
            row = self.get('/logins').json()['logins'][0]
            self.assertEqual(row['session']['last_request_at'], at + 589)
        count = len(self.bank.requests)
        with patch.object(session_activity, 'now', return_value=at + 1179):
            refused = self.post('/jobs', {'name': 'hana.accounts.list', 'login_id': self.login['id']})
            self.assertEqual(refused.json()['error'], 'session_idle_expired')
        self.assertEqual(count, len(self.bank.requests))

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
        self.assertEqual(accounts['result']['accounts'][0]['account_number'], joint_fixture.ACCOUNT)
        self.assertEqual(accounts['result']['rows'][0]['acctNo'], joint_fixture.ACCOUNT)
        self.assertNoLeak(accounts['events'], joint_fixture.ACCOUNT)
        again = self.run_job(self.submit('hana.accounts.list', login_id=self.login['id'])['id'])
        self.assertNotEqual(again['outcome'], 'success')  # One-shot per session, as in the CLI.
        self.assertIn('stopped', again['local'])
        target = self.register_account(self.login['id'], accounts)
        self.assertEqual(target['identity']['account_number'], joint_fixture.ACCOUNT)
        today = time.strftime('%Y-%m-%d')
        history = self.run_job(self.submit('hana.history.list', login_id=self.login['id'], target_id=target['id'],
                                           input={'start_date': today, 'end_date': today})['id'])
        self.assertEqual(history['outcome'], 'success', history)
        self.assertEqual(history['result']['rows'][0]['amount'], 10)
        self.assertTrue(history['result']['pagination_complete'])
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


    def fresh_query_setup(self):
        self.link_registration()
        self.joint_login()
        accounts = self.run_job(self.submit('hana.accounts.list', login_id=self.login['id'])['id'])
        return self.register_account(self.login['id'], accounts)

    def joint_login(self):
        return self.run_job(self.submit('hana.login', login_id=self.login['id'])['id'],
                            {'certificate_password': 'Synthetic-Password!'})

    def joint_query(self, target, name, parent=None, **input):
        today = time.strftime('%Y-%m-%d')
        return self.run_job(self.submit(name, login_id=self.login['id'], target_id=target['id'], parent_job_id=parent,
                                        input=input or (None if parent else {'start_date': today, 'end_date': today}))['id'])

    def two_period_setup(self):
        """A server day that puts 2024-10-10 on the past side of the two-year boundary."""
        target = self.fresh_query_setup()
        self.bank.overrides['/retrieveCurrDtm'] = joint_fixture.business({'dt': '20261010', 'tm': '120000', 'bussDdYn': 'Y'})
        self.bank.overrides['/retrievetxnInoAmtPst'] = joint_fixture.business({
            'r01': [{'trscDt': '20241010', 'trscAmt': 5}], 'r01Rowcount': 1})
        return target, {'start_date': '2024-10-01', 'end_date': '2024-10-20'}

    def test_history_collects_recent_and_past_in_one_job_and_follow_ups_reach_every_page(self):
        target, period = self.two_period_setup()
        count = len(self.bank.requests)
        history = self.joint_query(target, 'hana.history.list', **period)
        self.assertEqual(history['outcome'], 'success', history)
        self.assertTrue(history['result']['pagination_complete'])
        self.assertEqual([row['amount'] for row in history['result']['rows']], [10, 5])
        self.assertEqual([(s['stage'], s['kind']) for s in history['service_verdict']['stages']],
                         [('clock', 'clock'), ('account', 'account'), ('page', 'recent'), ('page', 'past')])
        bodies = {r[1].split('/')[-1]: json.loads(r[3]) for r in self.bank.requests[count:]}
        self.assertEqual(len(self.bank.requests), count + 4)
        self.assertEqual(bodies['retrievetxnNrstTrsc']['inqStrDt'], '20241011')
        self.assertEqual(bodies['retrievetxnInoAmtPst']['inqEndDt'], '20241010')
        self.assertNoLeak(history, 'USER-TOKEN', 'account-history-')
        count = len(self.bank.requests)
        # A row is addressed in the merged list; the second row is the first row of the past page.
        detail = self.joint_query(target, 'hana.history.detail', history['id'], row=2)
        self.assertEqual((detail['outcome'], detail['result']['source']), ('success', 'saved_ledger_row'), detail)
        self.assertEqual(detail['result']['detail']['amount'], 5)
        beyond = self.joint_query(target, 'hana.history.detail', history['id'], row=3)
        self.assertEqual((beyond['outcome'], beyond['local']['stopped']), ('not_started', 'detail_row_out_of_range'))
        export = self.joint_query(target, 'hana.history.export', history['id'])
        document = self.get(f"/artifacts/{export['artifacts'][0]['id']}").json()
        self.assertEqual([row['kind'] for row in document['rows']], ['recent', 'past'])
        self.assertTrue(document['pagination_complete'])
        self.assertEqual(len(self.bank.requests), count)
        # The next-page job is gone; the same query can be asked again in the same login.
        self.assertEqual(self.post('/jobs', {'name': 'hana.history.more', 'login_id': self.login['id'],
                                             'target_id': target['id'], 'parent_job_id': history['id']}).status_code, 404)
        again = self.joint_query(target, 'hana.history.list', **period, order='asc')
        self.assertEqual([row['amount'] for row in again['result']['rows']], [5, 10])
        repeated = self.joint_query(target, 'hana.history.list', **period)
        self.assertEqual(repeated['outcome'], 'success', repeated)
        self.assertEqual(len(self.bank.requests), count + 8)

    def test_history_keeps_received_pages_when_a_later_period_fails_and_never_retries(self):
        target, period = self.two_period_setup()
        self.bank.overrides['/retrievetxnInoAmtPst'] = (500, {}, b'{}')
        count = len(self.bank.requests)
        history = self.joint_query(target, 'hana.history.list', **period)
        self.assertEqual(history['outcome'], 'partial_success', history)
        self.assertFalse(history['result']['pagination_complete'])
        self.assertEqual([row['amount'] for row in history['result']['rows']], [10])
        self.assertEqual([s['accepted'] for s in history['service_verdict']['stages']], [True, True, True, False])
        self.assertEqual(len(self.bank.requests), count + 4)
        export = self.joint_query(target, 'hana.history.export', history['id'])
        self.assertEqual(export['outcome'], 'success', export)
        document = self.get(f"/artifacts/{export['artifacts'][0]['id']}").json()
        self.assertEqual((document['row_count'], document['pagination_complete']), (1, False))
        self.assertFalse(export['artifacts'][0]['complete'])
        self.assertEqual(len(self.bank.requests), count + 4)

    def test_history_stop_before_any_page_keeps_its_reason_and_the_accepted_stages(self):
        target = self.fresh_query_setup()
        self.bank.overrides['/retrieveSessAcctInfo'] = joint_fixture.business({'acctInfo': {
            'acctNo': joint_fixture.ACCOUNT, 'curCd': 'USD', 'tailNo': '01'}})
        count = len(self.bank.requests)
        stopped = self.joint_query(target, 'hana.history.list')
        self.assertEqual((stopped['outcome'], stopped['local']['stopped']),
                         ('unknown', 'this_account_uses_a_different_ledger_screen'), stopped)
        self.assertEqual([s['accepted'] for s in stopped['service_verdict']['stages']], [True, True])
        self.assertIsNone(stopped['result'])
        self.assertEqual(len(self.bank.requests), count + 2)

    def test_single_page_job_recorded_before_the_unified_query_still_exports_and_shows_details(self):
        from finance_cli.server.adapters.hana import send_two_step
        from finance_cli.services.hana import ledger
        target = self.fresh_query_setup()
        job = self.submit('hana.history.list', login_id=self.login['id'], target_id=target['id'],
                          input={'start_date': time.strftime('%Y-%m-%d'), 'end_date': time.strftime('%Y-%m-%d')})
        with self.db.read() as con:
            name = con.execute('SELECT name FROM sessions WHERE id=?', (job['session_id'],)).fetchone()[0]
        path = self.root / 'earlier-input.json'
        path.write_text(json.dumps({'account_index': 1, 'start_date': time.strftime('%Y%m%d'),
                                    'end_date': time.strftime('%Y%m%d')}))
        receipts = {}
        for stage in ('clock', 'account', 'page'):
            receipts[stage] = send_two_step(ledger.run, name, stage, path, **(
                {'clock': receipts['clock'], 'account_info': receipts['account']} if stage == 'page' else {}))['receipt_directory']
        with self.db.write() as con:
            con.execute("UPDATE jobs SET status='finished', outcome='success', attempt=? WHERE id=?", (json.dumps(
                {'history': {'path': str(path), 'receipts': receipts, 'more': False}}), job['id']))
        count = len(self.bank.requests)
        detail = self.joint_query(target, 'hana.history.detail', job['id'], row=1)
        self.assertEqual((detail['outcome'], detail['result']['detail']['amount']), ('success', 10), detail)
        export = self.joint_query(target, 'hana.history.export', job['id'])
        self.assertEqual((export['outcome'], export['result']['row_count']), ('success', 1), export)
        self.assertEqual(len(self.bank.requests), count)

    def test_history_and_inquiry_prime_fresh_joint_session_once(self):
        target = self.fresh_query_setup()
        for name in ('hana.history.list', 'hana.inquiry.history'):
            with self.subTest(name=name):
                self.joint_login()
                count = len(self.bank.requests)
                result = self.joint_query(target, name)
                self.assertEqual(result['outcome'], 'success', result)
                paths = [r[1] for r in self.bank.requests[count:]]
                self.assertTrue(paths[0].endswith(joint_fixture.PATHS['accounts']))
                self.assertEqual(sum(p.endswith(joint_fixture.PATHS['accounts']) for p in paths), 1)
                self.assertTrue(result['service_verdict']['stages'][0]['accepted'])
                count = len(self.bank.requests)
                other = 'hana.inquiry.history' if name == 'hana.history.list' else 'hana.history.list'
                cached = self.joint_query(target, other)
                self.assertEqual(cached['outcome'], 'success', cached)
                self.assertFalse(any(r[1].endswith(joint_fixture.PATHS['accounts'])
                                     for r in self.bank.requests[count:]))

    def test_joint_account_rejection_and_save_failure_are_not_replayed(self):
        from finance_cli.services.hana import store
        target = self.fresh_query_setup()
        self.joint_login()
        self.bank.overrides[joint_fixture.PATHS['accounts']] = joint_fixture.business({}, code='1')
        count = len(self.bank.requests)
        rejected = self.joint_query(target, 'hana.history.list')
        self.assertEqual(rejected['outcome'], 'rejected', rejected)
        self.assertFalse(rejected['service_verdict']['stages'][0]['accepted'])
        self.joint_query(target, 'hana.inquiry.history')
        self.assertEqual(len(self.bank.requests), count + 1)
        del self.bank.overrides[joint_fixture.PATHS['accounts']]
        self.joint_login()
        count = len(self.bank.requests)
        real_write = store.write_new

        def fail_selection(path, value):
            if path.name == 'account-selection.json':
                raise OSError('synthetic disk failure')
            return real_write(path, value)
        with patch.object(store, 'write_new', fail_selection):
            failed = self.joint_query(target, 'hana.history.list')
        self.assertEqual(failed['outcome'], 'not_started', failed)
        self.assertTrue(failed['service_verdict']['stages'][0]['accepted'])
        self.joint_query(target, 'hana.inquiry.history')
        self.assertEqual(len(self.bank.requests), count + 1)


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
                                           'credential': 'synthetic'}).json()
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

    def test_unified_cli_uses_encrypted_session_and_collects_all_pages(self):
        from finance_cli.services.hana import cli, onesign_cli, ledger_protocol as lp
        self.query_setup()
        self.services.override[lp.PATHS['clock']] = {'dt': '20261010', 'tm': '120000', 'bussDdYn': 'Y'}
        self.services.override[lp.PATHS['past']] = {'r01': [], 'r01Rowcount': 0}
        original = self.services.__call__
        requests = []
        def pages(scope, method, url, headers, body, cookies, timeout):
            if url.endswith(lp.PATHS['recent']):
                values = json.loads(body)
                requests.append(values)
                more = values['trscSeqNo'] == 0
                self.services.override[lp.PATHS['recent']] = {
                    'grid1': [{'trscAmt': 10}] * (20 if more else 1),
                    'recNcnt1': 20 if more else 1, 'nextTrscYn1': 'Y' if more else 'N', 'trscSeqNo1': 7}
            return original(scope, method, url, headers, body, cookies, timeout)
        from finance_cli.services.hana import onesign_queries
        args = cli.build().parse_args(['history', '--name', 'synthetic', '--account', onesign_fixture.SOURCE,
                                      '--start', '20241001', '--end', '20241020', '--send'])
        with patch.object(onesign_cli, 'password', return_value=onesign_fixture.PASSWORD), \
             patch.object(onesign_queries, 'send_http', side_effect=pages):
            result = cli.dispatch(args)
        self.assertTrue(result['complete'], result)
        self.assertTrue(result['accepted'])
        self.assertEqual(len(result['transactions']), 21)
        self.assertEqual([p['kind'] for p in result['pages']], ['recent', 'recent', 'past'])
        self.assertEqual([r['trscSeqNo'] for r in requests], [0, 7])
        self.assertNoLeak(result, onesign_fixture.PASSWORD, 'SYNTHETIC-LOGIN')

    def query_job(self, target, suffix, parent=None, **input):
        if parent is None:
            input = {'start_date': time.strftime('%Y-%m-%d'), 'end_date': time.strftime('%Y-%m-%d'), **input}
        return self.run_job(self.submit('hana.onesign.' + suffix, login_id=self.login['id'], target_id=target['id'],
                                        input=input, parent_job_id=parent)['id'], self.vault)

    def security_job(self, kind='limits'):
        return self.run_job(self.submit('hana.onesign.security.query', login_id=self.login['id'],
                                       input={'kind': kind})['id'], self.vault)

    def test_security_queries_use_signed_login_without_accounts_and_preserve_wire_contracts(self):
        from finance_cli.server import model
        from finance_cli.services.hana import hana_protocol, onesign_queries, security_protocol
        self.enterContext(patch.object(onesign_queries, 'send_http', self.services))
        self.signed_in()
        session = self.get('/logins').json()['logins'][0]['current_session_id']
        row = {'otpSeqNo': '910123456789', 'scrtMdclStCd': '903', 'scrtMdclStNm': '잠김',
               'otpVndrEntrNm': '합성 제조사', 'cookie': 'PRIVATE-COOKIE', 'token': 'PRIVATE-TOKEN'}
        values = {
            'limits': {'dd1TrnsLimAmt': '1234', 'bot1TrnsLimAmt': 120, 'scrtMdclDvCd': '1'},
            'limit-exception': {'oldDd1TrnsLimAmt': None, 'dd1TrnsPossLimAmt': '10000'},
            'security-media': {'errNcnt': 0, 'otpInfoSvcRecOutDto': [row, None],
                               'scrtCrdInfoSvcRecOutDto': {'secret': 'PRIVATE-CARD'}},
            'otp': {'allNcnt': '0', 'otpInfoInqSvcRecOutDto': [row]},
            'otp-accident': {'acdtRcvryPoss': False, 'otpAcdtRcvryInqSvcOutRecDto': [row]},
            'mobile-otp': {'issu': True, 'lgin': False, 'mbleOtpApcInqSvcOutRecDto': [row]},
        }
        count = len(self.services.calls)
        for kind, (path, omitted, screen) in security_protocol.QUERIES.items():
            with self.subTest(kind=kind):
                self.services.override[path] = {**values[kind], 'token': 'PRIVATE-TOKEN'}
                job = self.security_job(kind)
                self.assertEqual(job['outcome'], 'success', job)
                self.assertEqual(job['session_id'], session)
                self.assertIsNone(job['target_id'])
                self.assertFalse(job['result']['state_change_requested'])
                scope, sent_path, headers, body = self.services.calls[-1]
                self.assertEqual((scope, sent_path, body), ('bank', path, None if omitted else b'{}'))
                self.assertEqual(hana_protocol.decode_header(headers['hana-com-header'])['CNL_HDPT']['SCRN_ID'], screen)
                self.assertTrue(headers.get('one-access-token'))  # Including the public mobile OTP inquiry.
                self.assertEqual('content-type' in headers, not omitted)
                self.assertNoLeak(job, 'PRIVATE-COOKIE', 'PRIVATE-TOKEN', 'PRIVATE-CARD', '910123456789',
                                  onesign_fixture.PASSWORD, 'SYNTHETIC-LOGIN')
                observed = job['result']['observation']
                if kind == 'limits':
                    self.assertEqual(observed['fields']['dd1TrnsLimAmt'], '1234')
                    self.assertEqual(observed['fields']['bot1TrnsLimAmt'], 120)
                if kind == 'security-media':
                    self.assertIsNone(observed['rows'][1])
                    self.assertEqual(observed['rows'][0]['otpSeqNo'], '••••••••6789')
                if kind == 'mobile-otp':
                    self.assertTrue(observed['display']['locked'])
        self.assertEqual([c[1] for c in self.services.calls[count:]], [v[0] for v in security_protocol.QUERIES.values()])
        with self.db.write() as con:
            model.mark_session(con, session, 'consumed', 'transfer_prepared')
        self.assertEqual(self.security_job()['outcome'], 'success')
        with self.db.read() as con:
            current = model.current_session(con, self.login['id'])
            self.assertEqual((current['id'], current['state'], current['note']), (session, 'consumed', 'transfer_prepared'))
        for path in self.root.rglob('*'):
            if path.is_file() and path.suffix in ('.json', '.bin'):
                for secret in (b'PRIVATE-TOKEN', b'PRIVATE-CARD', b'PRIVATE-COOKIE'):
                    self.assertNotIn(secret, path.read_bytes(), str(path))
        feature = next(f for f in self.get('/capabilities').json()['features'] if f['id'] == 'hana-security')
        self.assertIn('hana.onesign.security.query', [j['name'] for j in feature['jobs']])

    def test_security_queries_preserve_acceptance_and_never_retry_rejections_or_losses(self):
        from finance_cli.services.hana import onesign_queries, security_protocol
        self.enterContext(patch.object(onesign_queries, 'send_http', self.services))
        self.signed_in()
        path = security_protocol.QUERIES['limits'][0]
        self.services.override[path] = b'not JSON'
        malformed = self.security_job()
        self.assertEqual(malformed['outcome'], 'success', malformed)
        self.assertIn('non_object_body', malformed['result']['observation']['diagnostics'])
        self.services.override[path] = b''
        empty = self.security_job()
        self.assertEqual(empty['outcome'], 'success', empty)
        self.assertIn('empty_body', empty['result']['observation']['diagnostics'])
        real_record = State.record

        def fail_receipt(state, run, name, value):
            if run.startswith('query-') and name == 'http-0001-response':
                raise OSError('synthetic disk failure')
            return real_record(state, run, name, value)

        with patch.object(State, 'record', fail_receipt):
            failed = self.security_job()
        self.assertEqual(failed['outcome'], 'success', failed)
        self.assertEqual(failed['service_verdict']['processing_status'], 'response_storage_failed')
        self.assertTrue(failed['local']['saved_rows_unreadable'])
        count = len(self.services.calls)
        self.services.override[path] = OSError('synthetic timeout')
        lost = self.security_job()
        self.assertEqual(lost['outcome'], 'unknown', lost)
        self.assertEqual(len(self.services.calls), count + 1)
        self.services.override[path] = {}

        def rejected(*args):
            status, headers, raw, cookies = self.services(*args)
            return 403, headers, raw, cookies

        with patch.object(onesign_queries, 'send_http', rejected):
            refused = self.security_job()
        self.assertEqual(refused['outcome'], 'rejected', refused)
        self.assertEqual(len(self.services.calls), count + 2)
        with self.assertRaisesRegex(ValueError, 'invalid_kind'):
            self.security_job('update-limit')
        row = self.get('/logins').json()['logins'][0]
        with patch.object(session_activity, 'now', return_value=row['session']['idle_expires_at']):
            with self.assertRaisesRegex(jobs.NotReady, 'session_idle_expired'):
                self.security_job()
        self.assertEqual(len(self.services.calls), count + 2)

    def test_onesign_login_extension_sends_one_native_request_and_keeps_the_bank_verdict(self):
        from finance_cli.services.hana import extend as native, hana_protocol, onesign_session
        self.signed_in()
        calls = []
        head = [('hana-sys-header', hana_protocol.encode_header({'CHNL_SYS_HDPT': {'PROC_RSLT_DV_CD': '0'}})),
                ('hana-com-header', hana_protocol.encode_header({'CNL_HDPT': {}}))]

        def bank(status):
            def exchange(scope, method, url, headers, body, cookies, timeout):
                calls.append((scope, method, url, body))
                return status, head if status == 200 else [], b'', cookies
            return functools.partial(onesign_session.extend, exchange=exchange)

        def activity():
            with self.db.read() as con:
                return con.execute('SELECT last_request_at FROM session_activity').fetchone()[0]
        before = activity()
        time.sleep(0.02)
        with patch.object(onesign_session, 'extend', bank(200)):
            job = self.run_job(self.submit('hana.onesign.session.extend', login_id=self.login['id'])['id'], self.vault)
        self.assertEqual((job['outcome'], job['service_verdict']['login_extension_accepted']), ('success', True), job)
        self.assertEqual(calls, [('bank', 'POST', hana_protocol.API + native.PATH, b'')])
        self.assertGreater(activity(), before, 'the request itself is the session activity')
        self.assertNoLeak(job, onesign_fixture.PASSWORD)
        with patch.object(onesign_session, 'extend', bank(500)):
            job = self.run_job(self.submit('hana.onesign.session.extend', login_id=self.login['id'])['id'], self.vault)
        self.assertEqual(job['outcome'], 'rejected', job)
        self.assertEqual(len(calls), 2, 'a rejected extension is not sent again')

    def test_idle_boundary_polling_restart_and_new_login(self):
        from finance_cli.server.db import Database
        at = time.time()
        with patch.object(session_activity, 'now', return_value=at):
            self.signed_in()
        with patch.object(session_activity, 'now', return_value=at + 589):
            queued = self.submit('hana.onesign.accounts', login_id=self.login['id'])
            row = self.get('/logins').json()['logins'][0]
            self.assertEqual(row['session']['last_request_at'], at)
            self.assertFalse(row['session']['idle_expired'])
            self.get('/jobs')
            self.get('/vaults')
        count = len(self.services.calls)
        with patch.object(session_activity, 'now', return_value=at + 590):
            row = self.get('/logins').json()['logins'][0]
            self.assertEqual(row['readiness'], 'login_required')
            self.assertTrue(row['session']['idle_expired'])
            self.assertEqual(row['session']['last_request_at'], at)
            with Database(self.db.file()).read() as con:
                session = con.execute('SELECT * FROM sessions WHERE id=?', (row['current_session_id'],)).fetchone()
                self.assertTrue(session_activity.metadata(con, session, 'hana')['idle_expired'])
                self.assertEqual((session['state'], json.loads(session['verdict'])), ('usable', {'accepted': True}))
            with self.assertRaisesRegex(jobs.NotReady, '^session_idle_expired$'):
                self.submit('hana.onesign.accounts', login_id=self.login['id'])
            stopped = self.run_job(queued['id'], self.vault)
            self.assertEqual((stopped['outcome'], stopped['local']['stopped']), ('not_started', 'session_idle_expired'))
            self.assertEqual(count, len(self.services.calls))
            self.signed_in()  # Explicit login is allowed; no automatic query follows it.
            fresh = self.get('/logins').json()['logins'][0]
            self.assertNotEqual(fresh['current_session_id'], row['current_session_id'])
            self.assertEqual(fresh['session']['last_request_at'], at + 590)
            self.assertFalse(fresh['session']['idle_expired'])

    def test_idle_expiry_during_secret_entry_and_at_send_boundary(self):
        at = time.time()
        with patch.object(session_activity, 'now', return_value=at):
            self.signed_in()
        count = len(self.services.calls)
        with patch.object(session_activity, 'now', return_value=at + 589) as clock:
            job = self.submit('hana.onesign.accounts', login_id=self.login['id'])

            def delayed_input(stream, names):
                clock.return_value = at + 590
                return dict(self.vault)

            with patch.object(worker, 'read_secrets', delayed_input):
                stopped = self.run_job(job['id'], self.vault)
            self.assertEqual((stopped['outcome'], stopped['local']['stopped']), ('not_started', 'session_idle_expired'))
            self.assertEqual(count, len(self.services.calls))
            # A slow preparation after reserve() is checked again at HTTP send.
            clock.return_value = at + 589
            job = self.submit('hana.onesign.accounts', login_id=self.login['id'])
            original = onesign.operate

            def delayed_send(*args, **kwargs):
                clock.return_value = at + 590
                return original(*args, **kwargs)

            with patch.object(onesign, 'operate', delayed_send):
                stopped = self.run_job(job['id'], self.vault)
            self.assertEqual(stopped['local']['stopped'], 'session_idle_expired')
            self.assertEqual(stopped['service_verdict']['error'], 'session_idle_expired')
            self.assertIsNone(stopped['service_verdict']['accepted'])
            self.assertEqual(count, len(self.services.calls))
            self.assertEqual(self.get('/logins').json()['logins'][0]['session']['last_request_at'], at)
            # Worker admission can also cross the deadline before its "ready" handshake.
            clock.return_value = at + 589

            def delayed_worker(job_id, step, secrets):
                clock.return_value = at + 590
                worker.run(self.db, job_id, step, control=io.StringIO(), stdin=io.StringIO())
                return 'skipped'

            with patch('finance_cli.server.app.start_with_secrets', delayed_worker):
                refused = self.post('/jobs', {'name': 'hana.onesign.accounts', 'login_id': self.login['id'],
                                             'secrets': self.vault})
            self.assertEqual((refused.status_code, refused.json()['error']), (409, 'session_idle_expired'))
            self.assertEqual(count, len(self.services.calls))

    def test_idle_expiry_preserves_transfer_guard_and_local_exports(self):
        at = time.time()
        with patch.object(session_activity, 'now', return_value=at):
            target = self.query_setup()
            history = self.query_job(target, 'history.list')
            prepared = self.prepare(target)
        count = len(self.services.calls)
        with patch.object(session_activity, 'now', return_value=at + 590):
            with self.assertRaisesRegex(jobs.NotReady, '^session_idle_expired$'):
                jobs.accept_confirmation(self.db, prepared['id'], prepared['awaiting']['digest'], 'web:test')
            final = self.get('/jobs/' + prepared['id']).json()
            self.assertEqual(final['status'], 'expired')
            self.assertEqual(final['service_verdict'], prepared['service_verdict'])
            with self.db.read() as con:
                session = con.execute('SELECT * FROM sessions WHERE id=?', (prepared['session_id'],)).fetchone()
                self.assertEqual((session['state'], session['note']), ('consumed', 'transfer_prepared'))
            exported = self.query_job(target, 'history.export', history['id'])
            self.assertEqual(exported['outcome'], 'success', exported)
            self.assertEqual(count, len(self.services.calls))
            self.assertEqual(self.get('/logins').json()['logins'][0]['session']['last_request_at'], at)

    def test_same_login_queries_before_and_after_transfer_and_sealed_receipts(self):
        from finance_cli.services.hana import ledger_protocol as lp
        target = self.query_setup()
        session = self.get('/logins').json()['logins'][0]['current_session_id']
        history = self.query_job(target, 'history.list')
        self.assertEqual(history['outcome'], 'success', history)
        self.assertEqual(history['result']['rows'][0]['amount'], 10)
        self.assertTrue(history['result']['pagination_complete'])
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
            self.assertNoLeak(job, onesign_fixture.PASSWORD, 'SYNTHETIC-OAT',
                              'PRIVATE-SYNTHETIC-ROW')
            self.assertNoLeak(job['events'], onesign_fixture.SOURCE)
        self.assertEqual(accounts['result']['accounts'][0]['account_number'], onesign_fixture.SOURCE)
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

    def paged_history(self, target, second):
        """One list job whose first recent page names a next page; `second` answers that page."""
        from finance_cli.services.hana import ledger_protocol as lp, onesign_queries
        row = self.services.override[lp.PATHS['recent']]['grid1'][0]
        sent = []

        def pages(scope, method, url, *rest):
            if url.endswith(lp.PATHS['recent']):
                sent.append(json.loads(rest[1]))
                if len(sent) == 1:
                    self.services.override[lp.PATHS['recent']] = {'grid1': [row], 'recNcnt1': 20, 'nextTrscYn1': 'Y',
                        'dtlsSeqNo1': 2, 'trscSeqNo1': 3, 'nextTrscDt1': '20260930'}
                else:
                    self.services.override[lp.PATHS['recent']] = {'grid1': [row], 'recNcnt1': 1, 'nextTrscYn1': 'N'}
            reply = self.services(scope, method, url, *rest)
            return second(reply) if url.endswith(lp.PATHS['recent']) and len(sent) == 2 else reply
        with patch.object(onesign_queries, 'send_http', pages):
            return self.query_job(target, 'history.list'), sent

    def test_query_follows_every_page_once_and_export_keeps_duplicates(self):
        target = self.query_setup()
        count = len(self.services.calls)
        history, sent = self.paged_history(target, lambda reply: reply)
        self.assertEqual(history['outcome'], 'success', history)
        self.assertTrue(history['result']['pagination_complete'])
        self.assertEqual(len(history['result']['rows']), 2)
        self.assertEqual([s['stage'] for s in history['service_verdict']['stages']], ['clock', 'account', 'page', 'page'])
        self.assertEqual([(body['dtlsSeqNo'], body['trscSeqNo']) for body in sent], [(0, 0), (2, 3)])
        self.assertEqual(len(self.services.calls), count + 4)
        self.assertEqual(self.post('/jobs', {'name': 'hana.onesign.history.more', 'login_id': self.login['id'],
            'target_id': target['id'], 'parent_job_id': history['id'], 'secrets': self.vault}).status_code, 404)
        detail = self.query_job(target, 'history.detail', history['id'], row=2)
        self.assertEqual((detail['outcome'], detail['result']['source']), ('success', 'saved_ledger_row'), detail)
        exported = self.query_job(target, 'history.export', history['id'])
        self.assertEqual(exported['result']['row_count'], 2)
        document = self.get('/artifacts/' + exported['artifacts'][0]['id']).json()
        self.assertFalse(document['duplicates_removed'])
        self.assertEqual(document['issues'][-1]['issue'], 'identical_row_preserved')
        self.assertEqual(len(self.services.calls), count + 4)

    def test_query_keeps_received_page_when_the_next_page_is_refused(self):
        target = self.query_setup()
        count = len(self.services.calls)
        history, _ = self.paged_history(target, lambda reply: (403, *reply[1:]))
        self.assertEqual(history['outcome'], 'partial_success', history)
        self.assertEqual([s['accepted'] for s in history['service_verdict']['stages']], [True, True, True, False])
        self.assertEqual(len(history['result']['rows']), 1)
        self.assertFalse(history['result']['pagination_complete'])
        self.assertEqual(len(self.services.calls), count + 4)
        exported = self.query_job(target, 'history.export', history['id'])
        self.assertEqual((exported['outcome'], exported['result']['row_count']), ('success', 1), exported)
        self.assertFalse(exported['result']['pagination_complete'])
        self.assertEqual(len(self.services.calls), count + 4)

    def test_query_bad_cursor_preserves_page_and_detail_uses_saved_identifiers(self):
        from finance_cli.services.hana import ledger_protocol as lp
        target = self.query_setup()
        value = self.services.override[lp.PATHS['recent']]
        value.update(recNcnt1=20, nextTrscYn1='Y')  # Missing trscSeqNo1: do not infer a next page.
        value['grid1'][0].update(atfMgntNo='SYNTHETIC-DETAIL', balFlctDvCd='2', atfPrfRankCd='314')
        self.services.override[lp.PATHS['automatic']] = {'trnsAmt': 10, 'wdrwAcctNo': onesign_fixture.SOURCE,
                                                        'cookie': 'SYNTHETIC-COOKIE'}
        count = len(self.services.calls)
        history = self.query_job(target, 'history.list')
        self.assertEqual(history['outcome'], 'partial_success', history)
        self.assertTrue(history['service_verdict']['stages'][-1]['accepted'])
        self.assertEqual(len(history['result']['rows']), 1)
        self.assertFalse(history['result']['pagination_complete'])
        self.assertEqual(history['local']['stopped'], 'continuation_cursor_requires_review')
        self.assertEqual(len(self.services.calls), count + 3)
        detail = self.query_job(target, 'history.detail', history['id'], row=1)
        self.assertEqual(detail['outcome'], 'success', detail)
        self.assertEqual(detail['result']['source'], 'bank_detail')
        self.assertEqual(self.services.calls[-1][1], lp.PATHS['automatic'])
        self.assertEqual(json.loads(self.services.calls[-1][3])['atfMgntNo'], 'SYNTHETIC-DETAIL')
        self.assertEqual(detail['result']['detail']['wdrwAcctNo'], onesign_fixture.SOURCE)
        self.assertNoLeak(detail, 'SYNTHETIC-COOKIE')
        self.assertNoLeak(detail['events'], onesign_fixture.SOURCE)

    def test_query_acceptance_survives_bad_data_and_response_storage_failure(self):
        from finance_cli.services.hana import ledger_protocol as lp
        target = self.query_setup()
        self.services.override[lp.PATHS['recent']] = b'not JSON'
        malformed = self.query_job(target, 'history.list')
        # The bank accepted the page; without readable rows the range is not known to be complete.
        self.assertEqual(malformed['outcome'], 'partial_success', malformed)
        self.assertTrue(malformed['service_verdict']['stages'][-1]['accepted'])
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

    def test_query_loads_current_session_accounts_and_cannot_mix_receipts(self):
        from finance_cli.services.hana import ledger_protocol as lp, onesign_queries
        target = self.query_setup()
        history = self.query_job(target, 'history.list')
        self.assertEqual(history['outcome'], 'success', history)
        with self.db.read() as con:
            saved = json.loads(jobs.get(con, history['id'])['attempt'])['history']['receipts']['page']
        self.signed_in()
        count = len(self.services.calls)
        fresh = self.query_job(target, 'history.list')
        self.assertEqual(fresh['outcome'], 'success', fresh)
        self.assertEqual([c[1] for c in self.services.calls[count:]],
                         [onesign.ACCOUNTS, lp.PATHS['clock'], lp.PATHS['account'], lp.PATHS['recent']])
        self.assertEqual([s['stage'] for s in fresh['service_verdict']['stages']],
                         ['accounts', 'clock', 'account', 'page'])
        self.assertEqual(fresh['session_id'], self.get('/logins').json()['logins'][0]['current_session_id'])
        count = len(self.services.calls)
        inquiry = self.query_job(target, 'inquiry.history')
        self.assertEqual(inquiry['outcome'], 'success', inquiry)
        self.assertEqual(len(self.services.calls), count + 1)
        with State('synthetic', onesign_fixture.PASSWORD) as state:
            current = list(state.snapshot()['sessions'])[-1]
            source = onesign_queries.Queries(state, current)
            with self.assertRaisesRegex(ValueError, 'query_login_identity_changed'):
                source.read_receipt(saved)
        foreign = self.post('/jobs', {'name': 'hana.onesign.history.export', 'login_id': self.login['id'],
                                      'target_id': target['id'], 'parent_job_id': history['id'], 'secrets': self.vault})
        self.assertEqual(foreign.json()['error'], 'session_consumed')

    def test_inquiry_can_be_first_query_after_login(self):
        from finance_cli.services.hana import inquiry
        target = self.query_setup()
        self.signed_in()
        count = len(self.services.calls)
        result = self.query_job(target, 'inquiry.history')
        self.assertEqual(result['outcome'], 'success', result)
        self.assertEqual([c[1] for c in self.services.calls[count:]], [onesign.ACCOUNTS, inquiry.PATHS['history']])
        self.assertTrue(result['service_verdict']['stages'][0]['accepted'])

    def test_account_preflight_never_uses_old_or_unusable_accounts(self):
        target = self.query_setup()
        cases = [({}, 'accounts_query_required_in_session'),
                 ({'mainAcctList': []}, 'account_not_in_session_accounts'),
                 ({'mainAcctList': [{'acctNo': onesign_fixture.RECIPIENT, 'curCd': 'KRW'}]},
                  'account_not_in_session_accounts')]
        for value, error in cases:
            with self.subTest(value=value):
                self.signed_in()
                self.services.override[onesign.ACCOUNTS] = value
                count = len(self.services.calls)
                result = self.query_job(target, 'history.list')
                self.assertEqual(result['local']['stopped'], error, result)
                self.assertEqual(result['outcome'], 'not_started')
                self.assertTrue(result['service_verdict']['stages'][0]['accepted'])
                self.assertEqual([c[1] for c in self.services.calls[count:]], [onesign.ACCOUNTS])
                # A recorded malformed/empty list is not silently refreshed.
                self.query_job(target, 'inquiry.history')
                self.assertEqual(len(self.services.calls), count + 1)

    def test_account_preflight_rejection_transport_loss_and_save_failure_stop_without_retry(self):
        target = self.query_setup()
        self.signed_in()
        count = len(self.services.calls)

        def rejected(*args):
            _, headers, raw, cookies = self.services(*args)
            return 403, headers, raw, cookies
        with patch.object(onesign, 'operate', functools.partial(onesign.operate, exchange=rejected)):
            refused = self.query_job(target, 'history.list')
        self.assertEqual(refused['outcome'], 'rejected', refused)
        self.assertFalse(refused['service_verdict']['stages'][0]['accepted'])
        self.assertEqual([c[1] for c in self.services.calls[count:]], [onesign.ACCOUNTS])
        self.signed_in()
        count = len(self.services.calls)
        original = self.services.override[onesign.ACCOUNTS]
        self.services.override[onesign.ACCOUNTS] = OSError('synthetic response lost')
        lost = self.query_job(target, 'history.list')
        self.assertEqual(lost['outcome'], 'unknown', lost)
        self.assertIsNone(lost['service_verdict']['stages'][0]['accepted'])
        self.assertEqual([c[1] for c in self.services.calls[count:]], [onesign.ACCOUNTS])
        self.services.override[onesign.ACCOUNTS] = original
        self.signed_in()
        real_record = State.record

        def fail_receipt(state, run, name, value):
            if run.endswith('-accounts') and name == 'http-0001-response':
                raise OSError('synthetic disk failure')
            return real_record(state, run, name, value)
        count = len(self.services.calls)
        with patch.object(State, 'record', fail_receipt):
            failed = self.query_job(target, 'inquiry.history')
        self.assertEqual(failed['outcome'], 'not_started', failed)
        self.assertTrue(failed['service_verdict']['stages'][0]['accepted'])
        self.assertEqual(failed['local']['stopped'], 'accounts_query_incomplete')
        self.assertEqual([c[1] for c in self.services.calls[count:]], [onesign.ACCOUNTS])

    def test_invalid_controls_send_no_account_preflight(self):
        target = self.query_setup()
        self.signed_in()
        count = len(self.services.calls)
        for suffix, value in [('history.list', {'start_date': '2099-01-01', 'end_date': '2099-01-01'}),
                              ('history.list', {'search': '😀' * 13}),
                              ('inquiry.history', {'start_date': '1900-01-01'})]:
            result = self.query_job(target, suffix, **value)
            self.assertEqual((result['outcome'], result['local']['stopped']),
                             ('not_started', 'invalid_history_controls'))
        self.assertEqual(len(self.services.calls), count)

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
        self.assertEqual(awaiting['preview']['source_account'], onesign_fixture.SOURCE)
        self.assertEqual(awaiting['preview']['recipient_account'], onesign_fixture.RECIPIENT)
        self.assertEqual(prepared['fixed']['target']['identity']['account_number'], onesign_fixture.SOURCE)
        self.assertEqual(prepared['result']['source_account'], onesign_fixture.SOURCE)
        with self.db.read() as con:
            saved = loads(jobs.get(con, prepared['id'])['awaiting'])
        self.assertEqual(saved['digest'], awaiting['digest'])
        self.assertEqual(saved['preview']['source_account'], '••••••••••1234')
        self.assertEqual(next(j for j in self.get('/jobs').json()['jobs'] if j['id'] == prepared['id'])
                         ['input']['recipient_account_number'], onesign_fixture.RECIPIENT)
        self.assertEqual(awaiting['verification'], 'live_partial')
        self.assertEqual(prepared['verification'], 'live_partial')
        self.assertIn('최종 이체 확정은 미확인', prepared['verification_note'])
        self.assertLessEqual(awaiting['expires_at'] - time.time(), 600)
        self.assertNoLeak(prepared, '6049', onesign_fixture.PASSWORD)
        self.assertNoLeak(prepared['events'], onesign_fixture.SOURCE, onesign_fixture.RECIPIENT)
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
