"""Hometax adapters against synthetic Node records; no Node process, no network."""
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from support import ServerCase, synthetic_certificate

from finance_cli.server import jobs, model, session_activity, worker
from finance_cli.server.adapters import hometax
from finance_cli.server.db import loads

SECRET_KEYS = ('cookie_jar', 'storage', 'storage_by_origin', 'session_origin', 'services', 'source', 'source_items',
               'common_screen_startup', 'report_pages', 'response', 'SYNTHETIC-COOKIE')
PERSONAL = {'userNm': '가상 사용자', 'tin': 'P0001', 'rprsTin': '', 'smprYn': 'N'}
BUSINESS = {'userNm': '가상 사용자', 'tin': 'B0002', 'rprsTin': 'P0001', 'smprYn': 'Y'}


def session_record(branch='success', **extra):
    return {'scope': 'browserless_business', 'cookie_jar': {'cookies': [{'key': 'SYNTHETIC-COOKIE'}]},
            'storage': {'localStorage': {'k': 'v'}}, 'storage_by_origin': {}, 'session_origin': 'https://x',
            'session_validation': {'branch': 'success', 'reason': 'verified'}, 'services': [{'response': 'raw'}],
            'common_screen_startup': {}, 'report_pages': [], 'warnings': [], 'session_file_saved': True,
            'branch': branch, **extra}


def tax_record(*, switched=False, **extra):
    checks = [{'operation': 'account.show', 'branch': 'success', 'reason': 'verified_session'}]
    if switched:
        checks.append({'operation': 'business.select', 'branch': 'success', 'reason': 'original_service_result'})
    return session_record(**{'target_verified': True, 'target_check': checks, **extra})


class FakeNode:
    """Writes synthetic records where the real Node command would."""

    def __init__(self, handlers):
        self.handlers, self.calls = handlers, []

    def __call__(self, script, config):
        key = script if script != 'business.mjs' else f"{config['command']}.{config['operation']}"
        self.calls.append((key, dict(config)))
        record = self.handlers[key](config) if callable(self.handlers[key]) else self.handlers[key]
        if record is None:
            return None, 'missing_result_json'
        output = Path(config['output'])
        if script in ('returns_report.mjs', 'report.mjs'):
            output.mkdir(mode=0o700)
            files = record.pop('_files', {})
            for name, text in files.items():
                (output / name).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                (output / name).write_text(text)
                (output / name).chmod(0o600)
            (output / 'result.json').write_text(json.dumps(record))
            (output / 'result.json').chmod(0o600)
        elif record is not False:
            output.write_text(json.dumps(record))
            output.chmod(0o600)
        return {k: record[k] for k in ('branch', 'reason', 'target_verified', 'target_check', 'timings')
                if isinstance(record, dict) and k in record}, None


class HometaxAdapterTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(hometax, 'check_runtime', lambda: None))
        self.enterContext(patch('finance_cli.server.capabilities.setup_reasons', return_value=[]))
        self.enroll()
        synthetic_certificate('login-cert')
        synthetic_certificate('invoice-cert')
        self.login = self.post('/logins', {'institution': 'hometax', 'method': 'joint_certificate', 'name': '홈택스',
                                           'credential': 'login-cert'}).json()

    def run_job(self, job_id, step=None, secrets=None, node=None):
        with self.db.read() as con:
            job = jobs.get(con, job_id)
        stdin = io.StringIO(json.dumps(secrets) + '\n' if secrets is not None else '')
        with patch.object(hometax, 'node', node):
            worker.run(self.db, job_id, step or job['step'], control=io.StringIO(), stdin=stdin)
        return self.get(f'/jobs/{job_id}').json()

    def submit(self, name, **fields):
        response = self.post('/jobs', {'name': name, 'login_id': self.login['id'], **fields})
        self.assertIn(response.status_code, (200, 202), response.text)
        return response.json()

    def assertNoSecrets(self, value):
        self.assertNotIn('SYNTHETIC-COOKIE', json.dumps(value, ensure_ascii=False))

        def walk(item):
            if isinstance(item, dict):
                for key, child in item.items():
                    if key != 'source' or child != 'stdout_summary':
                        self.assertNotIn(key, SECRET_KEYS)
                    walk(child)
            elif isinstance(item, list):
                for child in item:
                    walk(child)
        walk(value)

    def login_session(self):
        submitted, _ = jobs.submit(self.db, name='hometax.login', origin='web:test', login_id=self.login['id'])
        node = FakeNode({'browserless.mjs': session_record(login_request_observed=True, session_binding_observed=True)})
        result = self.run_job(submitted['id'], secrets={'certificate_password': 'Synthetic-Password!'}, node=node)
        self.assertEqual(result['outcome'], 'success', result)
        return result

    def test_idle_limit_requires_login_and_only_institution_work_moves_the_deadline(self):
        def row():
            return next(r for r in self.get('/logins').json()['logins'] if r['id'] == self.login['id'])

        with patch.object(session_activity, 'now', return_value=1000):
            logged_in = self.login_session()
        self.assertEqual(row()['session']['idle_expires_at'], 2790)
        with patch.object(session_activity, 'now', return_value=2789):
            self.assertEqual(row()['readiness'], 'ready')
            refresh = self.submit('hometax.session.refresh')
            node = FakeNode({'session.mjs': session_record()})
            refreshed = self.run_job(refresh['id'], node=node)
            self.assertEqual(refreshed['outcome'], 'success', refreshed)
            self.assertNotEqual(refreshed['result']['session_id'], logged_in['result']['session_id'])
            self.assertEqual(row()['session']['last_request_at'], 2789)
        with patch.object(session_activity, 'now', return_value=4578):
            self.assertEqual(row()['readiness'], 'ready')
            self.get('/jobs/' + refresh['id'])
            self.assertEqual(row()['session']['idle_expires_at'], 4579)
        with patch.object(session_activity, 'now', return_value=4579):
            self.assertEqual(row()['readiness'], 'login_required')
            self.assertTrue(row()['session']['idle_expired'])
            for name in ('hometax.session.refresh', 'hometax.targets.discover'):
                response = self.post('/jobs', {'name': name, 'login_id': self.login['id']})
                self.assertEqual(response.status_code, 409, response.text)
                self.assertEqual(response.json()['error'], 'session_idle_expired')
            # Local expiry preserves the institution's successful result and saved session verdict.
            self.assertEqual(row()['session']['state'], 'usable')
            self.assertEqual(self.get('/jobs/' + refresh['id']).json()['outcome'], 'success')
            self.login_session()
            self.assertEqual(row()['readiness'], 'ready')
            self.assertEqual(row()['session']['idle_expires_at'], 6369)
        self.assertEqual(len(node.calls), 1)

    def test_idle_expiry_after_submission_stops_worker_before_node(self):
        with patch.object(session_activity, 'now', return_value=1000):
            self.login_session()
            queued = self.submit('hometax.session.refresh')
        node = FakeNode({})
        with patch.object(session_activity, 'now', return_value=2790):
            result = self.run_job(queued['id'], node=node)
        self.assertEqual(result['outcome'], 'not_started', result)
        self.assertEqual(result['local']['stopped'], 'session_idle_expired')
        self.assertEqual(node.calls, [])

    def register(self, kind):
        discover, _ = jobs.submit(self.db, name='hometax.targets.discover', origin='web:test', login_id=self.login['id'])
        node = FakeNode({'account.show': session_record(data={'account': PERSONAL}),
                         'business.list': session_record(data={'items': [{'tin': 'B0002', 'tnmNm': '가상 스튜디오',
                                                                          'txprDscmNo': '1234567890'}],
                                                               'source_items': [{'tin': 'B0002'}]})})
        result = self.run_job(discover['id'], node=node)
        self.assertNoSecrets(result)
        refs = {c['kind']: c['ref'] for c in result['result']['candidates']}
        self.assertNotIn('B0002', json.dumps(result))
        return self.post(f"/logins/{self.login['id']}/targets", {'job_id': discover['id'], 'candidate': refs[kind]}).json()

    def test_login_registers_session_only_on_success_and_never_stores_password(self):
        result = self.login_session()
        self.assertNoSecrets(result)
        sessions = self.get(f"/logins/{self.login['id']}/sessions").json()
        self.assertEqual(sessions['current_session_id'], result['result']['session_id'])
        self.assertNotIn('location', json.dumps(sessions))
        failed, _ = jobs.submit(self.db, name='hometax.login', origin='web:test', login_id=self.login['id'])
        node = FakeNode({'browserless.mjs': session_record(branch='failure')})
        failure = self.run_job(failed['id'], secrets={'certificate_password': 'Synthetic-Password!'}, node=node)
        self.assertEqual(failure['outcome'], 'rejected')
        after = self.get(f"/logins/{self.login['id']}/sessions").json()
        self.assertEqual(after['current_session_id'], sessions['current_session_id'])
        self.assertEqual({s['state'] for s in after['sessions']}, {'usable'})
        wrong, _ = jobs.submit(self.db, name='hometax.login', origin='web:test', login_id=self.login['id'])
        node = FakeNode({})
        stopped = self.run_job(wrong['id'], secrets={'certificate_password': 'wrong'}, node=node)
        self.assertEqual((stopped['outcome'], stopped['local']['stopped']),
                         ('not_started', 'incorrect_password_or_damaged_credential'))
        self.assertEqual(node.calls, [])
        with self.db.read() as con:
            dump = json.dumps([dict(r) for r in con.execute('SELECT * FROM jobs')] +
                              [dict(r) for r in con.execute('SELECT * FROM job_events')])
        self.assertNotIn('Synthetic-Password!', dump)

    def test_business_query_checks_target_under_one_step_and_filters_output(self):
        self.login_session()
        target = self.register('business')
        self.assertEqual(target['identity']['business_number'], '••••••7890')
        job = self.submit('hometax.tax.dues', target_id=target['id'])
        node = FakeNode({
            'tax.dues': tax_record(switched=True, action_id='ATERMAAA004R01', reason='original_service_result',
                timings=[{'stage': 'session.open', 'duration_ms': 2800, 'source': 'private'},
                         {'stage': 'tax.dues', 'duration_ms': 6200},
                         {'stage': 'private', 'duration_ms': 1}, {'stage': 'tax.dues', 'duration_ms': 'private'}], data={
                'items': [{'itrfNm': '부가가치세', 'pmtAmt': 340000, 'txprDscmNo': '1234567890', 'nested': {'x': 1}}],
                'pages': [{'branch': 'success', 'items': [], 'page_info': {'pageNum': 1, 'totalCount': 1}}],
                'pagination': {'requested_all': False, 'complete': True}, 'source': {'raw': True}, 'account': BUSINESS})})
        result = self.run_job(job['id'], node=node)
        self.assertEqual([c[0] for c in node.calls], ['tax.dues'])
        self.assertEqual(node.calls[0][1]['target'], {'kind': 'business', 'tin': 'B0002'})
        self.assertTrue(node.calls[0][1]['timings'])
        self.assertEqual(result['outcome'], 'success', result)
        row = result['result']['items'][0]
        self.assertEqual((row['itrfNm'], row['pmtAmt'], row['txprDscmNo']), ('부가가치세', 340000, '••••••7890'))
        self.assertNotIn('nested', row)
        self.assertNoSecrets(result)
        self.assertEqual(result['local']['timings'], [{'stage': 'session.open', 'duration_ms': 2800},
                                                    {'stage': 'tax.dues', 'duration_ms': 6200}])
        self.assertEqual([c['operation'] for c in result['service_verdict']['target_check']],
                         ['account.show', 'business.select'])
        sessions = self.get(f"/logins/{self.login['id']}/sessions").json()['sessions']
        self.assertEqual([s['state'] for s in sessions].count('usable'), 1)

    def test_target_mismatch_stops_before_the_business_request(self):
        self.login_session()
        target = self.register('business')
        job = self.submit('hometax.tax.dues', target_id=target['id'])
        node = FakeNode({'tax.dues': tax_record(switched=True, target_verified=False, branch='no_action',
                                                reason='target_unverified', data={'account': PERSONAL})})
        result = self.run_job(job['id'], node=node)
        self.assertEqual((result['outcome'], result['local']['stopped']), ('unknown', 'target_unverified'))
        self.assertEqual([c[0] for c in node.calls], ['tax.dues'])
        self.assertEqual(result['local']['detail']['target_check'][1]['branch'], 'success')
        self.assertIsNone(result['result'])

    def test_page_notice_before_query_is_reported_without_its_text(self):
        self.login_session()
        target = self.register('personal')
        job = self.submit('hometax.invoice.list', target_id=target['id'], input={'direction': 'sales'})
        node = FakeNode({'account.show': session_record(data={'account': PERSONAL}),
                         'invoice.list': session_record(branch='no_action', reason='original_action_not_observed',
                                                        original_dialog={'message': 'synthetic private notice'}, data={})})
        result = self.run_job(job['id'], node=node)
        self.assertEqual(result['outcome'], 'unknown')
        self.assertIs(result['service_verdict']['original_dialog_observed'], True)
        self.assertNotIn('synthetic private notice', json.dumps(result))

    def test_unavailable_service_differs_from_zero_rows(self):
        self.login_session()
        target = self.register('personal')
        zero = self.submit('hometax.tax.dues', target_id=target['id'])
        node = FakeNode({'tax.dues': tax_record(reason='original_service_result', timings=None, target_check=None, data={
                             'items': [], 'pagination': {'complete': True}, 'account': PERSONAL})})
        result = self.run_job(zero['id'], node=node)
        self.assertEqual((result['outcome'], result['result']['items']), ('success', []))
        self.assertEqual((result['result']['list_omitted'], result['result']['amount_sum']), (False, None))
        omitted = self.submit('hometax.tax.dues', target_id=target['id'])
        node = FakeNode({'tax.dues': tax_record(reason='original_service_result', timings=None, target_check=None, data={
                             'pagination': {'complete': True}, 'source': {'amtSum': 0}, 'account': PERSONAL})})
        result = self.run_job(omitted['id'], node=node)
        self.assertEqual((result['outcome'], result['result']['items'], result['result']['list_omitted'],
                          result['result']['amount_sum']), ('success', None, True, 0))
        unavailable = self.submit('hometax.tax.dues', target_id=target['id'])
        node = FakeNode({'tax.dues': tax_record(branch='no_action', reason='original_dues_navigation_not_observed')})
        result = self.run_job(unavailable['id'], node=node)
        self.assertEqual(result['outcome'], 'unknown')
        self.assertIsNone(result['result']['items'])
        self.assertEqual(result['service_verdict']['reason'], 'original_dues_navigation_not_observed')

    def test_session_save_failure_keeps_verdict_and_marks_pointer_stale(self):
        self.login_session()
        target = self.register('personal')
        before = self.get(f"/logins/{self.login['id']}/sessions").json()['current_session_id']
        job = self.submit('hometax.tax.dues', target_id=target['id'])
        unsaved = tax_record(reason='original_service_result', data={'items': [], 'account': PERSONAL},
                                 session_file_saved=False)
        node = FakeNode({'tax.dues': unsaved})
        result = self.run_job(job['id'], node=node)
        self.assertEqual((result['outcome'], result['local']['session_saved']), ('success', False))
        sessions = self.get(f"/logins/{self.login['id']}/sessions").json()
        self.assertEqual(sessions['current_session_id'], before)
        current = [s for s in sessions['sessions'] if s['id'] == sessions['current_session_id']][0]
        self.assertEqual(current['state'], 'stale')
        refused = self.post('/jobs', {'name': 'hometax.tax.dues', 'login_id': self.login['id'], 'target_id': target['id']})
        self.assertEqual(refused.json()['error'], 'session_stale')

    def test_combined_query_keeps_stdout_success_when_result_file_cannot_be_saved(self):
        self.login_session()
        target = self.register('personal')
        job = self.submit('hometax.tax.dues', target_id=target['id'])
        calls = []

        def node(script, config):
            calls.append((script, config))
            return {'branch': 'success', 'reason': 'original_service_result', 'target_verified': True,
                    'target_check': [{'operation': 'account.show', 'branch': 'success'}],
                    'session_file_saved': False, 'timings': [{'stage': 'tax.dues', 'duration_ms': 42}]}, None

        result = self.run_job(job['id'], node=node)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result['outcome'], 'success', result)
        self.assertFalse(result['local']['session_saved'])
        self.assertEqual(result['local']['timings'], [{'stage': 'tax.dues', 'duration_ms': 42}])
        self.assertEqual(result['service_verdict']['source'], 'stdout_summary')
        self.assertIsNone(result['result']['items'])
        self.assertNoSecrets(result)

    def test_query_with_changed_or_unconfirmed_target_withholds_rows_without_rewriting_verdict(self):
        self.login_session()
        target = self.register('personal')
        for record in (tax_record(data={'account': BUSINESS, 'items': [{'itrfNm': '다른 대상'}]}),
                       session_record(data={'account': PERSONAL, 'items': [{'itrfNm': '확인되지 않은 대상'}]})):
            job = self.submit('hometax.tax.dues', target_id=target['id'])
            result = self.run_job(job['id'], node=FakeNode({'tax.dues': record}))
            self.assertEqual(result['outcome'], 'unknown')
            self.assertEqual(result['service_verdict']['branch'], 'success')
            self.assertTrue(result['local']['target_mismatch_after_query'])
            self.assertIsNone(result['result'])

    def test_revision_change_marks_sessions_stale_until_rechecked(self):
        self.login_session()
        target = self.register('personal')
        self.patch_(f"/logins/{self.login['id']}", {'expected_revision': 1, 'signing': {
            'invoice_sign': {'method': 'joint_certificate', 'credential': 'invoice-cert'}}})
        refused = self.post('/jobs', {'name': 'hometax.tax.dues', 'login_id': self.login['id'], 'target_id': target['id']})
        self.assertEqual(refused.json()['error'], 'session_stale')
        check = self.submit('hometax.session.refresh', input={'mode': 'resume'})
        node = FakeNode({'session.mjs': {**session_record(), 'session_validation': None}})
        self.assertEqual(self.run_job(check['id'], node=node)['outcome'], 'success')
        self.assertEqual(self.post('/jobs', {'name': 'hometax.tax.dues', 'login_id': self.login['id'],
                                             'target_id': target['id']}).status_code, 202)

    def test_fixed_session_is_not_replaced_by_a_newer_pointer(self):
        self.login_session()
        target = self.register('personal')
        first = self.submit('hometax.tax.dues', target_id=target['id'])
        second = self.submit('hometax.tax.dues', target_id=target['id'])
        node = FakeNode({'tax.dues': tax_record(data={'items': [], 'account': PERSONAL})})
        self.assertEqual(self.run_job(first['id'], node=node)['outcome'], 'success')
        result = self.run_job(second['id'], node=FakeNode({}))
        self.assertEqual((result['outcome'], result['local']['stopped']), ('not_started', 'fixed_session_not_usable'))

    def invoice_ready(self):
        self.patch_(f"/logins/{self.login['id']}", {'expected_revision': 1, 'signing': {
            'invoice_sign': {'method': 'joint_certificate', 'credential': 'invoice-cert'}}})
        self.login_session()
        target = self.register('business')
        draft = {'buyer': {'business_number': '123-45-67891', 'name': '가상 거래처'}, 'date': '2026-09-30',
                 'items': [{'month': '09', 'day': '30', 'name': '용역', 'supply_amount': 100, 'tax_amount': 10}],
                 'settlement': {'credit': '110', 'type': 'claim'}}
        job = self.submit('hometax.invoice.prepare', target_id=target['id'], input=draft)
        prepared = session_record(reason='original_preview_ready', data={'issued': False, 'account': BUSINESS, 'draft': {
            'splrInfrBizSVO': {'splrTnmNm': '가상 스튜디오', 'splrTin': 'INTERNAL'},
            'dmnrInfrBizSVO': {'dmnrTnmNm': '가상 거래처', 'dmnrTxprDscmNo': '1234567891'},
            'lsatInfrBizSVOList': [{'lsatNm': '용역', 'lsatSplCft': 100, 'lsatTxamt': 10}],
            'sncInfrBizSVO': {'wrtDt': '20260930', 'sumAmt': 110}}})
        node = FakeNode({'account.show': session_record(data={'account': BUSINESS}), 'invoice.prepare': prepared})
        result = self.run_job(job['id'], node=node)
        self.assertEqual(result['status'], 'awaiting_input', result)
        self.assertEqual(json.loads(Path(node.calls[1][1]['input']).read_text())['buyer']['business_number'],
                         '123-45-67891')
        return result, node.calls[1][1]['output']

    def test_invoice_prepare_confirm_issue_uses_the_same_draft_file_once(self):
        job, prepared_path = self.invoice_ready()
        awaiting = job['awaiting']
        self.assertEqual((awaiting['kind'], awaiting['next_step'], awaiting['requires']),
                         ('confirm', 'issue', ['certificate_password']))
        self.assertNotIn('splrTin', json.dumps(awaiting))
        self.assertEqual(awaiting['verification'], 'live_untested')
        self.assertNoSecrets(job)
        wrong = self.post(f"/jobs/{job['id']}/confirm", {'confirmation': 'x' * 64,
                                                         'secrets': {'certificate_password': 'p'}})
        self.assertEqual(wrong.json()['error'], 'confirmation_mismatch')
        with patch('finance_cli.server.app.start_with_secrets', return_value='started') as start:
            confirmed = self.post(f"/jobs/{job['id']}/confirm", {'confirmation': awaiting['digest'],
                                                                 'secrets': {'certificate_password': 'Synthetic-Password!'}})
        self.assertEqual(confirmed.json()['status'], 'queued')
        self.assertEqual(start.call_args[0][2], {'certificate_password': 'Synthetic-Password!'})
        issued = session_record(branch='no_action', reason='issuance_completion_unobserved', data={
            'storage_branch': 'success', 'approval_number': '20260930-00000000-00000001', 'source': {'raw': 1}})
        node = FakeNode({'invoice.issue': issued})
        result = self.run_job(job['id'], secrets={'certificate_password': 'Synthetic-Password!'}, node=node)
        config = node.calls[0][1]
        self.assertEqual((config['prepared'], config['session'], config['credential']),
                         (prepared_path, prepared_path, 'invoice-cert'))
        self.assertEqual(result['outcome'], 'partial_success')
        self.assertEqual(result['result']['approval_number'], '20260930-00000000-00000001')
        self.assertNoSecrets(result)
        again = self.post(f"/jobs/{job['id']}/confirm", {'confirmation': awaiting['digest'],
                                                         'secrets': {'certificate_password': 'p'}})
        self.assertEqual(again.json()['status'], 'finished')  # No second issuance attempt.

    def test_issue_verdict_survives_session_registration_failure(self):
        job, prepared_path = self.invoice_ready()
        with patch('finance_cli.server.app.start_with_secrets', return_value='started'):
            self.post(f"/jobs/{job['id']}/confirm", {'confirmation': job['awaiting']['digest'],
                                                     'secrets': {'certificate_password': 'Synthetic-Password!'}})
        issued = session_record(reason='original_email_result', data={
            'storage_branch': 'success', 'approval_number': '20260930-00000000-00000009'})
        with patch('finance_cli.server.model.add_session', side_effect=RuntimeError('database locked')):
            result = self.run_job(job['id'], secrets={'certificate_password': 'Synthetic-Password!'},
                                  node=FakeNode({'invoice.issue': issued}))
        self.assertEqual(result['outcome'], 'success', result)
        self.assertEqual(result['result']['approval_number'], '20260930-00000000-00000009')
        self.assertTrue(result['local']['session_registration_failed'])
        self.assertIsNotNone(result['confirmed_target'])  # The prepare step's confirmation is kept.

    def test_disabled_target_expires_a_pending_confirmation(self):
        job, _ = self.invoice_ready()
        self.patch_(f"/targets/{job['target_id']}", {'disabled': True})
        self.assertEqual(self.get(f"/jobs/{job['id']}").json()['status'], 'expired')
        refused = self.post(f"/jobs/{job['id']}/confirm", {'confirmation': job['awaiting']['digest'],
                                                           'secrets': {'certificate_password': 'p'}})
        self.assertEqual(refused.status_code, 409)

    def test_sessions_api_masks_the_current_taxpayer(self):
        self.login_session()
        target = self.register('personal')
        job = self.submit('hometax.tax.dues', target_id=target['id'])
        self.run_job(job['id'], node=FakeNode({'tax.dues': tax_record(data={'items': [], 'account': PERSONAL})}))
        text = json.dumps(self.get(f"/logins/{self.login['id']}/sessions").json())
        self.assertNotIn('P0001', text)

    def test_revision_change_after_prepare_requires_a_new_draft(self):
        job, _ = self.invoice_ready()
        login = self.get('/logins').json()['logins'][0]
        self.patch_(f"/logins/{login['id']}", {'expected_revision': login['revision'], 'signing': {
            'invoice_sign': {'method': 'joint_certificate', 'credential': 'login-cert'}}})
        self.assertEqual(self.get(f"/jobs/{job['id']}").json()['status'], 'expired')
        refused = self.post(f"/jobs/{job['id']}/confirm", {'confirmation': job['awaiting']['digest'],
                                                           'secrets': {'certificate_password': 'p'}})
        self.assertEqual(refused.status_code, 409)

    def test_issue_outcome_mapping(self):
        mapping = hometax.issue_outcome
        self.assertEqual(mapping({'branch': 'success'}, {}), 'success')
        self.assertEqual(mapping({'branch': 'failure', 'reason': 'original_certificate_rejected'}, {}), 'rejected')
        self.assertEqual(mapping({'branch': 'no_action', 'reason': 'previous_issuance_attempt'}, {}), 'not_started')
        self.assertEqual(mapping({'branch': 'no_action', 'reason': 'issuance_completion_unobserved'}, {}), 'unknown')
        self.assertEqual(hometax.outcome_of({'branch': 'failure', 'page_branches': ['success', 'failure']}),
                         'partial_success')
        self.assertEqual(hometax.outcome_of(None), 'unknown')

    def test_returns_receipt_registers_only_the_sandboxed_html(self):
        self.login_session()
        target = self.register('personal')
        job = self.submit('hometax.returns.receipt', target_id=target['id'], input={'return_id': 'R-1'})
        record = session_record(branch='success', reason='original_document_success', data={
            'query': {'source': {}}, 'selected': {'rtnCvaId': 'R-1'}, 'forms': [], 'documents': [{
                'form': None, 'batch': 1, 'branch': 'success', 'render_complete': True, 'capture': 'x',
                'artifact': {'saved': True, 'complete': True, 'file': 'document-001/report/report.html', 'page_count': 1}}]},
            collection={'complete': True, 'artifacts_complete': True},
            _files={'document-001/report/report.html': '<html><body>접수증</body></html>',
                    'document-001/source/capture.json': '{"cookie_jar": "SYNTHETIC-COOKIE"}'})
        node = FakeNode({'account.show': session_record(data={'account': PERSONAL}), 'returns_report.mjs': record})
        result = self.run_job(job['id'], node=node)
        self.assertEqual(result['outcome'], 'success', result)
        self.assertEqual(len(result['artifacts']), 1)
        artifact = result['artifacts'][0]
        self.assertEqual(artifact['media_type'], 'text/html; charset=utf-8')
        response = self.get(f"/artifacts/{artifact['id']}", params={'disposition': 'inline'})
        self.assertIn('sandbox', response.headers['content-security-policy'])
        self.assertIn('접수증', response.text)
        download = self.get(f"/artifacts/{artifact['id']}")
        self.assertTrue(download.headers['content-disposition'].startswith('attachment'))
        self.assertNoSecrets(result)
        self.assertEqual(self.get('/artifacts/af_0000000000000000').status_code, 404)


class HometaxCliLockTests(unittest.TestCase):
    def test_cli_fails_at_once_while_the_institution_lock_is_held(self):
        import contextlib
        import os
        import tempfile
        from finance_cli.cli.main import main
        from finance_cli.core import storage
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'FINANCE_HOME': str(Path(directory).resolve())}), \
                patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')):
            from hometax_cli import serial
            output = io.StringIO()
            with storage.lock(serial.lock_path()), contextlib.redirect_stdout(output), \
                    patch('hometax_cli.__main__.run_node', side_effect=AssertionError('must not run')):
                code = main(['--format', 'json-v1', 'hometax', 'tax', 'dues', '--session', 's.json',
                             '--output', str(Path(directory) / 'o.json'), '--send'])
            self.assertEqual((code, json.loads(output.getvalue())['result']['error']), (2, 'resource_busy'))


if __name__ == '__main__':
    unittest.main()
