"""Corporate web jobs exercise the real CLI services with synthetic exchanges."""
import base64
import json
from unittest.mock import patch

from support import synthetic_certificate
from test_hana_adapters import HanaCase
import test_hana_corporate_idpw as passwords
import test_hana_corporate_queries as query_fixtures
import test_hana_corporate_transfers as transfer_fixtures
import test_hana_corporate as certificate_fixtures

from finance_cli.core import storage
from finance_cli.server import jobs, model
from finance_cli.services.hana import store as shared
from finance_cli.services.hana_corporate import store, transport


class CorporateTests(HanaCase):
    exchange = query_fixtures.QueryTests.exchange
    session = query_fixtures.QueryTests.session

    @classmethod
    def setUpClass(cls):
        certificate_fixtures.CorporateTests.setUpClass.__func__(cls)

    def setUp(self):
        super().setUp()
        self.enroll()
        self.calls, self.responses = [], {}
        self.cookies = [{'name': 'SYNTHETIC-CORPORATE', 'value': 'SYNTHETIC-COOKIE'}]
        self.bank_exchange = self.exchange
        original = transport.Client.__init__
        def initialize(client, *args, **kwargs):
            kwargs['exchange'] = self.bank_exchange
            original(client, *args, **kwargs)
        self.enterContext(patch.object(transport.Client, '__init__', initialize))
        storage.directory(shared.root('settings').parent)
        storage.directory(shared.root('settings'))
        storage.atomic_json(shared.root('settings') / 'synthetic.json', {
            'format': 'finance-hana-keypad-v1', 'version': '6.2.2',
            'keypad_mac': base64.b64encode(passwords.MAC).decode()})
        response = self.post('/logins', {'institution': 'hana_corporate', 'method': 'id_password',
                                        'name': '합성 기업', 'credential': 'SyntheticId'})
        self.assertEqual(response.status_code, 200, response.text)
        self.connection = response.json()

    def adopt(self, path):
        with self.db.write() as con:
            session = model.add_session(con, login_id=self.connection['id'], location=str(path.relative_to(self.home)),
                revision=1, job_id=None, name=path.name, verdict={'accepted': True})
            model.set_pointer(con, self.connection['id'], session)
        self.responses['accounts'] = {'outRec01': [{'ACCT_NO': '000101', 'PRD_NM': '합성 기업계좌',
                                                   'BAL': '001200.000', 'CUR_CD': 'KRW', 'token': 'HIDDEN-TOKEN'}]}
        result = self.run_job(self.submit('hana.corporate.accounts', login_id=self.connection['id'])['id'])
        self.assertEqual(result['outcome'], 'success', result)
        self.account = self.register_account(self.connection['id'], result)
        return result

    def prepare(self):
        path = transfer_fixtures.TransferTests.fixture(self)
        self.adopt(path)
        job = self.submit('hana.corporate.transfer.prepare', login_id=self.connection['id'], target_id=self.account['id'],
                          input={'bank': '081', 'recipient': '000201', 'amount': '1000'})
        value = self.run_job(job['id'])
        self.assertEqual(value['status'], 'awaiting_input', value)
        self.assertEqual(value['awaiting']['requires'], [])
        self.assertNotIn('transfer-execute', [s for s, _ in self.calls])
        return value

    def confirm(self, value, secrets=None):
        jobs.accept_confirmation(self.db, value['id'], value['awaiting']['digest'], 'web:test')
        return self.run_job(value['id'], secrets)

    def test_idpw_login_accounts_history_and_channel_isolation(self):
        bank = passwords.Bank(self)
        self.bank_exchange = bank
        job = self.run_job(self.submit('hana.corporate.login-idpw', login_id=self.connection['id'])['id'],
                           {'login_password': passwords.PASSWORD})
        self.assertEqual(job['outcome'], 'success', job)
        self.assertTrue(job['result']['session_id'])
        self.assertNoLeak(job, passwords.PASSWORD, 'SYNTHETIC-MGMT', 'SYNTHETIC-CORPORATE')
        self.assertEqual(len(bank.calls), 6)
        listed = next(r for r in self.get('/logins').json()['logins'] if r['id'] == self.connection['id'])
        self.assertEqual(listed['session']['idle_seconds'], 590, 'no timeout was stated to this login')
        self.bank_exchange, self.cookies = self.exchange, [{'name': 'SYNTHETIC-CORPORATE'}]
        self.responses['accounts'] = {'outRec01': [{'ACCT_NO': '000101', 'PRD_NM': '합성 계좌', 'BAL': '001.00'}]}
        accounts = self.run_job(self.submit('hana.corporate.accounts', login_id=self.connection['id'])['id'])
        self.assertEqual(accounts['result']['accounts'][0]['balance'], '001.00')
        target = self.register_account(self.connection['id'], accounts)
        self.responses['history-krw'] = query_fixtures.QueryTests.page()
        history = self.run_job(self.submit('hana.corporate.history', login_id=self.connection['id'], target_id=target['id'])['id'])
        self.assertTrue(history['result']['complete'], history)
        self.assertEqual(history['result']['transactions'][0]['TRSC_AMT'], '001.00')
        self.assertEqual(self.post('/jobs', {'name': 'hana.accounts.list', 'login_id': self.connection['id']}).json()['error'], 'login_institution_mismatch')
        self.assertEqual(self.get('/credentials').json()['credentials'], [])
        self.assertNoLeak(self.get('/jobs').json(), passwords.PASSWORD, 'SYNTHETIC-MGMT')

    def test_idpw_login_counts_the_session_timeout_the_bank_stated(self):
        bank = passwords.Bank(self)
        bank.modifiers['app-info'] = lambda v: {'data': {**v['data'], 'sessionTimeout': '10'}}
        self.bank_exchange = bank
        job = self.run_job(self.submit('hana.corporate.login-idpw', login_id=self.connection['id'])['id'],
                           {'login_password': passwords.PASSWORD})
        self.assertEqual(job['outcome'], 'success', job)
        listed = next(r for r in self.get('/logins').json()['logins'] if r['id'] == self.connection['id'])
        self.assertEqual(listed['session']['idle_seconds'], 600)
        self.assertEqual(listed['session']['idle_expires_at'] - listed['session']['last_request_at'], 600)

    def test_explicit_login_rejection_and_success_with_followup_failure(self):
        bank = passwords.Bank(self)
        self.bank_exchange = bank
        bank.modifiers['login-idpw'] = lambda value: {'headerData': {'status': '500'}, 'data': {}}
        rejected = self.run_job(self.submit('hana.corporate.login-idpw', login_id=self.connection['id'])['id'],
                                {'login_password': passwords.PASSWORD})
        self.assertEqual(rejected['outcome'], 'rejected', rejected)
        bank.calls.clear(); bank.modifiers.clear()
        bank.modifiers['customer-check'] = lambda value: {'headerData': {'status': '500'}, 'data': {}}
        result = self.run_job(self.submit('hana.corporate.login-idpw', login_id=self.connection['id'])['id'],
                             {'login_password': passwords.PASSWORD})
        self.assertEqual(result['outcome'], 'success', result)
        self.assertTrue(result['result']['session_id'])

    def test_partial_accounts_are_linked_and_output_is_allowlisted(self):
        self.adopt(self.session())
        self.responses['accounts'] = lambda values: {'outRec01': [{'ACCT_NO': '000204', 'PRD_NM': '두번째'}]} \
            if values['tabType'] == ['00'] else {'headerData': {'status': '500'}, 'data': {}}
        result = self.run_job(self.submit('hana.corporate.accounts', login_id=self.connection['id'], input={'category': 'all'})['id'])
        self.assertTrue(result['service_verdict']['accepted'])
        self.assertEqual(result['outcome'], 'partial_success', result)
        self.assertFalse(result['result']['complete'])
        self.assertEqual(len(self.get('/targets').json()['targets']), 2)
        self.assertNoLeak(result, 'HIDDEN-TOKEN', 'SYNTHETIC-COOKIE')

    def test_empty_history_is_complete_and_partial_pages_remain_visible(self):
        self.adopt(self.session())
        self.responses['history-krw'] = {'REC_CNT': 0, 'ciq0015Output': {}}
        def run():
            return self.run_job(self.submit('hana.corporate.history', login_id=self.connection['id'], target_id=self.account['id'])['id'])
        result = run()
        self.assertEqual((result['result']['transactions'], result['result']['complete']), ([], True))
        self.responses['history-krw'] = lambda values: query_fixtures.QueryTests.page('Y') if values['PAGE_NO'] == ['1'] else {'headerData': {'status': '500'}, 'data': {}}
        partial = run()
        self.assertEqual((partial['outcome'], len(partial['result']['transactions'])), ('partial_success', 1))

    def test_transfer_without_auth_only_sends_after_confirmation_once(self):
        prepared = self.prepare()
        complete = self.confirm(prepared)
        self.assertEqual(complete['result']['transfer_status'], 'completed', complete)
        jobs.accept_confirmation(self.db, prepared['id'], prepared['awaiting']['digest'], 'web:test')
        self.run_job(prepared['id'])
        self.assertEqual([s for s, _ in self.calls].count('transfer-execute'), 1)
        follow = self.run_job(self.submit('hana.corporate.transfer.result', login_id=self.connection['id'], parent_job_id=prepared['id'])['id'])
        self.assertEqual(follow['result']['transfer_status'], 'completed', follow)

    def numeric_auth(self):
        public, _ = passwords.crypto.OpenSSL().curve(7)
        self.auth['NSHC_PUBLIC_KEY'] = base64.b64encode(passwords.envelope.public_key_envelope(b'SYNTHETIC', public, passwords.MAC)).decode()
        self.responses.update({'account-password': {'PW_VRFC_CPLT_YN': 'Y'}, 'otp': {'OTP_VALID_YN': 'Y'}})

    def test_only_bank_required_password_then_otp_then_shared_certificate(self):
        prepared = self.prepare()
        synthetic_certificate()
        self.auth.update(PW_VRFC_YN='Y', SCRT_MDCL_VRFC_YN='Y', SEND_CERT_SBMT_YN='Y')
        self.numeric_auth()
        value = self.confirm(prepared)
        self.assertEqual(value['awaiting']['requires'], ['account_password'])
        value = self.confirm(value, {'account_password': '0987'})
        self.assertEqual(value['awaiting']['requires'], ['otp'])
        value = self.confirm(value, {'otp': '098765'})
        self.assertEqual(value['awaiting']['requires'], ['certificate_password'])
        value = self.confirm(value, {'certificate_password': 'Synthetic-Password!'})
        self.assertEqual(value['result']['transfer_status'], 'completed', value)
        for name in ('unified-auth', 'account-password', 'otp', 'transfer-execute'):
            self.assertEqual([s for s, _ in self.calls].count(name), 1, name)
        self.assertNoLeak(value, '098765', 'Synthetic-Password!', 'NSHC_PUBLIC_KEY', 'SIGNED_MSG', 'SYNTHETIC-COOKIE')

    def test_ars_code_not_in_history_and_no_repeated_call_or_successful_check(self):
        prepared = self.prepare()
        self.auth.update(SCRT_MDCL_VRFC_YN='Y', RESULT_FDS_INQ='EATP')
        self.numeric_auth()
        self.responses.update({'ars-phones': {'ARS_OUTPUT_MSG': {'BIZ.CUM0118.OUT.REC': [
            {'SEQ_NO': '1', 'CERT_RQST_TEL_NO': 'SYNTHETIC-PHONE'}]}},
            'ars-request': {'ARS_APV_NO_RESULT': 'SUCCESS', 'ARS_APV_NO': '765432'},
            'ars-check': {'ARS_APV_NO_RESULT': 'SUCCESS'}})
        value = self.confirm(prepared)
        self.assertEqual(value['awaiting']['next_step'], 'ars')
        self.assertNoLeak(value, '765432', 'SYNTHETIC-PHONE')
        self.assertEqual(self.get('/jobs/' + value['id'] + '/corporate-ars').json(), {'code': '765432'})
        value = self.confirm(value)
        self.assertEqual(value['awaiting']['requires'], ['otp'])
        value = self.confirm(value, {'otp': '098765'})
        self.assertEqual(value['result']['transfer_status'], 'completed', value)
        for name in ('ars-request', 'ars-check', 'transfer-execute'):
            self.assertEqual([s for s, _ in self.calls].count(name), 1)
        self.assertEqual(self.get('/jobs/' + value['id'] + '/corporate-ars').status_code, 400)

    def test_cancel_preparation_closes_parent_and_never_sends_transfer(self):
        value = self.prepare()
        cancelled = self.run_job(self.submit('hana.corporate.transfer.cancel', login_id=self.connection['id'], parent_job_id=value['id'])['id'])
        self.assertEqual(cancelled['result']['transfer_status'], 'preparation_cancelled', cancelled)
        self.assertEqual(self.get('/jobs/' + value['id']).json()['status'], 'cancelled')
        self.assertNotIn('transfer-execute', [s for s, _ in self.calls])

    def test_later_preparation_cannot_replace_confirmed_job(self):
        prepared = self.prepare()
        storage.atomic_json(store.session_path('company') / 'pending-transfer.json', {'transfer': 'other'})
        result = self.confirm(prepared)
        self.assertEqual(result['local']['stopped'], 'prepared_transfer_changed')
        self.assertNotIn('transfer-execute', [s for s, _ in self.calls])

    def test_failed_result_query_preserves_accepted_submission(self):
        prepared = self.prepare()
        self.responses['transfer-result'] = RuntimeError('PRIVATE-RESPONSE')
        result = self.confirm(prepared)
        self.assertTrue(result['service_verdict']['accepted'], result)
        self.assertEqual(result['result']['transfer_status'], 'submitted')
        self.assertNoLeak(result, 'PRIVATE-RESPONSE')

    def test_invalid_local_otp_can_be_corrected_without_resending_bank_auth(self):
        prepared = self.prepare()
        self.auth.update(SCRT_MDCL_VRFC_YN='Y')
        self.numeric_auth()
        value = self.confirm(prepared)
        value = self.confirm(value, {'otp': 'wrong'})
        self.assertEqual(value['awaiting']['next_step'], 'otp', value)
        self.assertNotIn('otp', [s for s, _ in self.calls])
        value = self.confirm(value, {'otp': '098765'})
        self.assertEqual(value['result']['transfer_status'], 'completed', value)
        for name in ('unified-auth', 'otp', 'transfer-execute'):
            self.assertEqual([s for s, _ in self.calls].count(name), 1)

    def test_bank_otp_rejection_is_not_retried(self):
        prepared = self.prepare()
        self.auth.update(SCRT_MDCL_VRFC_YN='Y')
        self.numeric_auth()
        self.responses['otp'] = {'OTP_VALID_YN': 'N'}
        value = self.confirm(self.confirm(prepared), {'otp': '098765'})
        self.assertEqual(value['status'], 'finished', value)
        self.assertEqual(value['local']['stopped'], 'otp_not_verified')
        self.assertEqual([s for s, _ in self.calls].count('otp'), 1)
        self.assertNotIn('transfer-execute', [s for s, _ in self.calls])

    def test_diagnostic_warnings_and_scalar_allowlist_do_not_change_verdict(self):
        from finance_cli.server.adapters.hana_corporate import verdict, transfer_result
        value = {'accepted': True, 'stages': [{'stage': 'login-idpw', 'warnings': ['response_shape_notice']}],
                 'warnings': ['followup_storage_failed', 'PRIVATE-DATA!'],
                 'preview': {'acctNo': {'cookie': 'PRIVATE-COOKIE'}, 'items': [{'TRNS_AMT': '0001.00', 'token': 'PRIVATE-TOKEN'}]}}
        self.assertTrue(verdict(value)['accepted'])
        self.assertEqual(verdict(value)['stages'][0]['warnings'], ['response_shape_notice'])
        self.assertNoLeak(verdict(value), 'PRIVATE-DATA!')
        self.assertNoLeak(transfer_result(value), 'PRIVATE-COOKIE', 'PRIVATE-TOKEN')
        self.assertEqual(transfer_result(value)['preview']['items'][0]['TRNS_AMT'], '0001.00')

    def test_options_static_asset_and_capabilities(self):
        options = self.get('/corporate/options').json()
        self.assertEqual(options['selected'], 'synthetic')
        self.assertNotIn('keypad_mac', json.dumps(options))
        self.assertEqual(self.client.get('/static/corporate.js').status_code, 200)
        features = self.get('/capabilities').json()['features']
        self.assertEqual({f['id'] for f in features if f['area'] == 'corporate'},
                         {'corporate-login', 'corporate-extend', 'corporate-accounts', 'corporate-history',
                          'corporate-transfer'})
        self.assertTrue(all(f['status'] == 'available' for f in features if f['area'] == 'corporate'))

    def test_login_extension_keeps_the_bank_verdict_and_590_idle_seconds_count_as_logged_out(self):
        import time
        from finance_cli.server import session_activity
        from finance_cli.services.hana_corporate import session as extension
        self.adopt(self.session())
        row = lambda: next(r for r in self.get('/logins').json()['logins'] if r['id'] == self.connection['id'])
        self.assertTrue(time.time() + 580 < row()['session']['idle_expires_at'] <= time.time() + 590)
        self.assertEqual(row()['session']['idle_seconds'], 590)
        value = {'operation': 'session-extend', 'network_used': True, 'accepted': True, 'login_extension_accepted': True,
                 'session_ended': False, 'service_status': 'accepted', 'reason': 'login_extension_accepted',
                 'processing_status': 'completed', 'server_expires_at': None, 'warnings': [], 'stages': []}
        with patch.object(extension, 'extend', return_value=value) as sent:
            job = self.run_job(self.submit('hana.corporate.session.extend', login_id=self.connection['id'])['id'])
        self.assertEqual((job['outcome'], job['result']['login_extension_accepted']), ('success', True), job)
        self.assertEqual(sent.call_count, 1)
        self.assertEqual(sent.call_args.kwargs['send'], True)
        self.assertEqual(row()['readiness'], 'ready')
        with patch.object(session_activity, 'now', return_value=time.time() + 591):
            self.assertEqual(row()['readiness'], 'login_required')
            with self.assertRaisesRegex(jobs.NotReady, '^session_idle_expired$'):
                self.submit('hana.corporate.accounts', login_id=self.connection['id'])
            with self.assertRaisesRegex(jobs.NotReady, '^session_idle_expired$'):
                self.submit('hana.corporate.session.extend', login_id=self.connection['id'])
        ended = {**value, 'accepted': False, 'login_extension_accepted': False, 'session_ended': True,
                 'service_status': 'rejected', 'reason': 'session_ended', 'session_current_validity': 'ended'}
        with patch.object(extension, 'extend', return_value=ended) as sent:
            job = self.run_job(self.submit('hana.corporate.session.extend', login_id=self.connection['id'])['id'])
        self.assertEqual((job['outcome'], sent.call_count), ('rejected', 1), job)
        self.assertEqual(row()['readiness'], 'login_required', 'a session the bank ended is not used again')

    def certificate_login(self, method, bank, credential, inputs):
        from finance_cli.services.hana_corporate import login
        connection = self.post('/logins', {'institution': 'hana_corporate', 'method': method,
                                         'name': '합성 인증서 기업', 'credential': credential}).json()
        self.bank_exchange = bank
        original = login.login
        with patch.object(store, 'default_device', return_value=certificate_fixtures.device()), \
                patch.object(login, 'login', side_effect=lambda *a, **kw: original(*a, **kw, exchange=bank)):
            job = self.run_job(self.submit('hana.corporate.login' + ('-onesign' if method == 'onesign' else ''),
                                           login_id=connection['id'])['id'], inputs)
        self.assertEqual(job['outcome'], 'success', job)
        self.assertTrue(job['result']['session_id'])
        self.assertNoLeak(job, certificate_fixtures.PASSWORD, 'SYNTHETIC-COMPANY', 'SYNTHETIC-CONFIRMED-SIGNATURE')
        return job

    def test_joint_certificate_login_uses_shared_vault_and_automatic_device(self):
        bank = certificate_fixtures.CorporateTests.joint(self)
        job = self.certificate_login('joint_certificate', bank, 'shared', {'certificate_password': certificate_fixtures.PASSWORD})
        self.assertEqual(job['result']['login_method'], 'joint_certificate')
        self.assertEqual(len(self.get('/credentials').json()['credentials']), 1)

    def test_onesign_login_reuses_existing_personal_certificate_without_enrollment(self):
        bank = certificate_fixtures.CorporateTests.hana_certificate(self)
        job = self.certificate_login('onesign', bank, 'shared-one', {'vault_passphrase': certificate_fixtures.PASSWORD,
                                    'pin': certificate_fixtures.PIN})
        self.assertEqual(job['result']['login_method'], 'onesign')
        self.assertEqual(len(self.get('/credentials').json()['credentials']), 1)
        self.assertNotIn('/oqf' + certificate_fixtures.pin.LOGIN_PATH, [call[3] for call in bank.calls])
