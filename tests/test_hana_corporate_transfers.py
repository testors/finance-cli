"""Synthetic transfer submission, secret separation and partial outcomes."""
import base64
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from Crypto.PublicKey import RSA
from finance_cli.cli.main import main
from finance_cli.core import storage
from finance_cli.credentials.registry import Registry
from finance_cli.credentials.joint import crypto
from finance_cli.services.hana.nfilter_crypto import OpenSSL
from finance_cli.services.hana.nfilter_format import public_key_envelope, decode_public_key_envelope
from finance_cli.services.hana.nfilter_number import pack_numeric_input
from finance_cli.services.hana_corporate import store, transfers, transfer_protocol as wire
from test_hana_corporate import certificate, verify_cms, PASSWORD
import test_hana_corporate_queries as query_fixtures


class TransferTests(unittest.TestCase):
    setUp = query_fixtures.QueryTests.setUp
    session = query_fixtures.QueryTests.session
    exchange = query_fixtures.QueryTests.exchange

    @classmethod
    def setUpClass(cls):
        cls.key = RSA.generate(2048).export_key(format='DER', pkcs=8)
        cls.cert = certificate(cls.key)
        cls.encrypted = crypto.encrypt(cls.key, PASSWORD)

    def prepare(self, **kwargs):
        return transfers.prepare('000101', '081', '000201', '1000', send=True, exchange=self.exchange, **kwargs)

    def execute(self, **kwargs):
        return transfers.execute(send=True, exchange=self.exchange, **kwargs)

    def fixture(self):
        path = self.session()
        self.item = {'ACCT_NO': '000101', 'RCV_BNK_CD': '081', 'RCV_ACCT_NO': '000201', 'TRNS_AMT': 1000,
                     'COMM': '0', 'E_CHNL_TRSC_ACPN_NO': '000001', 'RCV_BNK_NM': '합성은행',
                     'WDRW_PSBK_MARK_CTT': '합성수취인', 'RCV_PSBK_MARK_CTT': '합성송금인', 'RMTE_NM': '합성수취인',
                     'CMSV_NO': '', 'MEMO': '', 'DUP_YN': 'N'}
        self.confirmation = {'acctNo': '000101', 'totlTrnsAmt': 1000, 'totalRduAfComm': '0',
                             'cts0003Output': {'CHNL_COMM_DV_CD': '01', 'CMNW_TMSG_UNQ_NO': '000012'},
                             'cts0004InRec': [self.item]}
        self.auth = {'LOGINED_TYPE_CD': '1', 'PW_VRFC_YN': 'N', 'SCRT_MDCL_VRFC_YN': 'N', 'SEND_CERT_SBMT_YN': 'N'}
        self.responses.update({
            'transfer-init': {'acctList': [{'accountNo': '000101', 'alias': '합성계좌'}],
                              'custNm': '합성송금인', 'owacNm': '합성송금인', 'paymPossAmt': '100000'},
            'transfer-recipient': {'resResult': '합성수취인'}, 'transfer-amount': {}, 'transfer-prepare': {},
            'transfer-confirm': self.confirmation, 'unified-auth': self.auth, 'transfer-execute': {},
            'transfer-result': {'cts0004Output': {'SYNC_YN': 'Y', 'BIZ.CTS0004.OUT.REC1': [self.item]}, 'cts0004InRec': [self.item],
                                'cts0004OutRec1': [{**self.item, 'ERR_CD': 'NCOM10058'}]}, 'transfer-clear': {}})
        return path

    def test_short_flow_uses_prepared_transaction_and_no_unneeded_secrets(self):
        self.fixture()
        output = self.prepare()
        self.assertTrue(output['accepted'], output)
        self.assertFalse(output['transfer_sent'])
        inputs = {name: lambda: self.fail('unneeded secret') for name in ('password', 'otp', 'account_password')}
        result = self.execute(inputs=inputs)
        self.assertTrue(result['accepted'], result)
        self.assertEqual(result['transfer_status'], 'completed')
        final = next(v for stage, v in self.calls if stage == 'transfer-execute')
        self.assertEqual(final, {})
        repeated = self.execute()
        self.assertEqual(repeated['error'], 'transfer_already_attempted_use_result')
        self.assertEqual(len([stage for stage, _ in self.calls if stage == 'transfer-execute']), 1)

    def test_plan_never_reads_state_certificate_or_secret(self):
        with patch.object(store, 'select', side_effect=AssertionError('state access')):
            for call in (lambda: transfers.prepare('000101', '081', '000201', '1000'), transfers.execute,
                         transfers.result, transfers.cancel):
                self.assertFalse(call()['network_used'])
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(main(['hana', 'corporate', 'transfer', 'execute']), 0)
            self.assertEqual(json.loads(stdout.getvalue())['processing_status'], 'planned')

    def test_duplicate_is_review_choice_and_not_bank_failure(self):
        self.fixture()
        self.item['DUP_YN'] = 'Y'
        self.prepare()
        result = self.execute()
        self.assertIsNone(result['accepted'])
        self.assertFalse(result['network_used'])
        self.assertEqual(result['error'], 'duplicate_transfer_confirmation_required')
        self.assertEqual(self.execute(allow_duplicate=True)['transfer_status'], 'completed')

    def test_failed_result_query_does_not_revoke_submission(self):
        self.fixture()
        self.prepare()
        self.responses['transfer-result'] = RuntimeError('SYNTHETIC-PRIVATE')
        result = self.execute()
        self.assertTrue(result['accepted'], result)
        self.assertTrue(result['transfer_sent'])
        self.assertEqual(result['transfer_status'], 'submitted')
        self.assertEqual(self.prepare()['error'], 'pending_transfer_exists_use_execute_result_or_cancel')
        self.responses['transfer-result'] = {'cts0004Output': {'SYNC_YN': ''}}
        checked = transfers.result(send=True, exchange=self.exchange)
        self.assertTrue(checked['accepted'])
        self.assertEqual(checked['transfer_status'], 'approval_requested')
        self.assertEqual(len([s for s, _ in self.calls if s == 'transfer-execute']), 1)

    def test_unknown_final_is_never_resent_and_error_has_no_private_text(self):
        self.fixture()
        self.prepare()
        self.responses['transfer-execute'] = RuntimeError('SYNTHETIC-PRIVATE')
        result = self.execute()
        self.assertIsNone(result['accepted'])
        self.assertTrue(result['transfer_sent'])
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(result))
        self.assertFalse(self.execute()['network_used'])

    def test_explicit_final_rejection_stays_distinct_from_unknown_transport(self):
        self.fixture()
        self.prepare()
        self.responses['transfer-execute'] = {'headerData': {'status': '500', 'errorCode': 'AUTH_58'}, 'data': {}}
        result = self.execute()
        self.assertIs(result['accepted'], False)
        self.assertEqual(result['transfer_status'], 'rejected')
        self.assertEqual(result['error'], 'permission_required')
        self.assertNotIn('transfer-result', [s for s, _ in self.calls])

    def test_serialization_and_cancel_prepared_only(self):
        path = self.fixture()
        with storage.lock(path / 'operation.lock'):
            self.assertFalse(self.prepare()['network_used'])
        self.prepare()
        self.assertFalse(self.prepare()['network_used'])
        self.assertEqual(transfers.cancel(send=True, exchange=self.exchange)['transfer_status'], 'preparation_cancelled')
        self.assertTrue(self.prepare()['accepted'])
        self.execute()
        self.assertEqual(transfers.cancel(send=True, exchange=self.exchange)['error'], 'submitted_transfer_cannot_be_cancelled_here')

    def test_no_recipient_name_continues_like_business_callback(self):
        self.fixture()
        self.responses['transfer-recipient'] = {'resResult': 'JSON_NO_DATA'}
        output = self.prepare()
        self.assertTrue(output['accepted'], output)
        body = next(v for stage, v in self.calls if stage == 'transfer-prepare')
        self.assertEqual(body['RMTE_NM'], [''])

    def test_original_partial_delay_approval_and_single_success_conditions(self):
        self.fixture()
        response = self.responses['transfer-result']
        self.assertEqual(wire.completion(response)['transfer_status'], 'completed')
        self.assertEqual(wire.completion({**response, 'dlayTrnsYn': 'Y'})['transfer_status'], 'delayed')
        self.item['RCV_ACCT_SEF_YN'] = 'Y'
        self.assertEqual(wire.completion({**response, 'dlayTrnsYn': 'Y'})['transfer_status'], 'completed')
        multiple = {**response, 'cts0004InRec': [self.item, self.item], 'errYn': 'Y', 'sussCnt': 1, 'errCnt': 1}
        self.assertEqual(wire.completion(multiple)['transfer_status'], 'partial')
        self.assertEqual(wire.completion({**multiple, 'allErrYn': 'Y'})['transfer_status'], 'rejected')
        multiple['errYn'] = 'N'
        self.assertEqual(wire.completion(multiple)['transfer_status'], 'approval_requested')

    def test_account_password_otp_and_shared_certificate_wire(self):
        path = self.fixture()
        Registry().import_npki('shared', self.cert, self.encrypted, PASSWORD.encode())
        mac = bytes(range(20))
        public, _ = OpenSSL().curve(7)
        self.auth.update(PW_VRFC_YN='Y', SCRT_MDCL_VRFC_YN='Y', SEND_CERT_SBMT_YN='Y',
                         NSHC_PUBLIC_KEY=base64.b64encode(public_key_envelope(b'SYNTHETIC', public, mac)).decode())
        def verified(stage, values, field, plain, response):
            encoded = values[field][0]
            length = 4 * ((len(public_key_envelope(b'', public, mac)) + 2) // 3)
            envelope = encoded[:length]
            _, client_public = decode_public_key_envelope(base64.b64decode(envelope), mac)
            _, shared = OpenSSL().curve(7, client_public)
            expected = envelope + base64.b64encode(OpenSSL().encrypt(shared[:16], pack_numeric_input(shared, plain))).decode()
            self.assertEqual(encoded, expected)
            return response
        self.responses['account-password'] = lambda v: verified('pw', v, 'ACCT_PW', '0123', {'PW_VRFC_CPLT_YN': 'Y'})
        self.responses['otp'] = lambda v: verified('otp', v, 'OTP_RSPS_CD', '012345', {'OTP_VALID_YN': 'Y'})
        def submitted(values):
            self.assertEqual(values['COMM_HEAD[LGIN_CERT_METH_CD]'], ['1'])
            self.assertEqual(verify_cms(values['COMM_HEAD[SIGNED_MSG]'][0], self.cert), wire.signing_bytes(
                wire.signed_fields(self.confirmation), {'date': '20261003', 'time': '120000'}))
            return {}
        self.responses['transfer-execute'] = submitted
        self.prepare()
        with patch('finance_cli.services.hana_corporate.keypad.resolve', return_value=('synthetic', mac)):
            result = self.execute(inputs={'password': lambda: PASSWORD.encode(), 'account_password': lambda: '0123', 'otp': lambda: '012345'})
        self.assertEqual(result['transfer_status'], 'completed', result)
        for file in path.rglob('request.json'):
            text = base64.b64decode(storage.read_json(file)['body']).decode()
            self.assertNotIn(PASSWORD, text)
            if file.parent.name in ('account-password', 'otp', 'transfer-execute'):
                self.assertIn('redacted', text)

    def test_ars_pause_resume_does_not_repeat_phone_request(self):
        self.fixture()
        self.auth.update(SCRT_MDCL_VRFC_YN='Y', RESULT_FDS_INQ='EATP')
        self.responses.update({'ars-phones': {'ARS_OUTPUT_MSG': {'BIZ.CUM0118.OUT.REC': [
            {'SEQ_NO': '0001', 'CERT_RQST_TEL_NO': 'SYNTHETIC-PHONE', 'CERT_RQST_TEL_NO_TYP_CD': '01'}]}},
            'ars-request': {'ARS_APV_NO_RESULT': 'SUCCESS', 'ARS_APV_NO': '1234'},
            'ars-check': {'ARS_APV_NO_RESULT': 'PENDING'}})
        self.prepare()
        first = self.execute(inputs={'ars_completed': lambda code: code == '1234'})
        self.assertEqual(first['error'], 'ars_authentication_pending')
        self.responses['ars-check'] = {'ARS_APV_NO_RESULT': 'SUCCESS'}
        self.auth['MOTP_USR_YN'] = 'Y'
        # The cached server selection is immutable; complete phone auth then
        # stop for a missing numeric input instead of reopening the telephone call.
        second = self.execute(ars_completed=True)
        self.assertFalse(second['transfer_sent'])
        self.assertEqual(len([s for s, _ in self.calls if s == 'ars-request']), 1)
        self.assertEqual(len([s for s, _ in self.calls if s == 'ars-check']), 2)

    def test_stopped_or_mobile_otp_branches_do_not_submit(self):
        self.fixture()
        self.prepare()
        self.auth.update(SCRT_MDCL_VRFC_YN='Y', MOTP_USR_YN='Y')
        result = self.execute()
        self.assertEqual(result['error'], 'mobile_otp_required_not_supported')
        self.assertFalse(result['transfer_sent'])

    def test_bank_delay_and_time_notice_do_not_block_preparation(self):
        self.fixture()
        self.responses['transfer-init']['dlayTrnsYn'] = True
        self.responses['server-time'] = {'date': '20261003', 'time': '170000', 'bizDayCheck': 'Y'}
        result = transfers.prepare('000101', '004', '000201', '1000', send=True, exchange=self.exchange)
        self.assertTrue(result['accepted'], result)
        self.assertIn('delayed_transfer_time_notice_check_result', result['warnings'])
        body = next(v for stage, v in self.calls if stage == 'transfer-prepare')
        self.assertEqual(body['DLAY_TRNS_YN'], ['Y'])
        self.assertEqual(len([s for s, _ in self.calls if s == 'server-time']), 3)

    def test_note_guard_keeps_single_digit_and_identity_notice_continues(self):
        body = {'CMSV_NO': 'aB-123', 'WDRW_PSBK_MARK_CTT': '1', 'RCV_PSBK_MARK_CTT': '', 'MEMO': ''}
        wire.check_notes(body, {})
        from finance_cli.services.hana_corporate.protocol import Stop
        with self.assertRaisesRegex(Stop, 'repeated_numeric_transfer_note'):
            wire.check_notes({**body, 'MEMO': '111'}, {})
        with self.assertRaisesRegex(Stop, 'invalid_cms_code'):
            wire.check_notes({**body, 'CMSV_NO': '합성'}, {})
        # A generated invalid-date sequence, not a person's identity.
        text = '999999199999'
        check = (11 - sum(int(c) * n for c, n in zip(text, (2,3,4,5,6,7,8,9,2,3,4,5))) % 11) % 10
        output = {}
        wire.check_notes({**body, 'MEMO': text + str(check)}, output)
        self.assertIn('personal_number_in_transfer_note_notice', output['warnings'])

    def test_request_response_and_result_storage_errors_preserve_completed_transfer(self):
        self.fixture()
        record = store.record
        def failing(path, value):
            if path.name in ('request.json', 'response.json', 'requested.json', 'finished.json', 'transfer-execute-received.json'):
                raise OSError('SYNTHETIC-PRIVATE')
            return record(path, value)
        with patch.object(store, 'record', side_effect=failing):
            prepared = self.prepare()
            output = self.execute()
        self.assertTrue(prepared['accepted'], prepared)
        self.assertTrue(output['accepted'], output)
        self.assertEqual(output['transfer_status'], 'completed')
        self.assertEqual(output['processing_status'], 'completed')
        self.assertFalse(self.execute()['network_used'])
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(output))

    def test_fds_stop_and_unknown_continue_follow_bank_selection(self):
        self.fixture()
        self.prepare()
        self.auth.update(SCRT_MDCL_VRFC_YN='Y', RESULT_FDS_INQ='ENTP')
        output = self.execute()
        self.assertEqual(output['error'], 'transfer_stopped_by_bank')
        self.assertFalse(output['transfer_sent'])
        self.assertNotIn('otp', [s for s, _ in self.calls])

    def test_cli_selection_and_secret_fd_conflicts_are_json_and_no_io(self):
        with patch.object(store, 'select', side_effect=AssertionError('state access')):
            for tail, error in [(['--credential=one', '--profile=two'], 'invalid_arguments'),
                    (['--account-password-fd=0', '--password-stdin', '--send'], 'secret_descriptors_must_be_distinct')]:
                with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()):
                    try:
                        code = main(['--format', 'json-v1', 'hana', 'corporate', 'transfer', 'execute', *tail])
                    except SystemExit as exc:
                        code = exc.code
                output = json.loads(stdout.getvalue())
                self.assertEqual(code, 2, output)
                self.assertEqual(output['exit_code'], code)
                self.assertIn(error, json.dumps(output))


if __name__ == '__main__':
    unittest.main()
