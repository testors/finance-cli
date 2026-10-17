"""Synthetic native transfer flow; network calls are intercepted and sockets forbidden."""
import base64
import json
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.core import storage
from finance_cli.services.shinhan import setup, transfer, transfer_protocol as protocol, transport
from finance_cli.services.shinhan.enrollment import Pending
from test_shinhan import PrivateHome, response, settings

SOURCE, DESTINATION = '000100001111', '000200002222'
ENTRY = {'jiAcNo': SOURCE, 'acNm': 'SYN-CHECKING', 'bnkC': '088', 'bnkG': '1', 'shbBankYn': 'Y'}
OWNER = {'ipAcSungNmS20': 'SYN-RECEIVER', 'icheGS1': '2', 'ipbnkCS3_display': 'SYN-BANK',
         'ipAcNoS16': DESTINATION, 'jiAcnoS16': SOURCE}
INQUIRY = {'trxSerS100': 'SYN-SERIAL', 'cltTrxnoS10': 'SYN-CLIENT',
           'acScnoOmitYnS1': 'Y', 'loginMthOmitYnS1': 'Y', 'secrityMdiaOmitYnS1': 'Y',
           'ipAcSungNmS20': 'SYN-RECEIVER', 'ipbnkCS3_display': 'SYN-BANK',
           'ipAcNoS16': DESTINATION, 'icheamtN15_originalValue': 100, 'aplFeamtN18': 0}
RECEIPT = {name: (100 if kind == 'double' else '0' if name == 'jiAcnoJanS21_originalValue' else '')
           for name, (kind, default) in protocol.RECEIPT.items() if default is None}


class TransferTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.install()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        storage.atomic_json(setup.root()/'session.json', {'cookie': 'JSESSIONID=SYN-COOKIE',
            'authenticated': True, 'credential': 'SYN-CERT', 'last_login_type': 'G', 'login': {'user': {}}})
        self.calls, self.replies = [], []
        def send(payload, cookie, *, path):
            document = json.loads(payload)
            key = bytes.fromhex(settings()['bank_key'])
            body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(document['dataBody'])), 16))
            self.calls.append((document['dataHeader']['trxCd'], body, path))
            if not self.replies:
                raise AssertionError('Unplanned request')
            answer = self.replies.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer
        self.enterContext(patch.object(transport, 'post', side_effect=send))

    def answer(self, body=None, result='SUCCESS', **header):
        self.replies.append(transport.Reply(200, [], response(result, body, **header)))

    def prepared(self, inquiry=None):
        for body in (ENTRY, {}, OWNER, INQUIRY if inquiry is None else inquiry):
            self.answer(body)
        report = transfer.run('prepare', bank='하나은행', account=DESTINATION, amount=100)
        self.assertTrue(report.get('prepared'), report)
        self.assertEqual(report['transfer_result'], 'not_sent')
        return report

    def no_input(self, stage, context):
        raise AssertionError('Unexpected input: '+stage)

    def test_prepare_does_not_transfer_and_uses_bank_default_not_generic_accounts(self):
        report = self.prepared()
        self.assertEqual([r[0] for r in self.calls], ['RSMDE1402A02', 'RSMDE1401A02', 'RSMDE0200A10', 'RSMDE1402A12'])
        self.assertEqual(self.calls[0][1], {'srchNoS30': ''})
        inquiry = self.calls[-1][1]
        self.assertEqual(inquiry['jiAcnoS16'], SOURCE)
        self.assertEqual((inquiry['ipbnkCS3'], inquiry['ipAcInMthS2']), ('081', '01'))
        self.assertEqual(inquiry['rcvEnc3'], protocol.field_encrypt('100', settings()))
        private = storage.read_json(report['data_file'])
        self.assertEqual((private['receiver_name'], private['amount'], private['fee']), ('SYN-RECEIVER', 100, 0))
        self.assertEqual(Path(report['data_file']).stat().st_mode & 0o777, 0o600)
        for secret in (SOURCE, DESTINATION, 'SYN-CLIENT', 'SYN-SERIAL', 'SYN-RECEIVER', 'SYN-COOKIE'):
            self.assertNotIn(secret, json.dumps(report))
        code, out, _ = self.call(['transfer', 'show'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['result']['preview']['amount'], 100)
        self.assertEqual(len(self.calls), 4)

    def test_omitted_auth_does_not_prompt_and_execution_is_once(self):
        self.prepared()
        self.answer({'addAuthDsYnS1': 'N'}); self.answer(RECEIPT)
        report = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual((report['bank_result'], report['transfer_result'], report['processing_status']),
                         ('success', 'success', 'complete'))
        self.assertEqual([r[0] for r in self.calls[-2:]], ['RSMDE1402A06', 'RSMDE1402A04'])
        self.assertEqual(self.calls[-1][1], {'cltTrxnoS10': 'SYN-CLIENT', 'trxSerS100': 'SYN-SERIAL',
            'feePntUsynS1': 'N', 'putuseFeeN10': 0, 'ipAcMemS20': '', 'jiAcMemS20': '', 'dupYnN1': '0', 'reqKey': ''})
        again = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual(again['required_action'], 'transfer_attempt_already_used')
        self.assertEqual(len(self.calls), 6)

    def test_auth_queue_password_pisp_otp_additional_before_execute(self):
        self.prepared(INQUIRY | {'acScnoOmitYnS1': 'N', 'loginMthOmitYnS1': 'N',
                                'secrityMdiaOmitYnS1': 'N', 'ygSecrityMdiaKS20': 'OTP'})
        sequence = []
        def encrypted(channel, provider, length):
            sequence.append(('keypad', length)); provider()
            return 'SYN-ENCRYPTED'
        def pisp(exchange, context, provider):
            sequence.append(('pisp', None))
        for body in (None, None, {'addAuthDsYnS1': 'N'}, RECEIPT):
            self.answer(body)
        with patch.object(transfer.keypad.Channel, 'read', encrypted), patch.object(transfer, 'pisp', pisp):
            report = transfer.run('execute', input_provider=lambda stage, _: b'1234' if stage == 'account_password' else b'123456')
        self.assertEqual(sequence, [('keypad', 4), ('pisp', None), ('keypad', 6)])
        self.assertEqual(report['transfer_result'], 'success')
        self.assertEqual([r[0] for r in self.calls[-4:]], ['RSMDE1402C01', 'RSMCM1100A04', 'RSMDE1402A06', 'RSMDE1402A04'])
        self.assertEqual(self.calls[-3][1]['nxtSvcCS20'], '')
        self.assertEqual(self.calls[-4][1], {'cltTrxnoS10': 'SYN-CLIENT', 'sub01': [{'jiAcno': SOURCE, 'scno': 'SYN-ENCRYPTED'}]})

    def test_timeout_and_repeated_execute_never_resend(self):
        self.prepared(); self.answer({'addAuthDsYnS1': 'N'})
        self.replies.append(transport.Reply(error='transport_error'))
        report = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual((report['bank_result'], report['transfer_result']), ('unknown', 'unknown'))
        self.assertEqual(report['required_action'], 'transfer_outcome_requires_history_check')
        transfer.run('execute', input_provider=self.no_input)
        self.assertEqual(sum(c[0] == 'RSMDE1402A04' for c in self.calls), 1)

    def test_exception_during_execute_is_unknown_and_preserves_claim(self):
        self.prepared(); self.answer({'addAuthDsYnS1': 'N'}); self.replies.append(OSError('SYN-PRIVATE-ERROR'))
        report = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual(report['transfer_result'], 'unknown')
        self.assertEqual(report['required_action'], 'transfer_outcome_requires_history_check')
        self.assertNotIn('SYN-PRIVATE-ERROR', json.dumps(report))
        self.assertEqual(transfer.run('execute', input_provider=self.no_input)['required_action'], 'transfer_attempt_already_used')

    def test_restored_prepared_session_cannot_replay_consumed_reference(self):
        self.prepared()
        original = storage.read_json(setup.root()/'session.json')
        self.answer({'addAuthDsYnS1': 'N'}); self.answer(RECEIPT)
        transfer.run('execute', input_provider=self.no_input)
        storage.atomic_json(setup.root()/'session.json', original)
        report = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual(report['required_action'], 'transfer_attempt_already_used')
        self.assertFalse(report['network_used'])

    def test_bank_success_is_preserved_on_receipt_or_local_save_error(self):
        self.prepared(); self.answer({'addAuthDsYnS1': 'N'}); self.answer({})
        report = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual((report['bank_result'], report['transfer_result']), ('success', 'success'))
        self.assertEqual(report['processing_status'], 'incomplete')
        self.assertFalse(report['receipt_available'])
        self.prepared(); self.answer({'addAuthDsYnS1': 'N'}); self.answer(RECEIPT)
        original = storage.atomic_json
        def save(path, value):
            if Path(path).name == 'transfer-result.json':
                raise OSError('SYN-DISK-FULL')
            return original(path, value)
        with patch.object(storage, 'atomic_json', side_effect=save):
            report = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual((report['transfer_result'], report['bank_result']), ('success', 'success'))
        self.assertEqual(report['local_status'], 'incomplete')

    def test_explicit_bank_failure_has_no_retry(self):
        self.prepared(); self.answer({'addAuthDsYnS1': 'N'}); self.answer({}, 'FAIL', resultCode='RIB80306')
        report = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual((report['transfer_result'], report['bank_result']), ('failure', 'failure'))
        self.assertEqual(report['required_action'], 'transfer_rejected')
        self.assertEqual(len(self.calls), 6)

    def test_additional_auth_failure_never_sends_execute(self):
        self.prepared(); self.answer({'addAuthDsYnS1': 'Y', 'grid01': []})
        with patch.object(transfer.additional_auth, 'authenticate', return_value={'인증여부': 'N'}) as auth:
            report = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual(report['transfer_result'], 'not_sent')
        self.assertEqual(auth.call_args.args[1], {'serviceSeq': '9', '이체건수': 1, '입금은행명': 'SYN-BANK'})
        self.assertNotIn('RSMDE1402A04', [c[0] for c in self.calls])

    def test_fraud_question_and_unknown_security_are_not_bypassed(self):
        for flags, action in [({'fincSagiQstnDsynS1': 'Y'}, 'transfer_fraud_questionnaire_required'),
                              ({'secrityMdiaOmitYnS1': 'N', 'ygSecrityMdiaKS20': '모바일_OTP'}, 'transfer_security_media_route_not_implemented')]:
            self.prepared(INQUIRY | flags)
            count = len(self.calls)
            report = transfer.run('execute', input_provider=self.no_input)
            self.assertEqual(report['required_action'], action)
            self.assertEqual(report['transfer_result'], 'not_sent')
            self.assertEqual(len(self.calls), count)

    def test_source_selection_uses_withdrawal_grid(self):
        self.answer(ENTRY)
        self.answer({'grid01': [{'jiAcnoS20': '000-3333', 'bnkCS5': '088', 'bnkG': '1', 'obnkYn': 'Y'}]})
        for body in ({}, OWNER, INQUIRY): self.answer(body)
        report = transfer.run('prepare', bank='081', account=DESTINATION, amount=100, source='000-3333')
        self.assertTrue(report['prepared'])
        self.assertEqual(self.calls[1][0], 'RSMDE1402B03')
        self.assertEqual(self.calls[-1][1]['jiAcnoS16'], '0003333')

    def test_backup_route_does_not_get_native_receiver(self):
        self.answer(ENTRY | {'transferPrType': '2'})
        report = transfer.run('prepare', bank='081', account=DESTINATION, amount=100)
        self.assertEqual(report['required_action'], 'transfer_backup_route_required')
        self.assertEqual(len(self.calls), 1)

    def test_no_send_no_files_no_prompts_or_network(self):
        with patch('getpass.getpass', side_effect=AssertionError('Prompt forbidden')):
            code, out, err = self.call(['transfer', 'execute', '--pin-file', '/nonexistent'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)['result']['error'], 'send_required')
        self.assertFalse(self.calls)

    def test_cli_prepared_and_execute_no_input_when_bank_omits_auth(self):
        self.prepared(); self.answer({'addAuthDsYnS1': 'N'}); self.answer(RECEIPT)
        code, out, err = self.call(['transfer', 'execute', '--no-input', '--send'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['result']['transfer_result'], 'success')
        for secret in (SOURCE, DESTINATION, 'SYN-SERIAL', 'SYN-CLIENT'):
            self.assertNotIn(secret, out+err)

    def test_auth_flags_preserve_exact_original_defaults_and_case(self):
        body = protocol.history.decode('{}', protocol.INQUIRY)
        auth = protocol.authentication(body)
        self.assertTrue(auth['account_password']); self.assertTrue(auth['security_media']); self.assertFalse(auth['login'])
        body.update(acScnoOmitYnS1='y', secrityMdiaOmitYnS1='Y ', loginMthOmitYnS1='n', dupYnS1='Y')
        auth = protocol.authentication(body)
        self.assertTrue(auth['account_password']); self.assertTrue(auth['security_media']); self.assertFalse(auth['login'])
        self.assertEqual(protocol.execute_request(body)['dupYnN1'], '1')

    def test_password_null_callback_and_unknown_body_do_not_add_checks(self):
        body = protocol.history.decode('{}', protocol.INQUIRY)
        self.assertEqual(protocol.password_request(body, {'accountNumber': SOURCE}, None)['sub01'][0]['scno'], '')
        verdict, document = protocol.parser(protocol.INQUIRY, 'inquiry')(
            transport.Reply(200, [], response('SUCCESS', {'acScnoOmitYnS1': None, 'unknown': [None]})))
        self.assertEqual(verdict['bank_result'], 'success')
        self.assertEqual(document['dataBody']['acScnoOmitYnS1'], '')

    def test_pisp_body_excludes_login_fields_and_never_becomes_reqkey(self):
        value = protocol.pisp_request({'alias': 'SYN-ALIAS', 'msb_version': '1'}, {'device_id': 'SYN-ID'},
                                     'SYN-UNIQUE', 'login261017010203', 'SYN-SIGNATURE')
        self.assertEqual(set(value), {'inputSignData'})
        self.assertEqual(len(value['inputSignData']), 8)
        self.assertNotIn('deviceId', value['inputSignData'])
        self.assertEqual(protocol.execute_request(protocol.history.decode('{}', protocol.INQUIRY))['reqKey'], '')

    def test_missing_pin_in_no_input_stops_before_final_request(self):
        self.prepared(INQUIRY | {'acScnoOmitYnS1': 'N'})
        with patch.object(transfer.keypad.Channel, 'read', side_effect=lambda provider, length: provider()):
            code, out, _ = self.call(['transfer', 'execute', '--no-input', '--send'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)['result']['required_action'], 'account_password_input_required')
        self.assertEqual(len(self.calls), 4)

    def test_missing_required_additional_flag_does_not_skip_authentication(self):
        self.prepared(); self.answer({})
        report = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual((report['bank_result'], report['transfer_result']), ('success', 'not_sent'))
        self.assertEqual(report['required_action'], 'transfer_additional_auth_check_body_unavailable')
        self.assertEqual(len(self.calls), 5)

    def test_nullable_owner_fields_keep_null_distinct_from_missing(self):
        verdict, document = protocol.parser(protocol.OWNER, 'owner')(
            transport.Reply(200, [], response('SUCCESS', {'ipAcNoS16': None})))
        self.assertEqual(verdict['bank_result'], 'success')
        self.assertIsNone(document['dataBody']['ipAcNoS16'])
        self.assertEqual(document['dataBody']['jiAcnoS16'], '')

    def test_failed_claim_stops_before_auth_or_transfer(self):
        self.prepared()
        original = storage.write_new
        def write(path, data):
            if Path(path).name == 'transfer-used.json':
                raise OSError('SYN-DISK-ERROR')
            return original(path, data)
        with patch.object(storage, 'write_new', side_effect=write):
            report = transfer.run('execute', input_provider=self.no_input)
        self.assertFalse(report['network_used'])
        self.assertEqual(report['transfer_result'], 'not_sent')
        self.assertEqual(len(self.calls), 4)

    def test_failed_receipt_metadata_save_keeps_transfer_success(self):
        self.prepared(); self.answer({'addAuthDsYnS1': 'N'}); self.answer(RECEIPT)
        original = storage.atomic_json
        def save(path, data):
            if Path(path).name == 'session.json' and data.get('transfer_pending', {}).get('result') == 'success':
                raise OSError('SYN-DISK-FULL')
            return original(path, data)
        with patch.object(storage, 'atomic_json', side_effect=save):
            report = transfer.run('execute', input_provider=self.no_input)
        self.assertEqual((report['bank_result'], report['transfer_result']), ('success', 'success'))
        self.assertFalse(report['session_saved'])

    def test_invalid_cli_amount_is_offline(self):
        code, out, _ = self.call(['transfer', 'prepare', '--to-bank', '081', '--to-account', DESTINATION,
                                  '--amount', '-1', '--send'])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(out)['result']['network_used'])
        self.assertFalse(self.calls)

    def test_blank_rejection_code_stays_unknown_in_local_status(self):
        for code in ('', ' ', '\u00a0'):
            self.prepared(); self.answer({'addAuthDsYnS1': 'N'}); self.answer({}, 'FAIL', resultCode=code)
            report = transfer.run('execute', input_provider=self.no_input)
            self.assertEqual(report['transfer_result'], 'unknown')
            self.assertEqual(transfer.run('show')['transfer_result'], 'unknown')
