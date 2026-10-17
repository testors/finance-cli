"""Loan document inquiries against synthetic bank replies only."""
import base64
import json
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.core import storage
from finance_cli.services.shinhan import loan_documents as docs, setup, transport
from test_shinhan import PrivateHome, settings, response


class LoanDocumentTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.install()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('External network forbidden')))
        self.state = {'cookie': 'JSESSIONID=SYN-COOKIE', 'authenticated': True, 'credential': 'SYN-CREDENTIAL',
                      'login': {'user': {'cusSungNmS30': 'SYN-PERSON', 'cusSungNmS20': 'WRONG-PERSON'}}}
        self.save()
        self.calls, self.replies = [], []
        def post(payload, cookie='', *, show_message=None):
            envelope = json.loads(payload)
            key = bytes.fromhex(settings()['bank_key'])
            body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(envelope['dataBody'])), 16))
            self.calls.append({'header': envelope['dataHeader'], 'body': body, 'show': show_message, 'cookie': cookie})
            return self.replies.pop(0)
        self.enterContext(patch.object(transport, 'post_web', side_effect=post))

    def save(self):
        storage.atomic_json(setup.root()/'session.json', self.state)

    def answer(self, body, result='SUCCESS', **header):
        self.replies.append(transport.Reply(200, [], response(result, body, **header)))

    def clock(self):
        self.answer({'getCurrentDateFmt': {'valueS20': '20261017100000'}, 'isOpDate': {'valueS20': 'true'}})

    def prepare_list(self, body, kind='rate'):
        if kind == 'rate': self.answer({'resultYn': 'N'})
        self.clock()
        self.answer(body)

    def selected(self, rows=None):
        self.state['loan_documents'] = {'rate': {'attempt': 'SYN-LIST', 'credential': self.state['credential'],
            'rows': rows if rows is not None else [{'aprvnoL10': 'SYN-APPROVAL', 'aprvSerL7': 'SYN-SERIAL', 'serL6': 'SYN-RECORD'}]}}
        self.save()

    def test_default_list_order_period_headers_and_private_data(self):
        self.prepare_list({'grid00': [{'aprvnoL10': 'SYN-FIRST', 'prdtNmS128': 'SYN-PRODUCT'},
                                     {'aprvnoL10': 'SYN-SECOND', 'irtcrBalMth': 2}], 'grid00Cnt': 99})
        code, out, err = self.call(['loan-documents', 'list', '--send'])
        result = json.loads(out)['result']
        self.assertEqual((code, result['count'], result['list_result']), (0, 2, 'success'))
        self.assertEqual([c['header']['trxCd'] for c in self.calls], ['RSMLO0000D04','RSMCM9000A03','RSMLO1101A08'])
        self.assertEqual(self.calls[-1]['body'], {'upmuG1L2': '5','balSjdtS8': '20261010','balEndtS8': '20261017'})
        self.assertEqual([c['show'] for c in self.calls], [True, False, False])
        self.assertTrue(all(c['header']['programId'] == docs.PROGRAMS['rate'] and c['cookie'] == self.state['cookie'] for c in self.calls))
        data = storage.read_json(result['data_file'])
        self.assertEqual([x['data']['aprvnoL10'] for x in data['documents']], ['SYN-SECOND','SYN-FIRST'])
        self.assertEqual(data['server_count'], 99)
        self.assertEqual(Path(result['data_file']).stat().st_mode & 0o777, 0o600)
        for secret in ('SYN-FIRST','SYN-PRODUCT','SYN-COOKIE','SYN-PERSON'):
            self.assertNotIn(secret, out+err)

    def test_credit_query_filters_document_kinds_and_preserves_expired_status(self):
        self.prepare_list({'grid00': [{'lonInetProfdK': 1}, {'lonInetProfdK': 3, 'lonInetProfdS': '5', 'sincdt': '2026.10.16'},
           {'lonInetProfdK': ' 6 ', 'lonInetProfdS': 7, 'sincdt': '2026-10-17'}, {'lonInetProfdK': 4.0, 'lonInetProfdS': 9}]}, 'credit')
        result = docs.run('list', kind='credit', start='2026-01-01', end='2026-10-17')
        self.assertEqual(result['count'], 3)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[-1]['body'], {'trxG':'14','lonInetProfdK':'99','inqSjdt':'20260101','inqEndt':'20261017'})
        entries = storage.read_json(result['data_file'])['documents']
        self.assertEqual([x['status'] for x in entries], ['발급거절','발송완료','발송가능기간만료'])
        self.assertEqual([x['index'] for x in entries], [1,2,3])

    def test_empty_grid_variants_are_successful_empty_lists(self):
        for value in (None, [], {}, 'undefined', 0, False):
            with self.subTest(value=value):
                self.prepare_list({'grid00':value})
                result = docs.run('list')
                self.assertEqual((result['bank_result'],result['count']),('success',0))

    def test_failure_or_unknown_is_not_empty_success_and_discards_previous_selection(self):
        for verdict in ('FAIL','unknown'):
            with self.subTest(verdict=verdict):
                self.selected()
                self.answer({'resultYn':'N'});self.clock();self.answer({},verdict)
                result = docs.run('list')
                self.assertNotIn('count',result)
                self.assertNotIn('rate',storage.read_json(setup.root()/'session.json')['loan_documents'])
                self.assertEqual(result['bank_result'],'failure' if verdict=='FAIL' else 'unknown')

    def test_null_body_preserves_observed_bank_success(self):
        self.prepare_list(None)
        result=docs.run('list')
        self.assertEqual(result['bank_result'],'success')
        self.assertEqual(result['processing_status'],'incomplete')
        self.assertNotIn('count',result)

    def notice(self, kind):
        return {'cdvalCodeNameC30':'100','cdvalCodeDesc2C1000':'//'+kind+'/title',
                'cdvalCodeDesc3C1000':base64.b64encode('은행 안내 <b>확인</b>'.encode()).decode(),
                'cdvalCodeDesc4C1000':'','cdvalCodeDesc5C1000':''}

    def test_notice_confirmation_uses_readable_private_text_before_list(self):
        self.answer({'resultYn':'Y','grid00':[self.notice('1')]});self.clock();self.answer({})
        def acknowledge(path):
            self.assertEqual(len(self.calls),1)
            self.assertIn('은행 안내',storage.read(path).decode())
            self.assertNotIn('<b>',storage.read(path).decode())
            return True
        result=docs.run('list',acknowledge=acknowledge)
        self.assertTrue(result['notice_acknowledged'])
        self.assertEqual(result['count'],0)

    def test_blocking_or_unacknowledged_notice_stops_before_period_query(self):
        for kind in ('1','2'):
            self.answer({'resultYn':'Y','grid00':[self.notice(kind)]})
            before=len(self.calls)
            result=docs.run('list')
            self.assertEqual(len(self.calls)-before,1)
            self.assertEqual(result['required_action'],'loan_notice_confirmation_required' if kind=='1' else 'loan_notice_blocks_service')
            self.assertEqual(result['bank_result'],'success')

    def test_notice_weekday_and_string_business_day_are_distinct(self):
        info='//1/title/Y/Y/202610170900/202610171000/Y/0000001/0900/1000/Y'
        now={'sbdate':'20261017','sbtime':'100000','isOPDate':'true'}
        self.assertFalse(docs.notice_active(info,lambda:now))
        self.assertTrue(docs.notice_active(info,lambda:{**now,'isOPDate':True}))

    def test_download_uses_selected_identifiers_first_detail_row_and_redirected_pdf_code(self):
        self.selected()
        detail={'loan':'SYN-LOAN','amount':123,'금리':4.5}
        self.answer({'grid00':[detail,{'ignored':True}]})
        pdf=b'%PDF-1.4\nSYNTHETIC'
        self.answer({'apdfDataB20000':base64.b64encode(pdf).decode()})
        code,out,err=self.call(['loan-documents','download','--send'])
        result=json.loads(out)['result']
        self.assertEqual(code,0)
        self.assertEqual([c['header']['trxCd'] for c in self.calls],['RSMLO1101A03','RSMCM9000D82'])
        self.assertEqual(self.calls[0]['body'],{'grid00Cnt':1,'grid00':[{'dbsAprvnoL10':'SYN-APPROVAL','dbsAprvSerL7':'SYN-SERIAL','dbsSerL6':'SYN-RECORD'}]})
        body=self.calls[1]['body']
        self.assertEqual(json.loads(body['apdfPrmtS4000']),detail)
        self.assertEqual((body['cusnmS30'],body['subChanS8']),('SYN-PERSON','03'))
        self.assertEqual(storage.read(result['document_file']),pdf)
        self.assertEqual(Path(result['document_file']).stat().st_mode & 0o777,0o600)
        self.assertTrue(result['document_available'])
        for secret in ('SYN-LOAN','SYN-APPROVAL','SYN-PERSON'):
            self.assertNotIn(secret,out+err)

    def test_download_requires_previous_list_and_exact_choice_without_extra_query(self):
        result=docs.run('download')
        self.assertEqual(result['required_action'],'loan_document_list_required')
        self.selected([{},{}])
        for index in (None,0,3):
            self.assertEqual(docs.run('download',index=index)['required_action'],'loan_document_selection_required')
        self.assertEqual(self.calls,[])
        self.state['credential']='SYN-OTHER';self.save()
        self.assertEqual(docs.run('download',index=1)['required_action'],'loan_document_list_required')

    def test_empty_detail_does_not_generate_pdf_or_invent_bank_failure(self):
        self.selected();self.answer({'grid00':[]})
        result=docs.run('download')
        self.assertEqual(result['bank_result'],'success')
        self.assertTrue(result['detail_empty'])
        self.assertFalse(result['document_available'])
        self.assertEqual(len(self.calls),1)

    def test_pdf_explicit_failure_does_not_erase_detail_success(self):
        self.selected();self.answer({'grid00':[{}]});self.answer({'rstCS10':'FAIL','rstMsgS200':'SYN-PRIVATE-MESSAGE'})
        result=docs.run('download')
        self.assertEqual((result['bank_result'],result['detail_result'],result['document_result']),('success','success','failure'))
        self.assertNotIn('SYN-PRIVATE-MESSAGE',json.dumps(result))

    def test_pdf_save_failure_preserves_available_document_and_bank_success(self):
        self.selected();self.answer({'grid00':[{}]});self.answer({'apdfDataB20000':'YWJj'})
        write=storage.write_new
        def fail_pdf(path,data):
            if Path(path).suffix=='.pdf':raise OSError('SYN-PRIVATE')
            return write(path,data)
        with patch.object(storage,'write_new',side_effect=fail_pdf):result=docs.run('download')
        self.assertEqual(result['bank_result'],'success')
        self.assertTrue(result['document_available'])
        self.assertFalse(result['document_saved'])
        self.assertEqual(result['local_status'],'incomplete')
        self.assertEqual(len(self.calls),2)

    def test_invalid_base64_is_local_processing_error_after_bank_success(self):
        self.selected();self.answer({'grid00':[{}]});self.answer({'apdfDataB20000':'a'})
        result=docs.run('download')
        self.assertEqual((result['bank_result'],result['detail_result'],result['document_result']),('success','success','viewer_requested'))
        self.assertEqual(result['processing_status'],'incomplete')

    def test_pdf_bank_failure_keeps_successful_detail_and_does_not_retry(self):
        self.selected();self.answer({'grid00':[{}]});self.answer({},'FAIL')
        result=docs.run('download')
        self.assertEqual((result['bank_result'],result['detail_result']),('failure','success'))
        self.assertEqual(len(self.calls),2)
        self.assertFalse(result['automatic_retry'])

    def test_list_storage_failure_keeps_query_success_and_count(self):
        self.prepare_list({'grid00':[{}]})
        write=storage.write_new
        def fail_data(path,data):
            if Path(path).name=='loan-documents.json':raise OSError('SYN-PRIVATE')
            return write(path,data)
        with patch.object(storage,'write_new',side_effect=fail_data):result=docs.run('list')
        self.assertEqual((result['bank_result'],result['list_result'],result['count']),('success','success',1))
        self.assertEqual(result['local_status'],'incomplete')

    def test_pdf_decoding_accepts_unpadded_and_ignorable_bytes_without_content_gate(self):
        self.assertEqual(docs.decode_pdf('Y W!Jj\n'),b'abc')
        self.assertEqual(docs.decode_pdf('YQ'),b'a')
        self.assertEqual(docs.decode_pdf('YWI'),b'ab')
        for value in ('YQ=', 'YWJj=', 'YWI==', 'YQ==YQ=='):
            with self.assertRaises(ValueError): docs.decode_pdf(value)

    def test_no_send_and_invalid_period_never_open_state_or_transmit(self):
        with patch.object(setup,'load',side_effect=AssertionError('Settings read')):
            for action in ('list','download'):
                self.assertEqual(json.loads(self.call(['loan-documents',action])[1])['result']['error'],'send_required')
            code,out,_=self.call(['loan-documents','list','--start-date','2026-10-17','--send'])
            self.assertEqual(code,2)
            self.assertFalse(json.loads(out)['result']['network_used'])
        self.assertEqual(self.calls,[])

    def test_missing_login_never_transmits(self):
        self.state['authenticated']=False;self.save()
        code,out,_=self.call(['loan-documents','list','--send'])
        self.assertEqual((code,json.loads(out)['result']['error']),(2,'login_required'))
        self.assertEqual(self.calls,[])
