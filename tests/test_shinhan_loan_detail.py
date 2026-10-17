"""Selected loan detail workflows with synthetic replies and no bank traffic."""
import base64
import copy
import json
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.core import storage
from finance_cli.services.shinhan import account_protocol, accounts, loan_detail as detail, setup, transport
from test_shinhan import PrivateHome, response, settings


def menu():
    return {'VERSION':'SYN-MENU', 'CHATBOT_ERR_LIST':'', 'BANK_CODE_SERACH_LIST':[], 'CATEGORY_MENU_LIST':[], 'LIGHT_PRG_KEY_DATA': {'B': 'PR_ID', 'A': 'ASIS_SCRID', 'R':'PROGRAM_LIST', 'P':'ASIS_PRID_MAP'},
            'R': [{'B': name, 'PR_TYPE': 'W', 'MOVE_URL': f'/web/pages/BM/BM03/{name[:6]}/{name}.html', 'LOGIN_LEVEL': '2', 'ID_USABLE_YN': 'N'} for name in detail.PROGRAMS],
            'P': [{'A': 'SYN-OLD-PAGE', 'B': 'BM0310S0402F01'}]}


class LoanDetailTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.install()
        self.settings = setup.load() | {'menu': menu()}
        storage.atomic_json(setup.root()/'settings.json', self.settings)
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.state = {'cookie': 'JSESSIONID=SYN-COOKIE', 'authenticated': True, 'credential': 'SYN-CERT',
                      'login': {'user': {'membGdS2': '02', 'loginLevS2': '8'}}}
        self.calls, self.replies = [], []
        def send(payload, cookie, *, show_message):
            document = json.loads(payload); key = bytes.fromhex(settings()['bank_key'])
            body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(document['dataBody'])),16))
            self.calls.append((document['dataHeader'], body, show_message))
            return self.replies.pop(0)
        self.enterContext(patch.object(transport, 'post_web', side_effect=send))
        self.selected()

    def selected(self, program='BM0302S0404F01', params=None):
        rows = [{'assetRefKey':'SYN-ROW','assetCtgrId':'C15','assetOrgC':'088','assetPrgId':program,
                 'assetPrgParam':json.dumps({'P':{'acno':'SYN-ACCOUNT','acnoS12':'SYN-AC-1'}} if params is None else params),
                 'assetBtnList':[{'assetBtnPrgId':'BM0302S0404F01'}]}]
        graph={'assetList':rows,'mainCtgrList':[{'ctgrId':'C15','assetRefKeyList':[{'assetRefKey':'SYN-ROW'}]}]}
        self.state['accounts']={'attempt':'SYN-LIST','credential':self.state['credential'],
                               'categories':account_protocol.categories(account_protocol.decode(json.dumps(graph)))}
        self.save()

    def save(self):
        storage.atomic_json(setup.root()/'session.json',self.state)

    def answer(self, body, result='SUCCESS', **header):
        self.replies.append(transport.Reply(200,[],response(result,body,**header)))

    def clock(self):
        self.answer({'getCurrentDateFmt':{'valueS20':'20261017'}})

    def test_selected_installment_uses_row_parameters_and_private_fields(self):
        self.answer({'acno':'SYN-ACCOUNT','dcTamt':'100000.01','dcJan':'0','aplIyul':'4.555','prdtCNmS100':'SYN-PRODUCT',
                     'fstYakjSjdt':'20260101','exeDudt':'20271117'})
        self.clock()
        code,out,err=self.call(['loan-detail','--send'])
        result=json.loads(out)['result'];data=storage.read_json(result['data_file'])
        self.assertEqual((code,result['bank_result'],result['detail_result']),(0,'success','success'))
        self.assertEqual([c[0]['trxCd'] for c in self.calls],['RSMLO1002A01','RSMCM9000A03'])
        self.assertEqual(self.calls[0][1],{'ysAcno':'SYN-ACCOUNT','대량거래여부':'2','실행번호':'0','조회구분':'1'})
        self.assertEqual(self.calls[1][1],{'bdtInqrGS20':'getCurrentDateFmt','dtFrmtS20':'yyyyMMdd'})
        self.assertEqual(data['fields']['interest_rate'],'4.555')
        self.assertEqual(data['fields']['balance'],'0')
        self.assertEqual(data['fields']['started_on'],'20260101')
        self.assertEqual(Path(result['data_file']).stat().st_mode & 0o777,0o600)
        for secret in ('SYN-ACCOUNT','SYN-AC-1','SYN-PRODUCT','100000.01'):
            self.assertNotIn(secret,out+err)

    def test_overdraft_alias_keeps_acnoS12_and_followup_rate_request(self):
        self.selected('SYN-OLD-PAGE',{'P':{'acno':'WRONG','acnoS12':'SYN-AC-1','prdtname':'SYN-NAME'}})
        self.clock();self.answer({'dcHdamt':'100','dcIyul':'4.5','masJan':'-20'});self.answer({'filler':'SYN-RATE'})
        result=detail.run();data=storage.read_json(result['data_file'])
        self.assertEqual([c[0]['trxCd'] for c in self.calls],['RSMCM9000A03','RSMLO0101A01','RSMLO1003A01'])
        self.assertTrue(all(c[0]['programId']=='BM0310S0402F01' for c in self.calls))
        self.assertEqual(self.calls[1][1]['acno'],'SYNAC1')
        self.assertEqual(self.calls[2][1],{'acno':'SYNAC1','bnkG':'1','upmuG':'1','jkwInqrYnS1':'1','imptdocProcG':'1','trxbrBnkGL1':'1'})
        self.assertEqual([c[2] for c in self.calls],[False,False,True])
        self.assertEqual(data['fields']['rate_description'],'SYN-RATE')
        self.assertEqual(data['fields']['product_name'],'SYN-NAME')

    def test_current_loan_has_distinct_contract_and_no_fabricated_start_date(self):
        self.selected('BM0302S0403F01',{'GP':{'acnoS12':'SYN-AC-2'}})
        self.clock();self.answer({'dcHdamt':'100','dcIyul':'3.4','dcDudt':'20271117','masJan':'0'})
        result=detail.run();data=storage.read_json(result['data_file'])
        self.assertEqual(self.calls[-1][0]['trxCd'],'RSMDE0105A08')
        self.assertEqual(self.calls[-1][1],{'acno':'SYNAC2','inqrSjdt':'20261017','inqrEndt':'20261017','procGL1':'0','sortGL1':'1',
                         'trxbrBnkGL1':'1','ysLotTrxG':'2','jhcnt':10,'trxGL3':'3','kwaG':'1','masS':'0','bnkG':'1'})
        self.assertNotIn('started_on',data['fields'])
        self.assertEqual(data['fields']['balance'],'0')

    def test_later_bank_failure_preserves_detail_payload_and_result(self):
        self.selected('BM0310S0402F01');self.clock();self.answer({'dcIyul':'4.5'});self.answer({},'FAIL')
        result=detail.run()
        self.assertEqual((result['bank_result'],result['detail_result']),('failure','success'))
        self.assertEqual(storage.read_json(result['data_file'])['account'],{'dcIyul':'4.5'})
        self.assertEqual(result['processing_status'],'incomplete')
        self.assertEqual(len(self.calls),3)

    def test_null_body_or_missing_account_number_stops_before_followup(self):
        for body in (None,{}):
            self.answer(body)
            before=len(self.calls);result=detail.run()
            self.assertEqual(len(self.calls)-before,1)
            self.assertEqual((result['bank_result'],result['detail_result']),('success','success'))
            self.assertEqual(result['processing_status'],'incomplete')

    def test_storage_error_does_not_change_bank_sequence_or_success(self):
        self.answer({'acno':'SYN-ACCOUNT'});self.clock()
        write=storage.atomic_json
        def fail(path,value):
            if Path(path).name=='loan-detail.json':raise OSError('SYN-PRIVATE')
            return write(path,value)
        with patch.object(storage,'atomic_json',side_effect=fail):result=detail.run()
        self.assertEqual((result['bank_result'],result['processing_status'],result['local_status']),('success','complete','incomplete'))
        self.assertEqual(len(self.calls),2)

    def test_selection_requires_same_credential_and_excludes_hidden_foreign_and_deposit(self):
        category=self.state['accounts']['categories'][0];row=category['assetList'][0]
        category['assetList']=[dict(row,isHide=True),dict(row,orgCode='999'),row]
        self.state['accounts']['categories'].insert(0,dict(category,categoryType='CHECKING_ACCOUNT',assetList=[dict(row)]))
        self.assertEqual(detail.select(self.state,None)[0],row)
        category['assetList'].append(dict(row))
        with self.assertRaises(detail.Pending):detail.select(self.state,None)
        for index in (0,3):
            with self.assertRaises(detail.Pending):detail.select(self.state,index)
        self.state['credential']='SYN-OTHER';self.save()
        self.assertEqual(detail.run(1)['required_action'],'loan_list_required')
        self.assertEqual(self.calls,[])

    def test_unknown_row_destination_never_uses_first_button_or_account_prefix(self):
        for name,action in [('', 'loan_row_has_no_destination'),('SYN-UNKNOWN','loan_destination_unavailable')]:
            self.selected(name)
            with patch.object(transport,'post',return_value=transport.Reply(200,[],response('FAIL',{}))):
                self.assertEqual(detail.run()['required_action'],action)
        self.assertEqual(self.calls,[])

    def test_server_program_lookup_selects_actual_destination_and_preserves_row_parameters(self):
        from finance_cli.services.shinhan import menu_protocol
        self.selected('SYN-REMOTE', {'P':{'acno':'SYN-SELECTED'}})
        remote=dict.fromkeys(menu_protocol.REMOTE_FIELDS,'') | {
            'prId':'BM0302S0404F01','prType':'W','loginLevel':'2',
            'moveUrl':'/web/pages/BM/BM03/BM0302/BM0302S0404F01.html'}
        self.answer({'acno':'SYN-SELECTED'});self.clock()
        with patch.object(transport,'post',return_value=transport.Reply(200,[],response('SUCCESS',remote))) as lookup:
            result=detail.run()
        lookup.assert_called_once()
        self.assertEqual(result['program_lookup_result'],'success')
        self.assertEqual(result['detail_result'],'success')
        self.assertEqual(self.calls[0][1]['ysAcno'],'SYN-SELECTED')
        self.assertEqual([c[0]['trxCd'] for c in self.calls],['RSMLO1002A01','RSMCM9000A03'])

    def test_changed_page_url_never_executes_previous_page_contract(self):
        self.settings['menu']['R'][0]['MOVE_URL']='/web/pages/SYN-CHANGED.html'
        storage.atomic_json(setup.root()/'settings.json',self.settings)
        result=detail.run()
        self.assertEqual(result['required_action'],'loan_destination_path_not_implemented')
        self.assertEqual(self.calls,[])

    def test_known_navigation_restrictions_stop_before_loan_request(self):
        variants=[({'emergency':True},'loan_banking_login_required'),
                  ({'login':{'user':{'membGdS2':'01'}}},'loan_banking_grade_required'),
                  ({'login':{'user':{'loginLevS2':'2'}}},'loan_other_login_required'),
                  ({'intro':{'programNotiList':[{'prId':'BM0302S0404F01','popType':'99'}]}},'loan_netfunnel_required')]
        baseline=copy.deepcopy(self.state)
        for changes,action in variants:
            self.state=baseline|changes;self.save()
            self.assertEqual(detail.run()['required_action'],action)
        self.assertEqual(self.calls,[])

    def test_native_direct_and_P_GP_parameters_are_distinct(self):
        for kind in ('overdraft','current'):
            self.assertEqual(detail.parameters('{"acnoS12":"SYN"}',kind),{})
            self.assertEqual(detail.parameters('{"P":{},"GP":{"acnoS12":"SYN"}}',kind),{'acnoS12':'SYN'})
        self.assertEqual(detail.parameters('{"acno":"SYN"}','installment'),{'acno':'SYN'})
        with self.assertRaises(detail.Pending):detail.parameters('{acno:SYN}','installment')

    def test_no_send_invalid_index_and_missing_login_never_query(self):
        with patch.object(setup,'load',side_effect=AssertionError('Settings read')):
            self.assertEqual(json.loads(self.call(['loan-detail'])[1])['result']['error'],'send_required')
            self.assertEqual(self.call(['loan-detail','--loan','0','--send'])[0],2)
        self.state['authenticated']=False;self.save()
        self.assertEqual(json.loads(self.call(['loan-detail','--send'])[1])['result']['error'],'login_required')
        self.assertEqual(self.calls,[])

    def test_failed_new_list_cannot_leave_a_stale_loan_selection(self):
        with patch.object(transport,'post',side_effect=OSError('SYN-PRIVATE')):
            accounts.run(loans=True)
        self.assertNotIn('accounts',storage.read_json(setup.root()/'session.json'))
        self.assertEqual(detail.run()['required_action'],'loan_list_required')
