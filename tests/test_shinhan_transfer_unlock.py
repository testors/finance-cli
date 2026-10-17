"""Synthetic ARS release requests; no external sockets or personal data."""
import base64
import json
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.core import storage
from finance_cli.services.shinhan import additional_auth, setup, transfer_unlock as unlock, transport
from finance_cli.services.shinhan.enrollment import Pending
from test_shinhan import PrivateHome, response, settings


class TransferUnlockTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.install()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        storage.atomic_json(setup.root()/'session.json', {'cookie':'SYN-COOKIE', 'authenticated':True,
            'login':{'user':{'cusSangtaeS2':'05', 'other':'SYN-USER-FIELD'}}})
        self.calls, self.replies = [], []
        def post(payload, cookie='', *, show_message=True):
            envelope = json.loads(payload)
            key = bytes.fromhex(settings()['bank_key'])
            body = json.loads(unpad(AES.new(key,AES.MODE_CBC,key[:16]).decrypt(base64.b64decode(envelope['dataBody'])),16))
            self.calls.append((envelope['dataHeader'],body,show_message))
            answer = self.replies.pop(0)
            if isinstance(answer,Exception): raise answer
            return answer
        self.enterContext(patch.object(transport,'post_web',side_effect=post))
        original = additional_auth.authenticate
        self.enterContext(patch.object(additional_auth,'authenticate',side_effect=lambda *a,**kw: original(*a,**kw,sleep=lambda s:None)))
        self.enterContext(patch.object(unlock.time,'sleep'))

    def answer(self,body=None,result='SUCCESS',**header):
        self.replies.append(transport.Reply(200,[],response(result,body,**header)))

    def prepare(self, *, final='SUCCESS', auth='Y', account=None):
        self.answer({'sub01Cnt':'1','sub01':[{'acno_originalValue':'000100001111'} if account is None else account]})
        self.answer({'getCurrentDateFmt':{'valueS20':'20000102100000'},'isOpDate':{'valueS20':'false'}})
        self.answer({'hpNoS12':'01000000000','hpDifrN1':'0'})
        self.answer({'getCurrentDateFmt':{'valueS20':'20000102 100000'}})
        self.answer({'isOpDate':{'valueS20':False}})
        self.answer({'sincNoS8':'SYN-ARS-REFERENCE'})
        self.answer({'addAuthCpltYnS1':auth})
        self.answer(None,final,resultCode='SYN-FAIL' if final=='FAIL' else '')

    def input(self,stage,context):
        if stage=='additional_select':
            self.assertEqual(context['methods'],('ars',))
            return {'method':'ars','kind':'0'}
        self.assertEqual(stage,'additional_response')
        return True

    def state(self):
        return storage.read_json(setup.root()/'session.json')

    def test_full_order_no_extra_authentication_and_empty_final_body_success(self):
        self.prepare()
        report=unlock.run(self.input)
        self.assertEqual([h['trxCd'] for h,b,s in self.calls],['RSMDE0000A01','RSMCM9000A03','RSMCM0301A02',
            'RSMCM9000A03','RSMCM9000A03','RSMCM1200A08','RSMCM1200A09','RSMDE0000A02'])
        self.assertEqual(self.calls[0][1],{})
        self.assertEqual(self.calls[1][1],{'bdtInqrGS20':'all','dtFrmtS20':'yyyyMMddHHmmss'})
        self.assertEqual(self.calls[5][1],{'영업시간내외':'0','authTypeS1':'0','upmuSeqS5':'35',
            'title':'장기미사용 정지해제','svcCS6':'D3352','hpNoS12':'01000000000','addAuthTelGbn':'0','isLogin':True})
        self.assertEqual(self.calls[6][1],{'authTypeS1':'0','upmuSeqS5':'35','svcCS6':'D3352',
            'nextSvcCS6':'D3352','sincNoS8':'SYN-ARS-REFERENCE','isLogin':True})
        self.assertEqual(self.calls[7][1],{'dmyS1':'0'})
        self.assertEqual([h['programId'] for h,b,s in self.calls], [unlock.PROGRAM]*2+
            [additional_auth.SELECT_PROGRAM]+[additional_auth.AUTH_PROGRAM]*4+[unlock.PROGRAM])
        self.assertEqual((report['unlock_result'],report['bank_result'],report['processing_status']),('success','success','complete'))
        self.assertEqual(self.state()['login']['user'],{'cusSangtaeS2':'OK','other':'SYN-USER-FIELD'})
        for secret in ('SYN-COOKIE','000100001111','01000000000','SYN-ARS-REFERENCE','SYN-USER-FIELD'):
            self.assertNotIn(secret,json.dumps(report))

    def test_noninteractive_request_and_resume_never_requests_ars_twice(self):
        self.prepare()
        code,out,_=self.call(['transfer','unlock','--auth-phone','0','--no-input','--send'])
        report=json.loads(out)['result']
        self.assertEqual(code,2)
        self.assertEqual(report['required_action'],'additional_ars_response_required')
        self.assertTrue(report['ars_pending'])
        self.assertEqual(len(self.calls),6)
        old_state=self.state()
        code,out,_=self.call(['transfer','unlock','--ars-completed','--no-input','--send'])
        self.assertEqual(code,0,out)
        self.assertEqual(json.loads(out)['result']['unlock_result'],'success')
        self.assertEqual(len(self.calls),8)
        storage.atomic_json(setup.root()/'session.json',old_state)
        report=unlock.run(self.input,ars_completed=True)
        self.assertEqual(report['required_action'],'transfer_unlock_auth_already_used')
        self.assertEqual(len(self.calls),8)

    def test_completion_without_request_never_starts_authentication(self):
        report=unlock.run(self.input,ars_completed=True)
        self.assertEqual(report['required_action'],'transfer_unlock_ars_request_required')
        self.assertFalse(report['network_used'])

    def test_send_is_required_before_loading_settings_or_input(self):
        with patch.object(setup,'load',side_effect=AssertionError('Must not load')):
            code,out,_=self.call(['transfer','unlock'])
        self.assertEqual(code,2)
        self.assertEqual(json.loads(out)['result']['error'],'send_required')
        self.assertFalse(self.calls)

    def test_not_suspended_is_local_condition_not_bank_failure(self):
        state=self.state();state['login']['user']['cusSangtaeS2']='OK'
        storage.atomic_json(setup.root()/'session.json',state)
        report=unlock.run(self.input)
        self.assertEqual(report['required_action'],'transfer_unlock_not_suspended')
        self.assertEqual(report['bank_result'],'unknown')
        self.assertFalse(self.calls)

    def test_missing_account_count_stops_without_losing_inquiry_success(self):
        self.answer({'sub01':[{}]})
        report=unlock.run(self.input)
        self.assertEqual(report['required_action'],'transfer_unlock_no_withdrawal_account')
        self.assertEqual((report['bank_result'],report['unlock_result']),('success','not_sent'))
        self.assertEqual(len(self.calls),1)

    def test_unused_account_field_is_not_an_extra_validation(self):
        self.prepare(account={})
        self.assertEqual(unlock.run(self.input)['unlock_result'],'success')

    def test_explicit_inquiry_failure_stops(self):
        self.answer({},'FAIL',resultCode='SYN-DENIAL')
        report=unlock.run(self.input)
        self.assertEqual((report['bank_result'],report['unlock_result']),('failure','not_sent'))
        self.assertEqual(len(self.calls),1)

    def test_unconfirmed_ars_does_not_unlock(self):
        self.prepare(auth='N')
        report=unlock.run(self.input)
        self.assertEqual(report['required_action'],'transfer_unlock_auth_incomplete')
        self.assertEqual(report['unlock_result'],'not_sent')
        self.assertEqual(len(self.calls),7)
        self.assertEqual(self.state()['login']['user']['cusSangtaeS2'],'05')

    def test_final_failure_does_not_update_customer_status(self):
        self.prepare(final='FAIL')
        report=unlock.run(self.input)
        self.assertEqual((report['bank_result'],report['unlock_result']),('failure','failure'))
        self.assertEqual(self.state()['login']['user']['cusSangtaeS2'],'05')
        self.assertEqual(len(self.calls),8)

    def test_final_network_exception_stays_unknown_and_does_not_retry(self):
        self.prepare();self.replies[-1]=TimeoutError('SYN-SECRET-EXCEPTION')
        report=unlock.run(self.input)
        self.assertEqual(report['unlock_result'],'unknown')
        self.assertEqual(report['required_action'],'transfer_unlock_outcome_unverified')
        self.assertNotIn('SYN-SECRET',json.dumps(report))
        self.assertEqual(self.state()['login']['user']['cusSangtaeS2'],'05')
        self.assertEqual(len(self.calls),8)

    def test_save_failure_after_success_preserves_success(self):
        self.prepare()
        real=storage.atomic_json
        def write(path,value):
            if path.name=='session.json' and value.get('login',{}).get('user',{}).get('cusSangtaeS2')=='OK':
                raise OSError('SYN-SAVE-SECRET')
            return real(path,value)
        with patch.object(storage,'atomic_json',side_effect=write):report=unlock.run(self.input)
        self.assertEqual((report['bank_result'],report['unlock_result']),('success','success'))
        self.assertFalse(report['session_saved'])
        self.assertEqual(report['local_status'],'incomplete')
        self.assertNotIn('SYN-SAVE-SECRET',json.dumps(report))

    def test_failed_response_archive_does_not_change_success(self):
        self.prepare()
        real=storage.write_new
        def write(path,value):
            if path.name.startswith('response-'): raise OSError('SYN-SECRET')
            return real(path,value)
        with patch.object(storage,'write_new',side_effect=write):report=unlock.run(self.input)
        self.assertEqual(report['unlock_result'],'success')
        self.assertEqual(report['local_status'],'incomplete')

    def test_page_coercion_and_initial_business_hours_boundaries(self):
        for value,expected in [('05',True),(5,True),(['05'],True),('5',False),(None,False),(True,False)]:
            self.assertEqual(unlock.suspended(value),expected)
        for value,expected in [('1',True),(1,True),(True,True),('0x1',True),([1],True),('bad',False),(None,False),({},False)]:
            self.assertEqual(unlock.positive(value),expected)
        for clock,day,expected in [('090000','true','0'),('090001','true','1'),('180000','true','0'),('100000',True,'0')]:
            params=unlock.parameters({}, {'getCurrentDateFmt':{'valueS20':'20000103'+clock},'isOpDate':{'valueS20':day}})
            self.assertEqual(params['영업시간내외'],expected)
            self.assertNotIn('계좌번호_상품코드',params)
