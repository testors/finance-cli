"""Synthetic certificate issuance, reopened vault, signed login and transfer.

No institution connections, application files, device or system credentials.
The fake service checks cryptography and wire requests, not just call counts.
"""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Util.Padding import pad
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from finance_cli.cli.main import main
from finance_cli.services.hana import onesign, onesign_bundle as bundle, onesign_crypto as pin
from finance_cli.services.hana import onesign_cmp as cmp, onesign_issue_protocol as issue
from finance_cli.services.hana import onesign_signup_protocol as signup, onesign_transfer as transfer
from finance_cli.services.hana import nfilter_crypto, nfilter_format, hana_protocol
from finance_cli.services.hana.onesign_codec import encode
from finance_cli.services.hana.onesign_state import State
from finance_cli.services.hana.onesign_keys import Ledger

PASSWORD = 'SYNTHETIC-vault-passphrase'
PIN = '604928'
SOURCE, RECIPIENT = '12345678901234', '23456789012345'
MAC = b'SYNTHETIC-MAC-KEY-12'


def certificate(key):
    private = serialization.load_pem_private_key(key.export_key(format='PEM',use_pkcs8=True).encode(),None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SYNTHETIC'),
                     x509.NameAttribute(NameOID.USER_ID,'SYNTHETIC')])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
        .serial_number(23).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1)).sign(private,hashes.SHA256())
        .public_bytes(serialization.Encoding.DER))


def secret_b(device):
    value = device.encode()
    key = hashlib.pbkdf2_hmac('sha1',value,pin.repeated_sha256(1058,value),2002,32)
    return pin.b64url(AES.new(key,AES.MODE_CBC,pin.repeated_sha256(552,value)[:16]).encrypt(pad(bytes(range(32)),16)))


def cmp_reply(request, cert):
    header = cmp.sequence(request)[0]
    fields, h = cmp.header_fields(header), cmp.sequence(header)
    params = cmp.pbm_parameters(bytes(64))
    response_header = cmp.seq(2,h[2],h[1],nfilter_format.der(0xa1,cmp.seq(cmp.oid(cmp.PBM),params)),
        nfilter_format.der(0xa4,fields[0xa4]),nfilter_format.der(0xa6,fields[0xa5]))
    one = cmp.seq(0,cmp.seq(0),cmp.seq(nfilter_format.der(0xa0,cert)))
    return cmp.protect(response_header,nfilter_format.der(0xa1,cmp.seq(cmp.seq(one))),'SYNTHETIC-MAC',params)


def check_cms(encoded, cert):
    value = cms.ContentInfo.load(base64.b64decode(encoded))['content']
    signer = value['signer_infos'][0]
    data = value['encap_content_info']['content'].native
    attrs = signer['signed_attrs']
    digest = next(a['values'][0].native for a in attrs if a['type'].native=='message_digest')
    if digest != hashlib.sha256(data).digest():
        raise AssertionError('CMS content digest changed')
    x509.load_der_x509_certificate(cert).public_key().verify(signer['signature'].native,
        b'\x31'+attrs.dump()[1:],ec.ECDSA(hashes.SHA256()))
    return data.decode()


class Services:
    def __init__(self, state, cert, public):
        self.state, self.cert, self.public = state,cert,public
        self.calls, self.override = [],{}
        self.device = state.snapshot()['profile']['device_id']
        self.material = pin.derive_pin(PIN,device_id=self.device,pin_salt='',pin_spec_version=2)
        self.auth = {'lginMdclCd':'S','otpCertYn':'N','certYn':'N','pinCertYn':'N'}
        self.own = False
        self.row = {'wdrwAcctNo':SOURCE,'wdrwBnkCd':'081','rcvBnkCd':'004','rcvAcctNo':RECIPIENT,
            'trnsAmt':100,'trnsTgb':'01','rduAfComm':0,'rmteNm':'합성 수취인','rmtrNm':'합성 송금인',
            'rcvPsbkMarkCtt':'합성 송금인','wdrwPsbkMarkCtt':'합성 수취인','slctDvCd':'','cshbUseAmt':0}
        self.history = {'rcvBnkCd':'004','rcvAcctNo':RECIPIENT,'trscAmt':100,'trscStNm':'완료',
            'wdrwAcctNo':SOURCE,'eChnlTrscAcpnNo':'SYNTHETIC-ACCEPT','chnlSvcCd':'A16','eChnlTrscUnqNo':'SYNTHETIC-HISTORY'}

    def __call__(self,scope,method,url,headers,body,cookies,timeout):
        path = urlsplit(url).path
        if scope=='bank':
            path=path.removeprefix(urlsplit(hana_protocol.API).path)
        self.calls.append((scope,path,headers,body))
        if path in self.override:
            value = self.override[path]
            if isinstance(value,BaseException):
                raise value
        elif scope=='ca':
            cmp.inspect_request(body,'SYNTHETIC-MAC')
            return 200,[('Content-Type',issue.CA_MIME)],cmp_reply(body,self.cert),[]
        elif scope=='ra':
            path = path.removeprefix(pin.RA_BASE_PATH)
            parsed = json.loads(body)
            if path=='/registerCertificate':
                assert parsed==issue.register_certificate_body(self.cert,'SYNTHETIC-MAC',self.material)
                value = {'resultCode':0,'pinSecret':'SYNTHETIC-SECRET','pinVersion':'V2'}
            elif path=='/nonce':
                value = {'resultCode':0,'nonce':'SYNTHETIC-NONCE'}
            elif path=='/checkPinVersion':
                value = {'resultCode':0}
            else:
                assert parsed==pin.request_secret_body(self.material,self.cert,'SYNTHETIC-NONCE','V2')
                salt=bytes(range(16))
                key=pin.repeated_sha256(1024,b'SYNTHETIC-NONCE',salt)
                encrypted=AES.new(key,AES.MODE_CBC,hashlib.sha256(salt).digest()[:16]).encrypt(pad(b'SYNTHETIC-SECRET',16))
                value={'resultCode':0,'requestSecret':pin.b64url(salt+encrypted)}
        elif method=='GET':
            name, val = {'app_public_key':('key-save-status','Successful'),
                'app_first_access':('nonce','SYNTHETIC-NONCE'),
                'get_access_token':('access-token','SYNTHETIC-ACCESS')}[path.rsplit('/',1)[1]]
            return 200,[(name,val)],b'',[]
        else:
            value = self.bank(path,body)
        head = [('hana-sys-header',hana_protocol.encode_header({'CHNL_SYS_HDPT':{'PROC_RSLT_DV_CD':'0'}})),
                ('hana-com-header',hana_protocol.encode_header({'CNL_HDPT':{}}))]
        if path==pin.LOGIN_PATH:
            head.append(('one-access-token','SYNTHETIC-LOGIN'))
        return 200,head,value if isinstance(value,bytes) else encode(value),[]

    def bank(self,path,body):
        if path==signup.WEB_PATHS['customer'] and json.loads(body).get('oneSignUseYn')=='Y':
            return {'regTyp':'A','oneSignUseYn':'N','custNo':'SYNTHETIC-CUSTOMER'}
        if path==pin.LOGIN_PATH:
            value=json.loads(body)
            if value.get('signDat'):
                text=check_cms(value['signDat'],self.cert)
                assert 'SYNTHETIC-CUSTOMER' in text and 'SYNTHETIC-BANK-NONCE' in text
            return {'custNo':'SYNTHETIC-CUSTOMER','lginCertMethCd':'S','hanaCertLginYn':'Y'}
        if path==pin.BANK_NONCE_PATH:
            return {'scrtRnum':'SYNTHETIC-BANK-NONCE','scBCertKey':secret_b(self.device)}
        if path in (issue.PATHS['keypad'],transfer.PATHS['keypad_key']):
            assert body==b''
            return {'apiRlseKey':self.public}
        if path==issue.PATHS['clock']:
            now=datetime.now(ZoneInfo('Asia/Seoul'))
            return {'dt':now.strftime('%Y%m%d'),'tm':now.strftime('%H%M%S'),'bussDdYn':'Y'}
        if path==issue.PATHS['registration']:
            return {'keyId':'SYNTHETIC-ID','macKey':'SYNTHETIC-MAC','berryName':'SYNTHETIC',
                'scBCertKey':secret_b(self.device),'custNo':'SYNTHETIC-CUSTOMER','existSeed':False}
        if path==issue.PATHS['pin-check']:
            parsed=json.loads(body)
            assert PIN not in body.decode() and parsed['pinNo']!=parsed['pinNoCnfm']
            return {'scss':True}
        if path in (issue.PATHS['signup-account'],transfer.PATHS['password']):
            assert json.loads(body)['acctPw']!='6049'
            return b'not JSON' if path==transfer.PATHS['password'] else {}
        if path==transfer.PATHS['withdrawal']:
            return {'ourAcctList':[{'acctNo':SOURCE,'openYn':'N','bnkCd':'081','acctNm':'합성 출금',
                'bnkNm':'하나','wdrwAcctSeqNo':1,'payBal':10000}]}
        if path==transfer.PATHS['session_accounts']:
            return {'allAcctListDto':{'accountMap':{SOURCE:{'mmdaHoldYn':'N'}}}}
        if path==transfer.PATHS['recent_accounts']:
            assert body==b'{}'
            return {'cmCertsYn':'N'}
        if path in (transfer.PATHS['pretransaction'],transfer.PATHS['additional_info']):
            return {'trnsList':[self.row],'totlTrnsAmt':100,'tmsgUnqNo13':'SYNTHETIC-PREPARED',
                'dupTrscVrfcYn':'N','fncFrdDgnsNcsyYn':'N','rcvAcctSefYn':'Y' if self.own else 'N','mmdaHoldYn':'N'}
        if path==transfer.PATHS['auth_means']:
            return self.auth
        if path in (transfer.PATHS['execute_other'],transfer.PATHS['execute_self']):
            value=json.loads(body)
            if self.own:
                assert set(value)=={'tmsgUnqNo'}
            else:
                text=check_cms(value['elecSignVluDat'],self.cert)
                assert RECIPIENT in text and '100' in text and 'SYNTHETIC-BANK-NONCE' in text
            return {'errNcnt':0}
        if path in (transfer.PATHS['history'],transfer.PATHS['detail']):
            return {'rec':[self.history]}
        table = {signup.WEB_PATHS['eligibility']:{'smsVrfcRslt':'Y'},
            signup.WEB_PATHS['customer']:{'regTyp':'A','oneSignUseYn':'N','custNo':'SYNTHETIC-CUSTOMER'},
            signup.WEB_PATHS['terms-status']:{},issue.PATHS['instant-number']:{},
            issue.PATHS['application']:{'apcNo':'SYNTHETIC-APPLICATION','frnr':False},
            issue.PATHS['image']:{'scss':True},issue.PATHS['identity']:{'rspsCd':'000'},
            issue.PATHS['signup-accounts']:{'expLginAllAcctInq':[{'acctNo':SOURCE}]},
            issue.PATHS['complete-signup']:{'custNo':'SYNTHETIC-CUSTOMER'},
            onesign.ACCOUNTS:{'mainAcctList':[{'acctNo':SOURCE}]}}
        if path in table:
            return table[path]
        if path in signup.WEB_PATHS.values():
            return b'ignored body'
        raise AssertionError('Unexpected endpoint '+path)


class FlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing_key=ECC.construct(curve='P-256',d=23)
        cls.cert=certificate(cls.signing_key)
        public,_=nfilter_crypto.OpenSSL().curve(17)
        cls.public=base64.b64encode(nfilter_format.public_key_envelope(b'SYNTHETIC',public,MAC)).decode()
        cls.settings={'version':'1.0.27','secure_token':'SYNTHETIC-TOKEN','sms_hash':'SYNTHETIC',
            'keypad_mac':base64.b64encode(MAC).decode(),'ca_certificate':base64.b64encode(cls.cert).decode(),
            'service_profile':{'system_header':{'CHNL_SYS_HDPT':{'synthetic':True}},'channel_header':{'CNL_HDPT':{'synthetic':True}},
                               'profile_provenance':{'source':'synthetic'}}}
        cls.template=onesign.initial(cls.settings)

    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='finance-onesign-test-')
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve()
        self.enterContext(patch.dict(os.environ,{'FINANCE_HOME':str(self.root/'home')}))
        self.enterContext(patch('socket.socket.connect',side_effect=AssertionError('Network forbidden')))
        self.enterContext(patch.object(ECC,'generate',return_value=self.signing_key))
        self.state=self.enterContext(State('synthetic',PASSWORD,copy.deepcopy(self.template)))
        self.services=Services(self.state,self.cert,self.public)
        self.inputs={'phone':lambda:{'name':'합성 이름','birth7':'9001011','phone':'01000000000','carrier':'4'},
            'agree':lambda *a:True,'sms':lambda:'012345','account':lambda rows:rows[0]['acctNo'],
            'account_password':lambda *a:'6049','new_pin':lambda:(PIN,PIN),'confirm_issue':lambda:True,'pin':lambda:PIN,
            'confirm':lambda value:True}
        self.serial=0

    def op(self,action,session='signup'):
        self.serial+=1
        return onesign.operate(self.state,action,'run-'+str(self.serial),session=session,
            send=True,inputs=self.inputs,exchange=self.services)

    def before_issue(self,kind='resident'):
        for action in (*onesign.PHONE,'begin-id'):
            result=self.op(action)
            self.assertEqual(result['processing_status'],'completed',(action,result))
        jpeg=b'\xff\xd8\xff\xc0\x00\x11\x08\x01\x00\x02\x00'+bytes(10)
        onesign.prepare_identity(self.state,kind,jpeg,{'name':'합성 이름','issueDate':'2020.02.29',
            'birthDate':'900101','resident':'1000000','regionCode':'11','driver1':'12','driver2':'345678','driver3':'90'})
        for action in ('identity','account'):
            result=self.op(action)
            self.assertEqual(result['processing_status'],'completed',(action,result))

    def enroll(self):
        self.before_issue()
        for action in ('issue','complete'):
            result=self.op(action)
            self.assertEqual(result['processing_status'],'completed',(action,result))

    def login(self):
        self.enroll()
        onesign.new_session(self.state,'login')
        result=self.op('login','login')
        self.assertEqual(result['processing_status'],'completed',result)

    def tr(self,action):
        self.serial+=1
        return transfer.operate(self.state,action,'payment','run-'+str(self.serial),'login',send=True,
            intent={'source_account':SOURCE,'recipient_bank_code':'004','recipient_account_number':RECIPIENT,'amount_krw':100},
            inputs=self.inputs,exchange=self.services)

    def test_issuance_reopen_login_transfer_and_portable_identity(self):
        self.login()
        result=self.op('accounts','login')
        self.assertEqual(result['processing_status'],'completed',result)
        prepared=self.tr('prepare')
        self.assertEqual(prepared['state'],'prepared',prepared)
        self.assertEqual(prepared['authentication']['bridge_type'],'noAuth')
        self.assertFalse(prepared['transfer_sent'])
        before=len(self.services.calls)
        result=self.tr('execute')
        self.assertTrue(result['original_result_success'],result)
        self.assertFalse(any(c[1].endswith('/requestSecretE') for c in self.services.calls[before:]))
        observed=self.tr('reconcile')
        self.assertTrue(observed['candidate_complete'],observed)
        self.assertFalse(observed['transfer_confirmed'])
        before=len(self.services.calls)
        self.assertEqual(self.tr('execute')['processing_status'],'stopped')
        self.assertEqual(before,len(self.services.calls))
        bundle.export_identity(self.state,self.root/'portable.json',PASSWORD)
        plain=bundle.opened((self.root/'portable.json').read_bytes(),PASSWORD)
        self.assertEqual(plain['version'],2)
        self.assertEqual(plain['cloud'],{})
        self.assertNotIn('sessions',plain)
        with patch.object(onesign.onesign_setup,'load',return_value=self.settings):
            bundle.activate('imported',self.root/'portable.json',PASSWORD,'settings')
        with State('imported',PASSWORD) as reopened:
            self.assertEqual(onesign.record(reopened)[0],onesign.record(self.state)[0])
            onesign.new_session(reopened,'fresh')
            result=onesign.operate(reopened,'login','new-login',session='fresh',send=True,
                inputs=self.inputs,exchange=Services(reopened,self.cert,self.public))
            self.assertTrue(result.get('logged_in'),result)
        for path in (self.root/'home').rglob('*'):
            self.assertEqual(path.stat().st_mode&0o077,0)
            if path.is_file():
                raw=path.read_bytes()
                for secret in (b'SYNTHETIC-CUSTOMER',SOURCE.encode(),b'SYNTHETIC-LOGIN',b'SYNTHETIC-SECRET'):
                    self.assertNotIn(secret,raw)

    def test_otp_and_pin_branches(self):
        self.login()
        self.services.auth['otpCertYn']='Y'
        result=self.tr('prepare')
        self.assertEqual(result['state'],'authentication_review',result)
        self.assertTrue(result['accepted'])
        before=len(self.services.calls)
        self.assertEqual(self.tr('execute')['processing_status'],'stopped')
        self.assertEqual(len(self.services.calls),before)

    def test_pin_reentry_and_confirmation(self):
        self.login()
        self.services.auth['pinCertYn']='Y'
        self.assertEqual(self.tr('prepare')['authentication']['bridge_type'],'pinHalf')
        self.inputs['confirm']=lambda _:False
        before=len(self.services.calls)
        result=self.tr('execute')
        self.assertEqual(result['error'],'transfer_confirmation_required')
        self.assertEqual(len(self.services.calls),before)
        self.inputs['confirm']=lambda _:True
        self.assertTrue(self.tr('execute')['original_result_success'])
        self.assertTrue(any(c[1].endswith('/requestSecretE') for c in self.services.calls[before:]))

    def test_self_account_branch_has_no_password_or_signature(self):
        self.login()
        self.services.own=True
        self.inputs['account_password']=lambda: self.fail('self transfer does not request password')
        self.inputs['pin']=lambda: self.fail('self transfer does not request PIN')
        self.assertEqual(self.tr('prepare')['state'],'prepared')
        self.assertTrue(self.tr('execute')['original_result_success'])

    def test_pin_cancellation_preserves_prepared_transfer_before_any_request(self):
        self.login()
        self.services.auth['pinCertYn']='Y'
        self.assertEqual(self.tr('prepare')['authentication']['bridge_type'],'pinHalf')
        before=len(self.services.calls)
        def cancel():
            raise KeyboardInterrupt
        self.inputs['pin']=cancel
        with self.assertRaises(KeyboardInterrupt):
            self.tr('execute')
        self.assertEqual(len(self.services.calls),before)
        self.assertEqual(self.state.snapshot()['transfers']['payment']['state'],'prepared')
        self.inputs['pin']=lambda:PIN
        self.assertTrue(self.tr('execute')['original_result_success'])
        after=len(self.services.calls)
        self.assertEqual(self.tr('execute')['processing_status'],'stopped')
        self.assertEqual(len(self.services.calls),after)

    def test_ca_timeout_cannot_reissue(self):
        self.before_issue()
        self.services.override[urlsplit(issue.CA_URL).path]=OSError('SYNTHETIC-timeout')
        result=self.op('issue')
        self.assertEqual(result['processing_status'],'stopped')
        self.assertIsNone(result['accepted'])
        self.assertTrue(self.state.snapshot()['issuance']['pending_key'])
        before=len(self.services.calls)
        self.assertEqual(self.op('issue')['processing_status'],'stopped')
        self.assertEqual(len(self.services.calls),before)

    def test_driver_document_reaches_issuance(self):
        self.before_issue('driver')
        for stage in ('issue','complete'):
            result=self.op(stage)
            self.assertEqual(result['processing_status'],'completed',result)

    def test_ca_success_survives_ledger_save_failure(self):
        self.before_issue()
        accept=Ledger.accept
        def broken(ledger,name,*args):
            if name=='issue-ca-verification':
                raise OSError('SYNTHETIC-full-disk')
            return accept(ledger,name,*args)
        with patch.object(Ledger,'accept',broken):
            result=self.op('issue')
        self.assertTrue(result['certificate_issued'],result)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['processing_status'],'stopped')

    def test_ca_success_with_unusable_key_is_not_reclassified_as_failed_issuance(self):
        self.before_issue()
        self.services.cert=certificate(ECC.construct(curve='P-256',d=29))
        result=self.op('issue')
        self.assertTrue(result['certificate_issued'],result)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['error'],'cmp_certificate_key_mismatch')
        self.assertEqual(self.state.snapshot()['records'],{})
        self.assertTrue(self.state.snapshot()['issuance']['certificate_issued'])
        self.assertTrue(self.state.snapshot()['issuance']['pending_certificate'])

    def test_explicit_identity_failure_is_rejected(self):
        for action in (*onesign.PHONE,'begin-id'):
            self.assertEqual(self.op(action)['processing_status'],'completed')
        jpeg=b'\xff\xd8\xff\xc0\x00\x11\x08\x01\x00\x02\x00'+bytes(10)
        onesign.prepare_identity(self.state,'resident',jpeg,{'name':'합성 이름','issueDate':'2020.02.29',
            'birthDate':'900101','resident':'1000000'})
        self.services.override[issue.PATHS['image']]={'scss':False}
        result=self.op('identity')
        self.assertFalse(result['accepted'],result)
        self.assertEqual(result['error'],'identity_image_upload_failed')
        self.assertFalse(any(c[1]==issue.PATHS['identity'] for c in self.services.calls))

    def test_bank_success_survives_response_record_failure(self):
        self.login()
        original=self.state.record
        def broken(run,name,value):
            if name.endswith('-response'):
                raise OSError('SYNTHETIC-full-disk')
            return original(run,name,value)
        with patch.object(self.state,'record',broken):
            result=self.op('accounts','login')
        self.assertTrue(result['accepted'],result)
        self.assertEqual(result['processing_status'],'stopped')

    def test_execution_timeout_does_not_replay(self):
        self.login()
        self.assertEqual(self.tr('prepare')['state'],'prepared')
        self.services.override[transfer.PATHS['execute_other']]=OSError('SYNTHETIC-timeout')
        result=self.tr('execute')
        self.assertIsNone(result['accepted'])
        before=len(self.services.calls)
        self.assertEqual(self.tr('execute')['processing_status'],'stopped')
        self.assertEqual(len(self.services.calls),before)

    def test_execution_verdict_precedes_disk_write_and_survives_reconcile_error(self):
        self.login()
        self.assertEqual(self.tr('prepare')['state'],'prepared')
        original=self.state.record
        def broken(run,name,value):
            if name.endswith('-response') and self.services.calls[-1][1]==transfer.PATHS['execute_other']:
                raise OSError('SYNTHETIC-full-disk')
            return original(run,name,value)
        with patch.object(self.state,'record',broken):
            result=self.tr('execute')
        self.assertTrue(result['execution_result']['original_result_success'],result)
        self.assertEqual(result['processing_status'],'stopped')
        self.assertTrue(self.state.snapshot()['transfers']['payment']['execution_attempted'])

    def test_explicit_transfer_failure_and_string_count_follow_source_predicate(self):
        self.assertFalse(transfer.observe_execution(b'{"errNcnt":1}')['execution_result']['accepted'])
        self.assertTrue(transfer.observe_execution(b'{"errNcnt":"1"}')['execution_result']['accepted'])
        self.assertIsNone(transfer.observe_execution(b'not JSON')['execution_result']['accepted'])
        self.login()
        self.assertEqual(self.tr('prepare')['state'],'prepared')
        self.services.override[transfer.PATHS['execute_other']]={'errNcnt':1}
        result=self.tr('execute')
        self.assertFalse(result['original_result_success'],result)
        self.services.override[transfer.PATHS['history']]=OSError('SYNTHETIC-timeout')
        result=self.tr('reconcile')
        self.assertFalse(result['execution_result']['original_result_success'],result)
        self.assertEqual(result['processing_status'],'stopped')

    def test_server_wrong_pin_stops_before_signed_login(self):
        self.enroll()
        onesign.new_session(self.state,'login')
        self.services.override[pin.RA_BASE_PATH+'/requestSecretE']={'resultCode':64001}
        before=len(self.services.calls)
        result=self.op('login','login')
        self.assertEqual(result['error'],'wrong_pin',result)
        self.assertFalse(result['accepted'])
        self.assertFalse(any(c[1]==pin.LOGIN_PATH for c in self.services.calls[before:]))
        before=len(self.services.calls)
        self.assertEqual(self.op('login','login')['processing_status'],'stopped')
        self.assertEqual(len(self.services.calls),before)

    def test_signed_session_binding_must_not_change(self):
        self.login()
        self.assertEqual(self.tr('prepare')['state'],'prepared')
        with self.state.transaction() as value:
            value['profile']['customer_number']='OTHER-SYNTHETIC'
        before=len(self.services.calls)
        result=self.tr('execute')
        self.assertEqual(result['processing_status'],'stopped')
        self.assertEqual(len(self.services.calls),before)

    def test_show_retains_interrupted_preparation(self):
        self.login()
        self.services.override[transfer.PATHS['pretransaction']]=OSError('SYNTHETIC-timeout')
        self.assertEqual(self.tr('prepare')['processing_status'],'stopped')
        result=transfer.operate(self.state,'show','payment',None,None)
        self.assertFalse(result['prepared'])
        self.assertFalse(result['execution_attempted'])

    def test_identity_removal_needs_the_store_lock_and_never_touches_other_stores(self):
        from finance_cli.services.hana.onesign_state import remove_identity
        from finance_cli.services.hana import store
        with State('spare',PASSWORD,copy.deepcopy(self.template)):
            pass
        self.assertTrue((store.root('identities')/'spare').is_dir())
        with self.assertRaises(OSError):  # 'synthetic' is open in setUp: its operation lock is held.
            remove_identity('synthetic')
        self.assertTrue((store.root('identities')/'synthetic').is_dir())
        result=remove_identity('spare')
        self.assertEqual((result['removed'],result['network_used']),(True,False))
        self.assertFalse((store.root('identities')/'spare').exists())
        with self.assertRaisesRegex(ValueError,'not_found'):
            remove_identity('spare')


class PlanTests(unittest.TestCase):
    def test_plan_never_opens_state_prompts_or_connects(self):
        commands=[['onesign','enroll','--name','x','--run','a'],
                  ['onesign','login','--name','x','--run','a','--session','s'],
                  ['transfer','execute','--name','x','--run','a','--session','s','--transaction','p']]
        with patch.object(State,'__enter__',side_effect=AssertionError),patch('getpass.getpass',side_effect=AssertionError), \
                patch('socket.socket.connect',side_effect=AssertionError):
            for args in commands:
                with redirect_stdout(io.StringIO()) as output,redirect_stderr(io.StringIO()):
                    result=main(['hana',*args])
                self.assertEqual(result,0)
                self.assertFalse(json.loads(output.getvalue())['network_used'])


if __name__=='__main__':
    unittest.main()
