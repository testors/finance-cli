"""One prepared KRW transfer, explicit confirmation, no OTP bypass or retry."""
import base64
from datetime import datetime
import hashlib
from zoneinfo import ZoneInfo

from . import onesign_crypto as pin, onesign_compat as compat, transfer_format
from . import onesign_transfer_protocol as protocol, nfilter_crypto, request_activity
from .onesign import record, ms
from .onesign_codec import encode
from .onesign_io import Client, send_http
from .onesign_workflow import Workflow
from .onesign_keys import EXTERNAL_ITEM
from .signing_text import signing_text
from .hana_protocol import decode_header, encode_header
from .evidence import account, amount, identifiers, nonblank
from .store import name as valid_name

PATHS = {
 'withdrawal':'/api/pcm/slct01/capi/acctInq/retrieveTrnsUsagWdrwAcctList',
 'session_accounts':'/public/pcm/lgin01/capi/lginSessMgnt/retrieveLginSess',
 'recent_accounts':'/api/pcm/trns01/capi/trnsInfoInq/retrieveTrnsNrstRcvNSefAcct',
 'pretransaction':'/api/pcm/trns01/capi/trnsRsevTrsc/executeTrnsRsevTrsc',
 'additional_info':'/api/pcm/trns01/capi/trnsInfoMgnt/saveTrnsAdtnInfo',
 'keypad_key':'/public/pcm/lgin01/capi/lginMgnt/executeNFilterKey',
 'password':'/api/pcm/trns01/capi/trnsTrsc/verifyTrnsWdrwAcctPw',
 'auth_means':'/public/pcm/lgin01/capi/addCert/retrieveAddCertMean',
 'server_time':'/public/pcm/etcs01/capi/dtInq/retrieveCurrDtm',
 'execute_self':'/api/pcm/trns01/capi/trnsTrsc/executeSefAcctTrnsTrsc',
 'execute_other':'/api/pcm/trns01/capi/trnsTrsc/executeTrnsTrsc',
 'history':'/api/pcm/trns01/capi/trnsPtclInq/retrievetxnOurTrns',
 'detail':'/api/pcm/trns01/capi/trnsPtclInq/retrievedtlOurTrnsPtcl'}


def checked_intent(value):
    pin.require(isinstance(value,dict) and set(value)=={'source_account','recipient_bank_code','recipient_account_number','amount_krw'},'transfer_intent_fields')
    pin.require(account(value['source_account']) is not None and account(value['recipient_account_number']) is not None,'transfer_account_format')
    pin.require(isinstance(value['recipient_bank_code'],str) and len(value['recipient_bank_code'])==3 and value['recipient_bank_code'].isdigit(),'recipient_bank_code_format')
    pin.require(type(value['amount_krw']) is int and 0 < value['amount_krw'] <= 2**53-1,'positive_whole_krw_required')
    result = dict(value,source_account=account(value['source_account']),recipient_account_number=account(value['recipient_account_number']))
    pin.require(result['source_account'] != result['recipient_account_number'] or result['recipient_bank_code'] not in protocol.OUR_CODES,'same_source_recipient')
    return result


def binding(state, session):
    value = state.snapshot()
    saved = value['sessions'][session]
    alias,entry = record(state)
    pin.require(saved.get('signed_login') is True,'onesign_signed_login_required')
    pin.require(saved['device_id']==value['profile']['device_id'] and saved['customer_number']==value['profile']['customer_number']
                and saved['certificate_sha256']==entry['fingerprint'],'transfer_login_identity_changed')
    return {'session':session,'device_id':saved['device_id'],'customer_number':saved['customer_number'],
            'certificate_sha256':entry['fingerprint'],'record_sha256':hashlib.sha256(encode(entry)).hexdigest()}


def request(client, stage, body):
    native = stage in ('keypad_key','server_time')
    headers = client.headers()
    if not native:
        common = decode_header(headers['hana-com-header'])
        common['CNL_HDPT']['SCRN_ID'] = 'TRNB0101002001'
        headers['hana-com-header'] = encode_header(common)
        headers['Content-Type'] = 'application/json;charset=utf-8'
    raw = client.request('bank','POST',PATHS[stage],headers,
                         b'' if stage=='keypad_key' else encode(body),web=not native,
                         observe=observe_execution if stage.startswith('execute_') else None)
    if stage == 'password':
        return {}  # The successful source callback ignores the response body.
    return compat.kotlin_object(raw,string_fields=('apiRlseKey',) if stage=='keypad_key' else ('dt','tm','bussDdYn')) if native else compat.web_value(raw)


def observe_execution(raw):
    value = compat.web_value(raw)
    accepted = None
    if isinstance(value,dict):
        rows = value.get('trnsList')
        first = rows[0] if isinstance(rows,list) and rows and isinstance(rows[0],dict) else {}
        count = {**first,**value}.get('errNcnt')
        accepted = not (type(count) in (int,float) and count==1)
    result = {'accepted':accepted,'original_result_success':accepted,'transfer_sent':True,
              'transfer_confirmed':False,'next':'reconcile','automatic_retry':False}
    # Common-header success and the transfer result-page predicate are separate.
    return {'execution_result':result}


def preview(transaction):
    row = transaction['data']['additional_info']['trnsList'][0]
    return {'transaction':transaction['name'],'source_account':transaction['source'],
        'recipient_bank_code':row['rcvBnkCd'],'recipient_account':row['rcvAcctNo'],'recipient_name':row['rmteNm'],
        'amount_krw':transaction['intent']['amount_krw'],'fee_krw':amount(row['rduAfComm']),
        'total_krw':amount(transaction['data']['additional_info']['totlTrnsAmt']),
        'authentication':transaction.get('route'),'state':transaction['state']}


def prepare(state, client, transaction, intent, password):
    intent = checked_intent(intent)
    valid_name(transaction)
    bound = binding(state,client.session)
    with state.transaction() as value:
        pin.require(transaction not in value['transfers'],'transfer_already_exists')
        saved = value['sessions'][client.session]
        pin.require(not saved.get('transfer_attempted'),'use_new_session_for_next_transfer')
        saved['transfer_attempted'] = True
        ctx = {'name':transaction,'binding':bound,'intent':intent,'source':intent['source_account'],
            'cfg':{'kind':'other','onesign':True},'state':'preparing','data':{},'receipts':{}}
        value['transfers'][transaction] = ctx
    def save():
        with state.transaction() as value:
            value['transfers'][transaction] = ctx
    def call(stage, body):
        result = request(client,stage,body)
        ctx['data'][stage] = result
        ctx['receipts'][stage] = {'request':{'body':body}}
        save()
        return result
    response = call('withdrawal',{'menuId':'TRNB0101002001','opbkAcctMarkYn':'Y','wdrwAcctMarkYn':'Y',
        'wdrwPossAmtMarkYn':'Y','inqMthdDv':'1','opbkBnkCd':'','opbkAcctNo':'','opbkInqMthdDv':'Y'})
    rows = response.get('ourAcctList')
    pin.require(isinstance(rows,list),'withdrawal_rows_unavailable')
    rows = [r for r in rows if isinstance(r,dict) and account(r.get('acctNo'))==ctx['source']]
    pin.require(len(rows)==1,'withdrawal_not_unique')
    w = rows[0]
    pin.require(w.get('openYn')=='N' and w.get('bnkCd')=='081' and not w.get('meetSeqNo') and not w.get('meetSacApcNo'),'ordinary_hana_account_required')
    ctx['withdrawal'] = w
    body = dict.fromkeys(('lginYn','custInfoYn','custInfoAdtnYn','lginTmpAllYn','allAcctPrdYn','allAcctOpbkYn',
                         'allAcctRtpnsYn','allAcctMyDatYn','exhgRtYn','usrAthtMap'),'N')
    body.update(allAcctPrdYn='Y',lginTmpList=[])
    value = call('session_accounts',body)
    pin.require(value.get('allAcctListDto',{}).get('accountMap',{}).get(ctx['source'],{}).get('mmdaHoldYn')=='N','non_mmda_account_required')
    recent = call('recent_accounts',{})
    pin.require(recent.get('cmCertsYn') in ('Y','N'),'certificate_flag_unavailable')
    value = call('pretransaction',{'chnlSvcCd':'A16','paymAcctNo':ctx['source'],'paymAcctNm':w['acctNm'],
        'rcvBnkCd':intent['recipient_bank_code'],'rcvAcctNo':intent['recipient_account_number'],
        'paytSqn':1 if intent['recipient_bank_code'] in protocol.OUR_CODES else 0,'trnsAmt':intent['amount_krw'],
        'wdrwSeqNo':protocol.numeric(w['wdrwAcctSeqNo'],'withdrawal_sequence'),'wdrwBnkCd':w['bnkCd'],
        'wdrwBnkNm':w['bnkNm'],'trnsSeqNo':1,'addTrnsYn':'N','svcDvCd':'ACCT_TRNS','rmtYn':'N'})
    pin.require(value.get('dupTrscVrfcYn')=='N' and value.get('fncFrdDgnsNcsyYn')=='N','additional_transfer_screen_required')
    pin.require(value.get('rcvAcctSefYn') in ('Y','N'),'self_account_classification_unavailable')
    ctx['cfg']['kind'] = 'self' if value['rcvAcctSefYn']=='Y' else 'other'
    row = protocol.transaction_row(ctx,'pretransaction',value)
    value = call('additional_info',{'trscSeqNo':1,'pintPrdLclasCd':'','cshbUseYn':'','cshbUseAmt':0,
        'rcvPsbkMarkCtt':transfer_format.mark(row.get('rcvPsbkMarkCtt') or ''),'wdrwPsbkMarkCtt':row.get('wdrwPsbkMarkCtt',''),
        'slctDvCd':row.get('slctDvCd') or '','trnsScheDt':'','trnsScheTm':'','custNtfyMdclCd':'','mmdaHoldYn':'N'})
    protocol.transaction_row(ctx,'additional_info',value)
    pin.require(value.get('mmdaHoldYn')=='N','mmda_state_changed')
    if ctx['cfg']['kind']=='other':
        public = call('keypad_key',None)['apiRlseKey']
        secret = password()
        try:
            pin.require(isinstance(secret,str) and len(secret)==4 and secret.isascii() and secret.isdigit(),'account_password_four_digits_required')
            cipher = nfilter_crypto.encrypt_numeric_password(public,secret,base64.b64decode(state.snapshot()['settings']['keypad_mac']))
        finally:
            del secret
        call('password',{'typCd':'1','acctNo':ctx['source'],'trnsAmt':value['totlTrnsAmt'],'acctSvcCd':'ACCT_TRNS','wdrwAcctVrfcYn':'Y','acctPw':cipher})
        response = call('auth_means',{'certDv':'transfer','addCertUncsYn':'N','scrtCrdSeqNoMarkYn':'N',
            'ofclCertsUseYn':recent['cmCertsYn'],'dtlsDv':'','scrtMdclMarkYn':'','easnCertYn':'',
            'faceCertUsePossMachYn':'N','sefCnfmAddMdclDv':''})
        ctx['route'] = pin.assess_transfer_auth(response,state.snapshot()['sessions'][client.session]['login_response'])
        ctx['state'] = 'prepared' if ctx['route']['candidate'] else 'authentication_review'
    else:
        ctx.update(route={'candidate':True,'sign_required':False,'reason':'server_self_account_branch'},state='prepared')
    save()
    return {**preview(ctx),'transfer_sent':False,'accepted':True}


def execute(state,client,transaction,control,confirm,pin_input):
    ctx = state.snapshot()['transfers'][transaction]
    pin.require(ctx['state']=='prepared','transfer_not_prepared_or_already_attempted')
    pin.require(ctx['binding']==binding(state,client.session),'transfer_binding_changed')
    pin.require(confirm(preview(ctx)) is True,'transfer_confirmation_required')
    entered = pin_input() if ctx['cfg']['kind']=='other' and ctx['route']['bridge_type']=='pinHalf' else None
    # Reserve the entire signing/execution operation before the first nonce.
    with state.transaction() as value:
        value['transfers'][transaction]['state']='executing'
    body = {'tmsgUnqNo':ctx['data']['additional_info']['tmsgUnqNo13']}
    if ctx['cfg']['kind']=='other':
        date = request(client,'server_time',{'bussDt':'','tgtDt':''})
        row = dict(ctx['data']['additional_info']['trnsList'][0],mmdaHoldYn='N')
        form = pin.transfer_form(transfer_format.form(row),date['dt'],date['tm'],bridge_type=ctx['route']['bridge_type'])
        tbs = signing_text(form)
        alias,entry = record(state)
        flow = Workflow(state,ctx['binding']['device_id'],None,client.bank,client.ra,ms,ledger_vault=control)
        reply = flow.exchange('transfer-bank-nonce',-3,client.bank,pin.BANK_NONCE_PATH,pin.bank_nonce_body(ctx['binding']['customer_number']))
        content = pin.bind_bank_nonce(tbs,pin.text(reply.get('scrtRnum'),empty=True)).encode()
        if ctx['route']['bridge_type']=='noAuth':
            sc_b = pin.text(reply.get('scBCertKey'))
            secret = pin.external_master_secret(sc_b,device_id=flow.store.device_id)
            flow.store._unlock(entry,secret,EXTERNAL_ITEM)
            nonce = flow.exchange('transfer-ra-nonce',-2,client.ra,'/nonce',{})
            pin.ra_nonce(nonce)
            cms = flow.store.sign(alias,content,sc_b_cert_key=sc_b)
        else:
            try:
                material = pin.derive_pin(entered,device_id=flow.store.device_id,pin_salt=entry['pinSalt'],pin_spec_version=entry['pinSpecVersion'])
            finally:
                del entered
            info = {'subjectDer':pin.b64url(pin.certificate_parts(pin.unb64url(entry['certificate']))[2]),'pinVersion':entry['pinVersion']}
            ra_secret = flow.ra_auth('transfer',info,material)
            cms = flow.store.sign(alias,content,material=material,ra_secret=ra_secret)
        body.update(svcDvCd='ACCT_TRNS',bizDvNm='transfer',elecSignVluDat=base64.b64encode(cms).decode(),crypAcnmNo='')
    with state.transaction() as value:
        value['transfers'][transaction].update(execution_attempted=True,execution_started_ms=ms())
    value = request(client,'execute_'+ctx['cfg']['kind'],body)
    result = client.last['execution_result']
    accepted = result['accepted']
    # Keep the observed bank result even if a later local write fails.
    client.last.update(service_status='accepted' if accepted is True else 'rejected' if accepted is False else 'unconfirmed',
                       execution_result=result)
    with state.transaction() as data:
        data['transfers'][transaction].update(state='executed',execution_response=value,execution_result=result)
    return result


def reconcile(state,client,transaction):
    ctx = state.snapshot()['transfers'][transaction]
    pin.require(ctx.get('execution_attempted'),'no_execution_to_reconcile')
    pin.require(ctx['binding']==binding(state,client.session),'transfer_binding_changed')
    pin.require(not ctx.get('reconcile_attempted'),'reconciliation_already_attempted')
    with state.transaction() as value:
        value['transfers'][transaction]['reconcile_attempted']=True
    date = datetime.fromtimestamp(ctx['execution_started_ms']/1000,ZoneInfo('Asia/Seoul')).strftime('%Y%m%d')
    history = request(client,'history',{'rqstNcnt':'20','strPost':'1','trnsRsltBizDvCd':'','trnsInqDvCd':'',
        'wdrwAcctNo':ctx['source'],'inqBascStrDt':date,'inqBascEndDt':date,'srchDvCd':'0','srchWdNm':'','trscSeqInqDvCd':'2'})
    rows = history.get('rec') if isinstance(history,dict) else None
    pin.require(isinstance(rows,list),'history_rows_unavailable')
    def matches(row):
        return isinstance(row,dict) and row.get('trscStNm')=='완료' and protocol.bank_equal(row.get('rcvBnkCd'),ctx['intent']['recipient_bank_code']) and account(row.get('rcvAcctNo'))==ctx['intent']['recipient_account_number'] and amount(row.get('trscAmt'))==ctx['intent']['amount_krw'] and row.get('wdrwAcctNo') in (None,ctx['source'])
    candidates = [row for row in rows if matches(row)]
    pin.require(len(candidates)==1 and identifiers(candidates[0]) is not None,'result_candidate_missing_or_ambiguous')
    selected = candidates[0]
    detail = request(client,'detail',identifiers(selected))
    rows = detail.get('rec') if isinstance(detail,dict) else None
    pin.require(isinstance(rows,list) and len(rows)==1 and matches(rows[0]),'detail_candidate_mismatch')
    pin.require(all(rows[0].get(k,v)==v for k,v in identifiers(selected).items()),'detail_identifiers_changed')
    result = {'candidate_complete':True,'transfer_confirmed':False,'match':'account_amount_and_linked_detail',
              'automatic_retry':False,'execution_result':ctx.get('execution_result')}
    with state.transaction() as value:
        value['transfers'][transaction].update(reconciliation=result,history=history,detail=detail)
    return result


def operate(state,action,transaction,run,session,*,send=False,intent=None,inputs=None,exchange=send_http):
    inputs = inputs or {}
    pin.require(action in ('show','prepare','execute','reconcile'),'unsupported_transfer_operation')
    if action=='show':
        ctx=state.snapshot()['transfers'][transaction]
        try:
            value=preview(ctx)
        except (KeyError,IndexError,TypeError):
            value={'transaction':transaction,'state':ctx['state'],'intent':ctx['intent'],'prepared':False}
        return {**value,'execution_attempted':ctx.get('execution_attempted',False),
            'execution_result':ctx.get('execution_result'),'reconciliation':ctx.get('reconciliation'),'network_used':False}
    if not send:
        return {'operation':'transfer-'+action,'transaction':transaction,'network_used':False,'next':'same_command_with_send'}
    control = state.begin_run(run,'transfer-'+action)
    client = Client(state,run,session,send=True,exchange=exchange)
    client.transfer_paths = set(PATHS.values())
    try:
        if action=='prepare':
            result = prepare(state,client,transaction,intent,inputs['account_password'])
        elif action=='execute':
            result = execute(state,client,transaction,control,inputs['confirm'],inputs['pin'])
        elif action=='reconcile':
            result = reconcile(state,client,transaction)
        else:
            raise pin.ProtocolError('unsupported_transfer_operation')
        with control.transaction() as value:
            value.update(outcome='completed',result=result)
        return {**result,'processing_status':'completed','network_used':client.sent>0}
    except Exception as exc:
        result = {'error':str(exc) if isinstance(exc,(pin.ProtocolError, request_activity.RequestBlocked)) else 'local_processing_error',
            'service_status':client.last['service_status'],'accepted':True if client.last['service_status']=='accepted' else False if client.last['service_status']=='rejected' else None,
            'processing_status':'stopped','network_used':client.sent>0,'automatic_retry':False,
            'execution_result':client.last.get('execution_result')}
        if result['execution_result'] is not None:
            result['accepted']=result['execution_result']['accepted']
            result['service_status']='accepted' if result['accepted'] is True else 'rejected' if result['accepted'] is False else 'unconfirmed'
        if result['execution_result'] is None:
            try:
                result['execution_result'] = state.snapshot()['transfers'].get(transaction,{}).get('execution_result')
            except Exception:
                result['diagnostic_storage_failed'] = True
        try:
            with control.transaction() as value:
                value.update(outcome='stopped',result=result)
        except Exception:
            result['diagnostic_storage_failed']=True
        return result
