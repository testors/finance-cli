"""Standalone OneSign identities, issuance and signed login."""
import base64
from datetime import datetime
import hashlib
import secrets
from zoneinfo import ZoneInfo

from Crypto.PublicKey import RSA

from . import hana_protocol, onesign_crypto as pin, onesign_setup, onesign_signup_protocol as signup
from . import onesign_issue_protocol as issue, nfilter_crypto, request_activity
from .onesign_io import Client, ACCOUNTS, send_http
from .onesign_keys import KeyStore
from .onesign_signup import Signup, ms
from .onesign_issuance import Issuance
from .onesign_state import State
from .onesign_workflow import Workflow
from .transport import USER_AGENT

PHONE = ('profile','authenticate','request-sms','verify-sms','consent')
ISSUE = ('begin-id','identity','list-accounts','account','issue','complete')


def initial(settings):
    if 'service_profile' not in settings:
        raise ValueError('configure_device_profile_first')
    android = secrets.token_hex(8)
    device = hana_protocol.device_uuid(android)
    key = RSA.generate(2048).export_key(format='DER',pkcs=8)
    return {'version':1,'profile':{'device_id':device,'customer_number':None,'agent':'하나은행',
            'app_identity':{'android_id':android,'key_sha256':hashlib.sha256(key).hexdigest(),
                'provenance':'generated-isolated-cli-identity','user_agent':USER_AGENT},
            'app_key':pin.b64url(key),'enrollment':{'state':'new'},'service_profile':settings['service_profile']},
        'settings':settings,'cloud':{},'records':{},'operations':{},'halted':False,'runs':{},'transfers':{},
        'sessions':{'signup':{'cookies':[]}},
        'signup':{'version':1,'session':'signup','state':'new','purpose':'issue','responses':{},'pending':None},
        'issuance':{'state':'new','responses':{},'pending':None,'certificate_issued':False}}


def initialize(name, settings_name, password):
    settings = onesign_setup.load(settings_name)
    with State(name,password,initial(settings)):
        pass
    return {'created':True,'name':name,'network_used':False,'next':'enroll'}


def record(state):
    value = state.snapshot()
    enrollment = value['profile']['enrollment']
    pin.require(enrollment.get('state') == 'ready','onesign_enrollment_not_ready')
    alias = enrollment['alias']
    result = KeyStore(state,value['profile']['device_id'])._record(value,alias)
    pin.require(result['authType'] & 1, 'pin_auth_not_registered')
    return alias,result


def new_session(state, name):
    from .store import name as valid_name
    valid_name(name)
    record(state)
    with state.transaction() as value:
        pin.require(name not in value['sessions'],'session_already_exists')
        value['sessions'][name] = {'cookies':[]}
    return {'session':name,'created':True,'network_used':False}


def jpeg_size(raw):
    pin.require(raw[:2] == b'\xff\xd8','identity_jpeg_required')
    offset = 2
    while offset+4 <= len(raw):
        pin.require(raw[offset] == 255,'identity_jpeg_invalid')
        while offset < len(raw) and raw[offset] == 255:
            offset += 1
        pin.require(offset < len(raw),'identity_jpeg_invalid')
        marker = raw[offset]
        offset += 1
        if marker in (0xd8,0xd9,1) or 0xd0 <= marker <= 0xd7:
            continue
        size = int.from_bytes(raw[offset:offset+2],'big')
        pin.require(size >= 2 and offset+size <= len(raw),'identity_jpeg_invalid')
        if marker in (0xc0,0xc1,0xc2):
            pin.require(size >= 8,'identity_jpeg_invalid')
            height,width = int.from_bytes(raw[offset+3:offset+5],'big'),int.from_bytes(raw[offset+5:offset+7],'big')
            pin.require(0 < width <= 1024 and height > 0,'identity_card_crop_width_over_1024')
            return width,height
        offset += size
    raise pin.ProtocolError('identity_jpeg_dimensions_missing')


def prepare_identity(state, kind, jpeg, fields):
    current = state.snapshot()['issuance']
    pin.require(current['state'] == 'id_ready' and not current.get('pending'),'identity_application_required')
    pin.require(len(jpeg) <= 8*1024*1024,'identity_image_too_large')
    jpeg_size(jpeg)
    application = current['application']
    value = {k:fields[k] for k in ('name','issueDate','birthDate')}
    value['encResidentNo'] = issue.encrypt_ocr_field(fields['resident'],application)
    if kind == 'driver':
        value['regionCode'] = fields['regionCode']
        for i,length in enumerate((2,6,2),1):
            value['encDriverLicenseExceptAreaNo'+str(i)] = issue.encrypt_ocr_field(fields['driver'+str(i)],application)
            value['encDriverLicenseExceptAreaNoMasking'+str(i)] = '●'*length
    value['encImage'] = issue.encrypt_ocr(jpeg,application)
    issue.validate_ocr(value,kind)
    with state.transaction() as data:
        data['issuance'].update(capture=value,capture_kind=kind,capture_source='user-reviewed-card-image-and-text')
    return {'prepared':True,'network_used':False,'identity_verified':False}


def operate(state, action, run, *, session='signup', send=False, inputs=None, exchange=send_http):
    """Callbacks supply secrets at their source-defined point, never from argv."""
    inputs = inputs or {}
    if action not in (*PHONE,*ISSUE,'login','accounts'):
        raise ValueError('unsupported_onesign_operation')
    remote = action not in ('profile','consent')
    if remote and not send:
        return {'operation':action,'network_used':False,'next':'same_command_with_send'}
    current = state.snapshot()
    pin.require(session in current['sessions'],'session_not_found')
    if action in (*PHONE,*ISSUE):
        pin.require(session == 'signup','issuance_signup_session_required')
    control = state.begin_run(run,action)
    client = Client(state,run,session,send=send,exchange=exchange)
    settings = current['settings']
    issuance = None
    try:
        if action in PHONE:
            value = Signup(state,'signup').execute(action,run,client.phone,
                profile_input=inputs.get('phone'),agree=inputs.get('agree'),sms_input=inputs.get('sms'),
                authenticate=lambda:client.authenticate(settings),app_hash=settings['sms_hash'],issue_new=True)
        elif action in ISSUE:
            issuance = Issuance(state,client.bank,client.image,client.ca,client.ra,ms,ledger_vault=control,
                encrypt_password=lambda public,digits:nfilter_crypto.encrypt_numeric_password(public,digits,base64.b64decode(settings['keypad_mac'])))
            if action == 'issue':
                pin.require(inputs['confirm_issue']() is True,'issuance_not_confirmed')
            current = state.snapshot()['issuance']
            value = issuance.execute(action,ocr=current.get('capture'),kind=current.get('capture_kind'),
                account_input=inputs.get('account'),password_input=inputs.get('account_password'),
                pin_input=inputs.get('new_pin'),ca_certificate=base64.b64decode(settings['ca_certificate']))
        elif action == 'login':
            alias,entry = record(state)
            with state.transaction() as data:
                saved = data['sessions'][session]
                pin.require(not saved.get('login_attempted'),'login_already_attempted_use_new_session')
                saved['login_attempted'] = True
            if not state.snapshot()['sessions'][session].get('app_authenticated'):
                client.authenticate(settings)
            flow = Workflow(state,current['profile']['device_id'],None,client.bank,client.ra,ms,ledger_vault=control)
            info = {k:entry[k] for k in ('pinSalt','pinVersion','fingerprint')}
            info['subjectDer'] = pin.b64url(pin.certificate_parts(pin.unb64url(entry['certificate']))[2])
            body = {'subjectDer':info['subjectDer'],'checkStatus':True}
            if info['pinVersion']:
                body['pinVersion'] = info['pinVersion']
            flow.exchange('check-pin-version',-2,client.ra,'/checkPinVersion',body)
            secret = inputs['pin']()
            try:
                request = flow.prepare_login(alias,info,secret,customer_number=current['profile']['customer_number'],
                                             moment=datetime.now(ZoneInfo('Asia/Seoul')))
            finally:
                del secret
            reply = flow.exchange('login',-3,client.bank,pin.LOGIN_PATH,request)
            pin.require(reply.get('lginCertMethCd') == 'S' and reply.get('hanaCertLginYn') == 'Y','onesign_signed_login_not_confirmed')
            with state.transaction() as data:
                data['profile']['customer_number'] = reply['custNo']
                data['sessions'][session].update(signed_login=True,certificate_sha256=entry['fingerprint'],
                    device_id=current['profile']['device_id'],customer_number=reply['custNo'])
            value = {'logged_in':True,'login_method':'S','session':session}
        else:
            pin.require(current['sessions'][session].get('signed_login') is True,'onesign_signed_login_required')
            reply = client.bank(ACCOUNTS,None)
            with state.transaction() as data:
                data['sessions'][session]['accounts'] = reply
            # User-requested account result; encrypted at rest, no automatic logging.
            value = {'accounts':reply,'session':session}
        with control.transaction() as result:
            result.update(outcome='completed',result=value)
        return {**value,'network_used':client.sent>0,'accepted':True,'processing_status':'completed','automatic_retry':False}
    except Exception as exc:
        code = str(exc) if isinstance(exc,(pin.ProtocolError, request_activity.RequestBlocked)) else 'local_processing_error'
        issued = bool(issuance and issuance.certificate_issued)
        try:
            issued = issued or state.snapshot()['issuance'].get('certificate_issued',False)
        except Exception:
            pass  # Preserve the in-memory service outcome when storage failed.
        if issued and client.last.get('scope')=='ca':
            client.last['service_status']='accepted'
        if code in ('identity_image_upload_failed','identity_verification_failed',
                    'issuance_account_verification_failed','issuance_pin_policy_failed','cmp_ca_error'):
            client.last['service_status']='rejected'
        result = {'error':code,'accepted':True if client.last['service_status']=='accepted' else False if client.last['service_status']=='rejected' else None,
            'service_status':client.last['service_status'],'processing_status':'stopped','certificate_issued':issued,
            'network_used':client.sent>0,'automatic_retry':False,'run':run}
        try:
            with control.transaction() as value:
                value.update(outcome='stopped',result=result)
        except Exception:
            result['diagnostic_storage_failed'] = True
        return result
