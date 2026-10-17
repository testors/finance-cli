"""Native immediate-transfer requests and consumed response fields (20.0.40)."""
import base64
from functools import partial
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from . import account_protocol as account, history_protocol as history, transfer_selection

ENDPOINT = '/serviceEndpoint/httpDigital/'
OWNER = account.strings('ipAcSungNmS20 savingBnkCd_display ipbnkCS3_display ipbnkCS3 icheGS1')
OWNER.update(ipAcNoS16=('nullable_string', ''), jiAcnoS16=('nullable_string', ''))
INQUIRY = account.strings('trxSerS100 cltTrxnoS10 dupYnS1 fincSagiQstnDsynS1 vrtlMneyAcYnS1 '
    'recent6MTransYn btmShtMsg1S100 btmShtMsg2S100 dirtyMoneyYn jiAcnoS16 jibnkCS3 jiBnkGS1 '
    'jiAcMemS20 ipAcNoS16 ipbnkCS3 ipbnkCS3_display savingBnkCd_display ipAcMemS20 ipAcSungNmS20 '
    'icheGS1 cmsC jibulPsbJanN15 icheUpmuGS2 icheDtlGS2 ygSecrityMdiaKS20 secrityMdiaOmitYnS1 '
    'secrityCdSer1S20 secrityCdSer2S20 acScnoOmitYnS1 loginMthKS50 loginMthOmitYnS1 ipinConnAdrOutS50 '
    'eSignOmitYnS1 feeUdaeRsnS100 eacDrynS1 imdichGnynS1 boninAcIcheYnS1 napbujSungNmS30 '
    'jingsuOrgNmS50 gwaSmokNmS30 remdrNapbuHalAmtS15 napbuAmtUpdYnS1')
INQUIRY.update(icheamtN15_originalValue=('double', 0.0), nmlFeamtN18=('int', 0), aplFeamtN18=('int', 0),
    jibulPsbJanN15_originalValue=('long', 0),
    fincSagiQstnMsg=([account.strings('fincSagiQstnMsgS120 fincSagiQstnAnsS1')], []))
ADDITIONAL = {'addAuthDsYnS1': ('string', None), 'grid01': ([account.strings('svcSeqS3')], [])}
PISP = {'authNoS64': ('string', None)}
RECEIPT = {name: ('string', None) for name in ('jiAcnoS16 jiBnkCS3 jibnkNm jiAcnoJanS21_originalValue '
    'jiAcMemS20 sndMnIdS50 ipAcno ipBnkCS3 ipbnkNmS50 ipAcSungNmS30 ipAcMemS20 ipinConnAdrOutS50 '
    'feamtS18 aplFeamtS18 nowYymmDtmMinSecS30 icheDtlGS2 cmsC drDtS8 drSerS8').split()}
RECEIPT.update(account.strings('savingBnkCd_display kakaoTalkShrMsgS300 kakaoTalkUrlS500 icheTranSno icheTranDt'))
RECEIPT['icheAmt_originalValue'] = ('double', None)


def parse_receipt(reply):
    verdict, document = history.parse_reply(reply, schema=RECEIPT, body_error='transfer_receipt_unavailable')
    if verdict['bank_result'] == 'success' and document.get('dataBody') is not None:
        body = document['dataBody']
        # These are the DTO's required fields, not additional success checks.
        if any(body[name] is None for name, (_, default) in RECEIPT.items() if default is None):
            verdict.update(processing_status='incomplete', error='transfer_receipt_unavailable')
            document['dataBody'] = None
    return verdict, document


def parser(schema, name):
    return partial(parse, schema=schema, name=name)


def parse(reply, *, schema, name):
    verdict, document = transfer_selection.parse_reply(reply, schema=schema, body_error=name+'_body_unavailable')
    if verdict['bank_result'] == 'success' and document.get('dataBody') is not None:
        body = document['dataBody']
        if any(body[field] is None for field, (_, default) in schema.items() if default is None):
            verdict.update(processing_status='incomplete', error=name+'_body_unavailable')
            document['dataBody'] = None
    return verdict, document


def bank_code(value):
    value = {'하나': '081', '하나은행': '081', 'hana': '081', '신한': '088',
             '신한은행': '088', 'shinhan': '088'}.get(value, value)
    if not isinstance(value, str) or not re.fullmatch('[0-9]{3}', value):
        raise ValueError('three_digit_bank_code_required')
    return value


def digits(value):
    return re.sub('[^0-9]', '', value)


def field_encrypt(value, settings):
    # Reuse the installed shared field-encryption key; no extra user secret.
    key = bytes.fromhex(settings['pin_check_key'])
    return base64.b64encode(AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pad(value.encode(), 16))).decode()


def owner_request(withdrawal, bank, number):
    return {'jiAcnoS16': withdrawal['accountNumber'].replace('-', ''),
            'jiBnkGS1': withdrawal['bankClassification'], 'jibnkCS3': withdrawal['bankCode'],
            'ipAcNoS16': digits(number), 'ipbnkCS3': bank, 'icheUpmuGS2': '01'}


def inquiry_request(withdrawal, bank, number, amount, name, settings, *, withdrawal_memo='', receiver_memo=''):
    body = owner_request(withdrawal, bank, number)
    vpn = settings.get('login_metadata', {}).get('vpnYn', 'X')
    body.update(jiAcMemS20=withdrawal_memo, ipAcMemS20=receiver_memo,
        rcvEnc1=field_encrypt(bank, settings), rcvEnc2=field_encrypt(body['ipAcNoS16'], settings),
        rcvrSungNmS30=name, rcvrConnAdrS20='', icheRqstDtS8='', icheRqstTimesS4='',
        icheamtN15=amount, icheSumAmtN15=amount, rcvEnc3=field_encrypt(str(amount), settings),
        ipAcInMthS2='01', cmsC='', icheDtlGS2='', vpnYn='X' if vpn == 'UNKNOWN' else vpn)
    return body


def authentication(body):
    return {'account_password': body['acScnoOmitYnS1'] != 'Y',
            'login': body['loginMthOmitYnS1'] == 'N',
            'security_media': body['secrityMdiaOmitYnS1'] != 'Y',
            'security_media_kind': body['ygSecrityMdiaKS20'],
            'fraud_questionnaire': body['fincSagiQstnDsynS1'] == 'Y',
            'duplicate': body['dupYnS1'] == 'Y', 'dirty_money': body['dirtyMoneyYn'] == 'Y',
            'recent_transfer': body['recent6MTransYn'] in ('', 'Y')}


def execute_request(body, *, withdrawal_memo='', receiver_memo=''):
    return {'cltTrxnoS10': body['cltTrxnoS10'], 'trxSerS100': body['trxSerS100'],
            'feePntUsynS1': 'N', 'putuseFeeN10': 0, 'ipAcMemS20': receiver_memo,
            'jiAcMemS20': withdrawal_memo, 'dupYnN1': '1' if body['dupYnS1'] == 'Y' else '0',
            'reqKey': ''}


def password_request(body, withdrawal, encrypted):
    return {'cltTrxnoS10': body['cltTrxnoS10'],
            'sub01': [{'jiAcno': withdrawal['accountNumber'], 'scno': encrypted if encrypted is not None else ''}]}


def additional_request(amount):
    return {'icheamt': amount, 'resvIcheGS1': 'N'}


def additional_parameters(body, bank_name):
    required = body['addAuthDsYnS1'] == 'Y'
    sequence = body['grid01'][0]['svcSeqS3'] if required and body['grid01'] else ''
    params = {'serviceSeq': sequence or '9', '이체건수': 1}
    if bank_name:
        params['입금은행명'] = bank_name
    return required, params


def pisp_request(credential, device, unique, plaintext, signature):
    return {'inputSignData': {'certSeqNo': credential['alias'], 'msbVrsnVl': credential['msb_version'],
        'custCctnMctlId': device['device_id'], 'crtcPtrnDcd': '10', 'crtcPtrnDataCon': unique,
        'tranElsgOnttCon': plaintext, 'tranElsgDataCon': signature, 'bioCrtcSuccYn': ''}}
