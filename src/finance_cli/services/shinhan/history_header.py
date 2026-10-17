"""Account header accompanying a Shinhan transaction history inquiry."""
import math

from . import account_protocol, history_protocol

TRANSACTION = 'RSMDE0105A21'
BUTTON = account_protocol.strings('assetBtnNm assetBtnPrgId assetBtnParam')
BODY = account_protocol.strings('depKS1 kwaNmS80 prdtC prdtBkkpNm acno guAcno icheAcnoS12 subAcno ltacnoS16 depIntS24 acJan jibulPsbAmtN182 acSS20 acSBadgeColor inetMkYnS1 eBbkYnS1 grpSvcLeaderYn grpSvcGroupId grbrnoS4 grbrnoS4_display bnkCdS3 bnkNm bnkNm_display acNmS100 dueDdS8')
BODY.update({key: ('int', -1) for key in 'bnkGN2 yeyakCnt silnmYn trxSotpacYn ibnkJiAcYnN1 opbJiAgrYn newAcCvtYnN1 assetBtnCtn'.split()})
BODY.update({key: ('long', -1) for key in ('acJan_originalValue', 'jibulPsbAmtN182_originalValue')})
BODY.update(depIyul=('double', 0.0), addIyul=('double', 0.0), assetBtnList=([BUTTON], []))


def parse_reply(reply):
    return history_protocol.parse_reply(reply, schema=BODY, body_error='history_header_body_unavailable')


def account_type(value):
    return {'1': 'DEMAND_DEPOSIT', '2': 'TIME_DEPOSIT', '3': 'TRUST', '6': 'FUND'}.get(value, 'UNKNOWN')


def mapped(body):
    fields = {'bnkNm_display': 'bankName', 'bnkCdS3': 'bankCode', 'acNmS100': 'accountName',
        'acno': 'accountNumber', 'acJan_originalValue': 'balance', 'jibulPsbAmtN182_originalValue': 'withdrawableAmount',
        'acSS20': 'accountStatus', 'acSBadgeColor': 'badgeColor', 'subAcno': 'subAccountNumber',
        'guAcno': 'oldAccountNumber', 'yeyakCnt': 'scheduledTransferCount', 'grpSvcGroupId': 'groupId',
        'depIntS24': 'interestAmount'}
    result = {target: body[source] for source, target in fields.items()}
    result.update(isWithdrawable=True, useOldAccount=body['newAcCvtYnN1'] == 0,
        hasBankBook=body['eBbkYnS1'] == 'Y', isGroupLeader=body['grpSvcLeaderYn'] == 'Y',
        isGroupLeaderAccount=body['grpSvcLeaderYn'] == 'Y' and len(body['grpSvcGroupId']) > 0,
        interestRate=body['depIyul']+body['addIyul'], accountType=account_type(body['depKS1']),
        buttons=[{'text': item['assetBtnNm'], 'programId': item['assetBtnPrgId'], 'param': item['assetBtnParam']}
                 for item in body['assetBtnList'] if item['assetBtnNm'] and item['assetBtnPrgId']])
    # The navigation object omits serializer defaults, including defaults in
    # nested buttons, then renames two fields only when their source is present.
    # Double.compare distinguishes -0.0 from the default +0.0.
    extra = {key: value for key, value in body.items() if value != BODY[key][1] or
             BODY[key][0] == 'double' and value == 0.0 and math.copysign(1, value) < 0}
    if 'assetBtnList' in extra:
        extra['assetBtnList'] = [{key: value for key, value in item.items() if value != BUTTON[key][1]}
                                 for item in extra['assetBtnList']]
    if 'eBbkYnS1' in extra:
        extra['eBbkYn'] = extra.pop('eBbkYnS1')
    if 'acno' in extra:
        extra['acnoS12'] = extra.pop('acno').replace('-', '')
    result['resultJson'] = extra
    return result
