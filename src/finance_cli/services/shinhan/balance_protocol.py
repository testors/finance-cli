"""Single-account balance request, typed response, and account balance mapping."""
import unicodedata

from . import account_protocol, history_protocol, transfer_selection

TRANSACTION = 'RSMDE1401A02'
ENDPOINT = '/serviceEndpoint/httpDigital'
LINK = account_protocol.strings('pgmId param')
BUTTON = account_protocol.strings('btnNmS100 msgCtntS2000 msgPyosiUmS1')
BUTTON['pgmLink'] = (LINK, {'pgmId': '', 'param': ''})
BODY = account_protocol.strings('acnoS12_originalValue acJanS18 jiUseAmtN182 chkMdErrYn tbnkTrnNoS3 errorMessage errorDescription nspErrorMessage')
BODY.update({name: ('int', 0) for name in ('bnkCN3', 'errYnN1', 'isOpenbankingError',
                                        'isOpenbankingNotAvailable', 'isMaintainanceError')})
BODY.update(orglAcJanN18=('double', 0.0), jiUseAmtN182_originalValue=('long', 0), btnList=([BUTTON], []))


def request(account, bank_code, bank_classification, currency=''):
    values = (account, bank_code, bank_classification, currency)
    if not all(isinstance(value, str) for value in values):
        raise ValueError('balance_request_input')
    return dict(zip(('acno', 'bnkCN3', 'bnkG', 'curCS3'), values))


def decode(text, schema=BODY):
    return history_protocol.decode(text, schema)


def parse(reply):
    return transfer_selection.parse_reply(reply, BODY, 'balance_body_unavailable')


def blank(text):
    # Kotlin Char.isWhitespace includes Unicode separators but not U+0085.
    return all(ch in '\t\n\v\f\r\x1c\x1d\x1e\x1f' or unicodedata.category(ch) in ('Zs', 'Zl', 'Zp') for ch in text)


def entity(body):
    error = body['errYnN1'] == 1
    message = body['errorMessage']
    if blank(message):
        message = '계좌확인필요' if error else ''
    return {'accountNumber': body['acnoS12_originalValue'], 'balanceDisplay': body['acJanS18'],
        'balance': body['orglAcJanN18'], 'paymentAvailableBalanceDisplay': body['jiUseAmtN182'],
        'paymentAvailableBalance': body['jiUseAmtN182_originalValue'],
        'isErrorDuringInspection': body['chkMdErrYn'] == 'Y', 'isError': error,
        'isOpenBankingError': body['isOpenbankingError'] == 1,
        'isOpenbankingNotAvailable': body['isOpenbankingNotAvailable'] == 1,
        'isMaintananceError': body['isMaintainanceError'] == 1,
        'balanceErrorMessage': message, 'balanceErrorMessageDescription': body['errorDescription'],
        'balanceErrorMessageNew': body['nspErrorMessage'], 'orgCode': str(body['bnkCN3']),
        'currency': '', 'refKey': '', 'turn': body['tbnkTrnNoS3'],
        'buttonList': [{'buttonName': button['btnNmS100'],
                       'programLink': {'programId': button['pgmLink']['pgmId'], 'param': button['pgmLink']['param']}}
                      for button in body['btnList']]}
