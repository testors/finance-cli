"""Transfer entry and withdrawal-list contracts, before receiver inquiry."""
import unicodedata

from . import account_protocol, history_protocol

CHECK_TRANSACTION = 'RSMDE1402A02'
WITHDRAWAL_TRANSACTION = 'RSMDE1402B03'
ENDPOINT = '/serviceEndpoint/httpDigital/'
LONG_MIN, LONG_MAX = -(2**63), 2**63-1
LIMITS = {'bf1DdIcheHndoAmtN13': 'day', 'bfTn1IcheHndoAmtN13': 'once',
          'd1NujkIcheAmt': 'accumulated', 'remdrD1IcheHndoAmtN13': 'remain'}
CHECK = account_protocol.strings(' '.join(LIMITS)+' transferPrType jiPsbAmt jiAcNo acNm bnkC bnkNm bnkG shbBankYn handoLimitAcYn')
CHECK.update({name+'_originalValue': ('double', 0.0) for name in [*LIMITS, 'jiPsbAmt']})
WITHDRAWAL_ROW = account_protocol.strings('acNm jiAcnoS20 bnkNm bnkCS5 bnkG jiPsbAmt obnkYn hndoLimtAcYnL1')
WITHDRAWAL_ROW['jiPsbAmt_originalValue'] = ('double', 0.0)
WITHDRAWAL = {'grid01': ([WITHDRAWAL_ROW], [])}


def decode(text, schema=CHECK):
    return account_protocol.decode(text, schema)


def check_request(account=''):
    if not isinstance(account, str):
        raise ValueError('transfer_account_input')
    # Screen input normalization happens before the repository. Here the
    # supplied account, including an empty string, is sent unchanged.
    return {'srchNoS30': account}


def withdrawal_request():
    return {}


def parse_reply(reply, schema, body_error):
    verdict, document = history_protocol.parse_reply(reply, schema=schema, body_error=body_error)
    if verdict['bank_result'] == 'failure':
        # Typed decoding precedes the native FAIL-to-exception adapter. Keep
        # observed FAIL, but do not treat a malformed body as a mapped denial.
        try:
            document = history_protocol.decode(reply.body.decode('utf-8-sig'),
                {'dataHeader': (account_protocol.HEADER, None), 'dataBody': (schema, None)})
        except (ValueError, ArithmeticError, UnicodeError, RecursionError):
            verdict.update(processing_status='incomplete', error=body_error)
    return verdict, document


def parse_check(reply):
    verdict, document = parse_reply(reply, CHECK, 'transfer_check_body_unavailable')
    if verdict['bank_result'] == 'failure' and verdict['processing_status'] == 'complete':
        converted = entry_failure(document['dataHeader'].get('resultCode'))
        if converted['kind'] is not None:
            verdict.update(entry_error=converted['kind'], entry_program=converted['program'])
    return verdict, document


def parse_withdrawal(reply):
    return parse_reply(reply, WITHDRAWAL, 'transfer_withdrawal_body_unavailable')


def entry_failure(code):
    # Only call for an A02 ResponseResultFailException, not another endpoint
    # or a transport/decoding error carrying a superficially similar code.
    kind, program = {'MDE00001': ('LazyTransferException', 'CA0511S0011F01'),
                     'MDE00002': ('RegisteredDeviceException', 'CA0514S0011F01'),
                     'MDE00003': ('SafeTransactionException', None)}.get(code, (None, None))
    return {'kind': kind, 'program': program}


def narrow(value):
    # The typed JSON reader rejects nonfinite doubles. Java double-to-long
    # truncates finite fractions toward zero and saturates at either bound.
    return max(LONG_MIN, min(LONG_MAX, int(value)))


def initial(body):
    account = {'accountName': body['acNm'], 'accountNumber': body['jiAcNo'],
        'bankName': body['bnkNm'], 'bankCode': body['bnkC'], 'bankClassification': body['bnkG'],
        'withdrawalPossibleAmount': narrow(body['jiPsbAmt_originalValue']),
        'withdrawalPossibleAmountDisplay': body['jiPsbAmt'],
        'isShinhanBank': body['shbBankYn'] == 'Y', 'isLimitAccount': body['handoLimitAcYn'] == 'Y'}
    value = {name: [] for name in ('myAccountList', 'favoriteRecentAccountList', 'myMemoList',
                                  'receiverMemoList', 'bankList', 'securityList')}
    value.update(transferType=body['transferPrType'], withdrawalAccount=account,
        limit={name: {'long': narrow(body[wire+'_originalValue']), 'str': body[wire]} for wire, name in LIMITS.items()})
    return value


def withdrawals(body):
    return [{'accountName': row['acNm'], 'accountNumber': row['jiAcnoS20'],
        'bankName': row['bnkNm'], 'bankCode': row['bnkCS5'], 'bankClassification': row['bnkG'],
        'withdrawalPossibleAmount': narrow(row['jiPsbAmt_originalValue']),
        'withdrawalPossibleAmountDisplay': row['jiPsbAmt'],
        'isShinhan': row['obnkYn'] == 'Y', 'isLimitAccount': row['hndoLimtAcYnL1'] == 'Y'} for row in body['grid01']]


def model(account):
    # This model limit is an initial value, not the customer's bank limit.
    return {**account, 'limit': LONG_MAX, 'needInquiryAmount': not account['isShinhan'],
            'balanceErrorMessage': '', 'withdrawalPossibleForeignAmount': None, 'productCode': ''}


def initial_model(value):
    account = dict(value['withdrawalAccount'])
    account['isShinhan'] = account.pop('isShinhanBank')
    account['withdrawalPossibleAmountDisplay'] = ''
    return {'bridgeType': 'BackUp' if value['transferType'] == '2' else 'Native',
            'limit': {name: amount['long'] for name, amount in value['limit'].items()},
            'withdrawalAccount': model(account)}


def withdrawal_model(value, *, balance_error=False):
    result = model(value)
    display = value['withdrawalPossibleAmountDisplay']
    if all(ch in '\t\n\v\f\r\x1c\x1d\x1e\x1f' or unicodedata.category(ch) in ('Zs', 'Zl', 'Zp') for ch in display):
        display = format(value['withdrawalPossibleAmount'], ',')
    result['withdrawalPossibleAmountDisplay'] = display+'원'
    result['balanceErrorMessage'] = '계좌확인필요' if balance_error else ''
    return result


def bridge_program(value):
    return 'SM0901S0025F01' if value['bridgeType'] == 'BackUp' else ''
