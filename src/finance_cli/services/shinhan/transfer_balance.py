"""Transfer withdrawal balance and limited-account state transitions."""
from . import balance_protocol, transfer_selection

LIMIT_TRANSACTION = 'RSMDE0105A11'
LIMIT_ENDPOINT = '/serviceEndpoint/httpDigital/'
LIMIT = {'dayJiHdamt': ('double', 0.0)}


def limit_request(account):
    if not isinstance(account, str):
        raise ValueError('transfer_limit_input')
    # Repository input is preserved; the screen normalizes before this call.
    return {'acno': account}


def parse_limit(reply):
    return transfer_selection.parse_reply(reply, LIMIT, 'transfer_limit_body_unavailable')


def limit_amount(body):
    return transfer_selection.narrow(body['dayJiHdamt'])


def apply_limit(account, amount=None):
    # DataResult.Error restores the model default. It is not a bank-approved
    # limit and must never be used as authorization to send that amount.
    return {**account, 'limit': transfer_selection.LONG_MAX if amount is None else amount}


def initial_balance(account, value):
    # A successful repository result can carry an account-level error.
    # Only the selected field changes, including preservation of stale display
    # and error text on a later successful balance response.
    if value['isError']:
        return {**account, 'balanceErrorMessage': value['balanceErrorMessage']}, 'error'
    return {**account, 'withdrawalPossibleAmount': value['paymentAvailableBalance']}, 'success'


def list_items(accounts, usage='ALL'):
    if usage not in ('ALL', 'SHINHAN'):
        raise ValueError('transfer_withdrawal_usage')
    return [{'account': transfer_selection.withdrawal_model(account),
             'balance_status': 'loading' if usage == 'ALL' and not account['isShinhan'] else 'idle'}
            for account in accounts if usage == 'ALL' or account['isShinhan']]


def balance_request(account):
    return balance_protocol.request(account['accountNumber'], account['bankCode'], account['bankClassification'])


def update_item(items, index, value=None):
    # DataResult.Error and a typed account-level error both update just this
    # row's view state. Matching uses the list index, not the account number.
    success = value is not None and not value['isError']
    result = list(items)
    if 0 <= index < len(result):
        account = dict(result[index]['account'])
        if success:
            amount = value['paymentAvailableBalance']
            account.update(withdrawalPossibleAmount=amount, withdrawalPossibleAmountDisplay=format(amount, ',')+'원')
        result[index] = {'account': account, 'balance_status': 'success' if success else 'error'}
    return result
