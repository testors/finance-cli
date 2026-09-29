"""Single ordinary KRW transfer preparation contract."""
from .evidence import account, amount, nonblank
from .onesign_crypto import require
OUR_CODES = {'5','05','005','81','081','025','033','082'}

def numeric(value, code):
    result = amount(value)
    require(result is not None, code)
    return result

def bank_equal(left, right):
    return left == right or (left in OUR_CODES and right in OUR_CODES)

def transaction_row(ctx, stage, payload):
    items = payload.get('trnsList')
    require(isinstance(items,list) and len(items)==1 and isinstance(items[0],dict),'single_transaction_required')
    row, intent = items[0], ctx['intent']
    require(account(row.get('wdrwAcctNo')) == ctx['source'],'returned_source_mismatch')
    require(row.get('wdrwBnkCd')=='081','returned_withdrawal_bank_mismatch')
    require(bank_equal(row.get('rcvBnkCd'),intent['recipient_bank_code']),'returned_bank_mismatch')
    aliases = {intent['recipient_account_number']}
    if stage != 'pretransaction':
        original = ctx['data']['pretransaction']['trnsList'][0]
        aliases.update(account(original.get(k)) for k in ('rcvAcctNo','nwAcctNo'))
    require(account(row.get('rcvAcctNo')) in aliases,'returned_recipient_mismatch')
    require(account(row.get('rcvAcctNo')) != ctx['source'] or intent['recipient_bank_code'] not in OUR_CODES,
            'returned_recipient_is_source')
    require(numeric(row.get('trnsAmt'),'returned_amount') == intent['amount_krw'],'returned_amount_mismatch')
    # transfer.types exports ACCOUNT as wire value "01", not its enum name.
    require(row.get('trnsTgb') == '01','unexpected_transaction_type')
    require(row.get('acctTgb') != 'SAVE_HOUS','housing_account_unsupported')
    # The original app diverts these Hana foreign-currency account tails.
    if row.get('rcvBnkCd') == '081':
        new_number=account(row.get('nwAcctNo'))
        if new_number:
            require(new_number[-2:] not in ('31','32','33','34','38','63'),'foreign_currency_recipient_unsupported')
    require(not row.get('trnsScheDt') and not row.get('trnsScheTm'),'scheduled_transfer_unsupported')
    require(row.get('openBankYn') in (None,'','N'),'openbank_unsupported')
    for container in (row,payload):
        for flag in ('rsvTrnsYn','dlayTrnsYn','mmsTrnsYn'):
            require(container.get(flag) in (None,'','N'),'non_immediate_transfer_flag')
    require(row.get('cshbUseYn') in (None,'','N') and row.get('cshbUseAmt') in (None,'',0,'0'),
            'hana_money_use_unsupported')
    require(nonblank(row.get('rmteNm')) and nonblank(row.get('rmtrNm')),'missing_party_names')
    fee = numeric(row.get('rduAfComm'),'missing_fee')
    total = numeric(payload.get('totlTrnsAmt'),'missing_total')
    require(total == intent['amount_krw'] + fee,'total_fee_mismatch')
    require(total <= numeric(ctx['withdrawal']['payBal'],'available_balance'),'insufficient_available_balance')
    require(nonblank(payload.get('tmsgUnqNo13')),'missing_prepared_id')
    if stage == 'additional_info':
        before = ctx['data']['pretransaction']['trnsList'][0]
        require(fee == amount(before['rduAfComm']),'fee_changed')
        require(all(row.get(k) == before.get(k) for k in ('rmteNm','rmtrNm','rcvBnkCd','rcvAcctNo')),
                'party_changed_during_preparation')
        req = ctx['receipts']['additional_info']['request']['body']
        require(all(row.get(k,'') == req[k] for k in ('rcvPsbkMarkCtt','wdrwPsbkMarkCtt','slctDvCd')),
                'saved_display_values_changed')
    return row
