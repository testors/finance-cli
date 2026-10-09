"""Personal multi-account KRW transfers from one withdrawal account (1–15 rows)."""
import base64
import csv
from datetime import datetime
from pathlib import Path
import re
from zoneinfo import ZoneInfo

from . import onesign_crypto as pin, onesign_compat as compat, nfilter_crypto
from . import onesign_transfer as transfer, onesign_transfer_protocol as protocol, transfer_format as fmt
from .evidence import account, amount, identifiers

SCREEN = 'TRNB0201002001'
PATHS = {
    'recipient': '/api/pcm/trns01/capi/pluAcctTrnsTrsc/retrievePluAcctTrnsOwac',
    'multi_pretransaction': '/api/pcm/trns01/capi/pluAcctTrnsTrsc/executePluAcctTrnsRsevTrsc',
}
REQUIRED = {'to_bank', 'to_account', 'amount'}
OPTIONAL = {'employee', 'credit_memo', 'debit_memo', 'cms_code'}


def checked_items(items):
    pin.require(isinstance(items, list) and 1 <= len(items) <= 15, 'multi_transfer_requires_1_to_15_rows')
    result = []
    for item in items:
        pin.require(isinstance(item, dict) and REQUIRED <= item.keys() <= REQUIRED | OPTIONAL,
                    'invalid_batch_row')
        pin.require(all(isinstance(v, str) for v in item.values()), 'invalid_batch_row')
        bank, recipient, raw_amount = (item[k].strip() for k in ('to_bank', 'to_account', 'amount'))
        pin.require(re.fullmatch('[0-9]{3}', bank) is not None, 'recipient_bank_code_format')
        recipient = account(recipient)
        pin.require(recipient is not None, 'transfer_account_format')
        pin.require(re.fullmatch('[0-9]{1,10}', raw_amount) is not None and 0 < int(raw_amount) <= 9999999999,
                    'multi_transfer_amount_out_of_range')
        credit, debit, cms = (item.get(k, '') for k in ('credit_memo', 'debit_memo', 'cms_code'))
        pin.require(len(fmt.units(credit)) <= (20 if bank in protocol.OUR_CODES else 10)
                    and len(fmt.units(debit)) <= 30, 'transfer_memo_too_long')
        pin.require(not any(ord(c) < 32 or ord(c) == 127 for c in credit + debit), 'invalid_transfer_memo')
        pin.require(re.fullmatch('[0-9a-zA-Z-]{0,20}', cms) is not None, 'invalid_cms_code')
        result.append({'to_bank': bank, 'to_account': recipient, 'amount': str(int(raw_amount)),
                       'credit_memo': credit, 'debit_memo': debit, 'cms_code': cms.upper()})
    return result


def read_items(path):
    try:
        with Path(path).open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream, strict=True)
            headers = reader.fieldnames or []
            pin.require(len(headers) == len(set(headers)) and REQUIRED <= set(headers) <= REQUIRED | OPTIONAL,
                        'invalid_batch_columns')
            return checked_items(list(reader))
    except (OSError, UnicodeError, csv.Error):
        raise pin.ProtocolError('batch_file_unreadable') from None


def summary(items):
    seen, duplicates = set(), []
    for index, item in enumerate(items, 1):
        key = (item['to_bank'], item['to_account'], item['amount'])
        if key in seen:
            duplicates.append(index)
        seen.add(key)
    return {'item_count': len(items), 'amount_krw': sum(int(i['amount']) for i in items),
            'duplicate_rows': duplicates}


def check(path):
    return {**summary(read_items(path)), 'bank_verified': False, 'transfer_sent': False,
            'network_used': False, 'processing_status': 'completed'}


def preparation_body(ctx, item, owner, index):
    w = ctx['withdrawal']
    return {'chnlSvcCd': 'A16', 'paymAcctNo': ctx['source'], 'paymAcctNm': w.get('acctNm', ''),
            'rcvBnkCd': item['to_bank'], 'rcvAcctNo': item['to_account'],
            'paytSqn': 1 if item['to_bank'] in protocol.OUR_CODES else 0, 'trnsAmt': int(item['amount']),
            'wdrwSeqNo': protocol.numeric(w['wdrwAcctSeqNo'], 'withdrawal_sequence'),
            'wdrwBnkCd': w['bnkCd'], 'wdrwBnkNm': w.get('bnkNm', ''), 'trnsNo': index,
            'svcDvCd': 'ACCT_TRNS', 'rcvPsbkMarkCtt': item['credit_memo'] or owner.get('rcvPsbkMarkCtt', ''),
            'wdrwPsbkMarkCtt': item['debit_memo'] or owner.get('wdrwPsbkMarkCtt', ''), 'spclMttr': '',
            'slctDvCd': item['cms_code'], 'mmdaHoldYn': 'N', 'sessTrnsInfoIntzYn': 'Y' if index == 1 else 'N'}


def forms(rows):
    # Multi-account signing uses "0" for absent Hana Money amounts.
    result = []
    for row in rows:
        form = fmt.form(dict(row, trnsTgb='01', mmdaHoldYn='N', trnsScheDt='', trnsScheTm=''))
        form[10]['value'] = fmt.text_of(0 if row.get('cshbUseAmt') is None else row['cshbUseAmt'])
        result.append(form)
    return result


def preview(ctx):
    value = ctx['data']['prepared']
    rows = [{'row': i, 'source_account': r.get('wdrwAcctNo'), 'recipient_bank_code': r.get('rcvBnkCd'),
             'recipient_account': r.get('rcvAcctNo'), 'recipient_name': r.get('rmteNm'),
             'amount_krw': amount(r.get('trnsAmt')), 'fee_krw': amount(r.get('rduAfComm')),
             'credit_memo': r.get('rcvPsbkMarkCtt'), 'debit_memo': r.get('wdrwPsbkMarkCtt'),
             'cms_code': r.get('slctDvCd')} for i, r in enumerate(value['trnsList'], 1)]
    amounts, fees = [r['amount_krw'] for r in rows], [r['fee_krw'] for r in rows]
    return {'transaction': ctx['name'], 'mode': 'multi', 'source_account': ctx['source'], 'items': rows,
            'item_count': len(rows), 'amount_krw': sum(amounts) if all(v is not None for v in amounts) else None,
            'fee_krw': sum(fees) if all(v is not None for v in fees) else None,
            'total_krw': amount(value.get('totlTrnsAmt')), 'input_summary': summary(ctx['intent']['items']),
            'warnings': ctx['warnings'], 'authentication': ctx.get('route'), 'state': ctx['state']}


def check_limits(items, owners, recent, withdrawal):
    total = sum(int(i['amount']) for i in items)
    balance = amount(withdrawal.get('payBal'))
    pin.require(balance is None or total <= balance, 'insufficient_available_balance')
    other = [int(i['amount']) for i, owner in zip(items, owners) if owner.get('rcvAcctSefYn') != 'Y']
    once, daily, used = (amount(recent.get(k)) for k in ('bot1TrnsLimAmt', 'dd1TrnsLimAmt', 'tdyTrnsAmt'))
    pin.require(once is None or all(v <= once for v in other), 'per_transfer_limit_exceeded')
    pin.require(daily is None or sum(other) <= daily, 'daily_transfer_limit_exceeded')
    pin.require(daily is None or used is None or sum(other) <= daily - used, 'remaining_daily_limit_exceeded')


def prepare(state, client, transaction, intent, password):
    pin.require(isinstance(intent, dict) and set(intent) == {'source_account', 'items'}, 'transfer_intent_fields')
    source, items = account(intent['source_account']), checked_items(intent['items'])
    pin.require(source is not None, 'transfer_account_format')
    for item in items:
        pin.require(item['to_account'] != source or item['to_bank'] not in protocol.OUR_CODES, 'same_source_recipient')
    bound = transfer.binding(state, client.session)
    with state.transaction() as value:
        pin.require(transaction not in value['transfers'], 'transfer_already_exists')
        saved = value['sessions'][client.session]
        pin.require(not saved.get('transfer_attempted'), 'use_new_session_for_next_transfer')
        saved['transfer_attempted'] = True
        ctx = {'name': transaction, 'mode': 'multi', 'binding': bound, 'source': source,
               'intent': {'source_account': source, 'items': items}, 'cfg': {'kind': 'other', 'onesign': True},
               'state': 'preparing', 'data': {}, 'receipts': {}, 'warnings': [], 'prepared_items': 0}
        value['transfers'][transaction] = ctx

    def save():
        with state.transaction() as value:
            value['transfers'][transaction] = ctx

    def call(stage, body, key=None):
        result = transfer.request(client, stage, body, multi=True)
        ctx['data'][key or stage] = result
        ctx['receipts'][key or stage] = {'request': {'body': body}}
        save()
        return result

    response = call('withdrawal', {'menuId': SCREEN, 'opbkAcctMarkYn': 'Y', 'wdrwAcctMarkYn': 'Y',
        'wdrwPossAmtMarkYn': 'Y', 'inqMthdDv': '1', 'opbkBnkCd': '', 'opbkAcctNo': '', 'opbkInqMthdDv': 'Y'})
    rows = [r for r in response.get('ourAcctList', []) if isinstance(r, dict) and account(r.get('acctNo')) == source]
    pin.require(len(rows) == 1, 'withdrawal_not_unique')
    w = ctx['withdrawal'] = rows[0]
    pin.require(w.get('bnkCd') == '081' and w.get('openYn') != 'Y'
                and not w.get('meetSeqNo') and not w.get('meetSacApcNo'), 'ordinary_hana_account_required')
    body = dict.fromkeys(('lginYn', 'custInfoYn', 'custInfoAdtnYn', 'lginTmpAllYn', 'allAcctPrdYn',
                         'allAcctOpbkYn', 'allAcctRtpnsYn', 'allAcctMyDatYn', 'exhgRtYn', 'usrAthtMap'), 'N')
    body.update(allAcctPrdYn='Y', lginTmpList=[])
    value = call('session_accounts', body)
    pin.require(value.get('allAcctListDto', {}).get('accountMap', {}).get(source, {}).get('mmdaHoldYn') != 'Y',
                'mmda_account_unsupported')
    recent = call('recent_accounts', {})
    owners = []
    for index, item in enumerate(items, 1):
        owner = call('recipient', {'rcvBnkCd': item['to_bank'], 'rcvAcctNo': item['to_account'],
            'trscDvCd': '2', 'wthrNm': w.get('rmteNm', ''), 'trnsAmt': int(item['amount'])}, 'recipient-' + str(index))
        pin.require(fmt.is_empty(owner.get('errCd')), 'recipient_lookup_rejected')
        owners.append(owner)
    check_limits(items, owners, recent, w)
    for index, (item, owner) in enumerate(zip(items, owners), 1):
        value = call('multi_pretransaction', preparation_body(ctx, item, owner, index), 'prepare-' + str(index))
        rows = [r for r in value.get('trnsList', []) if r.get('delYn') == 'N' and r.get('saveYn') == 'Y']
        pin.require(not rows or rows[0].get('errCd') != 'OCOM06367', 'account_password_reregistration_required')
        if value.get('dupTrnsYn') == 'Y':
            ctx['warnings'].append('bank_duplicate_transfer_row_' + str(index))
        ctx['prepared_items'] = index
        save()
    pin.require(bool(rows), 'prepared_rows_unavailable')
    pin.require(not any(not fmt.is_empty(r.get('errCd')) and not fmt.is_empty(r.get('errMsg')) for r in rows),
                'batch_preparation_row_error')
    pin.require(not any(r.get('acctTgb') == 'SAVE_HOUS' for r in rows), 'housing_account_unsupported')
    pin.require(not any(r.get('rcvBnkCd') == '081' and str(r.get('nwAcctNo', ''))[-2:]
                        in ('31', '32', '33', '34', '38', '63') for r in rows), 'foreign_currency_recipient_unsupported')
    pin.require(not any(r.get('fncFrdDgnsNcsyYn') == 'Y' for r in rows), 'fraud_diagnosis_required')
    ctx['data']['prepared'] = dict(value, trnsList=rows)
    # Differences are visible for confirmation; they do not negate the bank's preparation verdict.
    if len(rows) != len(items):
        ctx['warnings'].append('bank_confirmation_count_differs')
    for index, (r, item) in enumerate(zip(rows, items), 1):
        if (account(r.get('wdrwAcctNo')) != source or not protocol.bank_equal(r.get('rcvBnkCd'), item['to_bank'])
                or account(r.get('rcvAcctNo')) != item['to_account'] or amount(r.get('trnsAmt')) != int(item['amount'])):
            ctx['warnings'].append('bank_confirmation_differs_row_' + str(index))
    if summary(items)['duplicate_rows']:
        ctx['warnings'].append('duplicate_rows_in_input')
    ctx['cfg']['kind'] = 'self' if value.get('rcvAcctSefYn') == 'Y' else 'other'
    save()
    if ctx['cfg']['kind'] == 'self':
        ctx.update(route={'candidate': True, 'sign_required': False, 'reason': 'server_self_account_branch'}, state='prepared')
    else:
        public = call('keypad_key', None)['apiRlseKey']
        secret = password()
        try:
            pin.require(isinstance(secret, str) and re.fullmatch('[0-9]{4}', secret) is not None, 'account_password_four_digits_required')
            cipher = nfilter_crypto.encrypt_numeric_password(public, secret, base64.b64decode(state.snapshot()['settings']['keypad_mac']))
        finally:
            del secret
        call('password', {'typCd': '1', 'acctNo': source, 'trnsAmt': value['totlTrnsAmt'], 'acctSvcCd': 'ACCT_TRNS', 'acctPw': cipher})
        response = call('auth_means', {'certDv': 'transfer', 'addCertUncsYn': 'N', 'scrtCrdSeqNoMarkYn': 'N',
            'ofclCertsUseYn': recent.get('cmCertsYn', ''), 'dtlsDv': '', 'scrtMdclMarkYn': '', 'easnCertYn': '',
            'faceCertUsePossMachYn': 'N', 'sefCnfmAddMdclDv': ''})
        ctx['route'] = pin.assess_transfer_auth(response, state.snapshot()['sessions'][client.session]['login_response'])
        ctx['state'] = 'prepared' if ctx['route']['candidate'] else 'authentication_review'
    save()
    return {**preview(ctx), 'transfer_sent': False, 'accepted': True}


def observe_execution(raw):
    value = compat.web_value(raw)
    value = value if isinstance(value, dict) else {}
    rows = value.get('trnsList')
    items = []
    for index, row in enumerate(rows if isinstance(rows, list) else [], 1):
        success = (fmt.is_empty(row.get('errMsg')) and row.get('chnlTrscStCd') != '06') if isinstance(row, dict) else None
        items.append({'row': index, 'original_result_success': success,
                      'status': 'completed' if success is True else 'error' if success is False else 'unconfirmed'})
    count = value.get('errNcnt')
    all_success = type(count) in (int, float) and count == 0
    counts = [value.get(k) for k in ('cpltNcnt', 'prgrNcnt', 'errNcnt')]
    completed, progress, errors = (amount(int(v) if type(v) is float and v.is_integer() else v) for v in counts)
    any_success = all_success or any(r['original_result_success'] is True for r in items) or (completed or 0) + (progress or 0) > 0
    any_error = (errors or 0) > 0 or any(r['original_result_success'] is False for r in items)
    all_error = (bool(items) and all(r['original_result_success'] is False for r in items)) or (
        (errors or 0) > 0 and completed == 0 and progress == 0)
    status = 'partial' if any_success and any_error else 'completed' if all_success else 'failed' if all_error else 'unconfirmed'
    return {'execution_result': {'accepted': True if any_success else False if all_error else None,
        'original_result_success': all_success if value else None, 'transfer_status': status,
        'partial_success': any_success and any_error, 'items': items,
        'completed_count': completed, 'progress_count': progress, 'error_count': errors,
        'transfer_sent': True, 'transfer_confirmed': False, 'next': 'reconcile', 'automatic_retry': False}}


def reconcile(state, client, transaction):
    ctx = state.snapshot()['transfers'][transaction]
    pin.require(ctx.get('execution_attempted'), 'no_execution_to_reconcile')
    pin.require(ctx['binding'] == transfer.binding(state, client.session), 'transfer_binding_changed')
    pin.require(not ctx.get('reconcile_attempted'), 'reconciliation_already_attempted')
    with state.transaction() as data:
        data['transfers'][transaction]['reconcile_attempted'] = True
    date = datetime.fromtimestamp(ctx['execution_started_ms'] / 1000, ZoneInfo('Asia/Seoul')).strftime('%Y%m%d')
    history = transfer.request(client, 'history', {'rqstNcnt': '20', 'strPost': '1', 'trnsRsltBizDvCd': '', 'trnsInqDvCd': '',
        'wdrwAcctNo': ctx['source'], 'inqBascStrDt': date, 'inqBascEndDt': date, 'srchDvCd': '0', 'srchWdNm': '', 'trscSeqInqDvCd': '2'}, multi=True)
    rows = history.get('rec') if isinstance(history, dict) else None
    pin.require(isinstance(rows, list), 'history_rows_unavailable')
    prepared = ctx['data']['prepared']['trnsList']
    result = {'items': [], 'candidate_complete': False, 'transfer_confirmed': False,
              'execution_result': ctx.get('execution_result'), 'automatic_retry': False, 'history_page_size': 20}
    details = []

    def matches(row, expected):
        return (isinstance(row, dict) and row.get('trscStNm') == '완료'
                and protocol.bank_equal(row.get('rcvBnkCd'), expected.get('rcvBnkCd'))
                and account(row.get('rcvAcctNo')) == account(expected.get('rcvAcctNo'))
                and amount(row.get('trscAmt')) == amount(expected.get('trnsAmt'))
                and row.get('wdrwAcctNo') in (None, ctx['source']))

    for index, expected in enumerate(prepared, 1):
        candidates = [r for r in rows if matches(r, expected)]
        item = {'row': index, 'candidate_complete': False, 'match': 'missing_or_ambiguous'}
        result['items'].append(item)
        if (len(candidates) == 1 and identifiers(candidates[0]) is not None
                and sum(matches(candidates[0], other) for other in prepared) == 1):
            selected = identifiers(candidates[0])
            detail = transfer.request(client, 'detail', selected, multi=True)
            details.append(detail)
            dr = detail.get('rec') if isinstance(detail, dict) else None
            if (isinstance(dr, list) and len(dr) == 1 and matches(dr[0], expected)
                    and all(dr[0].get(k, v) == v for k, v in selected.items())):
                item.update(candidate_complete=True, match='account_amount_and_linked_detail')
        result['candidate_complete'] = all(i['candidate_complete'] for i in result['items']) and len(result['items']) == len(prepared)
        with state.transaction() as data:
            data['transfers'][transaction].update(reconciliation=result, history=history, detail=details)
    return result
