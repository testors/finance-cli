"""Corporate accounts and transaction history, with opaque continuation data."""
import calendar
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation
import re

from finance_cli.services.hana.onesign_io import send_http
from . import operations as op, protocol

TABS = {'withdrawal': ('00', 'outRec01'), 'deposits': ('01', 'outRec01'),
        'fund': ('02', 'outRec02'), 'loans': ('03', 'outRec03'), 'foreign': ('04', 'outRec05'),
        'payroll': ('05', 'outRec07'), 'favorites': ('99', 'outRec99')}
ACCOUNT_FIELDS = ('ACCT_NO', 'ACCT_SEQ_NO', 'ACCT_TYP_CD', 'ACCT_TYPE_CD', 'ACCT_ALNM', 'PRD_NM', 'SUBJ_NM',
                  'BAL', 'PRS_BAL', 'BF_ACCT_NO', 'TRF_BF_ACCT_NO', 'CUR_CD', 'TRSC_SPNS_YN',
                  'FUND_ASES_AMT', 'TRUS_CAMT', 'LON_LIM_AMT')
HISTORY_FIELDS = ('TRSC_DT', 'TRSC_TM', 'TRSC_PROC_TM', 'TRSC_SEQ_NO', 'DTLS_SEQ_NO', 'AMT_TYP_CD',
                  'BAL_FLCT_DV_CD', 'TRSC_AMT', 'PAYM_AMT', 'TRSC_AF_BAL', 'NW_SUMM_PSBK_RMRK',
                  'DLVY_SNTC_CTT1', 'RMRK', 'MEMO_CTT', 'CUR_CD', 'TRSC_SPCL_MTTR',
                  'PAYM_AMT_CTT', 'RCV_AMT_CTT', 'TRSC_AF_BAL_CTT', 'TRSC_KIND_CD_NM',
                  'COMM_AMT', 'LN_DPS_TRSC_KIND_NM', 'ORGN_INT', 'RPAY_AMT')


def account_number(value):
    protocol.require(isinstance(value, str), 'account_required')
    value = value.replace('-', '').replace(' ', '')
    protocol.require(re.fullmatch(r'[0-9]{1,20}', value) is not None, 'invalid_account')
    return value


def kind(account):
    suffix = account[-2:]
    if suffix in ('13', '14', '36'):
        return 'fund'
    if suffix in ('30', '31', '32', '33', '34', '38'):
        return 'foreign'
    if suffix in tuple(str(n) for n in range(40, 50)):
        return 'loan'
    return 'krw'


def accounts(*, category='withdrawal', session=None, send=False, exchange=send_http):
    output = op.result('accounts', send)
    if not send:
        return output
    with op.operation(output, session, exchange=exchange) as client:
        if client is None:
            return output
        protocol.require(category in TABS or category == 'all', 'invalid_account_category')
        categories = list(TABS)[:6] if category == 'all' else [category]
        output.update(accounts=[], categories=[], complete=False)
        for selected in categories:
            tab, field = TABS[selected]
            data = client.request('accounts', {'tabType': tab}, attempt_name='accounts-' + tab,
                                  observe=op.observe(output))
            rows = data.get(field)
            output['categories'].append({'category': selected, 'received': isinstance(rows, list)})
            if not isinstance(rows, list):
                op.warning(output, 'account_list_unavailable')
                continue
            clean = []
            for row in rows:
                if isinstance(row, dict):
                    item = op.pick(row, ACCOUNT_FIELDS)
                    item['category'] = selected
                    clean.append(item)
                else:
                    op.warning(output, 'account_row_unavailable')
            output['accounts'].extend(clean)
            client.saved.setdefault('accounts', {})[selected] = clean
        op.save(client)
        output['complete'] = all(r['received'] for r in output['categories']) and len(output['categories']) == len(categories)
    return output


def parse_date(value):
    protocol.require(isinstance(value, str) and re.fullmatch(r'\d{4}-?\d{2}-?\d{2}', value) is not None,
                     'invalid_history_date')
    try:
        text = value.replace('-', '')
        return date(int(text[:4]), int(text[4:6]), int(text[6:]))
    except ValueError:
        raise protocol.Stop('invalid_history_date') from None


def storage_boundaries(today):
    recent = today.replace(year=today.year - 2, day=min(today.day, calendar.monthrange(today.year - 2, today.month)[1]))
    old = date(today.year - 3, today.month, 1) + timedelta(days=today.day - 1)
    return recent, old.replace(day=1)


def periods(start, end, today, history_kind, order):
    first, last = parse_date(start), parse_date(end)
    protocol.require(first <= last and (last - first).days <= 365, 'history_period_must_be_within_one_year')
    if history_kind in ('fund', 'loan'):
        return [(first.strftime('%Y%m%d'), last.strftime('%Y%m%d'), 'N')]
    boundary, split = storage_boundaries(today)
    past = 'N' if first >= boundary and last >= boundary else 'Y'
    ranges = [(first, split - timedelta(days=1)), (split, last)] if first < split <= last else [(first, last)]
    if order == 'latest':
        ranges.reverse()
    return [(a.strftime('%Y%m%d'), b.strftime('%Y%m%d'), past) for a, b in ranges]


def history_body(history_kind, account, sequence, currency, start, end, past, direction='', order='latest',
                 search_type='', search='', cursor=None):
    c = cursor or {}
    page = c.get('PAGE_NO', 1)
    reverse = 'Y' if order == 'latest' else 'N'
    body = {'ACCT_NO': account, 'ACCT_SEQ_NO': sequence, 'CUR_CD': currency,
            'RCV_WDRW_DV_CD': direction, 'INQ_STR_DT': start, 'INQ_END_DT': end, 'RV_SEQ_INQ_YN': reverse,
            'INQ_RQRE_NCNT': 100, 'FAST_INQ_YN': 'N' if history_kind == 'krw' else '', 'PAGE_NO': page,
            'TRSC_SEQ_NO': c.get('TRSC_SEQ_NO', 0), 'DTLS_SEQ_NO': c.get('DTLS_SEQ_NO', 0),
            'PAST_TRSC_YN': past, 'NEXT_TRSC_YN': '' if page == 1 else 'Y'}
    if page != 1:
        body['WDRW_DSTN_DT'] = c.get('WDRW_DSTN_DT', '')
    if history_kind == 'krw':
        body.update(CUR_CD='KRW', TRSC_PTCL_SRCH_DV_CD=search_type, SRCH_STRN_CTT=search)
    elif history_kind == 'foreign':
        body['LN_DPS_TRSC_KIND_DTLS_CD'] = '0007'
    elif history_kind == 'fund':
        body = {'FUND_TRSC_KIND_DTLS_CD': '0007', 'FUND_ACCT_NO': account, 'RQST_NCNT': 100, 'PAGE_NO': page,
                'INQ_STR_DT': start, 'INQ_END_DT': end, 'RCV_WDRW_DV_CD': direction,
                'TRSC_DETL_PTCL_INQ_DV_CD': {'': '1', '1': '3', '2': '4'}[direction],
                'RV_SEQ_INQ_YN': reverse, 'TRSC_SEQ_INQ_DV_CD': '2' if reverse == 'Y' else '1',
                'CNTN_TRSC_DAT': c.get('CNTN_TRSC_DAT', '')}
    elif history_kind == 'loan':
        body = {'ACCT_NO': account, 'ACCT_SEQ_NO': sequence, 'RCV_WDRW_DV_CD': '', 'INQ_RQRE_NCNT': 100,
                'PAGE_NO': page, 'INQ_STR_DT': start, 'INQ_END_DT': end, 'RV_SEQ_INQ_YN': reverse,
                'SRCH_STRN_CTT': search, 'CNTN_TRSC_DAT': c.get('CNTN_TRSC_DAT', ''), 'LN_DPS_TRSC_KIND_DTLS_CD1': '0050'}
    return body


def number(value):
    try:
        return Decimal(str(value or 0))
    except InvalidOperation:
        return Decimal('NaN')


def history_page(data, history_kind, past, page):
    if history_kind == 'fund':
        nested, key, count_key = 'ciq0016Output', 'BIZ.CIQ0016.OUT.REC', 'REC_CNT'
    elif history_kind == 'loan':
        nested, key, count_key = 'cln0003Output', 'BIZ.CLN0003.OUT.REC', 'REC_NCNT'
    elif past == 'Y':
        nested, key, count_key = 'ciq0104Output', 'BIZ.CIQ0104.OUT.REC', None
    else:
        nested, key, count_key = 'ciq0015Output', 'BIZ.SIQ0001.OUT.REC1', None
    container = data.get(nested)
    protocol.require(isinstance(container, dict), 'history_data_unavailable')
    count = container.get(count_key) if count_key else data.get('REC_CNT')
    # A zero record count is an empty result, not a bank rejection.
    n = number(count)
    has_rows = (count not in (None, '', 0)) if history_kind == 'loan' else (not n.is_nan() and n > 0)
    rows = container.get(key, []) if has_rows else []
    protocol.require(isinstance(rows, list), 'history_rows_unavailable')
    result = []
    for row in rows:
        protocol.require(isinstance(row, dict), 'history_row_unavailable')
        clean = op.pick(row, HISTORY_FIELDS)
        if history_kind in ('krw', 'foreign') and past == 'Y':
            incoming, outgoing = number(row.get('TRSC_AMT')), number(row.get('PAYM_AMT'))
            direction = '1' if incoming != 0 else '2' if outgoing != 0 else '0'
            clean['display'] = {'BAL_FLCT_DV_CD': direction,
                                'TRSC_AMT': row.get('PAYM_AMT') if direction == '2' else row.get('TRSC_AMT'),
                                'NW_SUMM_PSBK_RMRK': row.get('DLVY_SNTC_CTT1')}
        result.append(clean)
    cursor = None
    if has_rows and data.get('nextTrscYn') == 'Y':
        cursor = {'PAGE_NO': page + 1}
        if history_kind in ('fund', 'loan'):
            cursor['CNTN_TRSC_DAT'] = data.get('cntnTrscDat', '')
        else:
            cursor.update(TRSC_SEQ_NO=data.get('trscSeqNo'), DTLS_SEQ_NO=data.get('dtlsSeqNo'),
                          WDRW_DSTN_DT=data.get('wdrwDstnDt'))
    return result, cursor, not has_rows and data.get('nextTrscYn') == 'Y'


def history(account, *, start=None, end=None, direction='', order='latest', search_type='', search='',
            currency=None, sequence=None, session=None, send=False, exchange=send_http):
    output = op.result('history', send)
    if not send:
        return output
    with op.operation(output, session, exchange=exchange) as client:
        if client is None:
            return output
        account = account_number(account)
        history_kind = kind(account)
        protocol.require(direction in ('', '1', '2') and order in ('latest', 'oldest'), 'invalid_history_filter')
        protocol.require(search_type in ('', '04', '03', '05', '02') and (not search_type or search), 'invalid_history_search')
        protocol.require(history_kind == 'krw' or not search_type, 'search_not_supported_for_account_type')
        protocol.require(history_kind != 'loan' or direction == '', 'loan_direction_not_supported')
        # Validate supplied dates before sending; defaults and storage boundaries use bank time.
        if start is not None:
            parse_date(start)
        if end is not None:
            parse_date(end)
        clock = op.current_time(client)
        today = parse_date(clock.get('date'))
        start = start or (today - timedelta(days=6)).strftime('%Y%m%d')
        end = end or today.strftime('%Y%m%d')
        ranges = periods(start, end, today, history_kind, order)
        output.update(account=account, account_type=history_kind, transactions=[], pages=[], complete=False)
        if history_kind == 'loan':
            if sequence is None:
                choices = client.request('loan-sequences', {'param1': 'nbankbook', 'lnDpsTrscKindDtlsCd1': '0062',
                    'inqRqreNcnt': 15, 'acctNoStrObj': account}).get('rec')
                sequence = choices[-1].get('ACCT_SEQ_NO', '') if isinstance(choices, list) and choices else ''
            currency = currency or ''
        else:
            info = client.request('account-info', {'acctNo': account}).get('outMap')
            protocol.require(isinstance(info, dict), 'account_info_unavailable')
            detail = info.get('ACCT_INFO') or {}
            sequence = sequence if sequence is not None else detail.get('accountSequntialNo') or ''
            selected_currency = currency
            currency = detail.get('currencyCode') or ''
            if history_kind == 'foreign' and account[-2:] == '38':
                currency = 'ALL'
            client.saved.setdefault('account_info', {})[account] = info
            if account[-2:] not in tuple(str(n) for n in range(50, 59)):
                foreign_fund = history_kind == 'fund' and currency not in ('', 'KRW')
                body = {'FUND_ACCT_NO': account} if foreign_fund else {'ACCT_NO': account, 'CUR_CD': currency}
                balance = client.request('fund-balance' if foreign_fund else 'balance', body)
                output['balance'] = op.pick(balance, ('PRS_BAL', 'CUR_CD'))
                currency = balance.get('CUR_CD', currency)
            try:
                client.request('customer-type')
            except protocol.Stop:
                op.warning(output, 'customer_type_unavailable')
            if history_kind == 'foreign' and account[-2:] == '38':
                values = client.request('currencies', {'ACCT_NO': account}).get('cfx0388Output', {})
                rows = values.get('BIZ.CFX0388.OUT.REC', [])
                output['currencies'] = [r.get('CUR_CD') for r in rows if isinstance(r, dict)]
            if selected_currency is not None:
                currency = '' if selected_currency.upper() == 'ALL' else selected_currency.upper()
        output.update(currency=currency, account_sequence=sequence)
        seen = set()
        for index, (first, last, past) in enumerate(ranges):
            cursor = None
            while True:
                body = history_body(history_kind, account, sequence, currency, first, last, past, direction, order, search_type, search, cursor)
                page = body['PAGE_NO']
                data = client.request('history-' + history_kind, body, attempt_name=f'history-{index}-{page}', observe=op.observe(output))
                rows, following, stalled = history_page(data, history_kind, past, page)
                output['transactions'].extend(rows)
                output['pages'].append({'start': first, 'end': last, 'page': page, 'received': len(rows), 'past': past})
                if history_kind == 'loan' and rows and number(sequence) != 0:
                    try:
                        detail = client.request('loan-detail', {'LN_DPS_TRSC_KIND_DTLS_CD1': '0003',
                            'ACCT_NO': account, 'ACCT_SEQ_NO': sequence}, attempt_name=f'loan-detail-{index}-{page}')
                        output['loan'] = op.pick(detail.get('ciq0011Output') or {},
                            ('NEW_DT', 'EXPI_DT', 'LON_LIM_AMT', 'PRS_BAL', 'NEXT_INT_PAYT_DT', 'APCL_IRRT', 'curCd'))
                    except protocol.Stop:
                        op.warning(output, 'loan_detail_unavailable')
                if stalled:
                    op.warning(output, 'empty_page_with_continuation')
                    return output
                if following is None:
                    break
                marker = (index, repr({k: v for k, v in following.items() if k != 'PAGE_NO'}))
                if marker in seen:
                    op.warning(output, 'repeated_history_cursor')
                    return output
                seen.add(marker)
                cursor = following
        output['complete'] = True
        op.save(client)
    return output
