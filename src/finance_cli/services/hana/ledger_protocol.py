"""Offline contract for the original SLCT Os (ordinary KRW) account ledger.

This is an account ledger, not the transfer-result evidence state machine.
The reference day is frozen from the original server-clock response.
"""
import calendar
from datetime import datetime, timedelta
import math

from .compat import truthy

PATHS = {
    'clock': '/public/pcm/etcs01/capi/dtInq/retrieveCurrDtm',
    'account': '/api/pcm/slct01/capi/acctInq/retrieveSessAcctInfo',
    'loan-account': '/api/pcm/slct01/capi/acctInq/retrieveLoanSessAcctInfo',
    'recent': '/api/pcm/slct01/capi/trscPtclInq/retrievetxnNrstTrsc',
    'past': '/api/pcm/slct01/capi/inoAmtTrscPtclInq/retrievetxnInoAmtPst',
    'compound': '/api/pcm/slct01/capi/trscPtclInq/retrievedtlCmpdTrsc',
    'automatic': '/api/pcm/slct01/capi/trscPtclInq/retrieveAtfInfo',
    'contact': '/api/pcm/slct01/capi/trscPtclMgnt/retrieveCtfcTrnsYn',
}
INOUT = {'01','02','04','05','07','08','50','51','52','53','54','57','58','60'}
SPECIAL_PRODUCTS = {
    '0200069000101','0270034000301','0200074000101','0200059000101','0200064000201',
    '0200057000101','0270033000101','0270044000101','0210094000101','0210094000201',
    '0210095000101','0210095000201','0100253000101','0200064000801','0200064000701',
    '0200072000101','0200021000201','0200021000301','0270028000101','0200070000101',
    '0210091000101','0210091000201','0210090000201','0271003000101','0271003000201','0271003000301',
}
MISSING = object()
JS_WHITESPACE = '\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff'


def nonempty(value):
    # oqf-sc ft/Ls: zero and false are NOT empty.
    return not (value is None or isinstance(value, str) and not value.strip(JS_WHITESPACE)
                or isinstance(value, (dict, list)) and not value)


def date(value):
    if not isinstance(value, str) or len(value) != 8 or not value.isascii() or not value.isdigit():
        raise ValueError('Expected yyyyMMdd')
    return datetime.strptime(value, '%Y%m%d').date()


def add_date(value, *, years=0, months=0, days=0):
    day = date(value)
    month_index = day.year * 12 + day.month - 1 + years * 12 + months
    year, month = divmod(month_index, 12)
    day = day.replace(year=year, month=month+1,
                      day=min(day.day, calendar.monthrange(year, month+1)[1]))
    return (day + timedelta(days=days)).strftime('%Y%m%d')


def account_screen(info):
    tail, biz = info.get('tailNo', ''), info.get('lnDpsBizDvCd', '')
    if info.get('componentType') == 'fund':
        return 'fund'
    if tail in INOUT or biz in ('3','4'):
        return ('special' if biz in ('3','4') or info.get('prdCd') in SPECIAL_PRODUCTS
                or tail == '52' and info.get('subjCd') in ('52','5M','5D','5E','5K') else 'inout')
    if tail in ('11','15','16','17','19','21','22','23','24','25','26','29'):
        return 'deposit'
    if tail in ('12','13','14','36'):
        return 'fund'
    if tail in ('41','42','43','44','45','46','47'):
        return 'loan'
    if tail in ('31','32','33','34','38'):
        return 'foreign'
    return 'inout'  # Original Cl fallback.


def plan(config, reference_day, account_number, *, local_day=None):
    start, end = config['start_date'], config['end_date']
    date(reference_day); date(start); date(end)
    # The popup checks the device day; Os uses server day for API routing.
    limit_day = local_day or reference_day
    if start < '19000101' or start > end or end > limit_day:
        raise ValueError('Invalid original date selection')
    if start <= add_date(end, years=-3):
        raise ValueError('Original Os query period must be less than three calendar years')
    direction, order, search = config.get('direction', 'all'), config.get('order', 'desc'), config.get('search', '')
    if direction not in ('all','deposit','withdrawal') or order not in ('desc','asc'):
        raise ValueError('Invalid ledger direction/order')
    if not isinstance(search, str) or len(search.encode('utf-16-le')) // 2 > 25:
        raise ValueError('Original search accepts up to 25 UTF-16 code units')
    boundary = add_date(reference_day, years=-2)
    recent_start = add_date(boundary, days=1)
    recent = {'inqEndDt': end, 'rvSeqInqYn': 'Y' if order == 'desc' else 'N',
              'rcvWdrwDvCd': {'all':'0','deposit':'1','withdrawal':'2'}[direction],
              'srchStrnCtt': search, 'acctNo': account_number, 'curCd': 'KRW',
              'inqStrDt': max(start, recent_start), 'dtlsSeqNo': 0, 'trscSeqNo': 0,
              'fastInqYn': 'N', 'wdrwDstnDt': '', 'nextTrscYn': '', 'inqRqreNcnt': 100,
              'trscPtclSrchDvCd': '99' if nonempty(search) else ''}
    past = {'inqStrDt': start, 'rowNcnt': 100, 'acctNo': account_number,
            'inqEndDt': min(end, boundary), 'pageNo': 1,
            'trscTypCd': {'all':'1','deposit':'2','withdrawal':'3'}[direction],
            'rmrk': search, 'trscAmt': 0, 'trscSpclMttr': '',
            'srtSeqDvCd': 'D' if order == 'desc' else 'A'}
    kinds = ['recent'] if start >= recent_start else ['past'] if end < recent_start else (
        ['recent','past'] if order == 'desc' else ['past','recent'])
    return {'reference_day': reference_day, 'boundary': recent_start, 'order': order,
            'segments': [{'kind': k, 'body': recent if k == 'recent' else past} for k in kinds]}


def number(value=MISSING):
    """JSON-domain JS Number, only for original cursors/count comparisons."""
    if value is MISSING:
        return math.nan
    if value is None:
        return 0
    if isinstance(value, (list, dict)):
        if isinstance(value, list):
            value = ','.join('' if v is None else str(v) for v in value)
        else:
            return math.nan
    if isinstance(value, str):
        value = value.strip(JS_WHITESPACE)
        if not value:
            return 0
        if value.lower().startswith(('0x','0b','0o')):
            try: return int(value, 0)
            except ValueError: return math.nan
    try:
        result = float(value)
        return int(result) if math.isfinite(result) and result.is_integer() else result
    except (ValueError, TypeError, OverflowError):
        return math.nan


def cursor(kind, payload):
    if kind == 'recent':
        if number(payload.get('recNcnt1', MISSING)) < 20 or payload.get('nextTrscYn1') != 'Y':
            return None
        return {'wdrwDstnDt': payload.get('nextTrscDt1') if truthy(payload.get('nextTrscDt1')) else '',
                'dtlsSeqNo': payload.get('dtlsSeqNo1') if truthy(payload.get('dtlsSeqNo1')) else 0,
                'trscSeqNo': number(payload.get('trscSeqNo1', MISSING)),
                'nextTrscYn': payload.get('nextTrscYn1') if truthy(payload.get('nextTrscYn1')) else ''}
    if kind == 'past':
        if number(payload.get('r01Rowcount', MISSING)) < 100:
            return None
        # Original returns response pageNo, never pageNo + 1.
        return {'pageNo': payload['pageNo']} if 'pageNo' in payload else {}
    raise ValueError('Not a ledger page')


def rows(kind, payload):
    key = 'grid1' if kind == 'recent' else 'r01'
    value = payload.get(key)
    if value is None:  # Original optional rows display an empty list.
        return []
    if not isinstance(value, list) or any(not isinstance(r, dict) for r in value):
        raise ValueError('Malformed ledger rows')
    return value


def diagnostics(kind, payload):
    result = []
    items = rows(kind, payload)
    key, count_key = ('grid1', 'recNcnt1') if kind == 'recent' else ('r01', 'r01Rowcount')
    if not isinstance(payload.get(key), list): result.append('rows_absent_or_null')
    count = number(payload.get(count_key, MISSING))
    if not math.isfinite(count): result.append('row_count_not_numeric')
    elif count != len(items): result.append('row_count_differs_from_array')
    return result


def detail_request(info, row):
    """Original Cn F→x/Y priority, including automatic, compound and contact."""
    if nonempty(row.get('atfMgntNo')) and row.get('balFlctDvCd') == '2':
        body = {'inqDvCd1':'001'}
        for target, source in [('trnsDt','trscDt'),('atfPrfRankCd','atfPrfRankCd'),
                               ('atfMgntNo','atfMgntNo'),('atfPrlProcNo','atfPrlProcNo'),
                               ('inpLedgSeqNo','inpLedgSeqNo')]:
            if source in row: body[target] = row[source]
        if row.get('atfPrfRankCd') == '315':
            if row.get('lnDpsTrscKindCd') == '301': body.update(wdrwAcctNo=info.get('acctNo'), rcvAcctNo='')
            elif row.get('lnDpsTrscKindCd') == '201': body.update(wdrwAcctNo='', rcvAcctNo=info.get('acctNo'))
        else:
            body['wdrwAcctNo'] = info.get('acctNo')
            if 'thrAcctNo' in row: body['rcvAcctNo'] = row['thrAcctNo']
        return 'automatic', body
    if row.get('amtTypCd') == 'ZN':
        return 'compound', {'acctNo': info.get('acctNo') or '',
                            'wdrwDstnDt': row.get('trscDt') if row.get('trscDt') is not None else '',
                            'acctSeqNo': info.get('acctSeqNo') if info.get('acctSeqNo') is not None else 0,
                            'trscSeqNo': row.get('trscSeqNo') if row.get('trscSeqNo') is not None else 0}
    if nonempty(row.get('globId')):
        return 'contact', {'echnlTrscUnqNo': row['globId'][:30]}
    return 'local', None


def display_row(row):
    """Fields used by the original list; raw row remains the authoritative copy."""
    movement, value, paid = row.get('balFlctDvCd'), row.get('trscAmt', MISSING), row.get('paymAmt', MISSING)
    is_zero = lambda v: type(v) in (int, float) and v == 0
    if truthy(movement):
        variation = 'none' if is_zero(value) else {'1':'increase','2':'decrease'}.get(movement, 'none')
    else:
        variation = 'increase' if not is_zero(value) else 'decrease' if not is_zero(paid) else 'none'
    label_field = 'dlvySntcCtt1' if nonempty(row.get('dlvySntcCtt1')) else 'nwSummPsbkRmrk'
    label = row.get(label_field)
    if row.get('thrBnkCd') not in ('','081') and row.get('amtTypCd') in ('KF92','57','58','M001'):
        label = f"{js_string(row.get(label_field, MISSING))}({js_string(row.get('thrBnkCdNm', MISSING))})"
    if row.get('bnksrTrnsyn') == 'Y':
        name = row.get('apltNm')
        if nonempty(row.get('trscSpclMttr')): name = js_string(row.get('apltNm', MISSING)) + js_string(row['trscSpclMttr'])
    else:
        name = row.get('rmrk') if nonempty(row.get('rmrk')) else row.get('trscSpclMttr')
    return {'date': row.get('trscDt'), 'time': row.get('trscTm'), 'type': label, 'name': name,
            'amount': row.get('paymAmt') if truthy(row.get('paymAmt')) else row.get('trscAmt'),
            'balance': row.get('trscAfBal'), 'currency': row.get('curCd'), 'variation': variation,
            'extra': row.get('trscSpclMttr') if nonempty(row.get('trscSpclMttr')) and nonempty(row.get('rmrk')) and row.get('nwSummPsbkRmrk') != '결제' else None,
            'memo': row.get('memoCtt') if row.get('memoCtt') is not None else ''}


def js_string(value):
    if value is MISSING: return 'undefined'
    if value is None: return 'null'
    if value is True: return 'true'
    if value is False: return 'false'
    return str(value)


def normalize_server_clock(value):
    """Native LocalDate yyyyMMdd and LocalTime HHmmss with the lenient (smart) resolver.

    The clock response requires dt, tm and bussDdYn. Day 31 is clamped to a
    shorter month and 24:00:00 is read as midnight, for the time only.
    """
    import re
    from finance_cli.core.errors import require
    day, time = value['dt'], value['tm']
    require(re.fullmatch('[0-9]{8}', day) is not None and re.fullmatch('[0-9]{6}', time) is not None,
            'server_clock_format')
    year, month, number_ = int(day[:4]), int(day[4:6]), int(day[6:])
    hour, minute, second = int(time[:2]), int(time[2:4]), int(time[4:])
    require(1 <= year <= 9999 and 1 <= month <= 12 and 1 <= number_ <= 31, 'server_date_invalid')
    number_ = min(number_, calendar.monthrange(year, month)[1])
    if hour == 24 and minute == second == 0:
        hour = 0
    require(0 <= hour < 24 and 0 <= minute < 60 and 0 <= second < 60, 'server_time_invalid')
    return {**value, 'dt': f'{year:04d}{month:02d}{number_:02d}', 'tm': f'{hour:02d}{minute:02d}{second:02d}'}
