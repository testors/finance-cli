"""Personal loan history and existing certificate queries; no issuance or delivery."""
from functools import cmp_to_key
import math

from . import ledger_protocol as dates
from .compat import truthy

BASE = '/api/pcm/slct01/capi/'
PATHS = {
    **{k: dates.PATHS[k] for k in ('clock', 'account', 'loan-account')},
    'loan-accounts': BASE + 'lonTrscPtclInq/retrieveLonIntList',
    'executions': BASE + 'lonTrscPtclInq/retrieveLonExecNo',
    'page': BASE + 'lonTrscPtclInq/retrievetxnLon',
    'interest': BASE + 'lonTrscPtclInq/retrievedtlLonInt',
    'certificates': BASE + 'cersIssuApcMgnt/retrievetxnCersIssuApc',
    'link': BASE + 'docOffrSysItf/retrieveProcRslt',
}
CERTIFICATES = {'financial': ('1', '금융거래확인서', '05'), 'debt': ('2', '부채증명원', '03')}


def period(reference, start=None, end=None, *, certificates=False):
    end = end or reference
    start = start or dates.add_date(reference, months=-3 if certificates else -6, days=1)
    for value in (reference, start, end):
        dates.date(value)
    if start > end or end > reference or start < '19000101':
        raise ValueError('invalid_query_period')
    if certificates and start < dates.add_date(end, months=-3):
        raise ValueError('certificate_query_period_exceeds_three_months')
    return {'inqStrDt': start, 'inqEndDt': end}


def account_request(selected):
    body = {'acctNo': selected['acctNo']}
    if truthy(selected.get('acctSeqNo')):
        return 'loan-account', {**body, 'acctSeqNo': selected['acctSeqNo']}
    return 'account', body


def execution_number(info):
    value = info.get('accountSequentialNo')
    result = dates.number('1' if value is None else value)
    if not math.isfinite(result):
        raise ValueError('loan_execution_number_unavailable')
    return result


def page_body(account, execution, query_period):
    return {'acctNo': account, 'acctSeqNo': execution, **query_period, 'inqRqreNcnt': 20,
            'pageNo': 1, 'wdrwDstnDt': '', 'trscSeqNo': '0', 'dtlsSeqNo': '0', 'nextTrscYn': ''}


def cursor(value):
    if value.get('nextTrscYn1') != 'Y':
        return None
    # Missing JS properties are omitted by JSON.stringify; null dates remain null.
    result = {'nextTrscYn': 'Y'}
    if 'nextTrscDt1' in value:
        result['wdrwDstnDt'] = value['nextTrscDt1']
    for target, source in (('trscSeqNo', 'trscSeqNo1'), ('dtlsSeqNo', 'dtlsSeqNo1')):
        if value.get(source) is not None:
            result[target] = js_string(value[source])
    return result


def next_body(first, value):
    next_cursor = cursor(value)
    if next_cursor is None:
        return None
    # A missing cursor property is omitted, not inherited from the initial page.
    return {**{k: v for k, v in first.items() if k not in
              ('wdrwDstnDt', 'trscSeqNo', 'dtlsSeqNo', 'nextTrscYn')}, **next_cursor}


def js_string(value):
    if isinstance(value, list):
        return ','.join('' if item is None else js_string(item) for item in value)
    if isinstance(value, dict):
        return '[object Object]'
    if type(value) is float and value.is_integer():
        return str(int(value))
    return dates.js_string(value)


def rows(value, key):
    result = value.get(key)
    if result is None:
        return []
    if not isinstance(result, list) or any(not isinstance(row, dict) for row in result):
        raise ValueError('query_rows_unavailable')
    return result


def strict_equal(a, b):
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return a is b
    if type(a) in (int, float) and type(b) in (int, float):
        return a == b
    return type(a) is type(b) and a == b


def interest_body(page, row):
    if row.get('lnDpsTrscKindCd') not in ('211', '221'):
        return None
    return {**{k: page[k] for k in ('acctNo', 'acctSeqNo') if k in page},
            **{k: row['trscDt'] for k in ('inqStrDt', 'inqEndDt') if 'trscDt' in row},
            'inqRqreNcnt': '100', 'lnDpsTrscKindDtlsCd1': '0017', 'nextInqStrRowNo': '0'}


def interest_rows(value, row):
    return [item for item in rows(value, 'gridId') if strict_equal(
        item.get('trscSeqNo', dates.MISSING), row.get('trscSeqNo', dates.MISSING))]


def certificate_body(kind, query_period):
    code, label, _ = CERTIFICATES[kind]
    return {**query_period, 'srchDvCd': code, 'srchDvNm': label}


def js_add(a, b):
    a = js_string(a) if isinstance(a, (dict, list)) else a
    b = js_string(b) if isinstance(b, (dict, list)) else b
    if isinstance(a, str) or isinstance(b, str):
        return js_string(a) + js_string(b)
    return dates.number(a) + dates.number(b)


def certificate_rows(value):
    # Optional result/array -> []; counts are display metadata, never a gate.
    groups = [(value or {}).get(key) or {} for key in ('rslt1', 'rslt2')]
    result = [row for group in groups for row in rows(group, 'sub1')]

    def compare(a, b):
        def timestamp(row):
            return dates.number(js_add(row.get('apcDt', dates.MISSING), row.get('apcTm', dates.MISSING)))
        delta = timestamp(b) - timestamp(a)
        return 0 if math.isnan(delta) or delta == 0 else 1 if delta > 0 else -1

    return sorted(result, key=cmp_to_key(compare))


def link_body(row):
    if row.get('vcertDvCd') not in ('05', '03'):
        raise ValueError('unsupported_certificate_type')
    return {k: row[k] for k in ('vcertDvCd', 'issuRqstNo', 'apcDt', 'apcTm') if k in row}


def certificate_count(value):
    counts = [(value.get(key) or {}).get('gridId1Rowcount') for key in ('rslt1', 'rslt2')]
    return js_add(*(0 if item is None else item for item in counts))


def loan_summary(info, page):
    rate = page.get('apclIrrt1')
    display_rate = rate if truthy(rate) else info.get('irrt') if truthy(info.get('irrt')) else 0
    return {'principal': page.get('newTrscAmt1'), 'balance': info.get('acctBal'),
            'rate': rate, 'account_rate': info.get('irrt'), 'display_rate': display_rate,
            'execution_date': info.get('lonExecDt'), 'expiry_date': info.get('expiDt'),
            'history_start_date': page.get('newDt1'), 'contract_period': None,
            'currency': info.get('curCd'), 'product_name': info.get('prdNm')}


def transaction(row):
    return {target: row.get(source) for target, source in (
        ('date', 'trscDt'), ('sequence', 'trscSeqNo'), ('type_code', 'lnDpsTrscKindCd'),
        ('type', 'lnDpsTrscKindNm'), ('repayment', 'rpayAmt'), ('interest', 'orgnInt'),
        ('fee', 'commAmt'), ('balance', 'trscAfBal'))}
