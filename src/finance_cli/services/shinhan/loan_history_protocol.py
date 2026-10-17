"""Installment loan ledger pages and a separate monthly interpretation."""
import calendar
from datetime import date
from decimal import Decimal
import math
import re

from . import web
from .additional_auth import js_text

TRANSACTION = 'RSMLO1002A01'
MISSING = object()


def period(year=None, start=None, end=None):
    if year is not None:
        if start is not None or end is not None:
            raise ValueError('loan_history_period_conflict')
        start, end = date(year, 1, 1).isoformat(), date(year, 12, 31).isoformat()
    if start is None or end is None:
        raise ValueError('loan_history_period_required')
    first, last = date.fromisoformat(start), date.fromisoformat(end)
    if first.isoformat() != start or last.isoformat() != end or first > last:
        raise ValueError('loan_history_period_invalid')
    return first.strftime('%Y%m%d'), last.strftime('%Y%m%d')


def request(account, start, end, cursor=MISSING):
    return {'trxGL3': '3', 'ysLotTrxG': '2', 'masS': '', 'nxtAcnoS12': '',
            'nxtExenoN7': '0', 'nxtTrxSnoN10': 0 if cursor is MISSING else cursor,
            'ysAcno': account, 'exeno': '0', 'kwaG': '', 'trxdt1': start, 'trxdt2': end}


def next_cursor(body):
    value = body if isinstance(body, dict) else {}
    flag, cursor = value.get('nextYnL1'), value.get('nxtTrxSnoN10')
    # Strict numeric 1, including 1.0 but excluding true and the string "1".
    if type(flag) in (int, float) and flag == 1 and web.truthy(cursor):
        return cursor
    return MISSING


def text(value):
    if isinstance(value, float) and math.isfinite(value):
        if value == 0:
            return '0'
        if 1e-6 <= abs(value) < 1e21:
            return format(Decimal(repr(value)), 'f').removesuffix('.0')
        return re.sub(r'e([+-])0+', r'e\1', repr(value)).replace('.0e', 'e')
    return 'undefined' if value is MISSING else js_text(value)


def property_key(value):
    return text(value)


def object_keys(value):
    # JS Object.entries visits array-index properties before other keys.
    numeric = [k for k in value if re.fullmatch(r'0|[1-9][0-9]*', k) and int(k) < 2**32-1]
    return sorted(numeric, key=int) + [k for k in value if k not in numeric]


def number(value):
    raw = value.replace(',', '').strip()
    if not raw:
        return 0.0
    try:
        return float(int(raw, 0)) if re.match(r'^0[xXbBoO]', raw) else float(raw)
    except ValueError:
        return math.nan


def format_sum(left, right):
    # The displayed interest sum follows JS Number and the amount formatter.
    # Raw bank amounts remain available separately for exact interpretation.
    value = number(left) + number(right)
    if not math.isfinite(value):
        return ''
    raw = text(value)
    whole, separator, fraction = raw.partition('.')
    digits = re.sub('[^0-9]', '', whole)
    grouped = re.sub(r'(?<=\d)(?=(\d{3})+$)', ',', digits)
    if separator:
        grouped += '.' + re.sub('[^0-9]', '', fraction)
    if grouped != '0' and grouped.startswith('0') and '.' not in grouped:
        grouped = re.sub('[^1-9]+', '', grouped, count=1)
    return ('-' if value < 0 else '') + grouped


def raw_rows(pages):
    for page in pages:
        # Missing/null grids and orphan interest rows are consumer errors,
        # not a bank rejection or an empty successful ledger.
        grid = page.get('grid04', MISSING) if isinstance(page, dict) else MISSING
        for row in grid if isinstance(grid, list) else [grid]:
            if row is None or row is MISSING:
                raise ValueError('loan_history_row_unavailable')
            yield row if isinstance(row, dict) else {}


def transactions(pages, order='OLDEST'):
    by_number = {}
    mapping = {'title': 'ysTrxKS20', 'amount': 'tramt', 'principalAmount': 'pramt',
               'interestAmount': 'intAmt', 'remainingAmount': 'trxafDcJan', 'date': 'trxdt'}
    for row in raw_rows(pages):
        key = property_key(row.get('trxSno', MISSING))
        if row.get('ysTrxKS20', MISSING) == '':
            item = {target: row[source] for target, source in
                    (('interestType', 'intKS20'), ('interestAmount', 'intAmt')) if source in row}
            item.update(interestPeriod=f"{text(row.get('sjdt', MISSING))} ~ {text(row.get('endt', MISSING))}",
                        interestRate=text(row.get('iyul', MISSING))+'%')
            parent = by_number[key]
            parent['interestAmount'] = format_sum(parent['interestAmount'], item['interestAmount'])
            parent.setdefault('interestList', []).append(item)
        else:
            by_number[key] = {target: row[source] for target, source in mapping.items() if source in row}
    by_date = {}
    for key in object_keys(by_number):
        row = by_number[key]
        by_date.setdefault(property_key(row.get('date', MISSING)), []).append(row)
    ordered = {key: by_date[key] for key in sorted(by_date, reverse=order != 'OLDEST')}
    return [[key, ordered[key]] for key in object_keys(ordered)]


def bank_date(value):
    if not isinstance(value, str):
        return None
    raw = value.replace('.', '').replace('-', '').strip()
    if not re.fullmatch('[0-9]{8}', raw):
        return None
    try:
        return date(int(raw[:4]), int(raw[4:6]), int(raw[6:]))
    except ValueError:
        return None


def monthly(pages, grouped, start, end, complete):
    """Group observed values without inventing opening balances or rate snapshots."""
    first, last = bank_date(start), bank_date(end)
    months = {}
    current = first.replace(day=1)
    while current <= last:
        key = current.strftime('%Y-%m')
        months[key] = {'month': key, 'transactions': [], 'interest_periods': [],
                       'month_end_balance': None, 'month_end_balance_status': 'unverified',
                       'month_end_rate': None, 'month_end_rate_status': 'not_provided'}
        current = date(current.year+1, 1, 1) if current.month == 12 else current.replace(month=current.month+1)
    dated = {}
    unassigned = 0
    for day, rows in grouped:
        parsed = bank_date(day)
        if parsed is not None:
            dated.setdefault(parsed, []).extend(rows)
            if parsed.strftime('%Y-%m') in months:
                months[parsed.strftime('%Y-%m')]['transactions'].extend(rows)
        else:
            unassigned += len(rows)
    # Rate segments belong to their accrual period, not just the payment month.
    for row in raw_rows(pages):
        if row.get('ysTrxKS20', MISSING) != '':
            continue
        a, b = bank_date(row.get('sjdt')), bank_date(row.get('endt'))
        if a is None or b is None:
            continue
        segment = {field: row[field] for field in ('trxSno', 'trxdt', 'intKS20', 'intAmt', 'sjdt', 'endt', 'iyul') if field in row}
        for key, month in months.items():
            m = date.fromisoformat(key+'-01')
            m_end = m.replace(day=calendar.monthrange(m.year, m.month)[1])
            if a <= m_end and b >= m:
                month['interest_periods'].append(segment)
    for key, month in months.items():
        m = date.fromisoformat(key+'-01')
        m_end = m.replace(day=calendar.monthrange(m.year, m.month)[1])
        observed = [(day, rows) for day, rows in dated.items() if first <= day <= m_end]
        if complete and not unassigned and last >= m_end and observed:
            day, rows = max(observed, key=lambda pair: pair[0])
            values = [r.get('remainingAmount') for r in rows]
            # Without a proven same-day sequence, differing balances are ambiguous.
            if values and values[0] not in (None, '') and all(v == values[0] for v in values):
                month.update(month_end_balance=values[0], month_end_balance_date=day.isoformat(),
                             month_end_balance_status='derived_from_last_transaction')
        # No principal repayment total: a ledger also contains disbursements,
        # corrections and other transaction types. Keep their original titles.
        month['transaction_count'] = len(month['transactions'])
        month['query_complete'] = complete
        month['unassigned_transaction_count'] = unassigned
    return list(months.values())
