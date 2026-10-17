"""Shinhan transaction history query, response and explicit page consumption."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import re
from zoneinfo import ZoneInfo

from . import account_protocol, transport

MIN_AMOUNT, MAX_AMOUNT = -(2**63), 2**63-1
TRANSACTION = 'RSMDE0105A20'
ENDPOINT = '/serviceEndpoint/httpDigital/'


class Reader(account_protocol.Reader):
    def value(self, kind):
        if kind != 'long' or self.peek() == 'n':
            return super().value(kind)
        value, _ = self.token()
        if not re.fullmatch(r'-?[0-9]+(?:[eE][+-]?[0-9]+)?', value):
            raise ValueError('history_long')
        number = Decimal(value)
        if not number.is_finite() or not MIN_AMOUNT <= number <= MAX_AMOUNT or number != number.to_integral_value():
            raise ValueError('history_long_range')
        return int(number)


ROW = account_protocol.strings('trxdt trxTime trxJkyoS6 trxJkyoS6_display jiamt ipamt trxCmmtCtntS24 jan trxBrNmS20 fil100Ctnt2 yndIpBnkC_display yndOppAcNo atmYn corrCancelYn')
ROW.update({name: ('double', 0.0) for name in ('jiamt_originalValue', 'ipamt_originalValue', 'jan_originalValue')})
ROW.update({name: ('int', 0) for name in ('ipjiG', 'trxno', 'subTrxnoL10')})
BODY = dict(rstCL1=('int', 0), nxtTrxnoL10=('int', 0), nxtSubTrxnoL10=('long', 0),
            masJan=('string', ''), jibulPsbJan=('string', ''), grd12=([ROW], []))


def decode(text, schema=BODY):
    reader = Reader(text)
    value = reader.value(schema)
    if reader.peek() or value is None:
        raise ValueError('history_json_document')
    return value


def parse_reply(reply):
    # A malformed success body is a local processing problem, not bank FAIL.
    try:
        text = reply.body.decode('utf-8-sig')
        document = decode(text, {'dataHeader': (account_protocol.HEADER, None)})
    except (ValueError, UnicodeError, RecursionError):
        return transport.parse(reply)
    verdict, _ = transport.parse(transport.Reply(reply.status, reply.headers, json.dumps(document).encode(), reply.error))
    if verdict['bank_result'] == 'success':
        try:
            document = decode(text, {'dataHeader': (account_protocol.HEADER, None), 'dataBody': (BODY, None)})
            if document['dataBody'] is None:
                raise ValueError('history_body_null')
        except (ValueError, ArithmeticError, RecursionError):
            verdict.update(processing_status='incomplete', error='history_body_unavailable')
            document['dataBody'] = None
    return verdict, document


@dataclass(frozen=True, repr=False)
class Query:
    account: str
    start: str = ''
    end: str = ''
    bank_class: int = 1
    transaction_type: str = 'DEFAULT'
    print_count: int = 100
    sort: str = 'LATEST_ORDER'
    min_amount: int = MIN_AMOUNT
    max_amount: int = MAX_AMOUNT
    keyword: str = ''

    def __post_init__(self):
        if not all(isinstance(value, str) for value in (self.account, self.start, self.end, self.keyword)):
            raise ValueError('history_string_input')
        if self.transaction_type not in ('DEFAULT', 'DEPOSIT', 'WITHDRAWAL', 'SHINHAN_ATM') or self.sort not in ('PAST_ORDER', 'LATEST_ORDER'):
            raise ValueError('history_filter_input')
        for value, bits in ((self.bank_class, 32), (self.print_count, 32), (self.min_amount, 64), (self.max_amount, 64)):
            if type(value) is not int or not -(2**(bits-1)) <= value < 2**(bits-1):
                raise ValueError('history_integer_input')

    def filters(self):
        amount = (self.min_amount, self.max_amount) != (MIN_AMOUNT, MAX_AMOUNT)
        direction = 0 if self.transaction_type == 'DEPOSIT' else 1 if self.transaction_type == 'WITHDRAWAL' else 2
        detail = 9 if self.keyword else 3 if direction < 2 else 1 if amount else 0
        inquiry = ((15, 16, 14) if amount else (12, 13, 11)) if self.keyword else ((11, 12, 0) if amount else (1, 2, 0))
        business = 2 if self.keyword or self.transaction_type != 'DEFAULT' or amount else 1
        return detail, business, inquiry[direction], self.transaction_type == 'SHINHAN_ATM'


def date_time(date, time, on_error=None):
    # SimpleDateFormat accepts overflows and trailing text. Date parsing errors
    # produce zero; a failure in the error observer itself must propagate.
    match = re.match(r'[ \t]*(-?\d+)\.[ \t]*(-?\d+)\.[ \t]*(-?\d+) [ \t]*(-?\d+):[ \t]*(-?\d+):[ \t]*(-?\d+)', date+' '+time)
    if match is None:
        if on_error is not None:
            on_error()
        return 0
    year, month, day, hour, minute, second = map(int, match.groups())
    year_delta, month = divmod(month-1, 12)
    # Calendar dates outside datetime's range and pre-1900 timezone/calendar
    # rules are not established. Do not silently convert them to a false zero.
    try:
        local = datetime(year+year_delta, month+1, 1) + timedelta(days=day-1, hours=hour, minutes=minute, seconds=second)
    except (ValueError, OverflowError) as exc:
        raise ValueError('history_date_range_unverified') from exc
    if local.year < 1900:
        raise ValueError('history_date_range_unverified')
    # On an overlap, Calendar chooses the later offset; on a gap it normalizes
    # forward using the offset before the transition.
    # The Java timezone table starts at 1900-01-01 UTC. Before its first
    # local overlap ends it uses the zone's raw +09:00 offset.
    zone = timezone(timedelta(hours=9)) if local < datetime(1900, 1, 1, 8, 27, 52) else ZoneInfo('Asia/Seoul')
    first, second = local.replace(tzinfo=zone), local.replace(tzinfo=zone, fold=1)
    aware = second if second.utcoffset() < first.utcoffset() else first
    delta = aware.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days*86400+delta.seconds)*1000


def rows(body, on_date_error=None):
    result = []
    for item in body['grd12']:
        deposit = item['ipjiG'] == 1
        result.append({'dateTime': date_time(item['trxdt'], item['trxTime'], on_date_error),
            'description': {'first': item['trxJkyoS6'], 'second': item['trxJkyoS6_display']},
            'transactionType': 'DEPOSIT' if deposit else 'WITHDRAWAL',
            'amount': item['ipamt_originalValue' if deposit else 'jiamt_originalValue'],
            'balance': item['jan_originalValue'], 'title': item['trxCmmtCtntS24'],
            'branchName': item['trxBrNmS20'], 'isCancelled': item['corrCancelYn'] == 'Y',
            'transactionNumber': item['trxno'], 'subTransactionNumber': item['subTrxnoL10'],
            'memo': item['fil100Ctnt2'], 'isAtm': item['atmYn'] == 'Y'})
    return result


@dataclass(repr=False)
class Cursor:
    transaction: int = 0
    subtransaction: int = 0
    has_next: bool = False

    def request(self, query):
        detail, business, inquiry, _ = query.filters()
        return {'acno': query.account, 'bnkG': query.bank_class, 'inqrSjdt': query.start,
                'inqrEndt': query.end, 'prntCntN8': query.print_count, 'procGL1': 0,
                'sortGL1': int(query.sort == 'LATEST_ORDER'), 'dtlAmt1N12': query.min_amount,
                'dtlAmt2N12': query.max_amount, 'sttGN1': int(self.has_next),
                'trxno': self.transaction, 'subTrxnoL10': self.subtransaction,
                'dtlGL1': detail, 'trxGL2': inquiry, 'cmsNo': query.keyword, 'upmuG': business}

    def page(self, query, body, key=None, on_date_error=None):
        if body is None:
            raise ValueError('history_body_null')
        info = {'accountBalance': body['masJan'], 'withdrawableAmount': body['jibulPsbJan'],
                'transactionType': 'DEFAULT', 'amount': 0.0, 'balance': 0.0, 'branchName': '',
                'dateTime': 0, 'description': {'first': '', 'second': ''}, 'isCancelled': False, 'title': ''}
        data = rows(body, on_date_error)
        if query.transaction_type == 'SHINHAN_ATM':
            data = [item for item in data if item['isAtm']]
        self.transaction, self.subtransaction = body['nxtTrxnoL10'], body['nxtSubTrxnoL10']
        self.has_next = body['rstCL1'] == 2
        key = 1 if key is None else key
        def int32(value):
            return (value+2**31) % 2**32-2**31
        return {'data': [info, *data], 'prevKey': None if key == 1 else int32(key-1),
                'nextKey': int32(key+1) if self.has_next else None,
                'itemsBefore': -(2**31), 'itemsAfter': -(2**31)}
