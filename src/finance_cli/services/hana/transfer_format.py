"""Pure Python port of the public web bundle's transfer formatting functions.

Covers string_utils.replaceSpecialCharChg, account-utils toAcctNo/toKEBAcctNo,
money.makeComma, date-utils.formatDate and the sign-form builder of the transfer
screen. Values are JSON as the bundle receives it: None is null/absent, and
numbers, booleans, lists and dicts follow JavaScript coercion. Inputs whose
JavaScript behavior is not reproduced raise ValueError instead of a guess.
"""
from decimal import Decimal
import re

WHITESPACE = ('\t\n\x0b\x0c\r \xa0          '
              '      　﻿')
COMMA = re.compile(r'\B(?=(?:[0-9]{3})+(?![0-9]))', re.ASCII)
FLOAT_PREFIX = re.compile(r'[+-]?(?:Infinity|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)')
ENTITIES = (('&divide;', '÷'), ('&times;', '×'), ('&pound;', '£'), ('&euro;', '€'), ('&cent;', '¢'),
            ('&yen;', '¥'), ('&bull;', '•'), ('&curren;', '¤'), ('&iquest;', '¿'), ('&iexcl;', '¡'),
            ('&deg;', '°'))
ENTITIES_AFTER = (('&middot;', '·'), ('&rsquo;', '’'), ('&lsquo;', '‘'), ('&ldquo;', '“'), ('&rdquo;', '”'))
ACCOUNT, NATIONAL_TAX, CONTACT = '01', '02', '03'


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_empty(value):
    """oqf-sc dt: null, blank string, or an empty array/object."""
    if value is None:
        return True
    if isinstance(value, (list, dict)):
        return not value
    return isinstance(value, str) and not value.strip(WHITESPACE)


def truthy(value):
    if value is None or value is False:
        return False
    if number(value):
        return value != 0 and value == value
    if isinstance(value, str):
        return bool(value)
    return True


def number_text(value):
    """Number.prototype.toString for a JSON number."""
    try:
        value = float(value)
    except OverflowError:
        value = float('inf') if value > 0 else float('-inf')
    if value != value:
        return 'NaN'
    if value == 0:
        return '0'
    if abs(value) == float('inf'):
        return 'Infinity' if value > 0 else '-Infinity'
    _, raw, exponent = Decimal(repr(abs(value))).as_tuple()
    point = len(raw) + exponent
    digits = ''.join(map(str, raw)).rstrip('0')
    count = len(digits)
    if count <= point <= 21:
        text = digits + '0' * (point - count)
    elif 0 < point <= 21:
        text = digits[:point] + '.' + digits[point:]
    elif -6 < point <= 0:
        text = '0.' + '0' * -point + digits
    else:
        power = point - 1
        text = digits[0] + ('.' + digits[1:] if count > 1 else '') + 'e' + ('+' if power >= 0 else '-') + str(abs(power))
    return ('-' if value < 0 else '') + text


def text_of(value):
    """JavaScript ToString for a value that is not null."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if number(value):
        return number_text(value)
    if isinstance(value, list):
        return ','.join('' if item is None else text_of(item) for item in value)
    return '[object Object]'


def float_prefix(text):
    """parseFloat: the finite numeric prefix, or None when NaN or infinite."""
    found = FLOAT_PREFIX.match(text.lstrip(WHITESPACE))
    if found is None:
        return None
    try:
        result = float(found.group().replace('Infinity', 'inf'))
    except ValueError:
        return None
    return result if abs(result) != float('inf') else None


def make_comma(value):
    """money.makeComma(value) with the decimal-places argument undefined."""
    if not (number(value) and value == 0) and not truthy(value):
        return ''
    if isinstance(value, str) and float_prefix(value) is None:
        return value
    parts = text_of(value).split('.')
    whole = COMMA.sub(',', parts[0])
    return whole + '.' + parts[1] if len(parts) > 1 and parts[1] else whole


def units(text):
    data = text.encode('utf-16-le', 'surrogatepass')
    return ''.join(chr(int.from_bytes(data[i:i + 2], 'little')) for i in range(0, len(data), 2))


def joined(text, *cuts):
    """UTF-16 substring pieces of an account number joined by dashes."""
    pieces = units(text)
    return '-'.join(pieces[a:b] for a, b in cuts).encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')


def account_value(value):
    if isinstance(value, (list, dict)):
        raise ValueError('unsupported_account_value')
    return value


def to_keb_acct_no(value):
    if value is None:
        return ''
    if not isinstance(account_value(value), str):
        return value
    size = len(units(value))
    if size == 14:
        return joined(value, (0, 3), (3, 9), (9, 14))
    if size == 12:
        return joined(value, (0, 3), (3, 9), (9, 12))
    if size == 11:
        return joined(value, (0, 3), (3, 5), (5, 10), (10, 11))
    return value


def loosely_equal(value, text):
    """JavaScript value == text for a numeric string literal."""
    if isinstance(value, str):
        return value == text
    return number(value) and value == int(text)


def to_acct_no(value, bank):
    if value is None:
        return ''
    account_value(value)
    if isinstance(bank, (list, dict)):
        raise ValueError('unsupported_bank_code')
    if is_empty(bank) or loosely_equal(bank, '081') or loosely_equal(bank, '81'):
        if not isinstance(value, str):
            return value
        size = len(units(value))
        if size == 14:
            return joined(value, (0, 3), (3, 9), (9, 14))
        if size == 12:
            return joined(value, (0, 3), (3, 9), (9, 12))
        return to_keb_acct_no(value) if size == 11 else value
    if loosely_equal(bank, '005') or loosely_equal(bank, '5'):
        return to_keb_acct_no(value)
    return value


def mark(value):
    """string_utils.replaceSpecialCharChg."""
    if not isinstance(value, str):
        raise ValueError('string_required')
    for entity, character in ENTITIES:
        value = value.replace(entity, character)
    value = re.sub('&#39|&#39;', "'", value)
    for entity, character in ENTITIES_AFTER:
        value = value.replace(entity, character)
    return value


def format_date(value, separator='-'):
    """date-utils.formatDate."""
    if not truthy(value):
        return ''
    separator = separator or '-'
    digits = re.sub('[^0-9]', '', text_of(value))
    date = [digits[:4], digits[4:6], digits[6:8]]
    if len(digits) == 6:
        return separator.join(date[:2])
    if len(digits) == 8:
        return separator.join(date)
    if len(digits) == 14:
        return separator.join(date) + ' ' + ':'.join((digits[8:10], digits[10:12], digits[12:14]))
    if len(digits) == 12:
        return separator.join(date) + ' ' + ':'.join((digits[8:10], digits[10:12]))
    return ''


def form(row):
    """Ordered sign-form entries of the transfer screen's newForm for one transaction."""
    if not isinstance(row, dict):
        raise ValueError('row_object_required')

    def get(key, default=''):
        value = row.get(key)
        return default if value is None else value

    def entry(name, signid, value):
        return {'name': name, 'signid': signid, 'value': value}

    kind = row.get('trnsTgb')
    items = []
    if kind == ACCOUNT:
        if not is_empty(row.get('trnsScheTm')):
            items.append(entry('trnsScheDt', '이체예정일시',
                               format_date(get('trnsScheDt'), '-') + ' ' + text_of(row['trnsScheTm']) + '시'))
        items += [
            entry('wdrwAcctNo', '출금계좌번호', to_acct_no(get('wdrwAcctNo'), row.get('wdrwBnkCd'))),
            entry('rcvBnkCd', '입금은행코드', get('rcvBnkCd')),
            entry('rcvAcctNo', '입금계좌번호', to_acct_no(get('rcvAcctNo'), row.get('rcvBnkCd'))),
            entry('trnsAmt', '이체금액', make_comma(get('trnsAmt', 0))),
            entry('rduAfComm', '수수료', make_comma(get('rduAfComm', 0))),
            entry('rcvPsbkMarkCtt', '받는분에게표기', get('rcvPsbkMarkCtt')),
            entry('wdrwPsbkMarkCtt', '나에게표기', get('wdrwPsbkMarkCtt')),
            entry('rmteNm', '수취인명', get('rmteNm')),
            entry('rmtrNm', '송금인명', get('rmtrNm')),
            entry('cshbUseYn', '하나머니사용여부', get('cshbUseYn')),
            entry('cshbUseAmt', '하나머니사용금액', '' if is_empty(row.get('cshbUseAmt')) else text_of(row['cshbUseAmt'])),
            entry('slctDvCd', 'CMS코드/모집인코드', get('slctDvCd'))]
        if row.get('mmdaHoldYn') == 'Y':
            items += [entry('mmdaIntPaymCd', 'MMDA이자지급코드', get('mmdaIntPaymCd')),
                      entry('mmdaIntRcvAcctNo', 'MMDA이자입금계좌번호', get('mmdaIntRcvAcctNo'))]
    elif kind == CONTACT:
        items += [
            entry('rmteTelNo', '연락처', get('rmteTelNo')),
            entry('wdrwAcctNo', '출금계좌번호', to_acct_no(get('wdrwAcctNo'), row.get('wdrwBnkCd'))),
            entry('trnsAmt', '이체금액', make_comma(get('trnsAmt', 0))),
            entry('rcvPsbkMarkCtt', '받는분에게표기', get('rcvPsbkMarkCtt')),
            entry('wdrwPsbkMarkCtt', '나에게표기', get('wdrwPsbkMarkCtt')),
            entry('rmteNm', '수취인명', get('rmteNm')),
            entry('rmtrNm', '송금인명', get('rmtrNm'))]
    elif kind == NATIONAL_TAX:
        items += [
            entry('today', '등록일자', ''),
            entry('levyInstNm', '청구기관명', get('levyInstNm')),
            entry('custNm', '납부자명', ''),
            entry('BnkCd', '납부은행', '하나'),
            entry('fnncStdElecPayNo', '계좌번호', get('fnncInpElecPayNo')),
            entry('rmndPayAmt', '납부금액', make_comma(get('trnsAmt', 0)))]
    else:
        raise ValueError('unsupported_transaction_type')
    return items
