"""Selected history destination parameters and the screen's initial period."""
import calendar
from datetime import date, datetime
import unicodedata
from zoneinfo import ZoneInfo

from giro import android_json
from .enrollment import Pending

PROGRAM = 'BM1509S0011F01'


def blank(value):
    return all(ch in '\t\n\v\f\r\x1c\x1d\x1e\x1f' or unicodedata.category(ch) in ('Zs', 'Zl', 'Zp') for ch in value)


def parameters(text):
    # Use the package's platform JSONObject codec, including optional string
    # coercion, nested P fallback and extended object syntax.
    value = android_json.parse_object(text)
    def opt(obj, name):
        if name not in obj.values:
            return ''
        result = android_json.java_text(obj.values[name])
        return '' if result is None else result
    def field(name):
        result = opt(value, name)
        nested = value.values.get('P')
        if blank(result):
            result = opt(nested, name) if isinstance(nested, android_json.JSONObject) else ''
        return result
    if not blank(opt(value, 'shortcutID')):
        raise Pending('history_shortcut_lookup_required')
    account = field('acnoS12').replace('-', '')
    if blank(account):
        raise Pending('history_account_parameters_required')
    asset = field('assetK')
    return {'acno': account, 'bnkCdS3': field('bnkCdS3'), 'assetK': '1' if blank(asset) else asset}


def period(start=None, end=None, *, now=None):
    if (start is None) != (end is None):
        raise ValueError('history_dates_required_together')
    if start is not None:
        values = [date.fromisoformat(value) for value in (start, end)]
        if any(value.isoformat() != raw for value, raw in zip(values, (start, end))):
            raise ValueError('history_date_format')
        return tuple(value.strftime('%Y.%m.%d') for value in values)
    clock = now or (lambda: datetime.now(ZoneInfo('Asia/Seoul')))
    first = clock().astimezone(ZoneInfo('Asia/Seoul')).date()
    year, month = divmod(first.year*12+first.month-1-3, 12)
    first = date(year, month+1, min(first.day, calendar.monthrange(year, month+1)[1]))
    last = clock().astimezone(ZoneInfo('Asia/Seoul')).date()
    return first.strftime('%Y.%m.%d'), last.strftime('%Y.%m.%d')
