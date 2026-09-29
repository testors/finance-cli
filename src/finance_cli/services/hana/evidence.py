"""Strict value checks for saved transfer rows. Coercions are refused on purpose."""
import re

IDS = ('eChnlTrscAcpnNo', 'chnlSvcCd', 'eChnlTrscUnqNo')


def nonblank(value):
    return isinstance(value, str) and bool(value.strip())


def amount(value):
    # Refuse fractional KRW, booleans and integers a JavaScript number cannot hold.
    if isinstance(value, str) and re.fullmatch(r'[0-9]+', value):
        value = int(value)
    return value if type(value) is int and 0 <= value <= 2**53 - 1 else None


def account(value):
    if not isinstance(value, str):
        return None
    value = value.replace('-', '')
    return value if re.fullmatch(r'[0-9]+', value) else None


def identifiers(row):
    return {key: row[key] for key in IDS} if all(nonblank(row.get(k)) for k in IDS) else None
