"""New certificate PIN input, customer-data check and PIN derivation."""
import base64
import hmac
import re
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from . import crypto, keypad, transport
from .enrollment import Pending


def validate(pin):
    if not isinstance(pin, bytes) or not re.fullmatch(rb'[0-9]{6}', pin):
        raise Pending('six_digit_pin_required')
    for a, b, c in zip(pin, pin[1:], pin[2:]):
        if a == b == c or b-a == c-b and abs(b-a) == 1:
            raise Pending('pin_consecutive_or_repeated_digits')


def check_customer(exchange, pin):
    key = bytes.fromhex(exchange.settings['pin_check_key'])
    encrypted = base64.b64encode(AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pad(base64.b64encode(pin), 16))).decode()
    step, document = exchange.bank('pin_customer_check', 'RSMCM1100D01', {'checkScnoS200': encrypted})
    exchange.report['pin_customer_lookup'] = step['result']
    data = document.get('dataBody') if isinstance(document, dict) else None
    # The use case permits the PIN on DataResult.Error, including null body
    # and response decoding errors. Only a decoded successful customer is used.
    if step['result'] != 'success' or not isinstance(data, dict):
        exchange.report['pin_customer_check'] = 'allowed_after_lookup_error'
        return
    try:
        values = {name: transport.primitive(data[name]) if name in data else ''
                  for name in ('rstS5', 'hpnoMid', 'hpnoLst', 'birthDt')}
        if any(name in data and data[name] is None for name in values):
            raise ValueError('pin_customer_decode_error')
    except (ValueError, TypeError):
        exchange.report['pin_customer_check'] = 'allowed_after_lookup_error'
        return
    prefix = pin[:4].decode('ascii')
    for reason, value in [('birth', values['birthDt']), ('phone', values['hpnoMid']+values['hpnoLst'])]:
        if prefix in value:
            exchange.report['pin_customer_check'] = reason+'_matches'
            raise Pending('pin_matches_'+reason)
    exchange.report['pin_customer_check'] = 'allowed'


def prepare(exchange, input_provider, *, channel=None):
    channel = channel or keypad.Channel(exchange)
    channel.prepare()
    salt = secrets.token_bytes(32)
    first = input_provider('pin', {})
    validate(first)
    unique = crypto.unique_value(first, salt)
    check_customer(exchange, first)
    second = input_provider('pin_repeat', {})
    validate(second)
    if not hmac.compare_digest(unique, crypto.unique_value(second, salt)):
        raise Pending('pin_confirmation_mismatch')
    exchange.report['pin_confirmation'] = 'matched'
    return unique, salt
