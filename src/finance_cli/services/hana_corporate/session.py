"""Extend an existing corporate cookie session once, without authentication."""
import json

from finance_cli.services.hana.onesign_io import send_http
from . import operations as op


def decode(raw):
    # Gson String fields retain the JSON numeric spelling (200 != 2e2).
    return json.loads(raw, parse_int=str, parse_float=str)


def string(value):
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return 'true' if value else 'false'
    raise ValueError('extension_string_field_invalid')


def assess(status, value):
    outcome = {'service_status': 'unconfirmed', 'reason': 'extension_response_unconfirmed',
               'login_extension_accepted': None, 'session_ended': False}
    if not 200 <= status < 300 or status in (204, 205) or not isinstance(value, dict):
        return outcome
    header, data = value.get('headerData'), value.get('data')
    if not isinstance(header, dict) or not isinstance(data, dict):
        return outcome
    try:
        code, result, logged_in = string(header.get('status')), string(data.get('result')), string(data.get('IS_LOGGED_IN'))
    except ValueError:
        return outcome
    if code == '200' and result == 'SUCCESS':
        accepted = logged_in == 'Y'
        outcome.update(service_status='accepted' if accepted else 'rejected',
                       reason='login_extension_accepted' if accepted else 'session_ended',
                       login_extension_accepted=accepted, session_ended=not accepted)
    return outcome


def extend(*, session=None, send=False, exchange=send_http):
    output = op.result('session-extend', send)
    output.update(login_extension_accepted=None, session_ended=False, server_expires_at=None, service_status='unconfirmed')
    if not send:
        return output
    with op.operation(output, session, exchange=exchange) as client:
        if client is None:
            return output

        def observe(receipt, payload):
            for key in ('login_extension_accepted', 'session_ended', 'reason', 'service_status'):
                output[key] = receipt[key]
            output['accepted'] = receipt['login_extension_accepted']
            if receipt['session_ended']:
                client.saved['session_ended'] = True
                output['session_current_validity'] = 'ended'

        client.request('extend', native=True, assessor=assess, decoder=decode, observe=observe)
    return output
