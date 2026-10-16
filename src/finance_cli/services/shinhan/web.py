"""React banking request envelopes and callback state, without a browser."""
import base64
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from . import transport


def truthy(value):
    # JavaScript arrays and objects are truthy even when empty.
    return value is not None and value is not False and value != '' and value != 0


def nullish(value):
    # sbIsNull also regards an empty JSON array/object as empty (unlike ||).
    return value is None or value == '' or isinstance(value, (list, dict)) and not value


def encode(transaction, body, settings, program, *, header=None):
    header = {**(header or {}), 'trxCd': transaction, 'uuid': settings['device']['device_id'],
              'subChannel': '03', 'programId': program, 'appG': 'supersol', 'encG': '1'}
    key = bytes.fromhex(settings['bank_key'])
    plain = json.dumps(body, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
    encrypted = base64.b64encode(AES.new(key, AES.MODE_CBC, key[:16]).encrypt(pad(plain, 16))).decode()
    return json.dumps({'dataBody': encrypted, 'dataHeader': header}, ensure_ascii=False, separators=(',', ':')).encode()


def parse(reply):
    result, document = transport.parse(reply)
    header = document.get('dataHeader') if isinstance(document, dict) else None
    header = header if isinstance(header, dict) else {}
    http_ok = reply.error is None and reply.status is not None and 200 <= reply.status < 300
    # The React resolver retains true for an absent/unknown business result.
    result['bridge_success'] = http_ok and header.get('result') != 'FAIL'
    result['callback_ready'] = True
    body = document.get('dataBody') if isinstance(document, dict) else None
    if result['bridge_success'] and isinstance(body, dict) and body.get('blklstG') == '5':
        result.update(callback_ready=False, required_action='service_precheck', processing_status='incomplete')
    elif not result['bridge_success']:
        code = header.get('resultCode')
        if code in ('RIB80306', 'RIB80307', 'MDE00016', 'RIB96472'):
            result.update(callback_ready=False, required_action='additional_authentication',
                          service_sequence={'RIB80306': '70', 'RIB80307': '70', 'MDE00016': '80', 'RIB96472': '81'}[code],
                          processing_status='incomplete')
        elif code in ('RIB00011', 'RIB00060', 'MCM00005', 'RIB00057'):
            result.update(callback_ready=False, required_action='session_notice', processing_status='incomplete')
    return result, document


def update_challenges(state, document):
    if not isinstance(document, dict):
        return
    groups = [document.get(name) for name in ('dataHeader', 'dataBody')]
    values = []
    for number in (1, 2):
        found = None
        for group in groups:
            if isinstance(group, dict):
                for name in (f'comSecChal{number}', f'COM_SEC_CHAL{number}', f'secChal{number}'):
                    value = group.get(name)
                    if truthy(value):
                        found = value
                        break
            if found is not None:
                break
        values.append(found)
    if any(not nullish(value) for value in values):
        state['web_challenges'] = ['' if nullish(value) else value for value in values]
