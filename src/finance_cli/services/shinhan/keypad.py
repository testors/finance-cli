"""Numeric keypad messages and the bank's Sol E2E channel."""
import hashlib
import hmac
import json
import re
import secrets

from . import e2e, transport
from .enrollment import Pending


def expand(key, message):
    value = hmac.digest(key, message, 'sha512')
    return hashlib.sha512(value[:32]).digest()+hashlib.sha512(value[32:]).digest()


def table(kr1, kr2, alphabet):
    if not kr1 or len(kr2) != 64 or not 10 <= len(alphabet) <= 125:
        raise ValueError('keypad_material_unavailable')
    left = expand(kr1, kr2)
    return [bytes(value ^ character for value in left[index:index+4])
            for index, character in enumerate(alphabet)]


def message(value, kr1, alphabet, *, random_bytes=secrets.token_bytes):
    if not isinstance(value, bytes) or not re.fullmatch(rb'[0-9]{1,125}', value):
        raise ValueError('numeric_keypad_input_required')
    for _ in range(11):
        kr2 = random_bytes(64)
        keys = table(kr1, kr2, alphabet)
        if len(set(keys)) == len(keys):
            break
    # The original keeps the final table even if all local rebuilds collide.
    right = expand(kr2, kr1)
    strokes = b''.join(bytes(left ^ mask for left, mask in zip(keys[alphabet.index(character)], right[index:index+4]))
                       for index, character in enumerate(value))
    # This order matches the observed builder serialization in the pinned SDK.
    return json.dumps({'SkProtocolMessage': {'op': 'skey', 'data': (kr2+strokes).hex().upper(),
                                            'cmd': 'res', 'type': None}}, separators=(',', ':'))


class Channel:
    def __init__(self, exchange):
        self.exchange = exchange
        self.handshake = None

    def send(self, stage, payload):
        step, document = self.exchange.bank(stage, 'RSMCM9006A03', {'trxG': '1', 'encData': payload})
        if step['result'] != 'success':
            raise Pending('sol_e2e_transport_unavailable')
        body = document.get('dataBody')
        if not isinstance(body, dict) or body.get('rstC') is None or body.get('rstVS2000') is None:
            raise ValueError('sol_e2e_response_unavailable')
        # The DTO requires both strings; the datasource consumes only rstVS2000.
        transport.primitive(body['rstC'])
        return transport.primitive(body['rstVS2000'])

    def initialize(self):
        raw = self.send('sol_e2e_init', e2e.initial(self.exchange.settings['e2e_key']))
        handshake = e2e.Handshake.challenge(raw)
        raw = self.send('sol_e2e_complete', handshake.request)
        if not handshake.finish(raw):
            self.exchange.report['sol_e2e_initialization'] = 'failure'
            raise Pending('sol_e2e_rejected')
        self.handshake = handshake
        self.exchange.report['sol_e2e_initialization'] = 'success'

    def prepare(self):
        if self.handshake is None:
            self.initialize()
        while True:
            raw = self.send('sol_e2e_health', self.handshake.health_request())
            if not e2e.health_error(raw):
                break
            # Protocol-directed reinitialization, not a transport-error retry.
            self.exchange.report['sol_e2e_reinitializations'] = self.exchange.report.get('sol_e2e_reinitializations', 0)+1
            self.initialize()
        self.exchange.report['sol_e2e_health'] = 'success'
        if not self.handshake.kr1:
            raise Pending('keypad_material_unavailable')

    def read(self, input_provider, length):
        alphabet = bytes.fromhex(self.exchange.settings['keypad_alphabet'])
        self.prepare()
        value = input_provider()
        if value is None:
            raise Pending('keypad_input_cancelled')
        if not isinstance(value, bytes) or len(value) != length:
            raise ValueError('keypad_input_length')
        return self.handshake.encrypt(message(value, self.handshake.kr1, alphabet))
