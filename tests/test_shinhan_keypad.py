"""Sol E2E handshake and numeric input against a synthetic bank transport."""
import base64
import hashlib
import hmac
import json
from unittest.mock import Mock, patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from finance_cli.services.shinhan import e2e, keypad, transport
from finance_cli.services.shinhan.enrollment import Pending
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, response, settings


class KeypadTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.install()
        self.exchange = Exchange(settings(), {'cookie': 'JSESSIONID=SYN-BANK'}, 'certificate_issue')
        self.channel = keypad.Channel(self.exchange)
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.challenge = b'SYNTHETIC-CHALLENGE'
        self.kr1 = bytes(range(32, 64))
        self.calls, self.health = [], []
        self.fail_health = False
        self.enterContext(patch.object(transport, 'post', self.server))

    def server(self, payload, cookie='', *, path=transport.ENDPOINT):
        outer = json.loads(payload)
        key = bytes.fromhex(settings()['bank_key'])
        body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(outer['dataBody'])), 16))
        self.assertEqual(outer['dataHeader']['trxCd'], 'RSMCM9006A03')
        self.assertEqual(body['trxG'], '1')
        self.assertEqual(cookie, 'JSESSIONID=SYN-BANK')
        inner = json.loads(body['encData'])['SeProtocolMessage']
        self.calls.append(inner['op'])
        if inner['op'] == '7E01':
            self.assertEqual(inner['data'], hmac.new(b'SYN-E2E', b'com.shinhan.sbanking', hashlib.sha256).hexdigest().upper())
            public = self.private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            raw = e2e.message(op='7E02', sp=public.hex(), sc=self.challenge.hex(), si=bytes(range(16)).hex())
        elif inner['op'] == '7E03':
            public = bytes.fromhex(inner['cp'])
            shared = self.private.exchange(ec.ECDH(), serialization.load_der_public_key(public))
            keys = hashlib.pbkdf2_hmac('sha512', shared, self.challenge, 1024, 64)
            self.aes_key, self.iv = keys[:32], bytes.fromhex(inner['cfi'])
            encrypted = bytes.fromhex(inner['ced'])
            self.assertEqual(unpad(AES.new(self.aes_key, AES.MODE_CBC, self.iv).decrypt(encrypted), 16), self.challenge)
            self.assertEqual(inner['cfm'], hmac.new(keys[32:], encrypted+self.iv+public, hashlib.sha256).hexdigest().upper())
            raw = e2e.message(op='7E04', result='0000', data=AES.new(self.aes_key, AES.MODE_CBC, self.iv).encrypt(pad(self.kr1, 16)).hex())
        else:
            self.assertEqual(inner['op'], '7E06')
            self.assertEqual(inner['data'], hmac.new(self.iv, self.aes_key, hashlib.sha256).hexdigest().upper())
            if self.fail_health:
                return transport.Reply(200, [], response('FAIL', None, resultCode='SYN-ERROR'))
            raw = self.health.pop(0) if self.health else '{}'
        # rstC is not an independent success condition in the original datasource.
        return transport.Reply(200, [], response(body={'rstC': 'SYN-IGNORED', 'rstVS2000': raw}))

    def test_numeric_stroke_vector_matches_original_and_position_mask(self):
        message = keypad.message(b'5802', self.kr1, b'0123456789', random_bytes=lambda _: bytes(range(64)))
        self.assertEqual(hashlib.sha256(message.encode()).hexdigest(), '0c9172560ee4f87a28ebadd448e6e643217de27f71d17e033bd168bf6bfdceb3')
        value = json.loads(message)['SkProtocolMessage']
        self.assertEqual(value['data'][128:], 'B74FB100EC67F06C9C0B31775112201A')
        self.assertIsNone(value['type'])

    def test_bank_handshake_health_then_input_and_encrypted_keypad_message(self):
        input_value = Mock(return_value=b'2468')
        encrypted = self.channel.read(input_value, 4)
        self.assertEqual(self.calls, ['7E01', '7E03', '7E06'])
        input_value.assert_called_once()
        ciphertext = bytes.fromhex(json.loads(encrypted)['SeProtocolMessage']['data'])
        message = json.loads(unpad(AES.new(self.aes_key, AES.MODE_CBC, self.iv).decrypt(ciphertext), 16))
        data = bytes.fromhex(message['SkProtocolMessage']['data'])
        kr2, strokes = data[:64], data[64:]
        keys, right = keypad.table(self.kr1, kr2, b'0123456789'), keypad.expand(kr2, self.kr1)
        decoded = bytes(keys.index(bytes(a ^ b for a, b in zip(strokes[i*4:i*4+4], right[i:i+4])))+48 for i in range(4))
        self.assertEqual(decoded, b'2468')
        public = json.dumps(self.exchange.report)
        for secret in (encrypted, '2468', self.kr1.hex(), 'SYN-BANK'):
            self.assertNotIn(secret, public)

    def test_next_keypad_uses_same_channel_but_performs_health_before_input(self):
        self.channel.read(lambda: b'1234567', 7)
        self.channel.read(lambda: b'1111', 4)
        self.assertEqual(self.calls, ['7E01', '7E03', '7E06', '7E06'])

    def test_protocol_health_error_reinitializes_but_network_failure_does_not(self):
        self.health = ['{"DSErrProtocolMessage":{"result":"0000"}}', '{}']
        self.channel.read(lambda: b'1234', 4)
        self.assertEqual(self.calls, ['7E01', '7E03', '7E06', '7E01', '7E03', '7E06'])
        self.assertEqual(self.exchange.report['sol_e2e_reinitializations'], 1)
        self.fail_health = True
        input_value = Mock(return_value=b'1234')
        with self.assertRaises(Pending):
            self.channel.read(input_value, 4)
        input_value.assert_not_called()
        self.assertEqual(len(self.calls), 7)

    def test_empty_kr1_preserves_initialization_success_without_asking_for_input(self):
        self.kr1 = b''
        input_value = Mock()
        with self.assertRaises(Pending) as stopped:
            self.channel.read(input_value, 4)
        input_value.assert_not_called()
        self.assertEqual(stopped.exception.action, 'keypad_material_unavailable')
        self.assertEqual(self.exchange.report['sol_e2e_initialization'], 'success')
        self.assertEqual(self.exchange.report['sol_e2e_health'], 'success')

    def test_collision_rebuild_is_local_and_keeps_last_table_after_ten_rebuilds(self):
        random_bytes = Mock(return_value=bytes(range(64)))
        with patch.object(keypad, 'table', return_value=[b'\0'*4]*10):
            keypad.message(b'1111', self.kr1, b'0123456789', random_bytes=random_bytes)
        self.assertEqual(random_bytes.call_count, 11)
        self.assertEqual(self.calls, [])

    def test_cancelled_input_and_invalid_length_send_no_password_business_request(self):
        with self.assertRaises(Pending):
            self.channel.read(lambda: None, 4)
        with self.assertRaises(ValueError):
            self.channel.read(lambda: b'123', 4)
        self.assertEqual(self.calls, ['7E01', '7E03', '7E06', '7E06'])
