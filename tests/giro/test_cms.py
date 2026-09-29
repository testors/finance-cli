import importlib.util
import unittest
from datetime import datetime, timezone, timedelta
from giro.cms import envelop_query
from giro.crypto import decrypt_body
from giro.errors import GiroError

@unittest.skipUnless(importlib.util.find_spec('asn1crypto') and importlib.util.find_spec('cryptography'), 'optional crypto packages unavailable')
class CmsTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'SYNTHETIC OFFLINE ONLY')])
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(cls.private.public_key()).serial_number(128).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(cls.private, hashes.SHA256())
        cls.cert = cert.public_bytes(serialization.Encoding.DER)

    def test_rsa_unwrap_and_seed_decrypt(self):
        from asn1crypto import cms, core, x509
        from cryptography.hazmat.primitives.asymmetric import padding
        for plaintext in (b'', b'x', bytes(16), '작업구분=로그인'.encode('euc-kr'), b'x' * 4096):
            with self.subTest(length=len(plaintext)):
                result = envelop_query(plaintext, self.cert)
                content = cms.ContentInfo.load(result.data)
                self.assertEqual(content['content_type'].native, 'enveloped_data')
                envelope = content['content']
                self.assertEqual(envelope['version'].native, 'v0')
                recipient = envelope['recipient_infos'][0].chosen
                self.assertEqual(recipient['version'].native, 'v0')
                self.assertEqual(recipient['rid'].chosen['serial_number'].native, 128)
                self.assertEqual(recipient['rid'].chosen['issuer'].dump(), x509.Certificate.load(self.cert)['tbs_certificate']['issuer'].dump())
                key = self.private.decrypt(recipient['encrypted_key'].native, padding.PKCS1v15())
                self.assertEqual(key, result.session_key)
                encrypted = envelope['encrypted_content_info']
                algorithm = core.Sequence.load(encrypted['content_encryption_algorithm'].dump())
                self.assertEqual(algorithm[0].native, '1.2.410.200004.1.4')
                self.assertEqual(algorithm[1].dump(), b'\x05\x00')
                self.assertEqual(decrypt_body(encrypted['encrypted_content'].native, key), plaintext)
                self.assertEqual(result.data, content.dump(force=True))
                self.assertEqual(encrypted['encrypted_content'].dump()[0], 128)

    def test_new_session_key_each_envelope(self):
        first = envelop_query(b'a=1', self.cert)
        second = envelop_query(b'a=1', self.cert)
        self.assertNotEqual(first.session_key, second.session_key)
        self.assertNotEqual(first.data, second.data)
        self.assertNotIn(first.session_key.hex(), repr(first))

    def test_malformed_certificate_does_not_leak(self):
        with self.assertRaises(GiroError) as error:
            envelop_query(b'a=1', b'SYNTHETIC BAD CERT')
        self.assertNotIn('SYNTHETIC', str(error.exception))

    def test_offline_components_chain_not_authentication(self):
        from unittest.mock import patch
        from giro.crypto import encode_pin, encrypt_text, _cbc, PIN_IV
        from giro.protocol import build_query, encrypted_form
        from giro.response import receive
        with patch('socket.socket', side_effect=AssertionError('offline only')):
            first = envelop_query(build_query('auth.device-status', {'deviceUniqNo': 'SYNTHETIC'}, device_id='SYNTHETIC').encode('euc-kr'), self.cert)
            latest = envelop_query(build_query('auth.datetime', {}, device_id='SYNTHETIC').encode('euc-kr'), self.cert)
            self.assertNotEqual(first.session_key, latest.session_key)
            pin = encode_pin('123450', latest.session_key)
            for (index, keypad_position) in enumerate((1, 2, 3, 4, 5, 10)):
                block = bytes.fromhex(pin)[index * 16:(index + 1) * 16]
                self.assertEqual(_cbc(latest.session_key, PIN_IV, block, decrypt=True), bytes((5, keypad_position)) + bytes(14))
            text = build_query('auth.pin', {'pin': pin, 'deviceUniqNo': 'SYNTHETIC'}, device_id='SYNTHETIC')
            encrypted = encrypt_text(text, latest.session_key)
            self.assertEqual(decrypt_body(encrypted, latest.session_key).decode('euc-kr'), text)
            self.assertTrue(encrypted_form(encrypted).startswith(b'encryptedData='))
            for kind in ('national', 'local', 'customs'):
                body = encrypt_text("{responseCode:'000',paymentList:[]}", latest.session_key).hex()
                parsed = receive(kind + '.list', 200, [('Mgiro-App-Encrypt', '1')], body, key=latest.session_key)
                self.assertTrue(parsed.app_success)
                self.assertEqual(parsed.query['paymentList'], [])

    def test_synthetic_entity_state_tax_chain_without_sockets(self):
        import gzip
        import json
        from datetime import date
        from unittest.mock import patch
        from giro.crypto import encrypt_text
        from giro.response import receive_bytes
        from giro.login_state import LoginState, replay
        from giro.bills import normalize_pages, due_bills

        def deliver(name, body, key, prior):
            encrypted_hex = encrypt_text(json.dumps(body), key).hex()
            entity = gzip.compress(b'\xff\xfe' + encrypted_hex.encode('utf-16-le'))
            headers = [('Content-Encoding', 'gzip'), ('Content-Type', 'text/plain; charset=US-ASCII'), ('Mgiro-App-Encrypt', '1')]
            received = receive_bytes(name, 200, headers, entity, key=key)
            self.assertTrue(received.app_success)
            return replay(name, received, prior)
        with patch('socket.socket', side_effect=AssertionError('offline only')):
            state = LoginState()
            first = envelop_query(b'deviceUniqNo=SYNTHETIC', self.cert)
            state.values['sessionKey'] = first.session_key
            state = deliver('auth.device-status', dict(responseCode='000', deviceRegYn='Y', pinLoginYn='Y', defaultLoginType='1'), first.session_key, state).state
            self.assertFalse(state.is_login)
            latest = envelop_query(b'', self.cert)
            self.assertNotEqual(first.session_key, latest.session_key)
            state.values['sessionKey'] = latest.session_key
            state = deliver('auth.datetime', dict(responseCode='000', currentDateTime='20260928000000'), latest.session_key, state).state
            state = deliver('auth.pin', dict(responseCode='000', sessionInfo=dict(userType='0', userId='SYNTHETIC')), latest.session_key, state).state
            self.assertTrue(state.is_login)
            self.assertTrue(state.values['isPinLogin'])
            self.assertEqual(state.values['currentDateTime'], '20260928000000')
            for kind in ('national', 'local', 'customs'):
                result = deliver(kind + '.list', dict(responseCode='000', paymentList=[dict(elecNo='SYNTHETIC', payLimitDate='20260930', payMny='1000')], pageNaviMap=dict(currentPage='1', totalPage='2', totalCount='2')), latest.session_key, state)
                bills = due_bills(normalize_pages(result.transport.query, kind), today=date(2026, 9, 28), within_days=7)
                self.assertTrue(bills['app_success'])
                self.assertFalse(bills['complete'])
                self.assertEqual(bills['bills'][0]['days_until_due'], 2)
                self.assertTrue(result.state.is_login)
                state = result.state
            from giro.response import receive
            ended = replay('national.list', receive('national.list', 200, [], '{responseCode:"301"}'), state)
            self.assertFalse(ended.state.is_login)
            self.assertEqual(ended.callback, 'disconnected_session')
            self.assertEqual(ended.state.values['sessionKey'], latest.session_key)
