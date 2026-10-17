"""Synthetic CA and bank boundaries for certificate PIN login, without traffic."""
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from asn1crypto import cms
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from finance_cli.core import storage
from finance_cli.credentials.registry import encode, decode
from finance_cli.credentials.shinhan import Registry
from finance_cli.services.shinhan import crypto, e2e, login, login_protocol, setup, transport
from test_shinhan import PrivateHome, settings, response


def certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic Certificate')])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).serial_number(1234567).public_key(key.public_key()).not_valid_before(datetime(2020, 1, 1)).not_valid_after(datetime(2040, 1, 1)).sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER), key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class CryptoTests(unittest.TestCase):
    def test_pin_derivation_and_attribute_order(self):
        self.assertEqual(crypto.unique_value(b'246802', bytes(range(32))), hashlib.pbkdf2_hmac('sha512', b'246802', bytes(range(32)), 2048, 64).hex().upper())
        attrs = crypto.attributes(b'261017123456Z', b'a'*32, b'nonce')
        parsed = cms.CMSAttributes.load(b'\x31'+attrs[1:])
        self.assertEqual([v['type'].dotted for v in parsed], ['1.2.840.113549.1.9.3', '1.2.840.113549.1.9.5', '1.2.840.113549.1.9.4', '1.2.840.113549.1.9.25.3'])

    def test_signature_is_over_set_tag_and_pkcs7_preserves_context_tag(self):
        cert, private = certificate()
        wire = crypto.sign(cert, private, b'login261017100000', b'SYN-NONCE', moment=datetime(2026, 10, 17, 10, 0, 1), now=datetime(2026, 10, 17, tzinfo=timezone.utc))
        signed = cms.ContentInfo.load(wire)['content']
        self.assertEqual(signed['encap_content_info']['content'].native, b'login261017100000')
        signer = signed['signer_infos'][0]
        attrs = signer['signed_attrs'].dump()
        self.assertEqual(attrs[0], 0xa0)
        self.assertEqual(signer['signature_algorithm']['algorithm'].dotted, '1.2.840.113549.1.1.11')
        x509.load_der_x509_certificate(cert).public_key().verify(signer['signature'].native, b'\x31'+attrs[1:], padding.PKCS1v15(), hashes.SHA256())
        with self.assertRaises(ValueError):
            crypto.sign(cert, private, b'login', b'')
        with self.assertRaises(ValueError):
            crypto.sign(cert, private, b'login', b'n', now=datetime(2050, 1, 1, tzinfo=timezone.utc))

    def test_e2e_independent_server_computes_same_keys_and_ciphertext(self):
        server = ec.derive_private_key(7, ec.SECP256R1())
        public = server.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        challenge, iv = b'SYN-CHALLENGE', bytes(range(16))
        client = e2e.Handshake.challenge(e2e.message(op='unexpected', sp=public.hex(), sc=challenge.hex(), si=(iv+b'extra').hex()), private_key=ec.derive_private_key(11, ec.SECP256R1()), random=b'\x01'*16)
        request = json.loads(client.request)['SeProtocolMessage']
        shared = server.exchange(ec.ECDH(), serialization.load_der_public_key(bytes.fromhex(request['cp'])))
        keys = hashlib.pbkdf2_hmac('sha512', shared, challenge, 1024, 64)
        out_iv = bytes.fromhex(request['cfi'])
        encrypted = bytes.fromhex(request['ced'])
        self.assertEqual(unpad(AES.new(keys[:32], AES.MODE_CBC, out_iv).decrypt(encrypted), 16), challenge)
        mac = hmac.new(keys[32:], encrypted+out_iv+bytes.fromhex(request['cp']), hashlib.sha256).hexdigest().upper()
        self.assertEqual(request['cfm'], mac)
        self.assertEqual(client.encrypt('value'), '')
        kr1 = b'SYN-KR1'
        final = e2e.message(op='unexpected', result='0000', data=AES.new(keys[:32], AES.MODE_CBC, out_iv).encrypt(pad(kr1, 16)).hex())
        self.assertTrue(client.finish(final))
        self.assertTrue(client.ready)
        self.assertEqual(client.kr1, kr1)
        wrapped = json.loads(client.encrypt('A1B2'))['SeProtocolMessage']['data']
        self.assertEqual(unpad(AES.new(keys[:32], AES.MODE_CBC, out_iv).decrypt(bytes.fromhex(wrapped)), 16), b'A1B2')
        self.assertEqual(json.loads(client.health_request())['SeProtocolMessage']['data'], hmac.new(out_iv, keys[:32], hashlib.sha256).hexdigest().upper())

    def test_e2e_final_success_is_separate_from_readiness(self):
        for plain, expected in ((bytes([16])*16, b''), (b'A'*15+b'\0', b'A'*15+b'\0'), (b'A'*15+b'\2', None)):
            context = e2e.Handshake(b'k'*32, b'i'*16, '')
            result = e2e.message(result='0000', data=AES.new(context.key, AES.MODE_CBC, context.iv).encrypt(plain).hex())
            self.assertTrue(context.finish(result))
            self.assertEqual(context.kr1, expected)
            self.assertEqual(context.ready, bool(expected))
        self.assertTrue(e2e.health_error(''))
        self.assertTrue(e2e.health_error('{"DSErrProtocolMessage":{"result":"0000"}}'))
        self.assertFalse(e2e.health_error('non-json'))
        self.assertFalse(e2e.health_error('{}'))
        self.assertFalse(e2e.health_error('{"SeProtocolMessage":{"result":"failure"}}'))

    def test_pin_failure_threshold_and_decode_do_not_invent_success(self):
        for count, clear in (('4', False), ('5', True), ('6', False), (None, False)):
            verdict = login_protocol.pin_verdict({'ERR_CD': 'RA3100', 'ERR_MSG': '', 'data': {'PIN_EROR_CNT': count}})
            self.assertEqual(verdict['clear_local'], clear)
            self.assertTrue(verdict['increment_failure_count'])
        self.assertEqual(login_protocol.pin_verdict({'ERR_CD': 'RA0000', 'ERR_MSG': '', 'data': None})['result'], 'success')
        self.assertEqual(login_protocol.pin_verdict({'ERR_CD': 'RA0000'})['result'], 'unknown')
        for count in ('', '1.0', True, 2**31):
            verdict = login_protocol.pin_verdict({'ERR_CD': 'RA3100', 'ERR_MSG': '', 'data': {'PIN_EROR_CNT': count}})
            self.assertEqual(verdict['branch'], 'count_decode_error')

    def test_three_identity_reads_and_request_defaults(self):
        identities = iter(['FIRST', 'SECOND', 'THIRD'])
        config = settings()
        config['login_metadata'] = {'vpnYn': 'UNKNOWN', 'pushToken': None}
        transaction, body, identity = login_protocol.login_request({'alias': '', 'msb_version': 'SYN'}, 'VALUE', 'TEXT', 'SIGNED', config, {'login_failed_count': -1, 'emergency': True}, device=lambda: next(identities))
        self.assertEqual((transaction, identity), ('RSMCM0201D08', 'THIRD'))
        self.assertEqual(body['mcmInptSignData']['deviceId'], 'FIRST')
        self.assertEqual(body['mcmInptSignData']['custCctnMctlId'], 'SECOND')
        self.assertEqual(body['mcmInptSignData']['tranElsgDataCon'], 'SIGNED')
        self.assertEqual(body['mcmInptSignData']['pkcs7SignedData'], '')
        self.assertEqual((body['vpnYn'], body['pushToken'], body['loginFailCnt']), ('X', '', -1))
        self.assertEqual(len(body), 22)
        self.assertEqual(len(body['mcmInptSignData']), 14)


class LoginTests(PrivateHome):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.private = certificate()

    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('External network forbidden')))
        self.install()
        self.pin, self.password = b'246802', b'SYN-VAULT-PASSWORD'
        self.unique = crypto.unique_value(self.pin, bytes(range(32)))
        self.material = {'state': 'issued', 'certificate': encode(self.cert), 'private_key': encode(self.private),
                         'pin_salt': encode(bytes(range(32))), 'access_key_digest': hashlib.sha256(self.unique.encode()).hexdigest(),
                         'alias': 'SYN-ALIAS', 'msb_version': 'SYN-VERSION', 'device_id': settings()['device']['device_id']}
        Registry().save('synthetic', self.password, self.material, create=True)
        storage.atomic_json(setup.root() / 'session.json', {'cookie': 'JSESSIONID=SYN-BANK'})
        self.ca_calls, self.bank_calls = [], []
        self.server = ec.derive_private_key(7, ec.SECP256R1())
        self.auth_code = 'RA0000'
        self.count = None
        self.nonce = 'SYN-NONCE'
        self.login_body = {}
        self.login_result = 'SUCCESS'
        self.kr1 = b'SYN-KR1'

    def ca(self, payload, cookie='', *, path):
        value = json.loads(payload)
        self.ca_calls.append((path, value, cookie))
        self.assertNotIn('SYN-BANK', cookie)
        if 'SeProtocolMessage' in value:
            fields = value['SeProtocolMessage']
            if fields['op'] == '7E01':
                public = self.server.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                text = e2e.message(sp=public.hex(), si=bytes(range(16)).hex(), sc=b'SYN-SERVER'.hex())
            elif fields['op'] == '7E03':
                shared = self.server.exchange(ec.ECDH(), serialization.load_der_public_key(bytes.fromhex(fields['cp'])))
                self.keys = hashlib.pbkdf2_hmac('sha512', shared, b'SYN-SERVER', 1024, 64)
                self.iv = bytes.fromhex(fields['cfi'])
                text = e2e.message(result='0000', data=AES.new(self.keys[:32], AES.MODE_CBC, self.iv).encrypt(pad(self.kr1, 16)).hex())
            else:
                self.assertEqual(fields['op'], '7E06')
                text = '{}'
        else:
            self.assertEqual(path, '/v1.1/prsn-cert/sec/auth')
            self.assertEqual(value['CUST_CCTN_MCTL_ID'], settings()['device']['uuid2'])
            wrapped = json.loads(value['CRTC_PTRN_DATA_CON'])['SeProtocolMessage']['data']
            plaintext = unpad(AES.new(self.keys[:32], AES.MODE_CBC, self.iv).decrypt(bytes.fromhex(wrapped)), 16)
            self.assertEqual(plaintext.decode(), self.unique)
            text = json.dumps({'ERR_CD': self.auth_code, 'ERR_MSG': 'SYN-PRIVATE-MESSAGE', 'data': {'PIN_EROR_CNT': self.count}})
        return transport.Reply(200, [('Set-Cookie', 'CASESSION=SYN-CA; Secure; Path=/')], text.encode())

    def bank(self, payload, cookie='', *, path):
        envelope = json.loads(payload)
        key = bytes(range(32))
        body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(envelope['dataBody'])), 16))
        transaction = envelope['dataHeader']['trxCd']
        self.bank_calls.append((transaction, body, cookie))
        self.assertNotIn('SYN-CA', cookie)
        if transaction == 'RSMCM0800C12':
            self.assertEqual(path, '/serviceEndpoint/httpDigital/')
            self.assertEqual(body, {})
            result = response(body={'randomUid': self.nonce})
        else:
            self.assertEqual(transaction, 'RSMCM0201C08')
            self.assertEqual(path, '/serviceEndpoint/httpDigital')
            signed = cms.ContentInfo.load(bytes.fromhex(body['mcmInptSignData']['tranElsgDataCon']))['content']
            signer = signed['signer_infos'][0]
            attrs = signer['signed_attrs'].dump()
            x509.load_der_x509_certificate(self.cert).public_key().verify(signer['signature'].native, b'\x31'+attrs[1:], padding.PKCS1v15(), hashes.SHA256())
            result = response(self.login_result, body=self.login_body)
        return transport.Reply(200, [], result)

    def run_login(self):
        with patch.object(transport, 'post_certificate', side_effect=self.ca), patch.object(transport, 'post', side_effect=self.bank):
            return login.run(None, self.password, lambda: self.pin)

    def test_complete_pin_nonce_sign_login_and_separate_cookie_jars(self):
        result = self.run_login()
        self.assertEqual(result['bank_result'], 'success', result)
        self.assertEqual(result['authentication'], 'bank_accepted')
        self.assertEqual(result['processing_status'], 'complete')
        self.assertEqual(len(self.ca_calls), 4)
        self.assertEqual(len(self.bank_calls), 2)
        self.assertIn('SYN-CA', self.ca_calls[-1][2])
        self.assertNotIn('SYN-', json.dumps(result))
        state = storage.read_json(setup.root() / 'session.json')
        self.assertTrue(state['authenticated'])
        self.assertEqual(state['credential'], 'synthetic')
        self.assertEqual(state['login'], {})
        self.assertEqual(Registry().load('synthetic', self.password)['private_key'], encode(self.private))

    def test_new_bank_login_invalidates_prepared_transfer_even_if_body_unavailable(self):
        for body in ({}, None):
            state = storage.read_json(setup.root()/'session.json')
            state['transfer_pending'] = {'attempt': 'SYN-OLD-PREPARE'}
            state['transfer_unlock'] = {'attempt': 'SYN-OLD-AUTH', 'status': 'awaiting_ars'}
            storage.atomic_json(setup.root()/'session.json', state)
            self.login_body = body
            result = self.run_login()
            self.assertEqual(result['bank_result'], 'success')
            self.assertNotIn('transfer_pending', storage.read_json(setup.root()/'session.json'))
            self.assertNotIn('transfer_unlock', storage.read_json(setup.root()/'session.json'))

    def test_pisp_reuses_pin_and_nonce_without_relogging_in(self):
        from finance_cli.services.shinhan import transfer
        from finance_cli.services.shinhan.exchange import Exchange
        state = storage.read_json(setup.root()/'session.json')
        exchange = Exchange(settings(), state, 'synthetic_pisp')
        sent = []
        def bank(payload, cookie='', *, path):
            envelope = json.loads(payload)
            transaction = envelope['dataHeader']['trxCd']
            sent.append(transaction)
            if transaction == 'RSMCM0800C12':
                return transport.Reply(200, [], response(body={'randomUid': self.nonce}))
            self.assertEqual(transaction, 'RSMDE0907A08')
            key = bytes.fromhex(settings()['bank_key'])
            body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(envelope['dataBody'])), 16))
            sign_data = body['inputSignData']
            self.assertEqual(sign_data['crtcPtrnDataCon'], self.unique)
            signed = cms.ContentInfo.load(bytes.fromhex(sign_data['tranElsgDataCon']))['content']
            signer = signed['signer_infos'][0]
            attrs = signer['signed_attrs'].dump()
            x509.load_der_x509_certificate(self.cert).public_key().verify(signer['signature'].native, b'\x31'+attrs[1:], padding.PKCS1v15(), hashes.SHA256())
            return transport.Reply(200, [], response(body={'authNoS64': 'SYN-PISP-TOKEN'}))
        with patch.object(transport, 'post_certificate', side_effect=self.ca), patch.object(transport, 'post', side_effect=bank):
            transfer.pisp(exchange, {'credential': 'synthetic'},
                          lambda stage, _: self.password if stage == 'storage_password' else self.pin)
        self.assertEqual(sent, ['RSMCM0800C12', 'RSMDE0907A08'])
        self.assertEqual(exchange.report['pisp_authentication'], 'success')
        self.assertNotIn('SYN-PISP-TOKEN', json.dumps(exchange.report))

    def test_pin_rejection_does_not_request_nonce_or_sign(self):
        self.auth_code, self.count = 'RA3100', '4'
        result = self.run_login()
        self.assertEqual(result['pin_authentication'], 'failure')
        self.assertEqual(result['bank_result'], 'unknown')
        self.assertEqual(self.bank_calls, [])
        state = storage.read_json(setup.root() / 'session.json')
        self.assertEqual(state['login_failed_count'], 1)
        self.assertNotIn('disabled_credentials', state)

    def test_fifth_failure_disables_connection_without_deleting_shared_archive(self):
        self.auth_code, self.count = 'RA3100', '5'
        self.run_login()
        state = storage.read_json(setup.root() / 'session.json')
        self.assertEqual(state['disabled_credentials'], ['synthetic'])
        self.assertTrue(Registry().path('synthetic').exists())
        with patch.object(transport, 'post_certificate') as post, self.assertRaises(ValueError):
            login.run(None, self.password, lambda: self.pin)
        post.assert_not_called()

    def test_nonce_empty_cannot_be_replaced_with_local_random(self):
        self.nonce = ''
        result = self.run_login()
        self.assertEqual(result['pin_authentication'], 'success')
        self.assertEqual(result['bank_result'], 'unknown')
        self.assertEqual(len(self.bank_calls), 1)
        self.assertEqual(result['error'], 'local_login_processing_error')

    def test_empty_kr1_preserves_handshake_success_but_cannot_prompt_or_authenticate(self):
        self.kr1 = b''
        with patch.object(transport, 'post_certificate', side_effect=self.ca), patch.object(transport, 'post', side_effect=self.bank):
            def no_pin():
                raise AssertionError('PIN must not be requested')
            result = login.run(None, self.password, no_pin)
        self.assertEqual(result['error'], 'keypad_material_unavailable')
        self.assertEqual(result['stages'][1]['result'], 'success')
        self.assertEqual(len(self.ca_calls), 3)
        self.assertEqual(self.bank_calls, [])

    def test_login_null_body_keeps_bank_success_but_not_local_completion(self):
        self.login_body = None
        result = self.run_login()
        self.assertEqual(result['bank_result'], 'success')
        self.assertEqual(result['authentication'], 'bank_accepted')
        self.assertEqual(result['processing_status'], 'incomplete')
        self.assertFalse(storage.read_json(setup.root() / 'session.json').get('authenticated', False))

    def test_storage_failure_after_login_preserves_bank_success(self):
        atomic = storage.atomic_json
        def save(path, value):
            if Path(path).name == 'session.json' and value.get('authenticated'):
                raise OSError('SYN-PRIVATE-ERROR')
            return atomic(path, value)
        with patch.object(storage, 'atomic_json', side_effect=save):
            result = self.run_login()
        self.assertEqual(result['bank_result'], 'success')
        self.assertEqual(result['local_status'], 'incomplete')
        self.assertFalse(result['session_saved'])
        self.assertEqual(len(self.bank_calls), 2)
        self.assertNotIn('SYN-PRIVATE', json.dumps(result))

    def test_credential_is_encrypted_and_bad_password_prevents_network(self):
        stored = Registry().path('synthetic').read_text()
        for secret in ('SYN-ALIAS', 'SYN-VERSION', encode(self.private), self.unique, self.password.decode()):
            self.assertNotIn(secret, stored)
        with patch.object(transport, 'post_certificate') as post, self.assertRaises(ValueError):
            login.run(None, b'wrong', lambda: self.pin)
        post.assert_not_called()

    def test_missing_send_never_opens_credential_or_prompts(self):
        with patch.object(Registry, 'select', side_effect=AssertionError('Credential read')), patch('getpass.getpass', side_effect=AssertionError('Secret read')):
            code, text, _ = self.call(['login'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(text)['result']['error'], 'send_required')


if __name__ == '__main__':
    unittest.main()
