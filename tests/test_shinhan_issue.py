"""Enrollment completion against synthetic CA/bank transports."""
from datetime import datetime
import hashlib
import hmac
import json
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from finance_cli.core import storage
from finance_cli.credentials.registry import decode
from finance_cli.credentials.shinhan import Registry
from finance_cli.credentials.joint.cms import sequence
from finance_cli.services.shinhan import cmp, crypto, issue, login, setup, transport
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, settings, response
from test_shinhan_cmp import genp, ip
from test_shinhan_login import certificate


class IssueTests(PrivateHome):
    @classmethod
    def setUpClass(cls):
        cls.ca, cls.ca_private = certificate()

    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.install()
        self.password = b'SYN-VAULT-PASSWORD'
        self.salt = bytes(range(32))
        self.unique = crypto.unique_value(b'246802', self.salt)
        self.enrollment = dict(referenceNumber='SYN-REF', authCode='SYN-AUTH', customerNumber='SYN-CUSTOMER', customerName='Synthetic Customer')
        self.state = {'cookie': 'JSESSIONID=SYN-BANK', 'simple_transfer_id': 'SYN-OLD', 'authentication_method': 'pattern'}
        self.exchange = Exchange(settings(), self.state, 'issue')
        self.calls = []
        self.confirm_response = cmp.wire(b'')
        self.registration = {'ERR_CD': 'RA0000', 'ERR_MSG': 'SYN-PRIVATE-MESSAGE'}
        self.register_status = 200
        self.bank_results = ['SUCCESS', 'SUCCESS']
        self.ip_status = 0
        self.cert = None
        self.enterContext(patch.object(transport, 'post_cmp', self.cmp_server))
        self.enterContext(patch.object(transport, 'post_certificate', self.ca_server))
        self.enterContext(patch.object(transport, 'post', self.bank_server))

    def cmp_server(self, payload, *, path):
        self.calls.append(path)
        message = cmp.unwire(payload)
        if path.endswith('/genm'):
            answer = genp(self.ca)
        elif path.endswith('/ir'):
            body = sequence(message)[1]
            request = sequence(sequence(cmp.content(body, 0xa0))[0])[0]
            template = sequence(sequence(request)[1])[0]
            public = serialization.load_der_public_key(b'\x30'+template[1:])
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic Issued Certificate')])
            ca = x509.load_der_x509_certificate(self.ca)
            key = serialization.load_der_private_key(self.ca_private, None)
            self.cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject).serial_number(4321).public_key(public).not_valid_before(datetime(2020, 1, 1)).not_valid_after(datetime(2040, 1, 1)).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
            answer = ip(self.cert, statuses=(self.ip_status,))
        else:
            self.assertTrue(path.endswith('/confirm'))
            self.assertEqual(sequence(message)[1], b'\xb3\x02\x05\0')
            return transport.Reply(200, [], self.confirm_response)
        return transport.Reply(200, [], cmp.wire(answer))

    def ca_server(self, payload, cookie='', *, path):
        self.calls.append(path)
        self.assertEqual(path, '/v1.1/prsn-cert/issue/regist-cert')
        self.assertNotIn('SYN-BANK', cookie)
        body = json.loads(payload)
        self.assertEqual(body['CERT_SEQ_NO'], '000000004321')
        self.assertEqual(body['PIN_DATA_CON'], self.unique)
        message = 'SYN-REFSYN-AUTH000000004321001SOL'+issue.MSB_VERSION+'SYN-CUSTOMER'+settings()['device']['device_id']+'ASYN-OS'+self.unique+'00'
        self.assertEqual(body['PARAMMAC'], hmac.new(b'SYN-AUTH', message.encode(), hashlib.sha256).hexdigest())
        return transport.Reply(self.register_status, [], json.dumps(self.registration).encode())

    def bank_server(self, payload, cookie='', *, path):
        envelope = json.loads(payload)
        transaction = envelope['dataHeader']['trxCd']
        self.calls.append(transaction)
        self.assertEqual(cookie, 'JSESSIONID=SYN-BANK')
        return transport.Reply(200, [], response(self.bank_results.pop(0), {'idS64': ''}))

    def run_issue(self):
        return issue.complete(self.exchange, self.enrollment, self.password, self.unique, self.salt)

    def test_complete_saves_issued_credential_and_preserves_empty_registration_fields(self):
        Registry().prepare('previous', self.password, self.unique, self.salt, settings()['device']['device_id'])
        result = self.run_issue()
        self.assertEqual(result['processing_status'], 'complete')
        self.assertEqual(result['certificate_issuance'], 'success')
        self.assertEqual(result['certificate_registration'], 'success')
        material = Registry().load(result['credential'], self.password)
        self.assertEqual(material['state'], 'issued')
        self.assertEqual(material['registration'], {'number': '', 'date': ''})
        self.assertEqual(material['alias'], '000000004321')
        self.assertEqual(decode(material['certificate']), self.cert)
        self.assertEqual(self.state['simple_transfer_id'], '')
        self.assertTrue(self.state['next_login_shinhan_certificate'])
        self.assertEqual(len(self.calls), 6)
        self.assertIn('previous', self.state['disabled_credentials'])
        self.assertTrue(Registry().path('previous').exists())
        self.assertEqual(login.select(), result['credential'])
        report = json.dumps(result)
        for secret in ('SYN-AUTH', 'SYN-CUSTOMER', 'SYN-PRIVATE-MESSAGE', 'SYN-BANK', self.unique, '000000004321'):
            self.assertNotIn(secret, report)
        self.assertEqual(Registry().path(result['credential']).stat().st_mode & 0o777, 0o600)

    def test_confirm_decode_failure_preserves_received_certificate_and_never_registers(self):
        self.confirm_response = b'bm90LWhleA=='
        result = self.run_issue()
        self.assertEqual(result['certificate_issuance'], 'success')
        self.assertEqual(result['cmp_confirm'], 'unknown')
        self.assertEqual(result['certificate_registration'], 'unknown')
        self.assertEqual(len(self.calls), 3)
        self.assertIn(result['credential'], self.state['disabled_credentials'])
        self.assertEqual(Registry().load(result['credential'], self.password)['state'], 'certificate_received')

    def test_ip_rejection_does_not_send_confirm_or_register(self):
        self.ip_status = 1
        result = self.run_issue()
        self.assertEqual(result['certificate_issuance'], 'failure')
        self.assertEqual(len(self.calls), 2)

    def test_registration_rejection_keeps_cmp_success_and_disables_new_connection(self):
        self.registration['ERR_CD'] = 'RE0000'
        result = self.run_issue()
        self.assertEqual(result['certificate_issuance'], 'success')
        self.assertEqual(result['cmp_confirm'], 'success')
        self.assertEqual(result['certificate_registration'], 'failure')
        self.assertEqual(self.state['authentication_method'], 'pin')
        self.assertEqual(len(self.calls), 4)

    def test_post_registration_business_error_does_not_erase_completion(self):
        self.bank_results = ['FAIL']
        result = self.run_issue()
        self.assertEqual(result['certificate_registration'], 'success')
        self.assertEqual(result['processing_status'], 'complete')
        self.assertEqual(result['simple_transfer_registration'], 'skipped')
        self.assertEqual(len(self.calls), 5)
        self.assertTrue(self.state['next_login_shinhan_certificate'])

    def test_simple_transfer_registration_error_still_completes(self):
        self.bank_results = ['SUCCESS', 'FAIL']
        result = self.run_issue()
        self.assertEqual(result['processing_status'], 'complete')
        self.assertEqual(result['simple_transfer_registration'], 'failure')
        self.assertEqual(self.state['simple_transfer_id'], 'SYN-OLD')

    def test_save_failure_after_receipt_does_not_reclassify_ca_success(self):
        original = Registry.save
        def save(registry, reference, password, value, **kwargs):
            if value['state'] == 'certificate_received':
                raise OSError('SYN-PRIVATE-IO')
            return original(registry, reference, password, value, **kwargs)
        with patch.object(Registry, 'save', save):
            result = self.run_issue()
        self.assertEqual(result['certificate_issuance'], 'success')
        self.assertEqual(result['processing_status'], 'incomplete')
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn('SYN-PRIVATE-IO', json.dumps(result))

    def test_save_failure_after_registration_preserves_remote_success_and_continues(self):
        original = Registry.save
        def save(registry, reference, password, value, **kwargs):
            if value['state'] == 'issued':
                raise OSError('SYN-PRIVATE-IO')
            return original(registry, reference, password, value, **kwargs)
        with patch.object(Registry, 'save', save):
            result = self.run_issue()
        self.assertEqual(result['certificate_registration'], 'success')
        self.assertFalse(result['credential_saved'])
        self.assertEqual(result['local_status'], 'incomplete')
        self.assertEqual(len(self.calls), 6)

    def test_http_204_resets_preferences_without_claiming_registration_success(self):
        self.register_status = 204
        result = self.run_issue()
        self.assertEqual(result['certificate_registration'], 'unknown')
        self.assertEqual(self.state['authentication_method'], 'pin')
        self.assertEqual(len(self.calls), 4)
