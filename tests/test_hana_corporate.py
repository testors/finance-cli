"""Synthetic corporate login flows. Socket access is forbidden in every test."""
import base64
import contextlib
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from Crypto.Cipher import AES
from Crypto.PublicKey import ECC, RSA
from Crypto.Util.Padding import pad
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509.oid import NameOID

from finance_cli.cli.main import main
from finance_cli.core import storage
from finance_cli.credentials.registry import Registry
from finance_cli.credentials.joint import crypto
from finance_cli.services.hana import onesign as shared, onesign_crypto as pin, hana_protocol
from finance_cli.services.hana.onesign_keys import KeyStore
from finance_cli.services.hana.onesign_state import State
from finance_cli.services.hana_corporate import protocol, store, login, onesign

PASSWORD = 'SYNTHETIC-vault-password'
PIN = '604928'
RA_SECRET = 'SYNTHETIC-RA-SECRET'


def certificate(key):
    private = serialization.load_der_private_key(key, None)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'SYNTHETIC'),
                         x509.NameAttribute(NameOID.USER_ID, 'SYNTHETIC')])
    now = datetime.now(timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(private.public_key())
            .serial_number(60034).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .sign(private, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


def verify_cms(encoded, expected_cert):
    data = cms.ContentInfo.load(base64.b64decode(encoded))['content']
    content = data['encap_content_info']['content'].native
    cert = data['certificates'][0].chosen.dump()
    assert cert == expected_cert
    signer = data['signer_infos'][0]
    attrs = signer['signed_attrs']
    digest = next(a['values'][0].native for a in attrs if a['type'].native == 'message_digest')
    assert digest == hashlib.sha256(content).digest()
    signed = bytes([0x31]) + attrs.dump()[1:]
    key = x509.load_der_x509_certificate(cert).public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signer['signature'].native, signed, ec.ECDSA(hashes.SHA256()))
    else:
        key.verify(signer['signature'].native, signed, padding.PKCS1v15(), hashes.SHA256())
    return content


def device():
    agent = dict.fromkeys(('platform', 'brand', 'model', 'version', 'deviceId', 'phoneNumber', 'countryIso',
                          'timeZoneId', 'telecom', 'simSerialNumber', 'subscriberId', 'appVersion', 'phoneName',
                          'appName', 'uid', 'hUid', 'terminalInfoId', 'etcStr', 'userAgent'), '')
    agent.update(platform='Android', brand='SYNTHETIC', model='SYNTHETIC', version='14',
                 deviceId='SYNTHETIC-CORPORATE-DEVICE', hUid='SYNTHETIC-CORPORATE-DEVICE', uid='SYNTHETIC-ID',
                 appVersion='6.2.2', appName='HanaNCBS', userAgent='SYNTHETIC-WebView', deviceWidth=400,
                 deviceHeight=800, timeZoneId='Asia/Seoul')
    return {'custom_user_agent': agent}


class FakeBank:
    def __init__(self, case, method='2'):
        self.case, self.method, self.calls = case, method, []
        self.corporate_cookies = [{'name': 'SYNTHETIC-CORPORATE-COOKIE'}]
        self.personal_cookies = [{'name': 'SYNTHETIC-PERSONAL-COOKIE'}]
        self.modifiers = {}
        self.external_text = 'SYNTHETIC 서버 원문 +%&'
        self.details = [{'elecSignOtxtDat': self.external_text, 'opaque': 'keep-1'},
                        {'elecSignOtxtDat': 'SYNTHETIC second', 'opaque': 'keep-2'}]
        self.secret_error = False
        self.personal_modifier = lambda path, value: value

    def __call__(self, scope, method, url, headers, body, cookies, timeout):
        parsed = urlsplit(url)
        self.calls.append((scope, method, parsed.netloc, parsed.path, copy.deepcopy(headers), body, copy.deepcopy(cookies)))
        if parsed.netloc == 'cmb.hanabank.com':
            stage = next(k for k, path in protocol.PATHS.items() if path == parsed.path)
            self.case.assertEqual(cookies, [] if stage == 'emergency' else self.corporate_cookies)
            self.case.assertNotIn('access-token', headers)
            self.case.assertNotIn('one-access-token', headers)
            self.case.assertEqual(json.loads(headers['CUSTOM_USER_AGENT']), device()['custom_user_agent'])
            if stage in ('emergency', 'app-info') or stage == 'nonce' and self.method == '2':
                self.case.assertEqual((method, body, headers['Content-Type']), ('POST', b'', 'application/json'))
            elif stage in ('nonce', 'onesign-confirm'):
                self.case.assertEqual((method, body), ('GET', None))
            values = {'emergency': {'emergency_yn': 'N'},
                      'app-info': {'appInfo': {'minVerNo': '6.2.0', 'prsVerNo': '6.2.2'}, 'noticeInfo': None},
                      'nonce': {'delfinoNonce': 'SYNTHETIC +한글~*'},
                      'onesign-request': {'RSLT_NM': 'SYNTHETIC', 'txid': 'SYNTHETIC-TX'},
                      'onesign-confirm': {'ACPN_PROC_RSLT_CD': '2', 'ELEC_SIGN_VLU_DAT': 'SYNTHETIC-CONFIRMED-SIGNATURE'},
                      'login': {'LOGIN_RESULT': 'OK', 'SMT_PHBK_NTRY_YN': 'Y', 'USR_MGNT_NO': 'SYNTHETIC-COMPANY', 'PSNL_ENPR_YN': 'Y'},
                      'withdrawal-info': {}, 'customer-check': {'AUTH_58_YN': 'N'}}
            if stage == 'onesign-request':
                fields = parse_qs(body.decode(), keep_blank_values=True)
                self.case.assertIn('하나인증서 로그인[LOGIN]', fields['tbsData'][0])
                self.case.assertTrue(fields['tbsData'][0].endswith('SYNTHETIC%20%2B%ED%95%9C%EA%B8%80~*'))
            if stage == 'login':
                fields = parse_qs(body.decode(), keep_blank_values=True)
                self.case.assertEqual(fields['LGIN_CERT_METH_CD'], [self.method])
                self.case.assertEqual(fields['COMM_HEAD[LGIN_CERT_METH_CD]'], [self.method])
                signature = fields['COMM_HEAD[SIGNED_MSG]'][0]
                if self.method == '2':
                    self.case.assertEqual(fields['COMM_HEAD[TKN_ISS_NO1]'], [''])
                    self.case.assertEqual(fields['COMM_HEAD[TKN_ISS_NO2]'], [''])
                    self.case.assertEqual(verify_cms(signature, self.case.rsa_cert), b'login=certLogin&delfinoNonce=SYNTHETIC+%2B%C7%D1%B1%DB%7E*')
                else:
                    self.case.assertEqual(signature, 'SYNTHETIC-CONFIRMED-SIGNATURE')
            value = {'headerData': {'status': '200'}, 'data': values[stage]}
            if stage in self.modifiers:
                value = self.modifiers[stage](value)
            return 200, [], json.dumps(value).encode(), self.corporate_cookies
        if scope == 'ra':
            self.case.assertEqual(parsed.netloc, 'hanacert.hanabank.com')
            self.case.assertNotEqual(cookies, self.corporate_cookies)
            path = '/' + parsed.path.rsplit('/', 1)[1]
            if path == '/nonce':
                value = {'resultCode': 0, 'nonce': 'SYNTHETIC-RA-NONCE'}
            else:
                self.case.assertEqual(path, '/requestSecretE')
                expected = pin.request_secret_body(self.case.material, self.case.ecc_cert, 'SYNTHETIC-RA-NONCE', '')
                self.case.assertEqual(json.loads(body), expected)
                salt = bytes(range(16))
                key = pin.repeated_sha256(1024, b'SYNTHETIC-RA-NONCE', salt)
                encrypted = AES.new(key, AES.MODE_CBC, hashlib.sha256(salt).digest()[:16]).encrypt(pad(RA_SECRET.encode(), 16))
                value = {'resultCode': 64001} if self.secret_error else {'resultCode': 0, 'requestSecret': pin.b64url(salt + encrypted)}
            return 200, [], json.dumps(value).encode(), []
        self.case.assertEqual(parsed.netloc, 'oqf.hanabank.com:8443')
        self.case.assertNotEqual(cookies, self.corporate_cookies)
        self.case.assertNotIn('CUSTOM_USER_AGENT', headers)
        path = parsed.path.removeprefix('/oqf')
        if method == 'GET':
            name, val = {'app_public_key': ('key-save-status', 'Successful'),
                         'app_first_access': ('nonce', 'SYNTHETIC-NONCE'),
                         'get_access_token': ('access-token', 'SYNTHETIC-ACCESS')}[path.rsplit('/', 1)[1]]
            return 200, [(name, val)], b'', self.personal_cookies
        self.case.assertEqual(cookies, self.personal_cookies)
        self.case.assertEqual(headers['one-access-token'], '')
        self.case.assertEqual(hana_protocol.decode_header(headers['hana-com-header'])['CNL_HDPT']['SCRN_ID'], 'COMB0306001401')
        request = json.loads(body)
        if path == onesign.PRE:
            self.case.assertEqual(request['custNoWtBox'], 'SYNTHETIC-CUSTOMER')
            value = {'rsltCd': 'NORMAL', 'easnCertPtcl': {'certTrscId': 'SYNTHETIC-RETURNED-TX', 'easnCertDtlsList': self.details}}
        else:
            self.case.assertEqual(path, onesign.SUBMIT)
            self.case.assertEqual(request['certTrscId'], 'SYNTHETIC-RETURNED-TX')
            self.case.assertIs(request['tst'], False)
            rows = request['easnCertSignList']
            self.case.assertEqual(verify_cms(rows[0]['elecSignVluDat'], self.case.ecc_cert), self.external_text.encode())
            self.case.assertEqual(rows[0]['elecSignVluDat'], rows[1]['elecSignVluDat'])
            self.case.assertEqual([{k: v for k, v in r.items() if k != 'elecSignVluDat'} for r in rows], self.details)
            value = {'rsltCd': 'NORMAL'}
        head = [('hana-sys-header', hana_protocol.encode_header({'CHNL_SYS_HDPT': {'PROC_RSLT_DV_CD': '0'}}))]
        return 200, head, json.dumps(self.personal_modifier(path, value)).encode(), self.personal_cookies


class CorporateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_private = RSA.generate(2048).export_key(format='DER', pkcs=8)
        cls.rsa_cert = certificate(cls.rsa_private)
        cls.ecc = ECC.generate(curve='P-256')
        cls.ecc_cert = certificate(cls.ecc.export_key(format='DER', use_pkcs8=True))
        cls.encrypted = crypto.encrypt(cls.rsa_private, PASSWORD)
        cls.template = shared.initial({'secure_token': 'SYNTHETIC-TOKEN', 'service_profile': {
            'system_header': {'CHNL_SYS_HDPT': {'synthetic': True}}, 'channel_header': {'CNL_HDPT': {'synthetic': True}}}})

    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.home = Path(temporary).resolve() / 'home'
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(self.home)}))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))

    def joint(self):
        Registry().import_npki('shared', self.rsa_cert, self.encrypted, PASSWORD.encode())
        store.create('company', device())
        return FakeBank(self)

    def hana_certificate(self):
        with State('shared-one', PASSWORD, copy.deepcopy(self.template)) as state:
            device_id = state.snapshot()['profile']['device_id']
            self.material = pin.derive_pin(PIN, device_id=device_id, pin_salt='', pin_spec_version=2)
            alias = KeyStore(state, device_id).import_key(self.ecc_cert, SimpleNamespace(key=self.ecc, r=bytes(range(32))),
                                                        self.material, RA_SECRET, '')
            with state.transaction() as value:
                value['profile']['customer_number'] = 'SYNTHETIC-CUSTOMER'
                value['profile']['enrollment'] = {'state': 'ready', 'alias': alias}
            self.before_record = state.snapshot()['records']
        store.create('company', device())
        return FakeBank(self, 'S')

    def run_login(self, bank, method='2'):
        return login.login('company', method, 'shared' if method == '2' else 'shared-one', send=True,
                           inputs={'password': lambda: PASSWORD.encode() if method == '2' else PASSWORD, 'pin': lambda: PIN}, exchange=bank)

    def test_joint_login_wire_cms_and_shared_store(self):
        bank = self.joint()
        before = (Registry().root / 'index.json').read_bytes()
        result = self.run_login(bank)
        self.assertTrue(result['accepted'], result)
        self.assertEqual(result['processing_status'], 'completed', result)
        self.assertEqual([r[3] for r in bank.calls], [protocol.PATHS[k] for k in ('emergency', 'app-info', 'nonce', 'login', 'withdrawal-info', 'customer-check')])
        saved = storage.read_json(store.session_path('company') / 'session.json')
        self.assertEqual(saved['credential']['ref'], 'shared')
        self.assertEqual(saved['login_response']['USR_MGNT_NO'], 'SYNTHETIC-COMPANY')
        self.assertEqual((Registry().root / 'index.json').read_bytes(), before)
        for path in store.session_path('company').rglob('*'):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotIn(self.rsa_private, path.read_bytes())
        self.assertNotIn('SYNTHETIC-COMPANY', json.dumps(result))

    def test_onesign_uses_existing_key_and_no_personal_bank_login(self):
        bank = self.hana_certificate()
        result = self.run_login(bank, 'S')
        self.assertTrue(result['accepted'], result)
        self.assertEqual(result['external_auth_status'], 'accepted')
        saved = storage.read_json(store.session_path('company') / 'session.json')
        self.assertEqual(saved['credential']['type'], 'onesign')
        self.assertEqual(saved['credential']['ref'], 'shared-one')
        with State('shared-one', PASSWORD) as state:
            self.assertEqual(state.snapshot()['records'], self.before_record)
            self.assertEqual(len(state.snapshot()['records']), 1)
        paths = [r[3] for r in bank.calls]
        self.assertNotIn('/oqf' + pin.LOGIN_PATH, paths)
        self.assertNotIn('/oqf' + pin.BANK_NONCE_PATH, paths)
        self.assertNotIn(PASSWORD, json.dumps(result))
        self.assertNotIn(PIN, json.dumps(result))

    def test_login_success_survives_response_storage_failure(self):
        bank = self.joint()
        original = store.record
        def fail(path, value):
            if path.name == 'response.json' and path.parent.name == 'login':
                raise OSError('SYNTHETIC-PRIVATE')
            return original(path, value)
        with patch.object(store, 'record', side_effect=fail):
            result = self.run_login(bank)
        self.assertIs(result['accepted'], True)
        self.assertIs(result['session_saved'], False)
        self.assertEqual(result['error'], 'response_storage_failed')
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(result))
        self.assertEqual(len(bank.calls), 4)

    def test_success_survives_later_business_error(self):
        bank = self.joint()
        bank.modifiers['customer-check'] = lambda _: {'headerData': {'status': '500', 'errorCode': 'AUTH_58'}, 'data': {}}
        result = self.run_login(bank)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['error'], 'permission_required')

    def test_success_survives_outcome_record_failure(self):
        bank = self.joint()
        original = store.record
        with patch.object(store, 'record', side_effect=lambda p, v: (_ for _ in ()).throw(OSError()) if p.name == 'outcome.json' else original(p, v)):
            result = self.run_login(bank)
        self.assertTrue(result['accepted'])
        self.assertTrue(result['diagnostic_storage_failed'])

    def test_transport_unknown_and_no_second_attempt_or_secret_prompt(self):
        bank = self.joint()
        def broken(*args):
            raise TimeoutError('SYNTHETIC-PRIVATE')
        first = self.run_login(broken)
        self.assertIsNone(first['accepted'])
        self.assertTrue(first['network_used'])
        second = login.login('company', '2', 'shared', send=True, inputs={'password': lambda: self.fail('secret requested')}, exchange=bank)
        self.assertEqual(second['error'], 'login_already_attempted_use_new_session')
        self.assertFalse(second['network_used'])
        self.assertFalse(bank.calls)

    def test_210_login_callback_is_success(self):
        bank = self.joint()
        bank.modifiers['login'] = lambda v: {**v, 'headerData': {'status': 210}}
        self.assertTrue(self.run_login(bank)['accepted'])

    def test_missing_login_result_stays_unknown(self):
        bank = self.joint()
        bank.modifiers['login'] = lambda v: {**v, 'data': {}}
        result = self.run_login(bank)
        self.assertIsNone(result['accepted'])
        self.assertEqual(len(bank.calls), 4)

    def test_enrollment_precedes_ok(self):
        bank = self.joint()
        bank.modifiers['login'] = lambda v: {**v, 'data': {'SMT_PHBK_NTRY_YN': 'N', 'LOGIN_RESULT': 'OK'}}
        result = self.run_login(bank)
        self.assertIsNone(result['accepted'])
        self.assertEqual(result['error'], 'corporate_enrollment_required')

    def test_explicit_login_business_error(self):
        bank = self.joint()
        bank.modifiers['login'] = lambda _: {'headerData': {'status': '959'}, 'data': {}}
        self.assertIs(self.run_login(bank)['accepted'], False)

    def test_onesign_mapping_is_reported_without_registration(self):
        bank = self.hana_certificate()
        bank.modifiers['onesign-confirm'] = lambda v: {**v, 'data': {**v['data'], 'GO_HANA_CERT_REG': 'Y', 'GO_HANA_CERT_AUTO_REG': 'Y'}}
        result = self.run_login(bank, 'S')
        self.assertIsNone(result['accepted'])
        self.assertEqual(result['error'], 'corporate_id_link_required')
        self.assertEqual(bank.calls[-1][3], protocol.PATHS['onesign-confirm'])

    def test_onesign_pending_does_not_poll(self):
        bank = self.hana_certificate()
        bank.modifiers['onesign-confirm'] = lambda v: {**v, 'data': {'ACPN_PROC_RSLT_CD': '1'}}
        result = self.run_login(bank, 'S')
        self.assertEqual(result['error'], 'external_confirmation_pending')
        self.assertEqual(sum(r[3] == protocol.PATHS['onesign-confirm'] for r in bank.calls), 1)

    def test_wrong_pin_never_submits_or_repeats_ra(self):
        bank = self.hana_certificate()
        bank.secret_error = True
        result = self.run_login(bank, 'S')
        self.assertIsNone(result['accepted'])
        self.assertTrue(result['network_used'])
        self.assertEqual(result['error'], 'wrong_pin')
        self.assertEqual(sum(r[3].endswith('/requestSecretE') for r in bank.calls), 1)
        self.assertFalse(any(r[3].endswith('/easnCertElecSign') for r in bank.calls))

    def test_bootstrap_notice_stops_before_nonce(self):
        bank = self.joint()
        bank.modifiers['app-info'] = lambda v: {**v, 'data': {**v['data'], 'noticeInfo': {'text': 'SYNTHETIC-PRIVATE'}}}
        result = self.run_login(bank)
        self.assertEqual(result['error'], 'app_notice_requires_review')
        self.assertEqual(len(bank.calls), 2)

    def test_form_and_tbs_encoding(self):
        self.assertEqual(protocol.form({'COMM_HEAD': {'SIGNED_MSG': 'a+b/c='}, 'empty': {}, 'x': ['a b', None]}),
                         b'COMM_HEAD%5BSIGNED_MSG%5D=a%2Bb%2Fc%3D&x%5B%5D=a%20b&x%5B%5D=')
        self.assertEqual(protocol.joint_tbs('SYNTHETIC +한글~*'), b'login=certLogin&delfinoNonce=SYNTHETIC+%2B%C7%D1%B1%DB%7E*')

    def test_no_send_no_store_or_secrets_in_both_output_formats(self):
        for versioned in (False, True):
            for command, selection in (('login', ['--profile=missing']), ('login-onesign', ['--name=missing'])):
                out = io.StringIO()
                with contextlib.redirect_stdout(out), patch('getpass.getpass', side_effect=AssertionError('secret requested')):
                    code = main((['--format', 'json-v1'] if versioned else []) + ['hana', 'corporate', command, '--session=s', *selection])
                value = json.loads(out.getvalue())
                if versioned:
                    self.assertEqual(value['exit_code'], code)
                    value = value['result']
                self.assertEqual(code, 0)
                self.assertIsNone(value['accepted'])
                self.assertFalse(value['network_used'])
        self.assertFalse(self.home.exists())

    def test_conflicting_selection_stops_before_secret(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch('getpass.getpass', side_effect=AssertionError('secret requested')):
            with self.assertRaises(SystemExit) as raised:
                main(['--format', 'json-v1', 'hana', 'corporate', 'login', '--session=s', '--credential=one', '--profile=two', '--send'])
            code = raised.exception.code
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())['result']['error'], 'invalid_arguments')
        self.assertFalse(self.home.exists())

    def test_multi_sign_response_stops_before_pin(self):
        bank = self.hana_certificate()
        bank.personal_modifier = lambda p, v: {**v, 'easnCertPtcl': {**v['easnCertPtcl'], 'elecCertRqstCd': '004'}} if p == onesign.PRE else v
        result = login.login('company', 'S', 'shared-one', send=True, exchange=bank,
                             inputs={'password': lambda: PASSWORD, 'pin': lambda: self.fail('PIN requested')})
        self.assertEqual(result['error'], 'external_multi_sign_not_supported')
        self.assertFalse(any(r[0] == 'ra' for r in bank.calls))

    def test_one_sign_success_survives_personal_receipt_failure(self):
        bank = self.hana_certificate()
        original = State.record
        def fail(state, run, name, value):
            if name.endswith('-response') and isinstance(value, dict) and 'body' in value:
                raw = base64.b64decode(value['body'])
                if raw == b'{"rsltCd": "NORMAL"}':
                    raise OSError('SYNTHETIC-PRIVATE')
            return original(state, run, name, value)
        with patch.object(State, 'record', fail):
            result = self.run_login(bank, 'S')
        self.assertEqual(result['external_auth_status'], 'accepted')
        self.assertIsNone(result['accepted'])
        self.assertEqual(result['error'], 'response_storage_failed')
        self.assertFalse(any(r[3] == protocol.PATHS['onesign-confirm'] for r in bank.calls))

    def test_empty_callback_stops_without_executing_server_code(self):
        bank = self.hana_certificate()
        bank.modifiers['onesign-confirm'] = lambda v: {**v, 'data': {**v['data'], 'CB_SUCCESS_NAME': ''}}
        self.assertEqual(self.run_login(bank, 'S')['error'], 'external_callback_unhandled')

    def test_unknown_envelope_never_infers_success_or_failure(self):
        for status, value in ((200, {}), (503, {'headerData': {'status': 200}}), (200, {'headerData': {}})):
            self.assertEqual(protocol.assess(status, value)['service_status'], 'unconfirmed')

    def test_wrong_certificate_password_never_requests_nonce(self):
        bank = self.joint()
        result = login.login('company', '2', 'shared', send=True, inputs={'password': lambda: b'wrong'}, exchange=bank)
        self.assertFalse(result['network_used'])
        self.assertFalse(bank.calls)
        self.assertFalse((store.session_path('company') / 'login-attempt.json').exists())

    def test_interrupt_after_login_preserves_acceptance(self):
        bank = self.joint()
        def interrupted(*args):
            if args[2].endswith(protocol.PATHS['withdrawal-info']):
                raise KeyboardInterrupt()
            return bank(*args)
        result = self.run_login(interrupted)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['error'], 'interrupted')
        self.assertFalse(result['automatic_retry'])

    def test_onesign_missing_pin_terminal_stops_without_opening_vault(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch('finance_cli.services.hana_corporate.cli.os.open', side_effect=OSError()), \
             patch('getpass.getpass', side_effect=AssertionError('secret requested')):
            code = main(['hana', 'corporate', 'login-onesign', '--session=s', '--name=one', '--send', '--password-stdin'])
        self.assertEqual(code, 2)
        result = json.loads(out.getvalue())
        self.assertEqual(result['error'], 'pin_terminal_required')
        self.assertFalse(result['network_used'])
        self.assertFalse(self.home.exists())


if __name__ == '__main__':
    unittest.main()
