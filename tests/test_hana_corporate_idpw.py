"""Synthetic ID/password bank exchange; every socket connection is forbidden."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import zipfile

from finance_cli.cli.main import main
from finance_cli.core import storage
from finance_cli.services.hana import nfilter_crypto as crypto, nfilter_format as envelope, store as shared
from finance_cli.services.hana_corporate import idpw, keypad, protocol, store
from test_hana_corporate import device

MAC = bytes(range(20))
PASSWORD = ' aB09!@~* '  # Spaces are significant, including at both ends.


class Bank:
    def __init__(self, case):
        self.case, self.calls, self.modifiers = case, [], {}
        self.cipher = None
        public, _ = crypto.OpenSSL().curve(7)
        self.public_key = base64.b64encode(envelope.public_key_envelope(b'SYNTHETIC', public, MAC)).decode()
        self.client_prefix = len(base64.b64encode(envelope.public_key_envelope(b'', public, MAC)))

    def __call__(self, scope, method, url, headers, body, cookies, timeout):
        self.case.assertEqual((scope, urlsplit(url).netloc), ('bank', 'cmb.hanabank.com'))
        stage = next(k for k, path in protocol.PATHS.items() if path == urlsplit(url).path)
        self.calls.append(stage)
        self.case.assertEqual(cookies, [] if stage == 'emergency' else [{'name': 'SYNTHETIC-CORPORATE'}])
        self.case.assertNotIn('access-token', headers)
        if stage in ('emergency', 'app-info', 'keypad-key'):
            self.case.assertEqual((method, body, headers['Content-Type']), ('POST', b'', 'application/json'))
        if stage == 'login-idpw':
            self.case.assertEqual(method, 'POST')
            self.case.assertEqual(headers['Content-Type'], 'application/x-www-form-urlencoded')
            self.case.assertEqual(headers['User-Agent'], 'okhttp/5.0.0-alpha.10')
            self.case.assertEqual(headers['charset'], 'UTF-8')
            self.case.assertEqual(headers['Cache-Control'], 'no-cache')
            form = parse_qs(body.decode(), keep_blank_values=True)
            self.case.assertEqual(list(form), ['LGIN_CERT_METH_CD', 'VRTL_LGIN_YN', 'USER_ID', 'LOGIN_PW', 'IS_PUSH', 'C2DM_IDNM'])
            self.case.assertEqual({k: v for k, v in form.items() if k != 'LOGIN_PW'}, {
                'LGIN_CERT_METH_CD': ['1'], 'VRTL_LGIN_YN': ['N'], 'USER_ID': ['SYNTHETICID'], 'IS_PUSH': ['N'], 'C2DM_IDNM': ['']})
            self.cipher = form['LOGIN_PW'][0]
            der = base64.b64decode(self.cipher[:self.client_prefix], validate=True)
            info, client_public = envelope.decode_public_key_envelope(der, MAC)
            self.case.assertEqual(info, b'')
            _, shared_x = crypto.OpenSSL().curve(7, client_public)
            self.case.assertEqual(base64.b64decode(self.cipher[self.client_prefix:], validate=True),
                                  crypto.OpenSSL().encrypt(shared_x[:16], PASSWORD.encode('ascii')))
        values = {'emergency': {'emergency_yn': 'N'},
                  'app-info': {'appInfo': {'minVerNo': '6.2.0', 'prsVerNo': '6.2.2'}, 'noticeInfo': None},
                  'keypad-key': {'publicKey': self.public_key},
                  'login-idpw': {'USR_MGNT_NO': 'SYNTHETIC-MGMT', 'PSNL_ENPR_YN': 'Y', 'LOGIN_TIME': 1234},
                  'withdrawal-info': {}, 'customer-check': {'AUTH_58_YN': 'N'}, 'logout': {}}
        response = {'headerData': {'status': '200'}, 'data': values[stage]}
        response = self.modifiers.get(stage, lambda x: x)(response)
        return 200, [], json.dumps(response).encode(), [{'name': 'SYNTHETIC-CORPORATE'}]


class IdPasswordTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve() / 'home'
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(self.home)}))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.enterContext(patch('socket.create_connection', side_effect=AssertionError('Network forbidden')))

    def prepare(self, name='company'):
        store.create(name, device())
        directory = storage.directory(shared.root('settings'))
        if not (directory / 'common.json').exists():
            storage.write_new(directory / 'common.json', json.dumps({
                'format': 'finance-hana-keypad-v1', 'version': '6.2.2', 'keypad_mac': base64.b64encode(MAC).decode()}).encode())
        return Bank(self)

    def execute(self, bank, name='company'):
        return idpw.login(name, 'SyntheticId', 'common', send=True, inputs={'password': lambda: PASSWORD}, exchange=bank)

    def settings_only(self, name='shared-keypad', material=MAC):
        storage.directory(shared.root('settings'))
        storage.write_new(shared.root('settings') / (name + '.json'), json.dumps({
            'format': 'finance-hana-settings-v1', 'version': '1.0.27',
            'keypad_mac': base64.b64encode(material).decode()}).encode())

    def test_minimal_cli_creates_session_and_uses_shared_settings(self):
        self.settings_only()
        bank = Bank(self)
        invoke = idpw.login
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch('getpass.getpass', return_value=PASSWORD) as prompt, \
             patch.object(idpw, 'login', side_effect=lambda *a, **kw: invoke(*a, **kw, exchange=bank)):
            code = main(['hana', 'corporate', 'login-idpw', '--user-id=SyntheticId', '--send'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0, result)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['settings'], 'shared-keypad')
        self.assertTrue(result['session'].startswith('login-'))
        self.assertTrue(store.inspect(result['session'])['attempted'])
        self.assertEqual(prompt.call_count, 1)
        self.assertFalse(shared.root('identities').exists())
        self.assertNotIn(PASSWORD, output.getvalue())

    def test_missing_named_session_is_prepared_once_and_attempt_never_reused(self):
        self.settings_only()
        bank = Bank(self)
        result = idpw.login('chosen', 'SyntheticId', None, send=True, inputs={'password': lambda: PASSWORD}, exchange=bank)
        self.assertTrue(result['accepted'], result)
        self.assertEqual(result['session'], 'chosen')
        blocked = idpw.login('chosen', 'SyntheticId', None, send=True,
                             inputs={'password': lambda: self.fail('reprompt')}, exchange=bank)
        self.assertEqual(blocked['error'], 'login_already_attempted_use_new_session')
        self.assertEqual(bank.calls.count('login-idpw'), 1)

    def test_auto_sessions_isolate_cookies_and_keep_client_identity(self):
        self.settings_only()
        results = [idpw.login(None, 'SyntheticId', None, send=True,
                             inputs={'password': lambda: PASSWORD}, exchange=Bank(self)) for _ in range(2)]
        self.assertTrue(all(row['accepted'] for row in results), results)
        self.assertNotEqual(results[0]['session'], results[1]['session'])
        profiles = [storage.read_json(store.session_path(row['session']) / 'device.json') for row in results]
        self.assertEqual(profiles[0], profiles[1])
        agent = profiles[0]['custom_user_agent']
        self.assertEqual(agent['deviceId'], store.app_uuid(agent['terminalInfoId'], agent['model']))
        self.assertEqual(agent['deviceId'], agent['hUid'])
        self.assertRegex(agent['uid'], '^[0-9a-f]{16}$')
        for path in [store.root().parent / 'client.json', *[store.session_path(row['session']) / 'device.json' for row in results]]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_existing_explicit_device_profile_is_preserved(self):
        bank = self.prepare()
        before = (store.session_path('company') / 'device.json').read_bytes()
        self.assertTrue(self.execute(bank)['accepted'])
        self.assertEqual((store.session_path('company') / 'device.json').read_bytes(), before)
        self.assertFalse((store.root().parent / 'client.json').exists())

    def test_minimal_plan_both_formats_do_not_read_or_create_local_state(self):
        for format_args in ([], ['--format', 'json-v1']):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), patch.object(keypad, 'resolve', side_effect=AssertionError('settings')), \
                 patch.object(store, 'prepare_idpw', side_effect=AssertionError('session')), \
                 patch('getpass.getpass', side_effect=AssertionError('password')):
                code = main([*format_args, 'hana', 'corporate', 'login-idpw', '--user-id=SyntheticId'])
            result = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual((result['result'] if format_args else result)['processing_status'], 'planned')
        self.assertFalse(self.home.exists())

    def test_absent_settings_stop_before_password_and_client_creation(self):
        result = idpw.login(None, 'SyntheticId', None, send=True,
                            inputs={'password': lambda: self.fail('password')}, exchange=lambda *a: self.fail('network'))
        self.assertEqual(result['error'], 'keypad_settings_required_run_setup_extract')
        self.assertFalse(result['network_used'])
        self.assertFalse(self.home.exists())

    def test_same_keypad_material_needs_no_manual_selection(self):
        self.settings_only('first')
        self.settings_only('second')
        self.assertEqual(keypad.resolve(), ('first', MAC))
        self.settings_only('different', bytes(reversed(MAC)))
        result = idpw.login(None, 'SyntheticId', None, send=True, inputs={'password': lambda: self.fail('password')})
        self.assertEqual(result['error'], 'multiple_keypad_settings_specify_settings')
        self.assertFalse(store.root().exists())
        self.assertEqual(keypad.resolve('second'), ('second', MAC))

    def test_explicit_missing_settings_do_not_fall_back(self):
        self.settings_only()
        result = idpw.login(None, 'SyntheticId', 'missing', send=True, inputs={'password': lambda: self.fail('password')})
        self.assertEqual(result['error'], 'keypad_settings_not_found')
        self.assertFalse(store.root().exists())

    def test_client_storage_failure_stops_without_network(self):
        self.settings_only()
        with patch.object(store, 'record', side_effect=OSError('SYNTHETIC-PRIVATE')):
            result = idpw.login(None, 'SyntheticId', None, send=True, inputs={'password': lambda: self.fail('password')})
        self.assertFalse(result['network_used'])
        self.assertIsNone(result['accepted'])
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(result))

    def test_invalid_saved_client_is_not_silently_replaced(self):
        self.settings_only()
        directory = storage.directory(store.root().parent)
        path = directory / 'client.json'
        store.record(path, {'format': 'unsupported'})
        before = path.read_bytes()
        result = idpw.login(None, 'SyntheticId', None, send=True, inputs={'password': lambda: self.fail('password')})
        self.assertEqual(result['error'], 'unsupported_corporate_client')
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse(result['network_used'])

    def test_complete_wire_encryption_cookie_isolation_and_no_certificate(self):
        bank = self.prepare()
        with patch('finance_cli.credentials.registry.Registry.material', side_effect=AssertionError('certificate accessed')), \
             patch('finance_cli.services.hana.onesign_state.State.__enter__', side_effect=AssertionError('vault accessed')):
            result = self.execute(bank)
        self.assertIs(result['accepted'], True, result)
        self.assertEqual(result['processing_status'], 'completed', result)
        self.assertEqual(bank.calls, ['emergency', 'app-info', 'keypad-key', 'login-idpw', 'withdrawal-info', 'customer-check'])
        saved = storage.read_json(store.session_path('company') / 'session.json')
        self.assertEqual(saved['login_method'], '1')
        self.assertEqual(saved['user_id'], 'SYNTHETICID')
        self.assertTrue(saved['login_verified'])
        raw = storage.read_json(store.session_path('company') / 'login-idpw/request.json')
        fields = parse_qs(base64.b64decode(raw['body']).decode(), keep_blank_values=True)
        self.assertEqual(fields['LOGIN_PW'], ['[redacted]'])
        self.assertEqual(fields['USER_ID'], ['[redacted]'])
        for path in store.session_path('company').rglob('*.json'):
            self.assertNotIn(PASSWORD, path.read_text())
            self.assertNotIn(bank.cipher, path.read_text())
        self.assertNotIn('SYNTHETICID', json.dumps(result))
        self.assertEqual(result['follow_up']['app_fds'], 'not_implemented')

    def test_native_status_and_gson_scalar_contract(self):
        for value, expected in [('200', 'accepted'), (200, 'accepted'), ('210', 'rejected'), (210, 'rejected'),
                                (200.0, 'rejected'), ('200.0', 'rejected'), (False, 'rejected'), (' 200', 'rejected'),
                                (None, 'unconfirmed'), ('', 'unconfirmed'), ({}, 'unconfirmed'), ([], 'unconfirmed')]:
            with self.subTest(value=value):
                self.assertEqual(protocol.assess_native(200, {'headerData': {'status': value}})['service_status'], expected)
        self.assertEqual(protocol.assess_native(503, {'headerData': {'status': '200'}})['service_status'], 'unconfirmed')
        self.assertEqual(protocol.assess_native(200, {})['service_status'], 'unconfirmed')

    def test_210_is_not_native_success(self):
        bank = self.prepare()
        bank.modifiers['login-idpw'] = lambda v: {**v, 'headerData': {'status': '210'}}
        result = self.execute(bank)
        self.assertIs(result['accepted'], False)
        self.assertEqual(bank.calls[-1], 'login-idpw')

    def test_certificate_login_fields_do_not_override_native_success(self):
        bank = self.prepare()
        bank.modifiers['login-idpw'] = lambda v: {**v, 'data': {'LOGIN_RESULT': 'NOT_OK', 'SMT_PHBK_NTRY_YN': 'N'}}
        self.assertIs(self.execute(bank)['accepted'], True)

    def test_accepted_with_missing_data_preserves_acceptance(self):
        bank = self.prepare()
        bank.modifiers['login-idpw'] = lambda v: {**v, 'data': None}
        result = self.execute(bank)
        self.assertIs(result['accepted'], True)
        self.assertEqual(result['error'], 'response_data_unavailable')
        self.assertEqual(bank.calls[-1], 'login-idpw')

    def test_missing_status_stays_unknown(self):
        bank = self.prepare()
        bank.modifiers['login-idpw'] = lambda v: {**v, 'headerData': {}}
        self.assertIsNone(self.execute(bank)['accepted'])

    def test_password_error_counts_and_agreement_no_retry_or_secret_echo(self):
        for index, code in enumerate([*protocol.PASSWORD_ERRORS, 'UNFY_AGREE_URL', 'BCBI10114']):
            with self.subTest(code=code):
                name = 'company' + str(index)
                bank = self.prepare(name)
                bank.modifiers['login-idpw'] = lambda v: {**v, 'headerData': {'status': '500', 'errorCode': code, 'errorMessage': 'SYNTHETIC-PRIVATE-ERROR'}}
                result = self.execute(bank, name)
                self.assertIs(result['accepted'], False)
                self.assertEqual(result['business_error_code'], code)
                self.assertEqual(result.get('password_failures_reported'), protocol.PASSWORD_ERRORS.get(code))
                self.assertEqual(bank.calls.count('login-idpw'), 1)
                self.assertNotIn('SYNTHETIC-PRIVATE-ERROR', json.dumps(result))
                self.assertEqual(bank.calls[-1], 'login-idpw')

    def test_unknown_error_code_is_not_echoed(self):
        bank = self.prepare()
        bank.modifiers['login-idpw'] = lambda v: {**v, 'headerData': {'status': '500', 'errorCode': 'SYNTHETIC-PRIVATE-ID'}}
        result = self.execute(bank)
        self.assertEqual(result['reason'], 'business_error')
        self.assertNotIn('SYNTHETIC-PRIVATE-ID', json.dumps(result))

    def test_bad_key_stops_before_password_submission(self):
        bank = self.prepare()
        bank.modifiers['keypad-key'] = lambda v: {**v, 'data': {'publicKey': 'invalid'}}
        result = self.execute(bank)
        self.assertIsNone(result['accepted'])
        self.assertEqual(result['error'], 'keypad_encryption_failed')
        self.assertEqual(bank.calls[-1], 'keypad-key')

    def test_key_210_stops_before_password_submission(self):
        bank = self.prepare()
        bank.modifiers['keypad-key'] = lambda v: {**v, 'headerData': {'status': '210'}}
        self.assertIsNone(self.execute(bank)['accepted'])
        self.assertEqual(bank.calls[-1], 'keypad-key')

    def test_input_boundaries_do_not_normalize_password(self):
        self.assertEqual(protocol.user_id('aBcD0123'), 'ABCD0123')
        self.assertEqual(protocol.user_id('a' * 20), 'A' * 20)
        for value in ('abc', 'a' * 21, ' abcd', 'abc_', 'abcd한', '１２３４'):
            with self.assertRaises(protocol.Stop):
                protocol.user_id(value)
        for value in ('abcdef', 'A' * 16, PASSWORD):
            self.assertEqual(protocol.id_password(value), value)
        for value in ('abcde', 'a' * 17, 'abc\nxyz', 'abc한글xyz', None):
            with self.assertRaises(protocol.Stop):
                protocol.id_password(value)

    def test_invalid_input_no_network_or_attempt(self):
        bank = self.prepare()
        result = idpw.login('company', 'SyntheticId', 'common', send=True, inputs={'password': lambda: 'x' * 17}, exchange=bank)
        self.assertEqual(result['error'], 'invalid_login_password')
        self.assertFalse(bank.calls)
        self.assertFalse((store.session_path('company') / 'login-attempt.json').exists())

    def test_inconsistent_push_rejected_before_password(self):
        bank = self.prepare()
        profile = device()
        profile['push'] = {'is_push': 'Y', 'token': 'SYNTHETIC', 'management_number': ''}
        storage.atomic_json(store.session_path('company') / 'device.json', profile)
        result = idpw.login('company', 'SyntheticId', 'common', send=True, inputs={'password': lambda: self.fail('prompt')}, exchange=bank)
        self.assertEqual(result['error'], 'inconsistent_push_profile')
        self.assertFalse(bank.calls)

    def test_native_form_punctuation_and_null(self):
        self.assertEqual(protocol.native_form({'USER_ID': "SYNTHETIC +~!()'", 'LOGIN_PW': 'SYNTHETIC+/= &~', 'empty': '', 'absent': None, 'star': '*'}),
                         b'USER_ID=SYNTHETIC+%2B%7E%21%28%29%27&LOGIN_PW=SYNTHETIC%2B%2F%3D+%26%7E&empty=&star=*')

    def test_storage_failure_after_success_never_revokes_login(self):
        bank = self.prepare()
        original = store.record
        def fail(path, value):
            if path.name == 'response.json' and path.parent.name == 'login-idpw':
                raise OSError('SYNTHETIC-PRIVATE')
            return original(path, value)
        with patch.object(store, 'record', side_effect=fail):
            result = self.execute(bank)
        self.assertIs(result['accepted'], True)
        self.assertFalse(result['session_saved'])
        self.assertEqual(result['error'], 'response_storage_failed')
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(result))

    def test_followup_errors_allow_customer_check_and_preserve_login(self):
        bank = self.prepare()
        for stage in ('withdrawal-info', 'customer-check'):
            bank.modifiers[stage] = lambda v: {**v, 'headerData': {'status': '500', 'errorCode': 'AUTH_58'}}
        result = self.execute(bank)
        self.assertIs(result['accepted'], True)
        self.assertEqual(result['processing_status'], 'completed')
        self.assertEqual(bank.calls[-1], 'customer-check')
        self.assertEqual(result['follow_up']['customer_guidance'], 'unconfirmed')

    def test_customer_guidance_and_mandatory_logout(self):
        bank = self.prepare()
        bank.modifiers['customer-check'] = lambda v: {**v, 'data': {'CRPN_REG_NO': '1101110672538', 'LGIN_CERT_METH_CD': '1'}}
        result = self.execute(bank)
        self.assertIs(result['accepted'], True)
        self.assertEqual(result['session_current_validity'], 'logged_out')
        self.assertEqual(result['session_usage'], 'certificate_login_required')
        self.assertEqual(bank.calls[-1], 'logout')
        self.assertFalse(storage.read_json(store.session_path('company') / 'session.json')['login_verified'])

    def test_logout_failure_remains_distinct_from_login_acceptance(self):
        bank = self.prepare()
        bank.modifiers['customer-check'] = lambda v: {**v, 'data': {'CRPN_REG_NO': 1101110672538, 'LGIN_CERT_METH_CD': 1}}
        bank.modifiers['logout'] = lambda v: {**v, 'headerData': {'status': '500'}}
        result = self.execute(bank)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['session_current_validity'], 'unverified')
        self.assertEqual(result['follow_up']['logout'], 'unconfirmed')
        self.assertEqual(result['session_usage'], 'certificate_login_required')

    def test_edd_branches_require_no_automatic_registration(self):
        for edd in ('Y', 'Y1', 'Y2'):
            for quality in ('014', 'other'):
                self.assertEqual(protocol.customer_guidance({'eddCddPopUpYn': edd, 'CUST_QUAL_CD': quality}),
                                 'customer_verification_choice_required' if quality == '014' else 'visit_branch_notice')
        bank = self.prepare()
        bank.modifiers['customer-check'] = lambda v: {**v, 'data': {'eddCddPopUpYn': 'Y', 'CUST_QUAL_CD': '014'}}
        result = self.execute(bank)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['follow_up']['customer_guidance'], 'customer_verification_choice_required')
        self.assertEqual(bank.calls[-1], 'customer-check')

    def test_timeout_consumes_attempt_without_reprompt_or_retry(self):
        bank = self.prepare()
        def interrupted(*args):
            if args[2].endswith(protocol.PATHS['login-idpw']):
                raise TimeoutError('SYNTHETIC-PRIVATE')
            return bank(*args)
        result = self.execute(interrupted)
        self.assertIsNone(result['accepted'])
        self.assertEqual(result['error'], 'transport_interrupted_no_automatic_retry')
        retry = idpw.login('company', 'SyntheticId', 'common', send=True, inputs={'password': lambda: self.fail('reprompt')}, exchange=bank)
        self.assertFalse(retry['network_used'])
        self.assertEqual(retry['error'], 'login_already_attempted_use_new_session')

    def test_interrupt_after_success_is_preserved(self):
        bank = self.prepare()
        def interrupted(*args):
            if args[2].endswith(protocol.PATHS['withdrawal-info']):
                raise KeyboardInterrupt()
            return bank(*args)
        result = self.execute(interrupted)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['error'], 'interrupted')

    def test_no_send_no_disk_or_input_for_both_cli_formats(self):
        for format_args in ([], ['--format', 'json-v1']):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), patch('getpass.getpass', side_effect=AssertionError('prompt')), \
                 patch.object(keypad, 'load', side_effect=AssertionError('settings read')):
                code = main([*format_args, 'hana', 'corporate', 'login-idpw', '--session=missing', '--user-id=SyntheticId', '--settings=missing', '--password-stdin'])
            result = json.loads(out.getvalue())
            if format_args:
                self.assertEqual(result['exit_code'], code)
                result = result['result']
            self.assertEqual(code, 0)
            self.assertFalse(result['network_used'])
        self.assertFalse(self.home.exists())

    def test_cli_password_stdin_preserves_spaces_and_reads_one_line(self):
        self.settings_only()
        bank = Bank(self)
        invoke = idpw.login
        stream = io.TextIOWrapper(io.BytesIO((PASSWORD + '\r\nDO-NOT-READ\n').encode()))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch('sys.stdin', stream), patch('getpass.getpass', side_effect=AssertionError('prompt')), \
             patch.object(idpw, 'login', side_effect=lambda *a, **kw: invoke(*a, **kw, exchange=bank)):
            code = main(['--format', 'json-v1', 'hana', 'corporate', 'login-idpw', '--user-id=SyntheticId', '--password-stdin', '--send'])
        self.assertEqual(code, 0, out.getvalue())
        self.assertTrue(json.loads(out.getvalue())['result']['accepted'])
        self.assertEqual(stream.buffer.read(), b'DO-NOT-READ\n')

    def test_fresh_crypto_and_all_printable_ascii(self):
        bank = self.prepare()
        first = crypto.encrypt_character_password(bank.public_key, PASSWORD, MAC)
        second = crypto.encrypt_character_password(bank.public_key, PASSWORD, MAC)
        self.assertNotEqual(first, second)
        chars = ''.join(map(chr, range(32, 127)))
        for offset in range(0, len(chars), 16):
            text = chars[offset:offset + 16]
            value = crypto.encrypt_character_password(bank.public_key, text, MAC)
            _, public = envelope.decode_public_key_envelope(base64.b64decode(value[:bank.client_prefix]), MAC)
            _, shared_x = crypto.OpenSSL().curve(7, public)
            self.assertEqual(base64.b64decode(value[bank.client_prefix:]), crypto.OpenSSL().encrypt(shared_x[:16], text.encode('ascii')))
        with self.assertRaises(ValueError):
            crypto.encrypt_character_password(bank.public_key, PASSWORD, b'wrong')

    def test_setup_synthetic_package_and_shared_settings_without_enrollment(self):
        data = b'SYNTHETIC-HEADER' + MAC + b'SYNTHETIC-TAIL'
        path = self.home.parent / 'synthetic-package.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr(keypad.ENTRY, data)
        with patch.object(keypad, 'DIGEST', hashlib.sha256(data).hexdigest()), patch.object(keypad, 'OFFSET', len(b'SYNTHETIC-HEADER')):
            result = keypad.install(path, 'company-settings')
            self.assertFalse(result['network_used'])
            self.assertEqual(keypad.load('company-settings'), MAC)
            with self.assertRaises(FileExistsError):
                keypad.install(path, 'company-settings')
        self.assertFalse(shared.root('identities').exists())
        settings = shared.root('settings') / 'existing.json'
        storage.write_new(settings, json.dumps({'format': 'finance-hana-settings-v1', 'version': '1.0.27',
                                               'keypad_mac': base64.b64encode(MAC).decode()}).encode())
        self.assertEqual(keypad.load('existing'), MAC)

    def test_setup_unknown_package_leaves_no_settings(self):
        path = self.home.parent / 'synthetic-package.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr(keypad.ENTRY, b'SYNTHETIC-UNKNOWN')
        with self.assertRaises(protocol.Stop):
            keypad.install(path, 'bad')
        self.assertFalse(shared.root('settings').exists())


    def test_invalid_package_cli_has_structured_error(self):
        path = self.home.parent / 'invalid.zip'
        path.write_bytes(b'SYNTHETIC-NOT-A-PACKAGE')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(['--format', 'json-v1', 'hana', 'corporate', 'setup', 'extract', '--package', str(path), '--settings=bad'])
        result = json.loads(out.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(result['result']['error'], 'invalid_keypad_package')
        self.assertNotIn(str(path), out.getvalue())

    def test_success_survives_outcome_failure(self):
        bank = self.prepare()
        record = store.record
        def fail(path, value):
            if path.name == 'outcome.json':
                raise OSError('SYNTHETIC-PRIVATE')
            return record(path, value)
        with patch.object(store, 'record', side_effect=fail):
            result = self.execute(bank)
        self.assertTrue(result['accepted'])
        self.assertTrue(result['diagnostic_storage_failed'])

    def test_logout_acceptance_survives_session_storage_failure(self):
        bank = self.prepare()
        bank.modifiers['customer-check'] = lambda v: {**v, 'data': {'CRPN_REG_NO': '1101110672538', 'LGIN_CERT_METH_CD': '1'}}
        save = storage.atomic_json
        def fail(path, value):
            if value.get('login_verified') is False and value.get('session_usage'):
                raise OSError('SYNTHETIC-PRIVATE')
            return save(path, value)
        with patch.object(storage, 'atomic_json', side_effect=fail):
            result = self.execute(bank)
        self.assertTrue(result['accepted'])
        self.assertFalse(result['session_saved'])
        self.assertEqual(result['session_current_validity'], 'logged_out')
        self.assertEqual(result['follow_up']['logout'], 'accepted')
        self.assertEqual(result['error'], 'session_storage_failed')


if __name__ == '__main__':
    unittest.main()
