"""Synthetic native extensions: one request, no signing, preserved service verdicts."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from finance_cli.cli.main import main
from finance_cli.core import storage
from finance_cli.services.hana import extend as native, hana_protocol, onesign_io, onesign_session
from finance_cli.services.hana.onesign_state import State
from finance_cli.services.hana_corporate import session as corporate, store as corporate_store


class PrivateHome(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name).resolve()
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(self.home)}))
        self.enterContext(patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden')))
        self.calls = []

    def cli(self, args, versioned=False):
        with contextlib.redirect_stdout(io.StringIO()) as stream:
            code = main((['--format', 'json-v1'] if versioned else []) + args)
        value = json.loads(stream.getvalue())
        if versioned:
            self.assertEqual(value['exit_code'], code)
            value = value['result']
        return code, value


class OneSignExtension(PrivateHome):
    def setUp(self):
        super().setUp()
        self.password = 'SYNTHETIC-vault-password'
        self.headers = {'nonce': 'SYNTHETIC-NONCE', 'access-token': 'SYNTHETIC-ACCESS',
                        'one-access-token': 'SYNTHETIC-OAT', 'User-Agent': 'SYNTHETIC/1'}
        self.old_cookies = [{'name': 'SYNTHETIC', 'value': 'SYNTHETIC-OLD'}]
        self.new_cookies = [{'name': 'SYNTHETIC', 'value': 'SYNTHETIC-NEW'}]
        initial = {'sessions': {'login': {'signed_login': True, 'app_authenticated': True,
                    'headers': self.headers, 'cookies': self.old_cookies}}, 'runs': {}}
        with State('personal', self.password, initial):
            pass
        self.head = [('hana-sys-header', hana_protocol.encode_header({'CHNL_SYS_HDPT': {'PROC_RSLT_DV_CD': '0'}})),
                     ('hana-com-header', hana_protocol.encode_header({'CNL_HDPT': {}}))]
        self.status, self.raw = 200, b''

    def exchange(self, scope, method, url, headers, body, cookies, timeout):
        self.calls.append((scope, method, url, headers, body, cookies))
        self.assertEqual((scope, method, url, body), ('bank', 'POST', hana_protocol.API + native.PATH, b''))
        self.assertEqual(headers['one-access-token'], 'SYNTHETIC-OAT')
        self.assertEqual(headers['content-type'], 'application/json')
        if isinstance(self.raw, BaseException):
            raise self.raw
        return self.status, self.head, self.raw, self.new_cookies

    def extend(self, **kwargs):
        with State('personal', self.password) as state:
            return onesign_session.extend(state, send=True, exchange=self.exchange, **kwargs)

    def test_empty_and_non_json_success_with_cookie_update_and_no_token_replacement(self):
        self.head.append(('one-access-token', 'SYNTHETIC-CHANGED'))
        for raw in (b'', b'null', b'false', b'not-json'):
            self.raw = raw
            result = self.extend()
            self.assertTrue(result['accepted'])
            self.assertTrue(result['cookies_saved'])
            self.assertIsNone(result['server_expires_at'])
            self.assertEqual(result['native_client_timer_reset_ms'], 600000)
            self.assertIn('response_one_access_token_differs_from_saved_session', result['warnings'])
            self.assertNotIn('SYNTHETIC', json.dumps(result))
        self.assertEqual(len(self.calls), 4)
        with State('personal', self.password) as state:
            saved = state.snapshot()['sessions']['login']
            self.assertTrue(saved['signed_login'])
            self.assertEqual(saved['headers'], self.headers)
            self.assertEqual(saved['cookies'], self.new_cookies)

    def test_native_failures_and_timeout_are_distinct_and_never_retried(self):
        cases = [(204, self.head, b'', False), (500, self.head, b'{}', False),
                 (200, self.head[:1], b'', False), (200, self.head, TimeoutError('SYNTHETIC-SECRET'), None)]
        for status, headers, raw, accepted in cases:
            self.status, self.head, self.raw = status, headers, raw
            before = len(self.calls)
            result = self.extend()
            self.assertIs(result['accepted'], accepted)
            self.assertEqual(len(self.calls), before + 1)
            self.assertNotIn('SYNTHETIC-SECRET', json.dumps(result))

    def test_same_run_cannot_be_replayed(self):
        self.assertTrue(self.extend(run='once')['accepted'])
        second = self.extend(run='once')
        self.assertFalse(second['network_used'])
        self.assertEqual(len(self.calls), 1)

    def test_missing_and_ambiguous_sessions_stop_before_request(self):
        with State('personal', self.password) as state:
            with state.transaction() as value:
                value['sessions']['second'] = copy.deepcopy(value['sessions']['login'])
        result = self.extend()
        self.assertEqual(result['error'], 'multiple_onesign_sessions_use_session')
        self.assertFalse(self.calls)
        self.assertTrue(self.extend(session='second')['accepted'])
        self.assertFalse(self.extend(session='signup')['network_used'])

    def test_success_survives_receipt_and_cookie_storage_failure(self):
        for fail_cookie in (False, True):
            with State('personal', self.password) as state:
                original_record, original_write = state.record, state._write
                def record(run, name, value):
                    if name.endswith('-response') and not fail_cookie:
                        raise OSError('SYNTHETIC-SECRET')
                    return original_record(run, name, value)
                def write(value):
                    if fail_cookie and value['sessions']['login']['cookies'] == self.new_cookies:
                        raise OSError('SYNTHETIC-SECRET')
                    return original_write(value)
                with patch.object(state, 'record', side_effect=record), patch.object(state, '_write', side_effect=write):
                    result = onesign_session.extend(state, send=True, exchange=self.exchange)
            self.assertTrue(result['accepted'])
            self.assertTrue(result['login_extension_accepted'])
            self.assertEqual(result['processing_status'], 'stopped')
            self.assertFalse(result['cookies_saved'])
            self.assertNotIn('SYNTHETIC-SECRET', json.dumps(result))

    def test_plan_and_short_cli_both_formats(self):
        for versioned in (False, True):
            with (patch('finance_cli.services.hana.onesign_cli.State', side_effect=AssertionError('opened')),
                  patch('finance_cli.services.hana.onesign_cli.password', side_effect=AssertionError('prompted'))):
                code, result = self.cli(['hana', 'onesign', 'extend', '--name', 'personal'], versioned)
            self.assertEqual(code, 0)
            self.assertFalse(result['network_used'])
            with patch('finance_cli.services.hana.onesign_cli.password', return_value=self.password), patch.object(
                    onesign_session, 'Client', side_effect=lambda *args, **kw: onesign_io.Client(*args, **dict(kw, exchange=self.exchange))):
                code, result = self.cli(['hana', 'onesign', 'extend', '--name', 'personal', '--send'], versioned)
            self.assertEqual(code, 0)
            self.assertTrue(result['accepted'])

    def test_identity_lock_is_held_during_request(self):
        def exchange(*args):
            with self.assertRaises(BlockingIOError):
                with State('personal', self.password):
                    self.fail('concurrent identity operation entered')
            return self.exchange(*args)
        with State('personal', self.password) as state:
            result = onesign_session.extend(state, send=True, exchange=exchange)
        self.assertTrue(result['accepted'])


class CorporateExtension(PrivateHome):
    def setUp(self):
        super().setUp()
        corporate_store.create('company', corporate_store.default_device())
        self.path = corporate_store.session_path('company')
        corporate_store.record(self.path / 'login-attempt.json', {'login_method': '1'})
        self.saved = {'channel': 'corporate', 'login_verified': True, 'login_method': '1',
                      'cookies': [{'name': 'SYNTHETIC', 'value': 'SYNTHETIC-COOKIE'}]}
        storage.atomic_json(self.path / 'session.json', self.saved)
        self.raw = b'{"headerData":{"status":"200"},"data":{"result":"SUCCESS","IS_LOGGED_IN":"Y"}}'
        self.status = 200

    def exchange(self, scope, method, url, headers, body, cookies, timeout):
        self.calls.append((method, url, body))
        self.assertEqual((method, url, body), ('POST', 'https://cmb.hanabank.com/CCOM/COM01/RESTART_TIMER.do', b''))
        self.assertEqual(headers['Content-Type'], 'application/json')
        self.assertEqual(headers['Cache-Control'], 'no-cache')
        self.assertEqual(cookies, self.saved['cookies'])
        if isinstance(self.raw, BaseException):
            raise self.raw
        return self.status, [], self.raw, cookies

    def test_success_all_saved_login_methods_without_authentication(self):
        for method in ('1', '2', 'S'):
            storage.atomic_json(self.path / 'session.json', dict(self.saved, login_method=method))
            result = corporate.extend(send=True, exchange=self.exchange)
            self.assertTrue(result['accepted'])
            self.assertTrue(result['login_extension_accepted'])
            self.assertIsNone(result['server_expires_at'])
            self.assertNotIn('SYNTHETIC', json.dumps(result))
        self.assertEqual(len(self.calls), 3)

    def test_endpoint_branch_matrix_and_gson_numeric_spelling(self):
        for code in ('"200"', '200', '"210"', '210', '2e2', '200.0', 'true', '{}', 'null'):
            self.raw = ('{"headerData":{"status":'+code+'},"data":{"result":"SUCCESS","IS_LOGGED_IN":"Y"}}').encode()
            result = corporate.extend(send=True, exchange=self.exchange)
            self.assertIs(result['accepted'], True if code in ('"200"', '200') else None)
        for data in ({}, {'result': 'OTHER'}, {'result': 'SUCCESS', 'IS_LOGGED_IN': {}}, None):
            self.raw = json.dumps({'headerData': {'status': '200'}, 'data': data}).encode()
            self.assertIsNone(corporate.extend(send=True, exchange=self.exchange)['accepted'])

    def test_ended_session_persists_without_erasing_login_proof(self):
        for logged in ('N', None, False):
            storage.atomic_json(self.path / 'session.json', self.saved)
            self.raw = json.dumps({'headerData': {'status': '200'}, 'data': {'result': 'SUCCESS', 'IS_LOGGED_IN': logged}}).encode()
            result = corporate.extend(send=True, exchange=self.exchange)
            self.assertFalse(result['accepted'])
            saved = storage.read_json(self.path / 'session.json')
            self.assertTrue(saved['login_verified'])
            self.assertTrue(saved['session_ended'])
            before = len(self.calls)
            corporate.extend(session='company', send=True, exchange=self.exchange)
            self.assertEqual(len(self.calls), before)

    def test_missing_body_and_interrupted_response_stay_unconfirmed(self):
        for raw in (b'', b'null', b'not-json', TimeoutError('SYNTHETIC-SECRET')):
            self.raw = raw
            result = corporate.extend(send=True, exchange=self.exchange)
            self.assertIsNone(result['accepted'])
            self.assertNotIn('SYNTHETIC-SECRET', json.dumps(result))
        self.assertEqual(len(self.calls), 4)

    def test_success_survives_receipt_or_session_storage_failure(self):
        original = corporate_store.record
        def record(path, value):
            if path.name == 'response.json':
                raise OSError('SYNTHETIC-SECRET')
            return original(path, value)
        with patch.object(corporate_store, 'record', side_effect=record):
            result = corporate.extend(send=True, exchange=self.exchange)
        self.assertTrue(result['accepted'])
        self.assertIn('response_storage_failed', result['stages'][0]['warnings'])
        with patch.object(storage, 'atomic_json', side_effect=OSError('SYNTHETIC-SECRET')):
            result = corporate.extend(send=True, exchange=self.exchange)
        self.assertTrue(result['accepted'])
        self.assertFalse(result['session_saved'])

    def test_lock_prevents_concurrent_extension(self):
        with storage.lock(self.path / 'operation.lock'):
            result = corporate.extend(send=True, exchange=self.exchange)
        self.assertFalse(result['network_used'])
        self.assertFalse(self.calls)

    def test_short_cli_and_plan_both_formats(self):
        original = corporate.extend
        for versioned in (False, True):
            with patch.object(corporate_store, 'select', side_effect=AssertionError('state accessed')):
                code, result = self.cli(['hana', 'corporate', 'session', 'extend'], versioned)
            self.assertEqual(code, 0)
            self.assertFalse(result['network_used'])
            with patch.object(corporate, 'extend', side_effect=lambda **kwargs: original(**kwargs, exchange=self.exchange)):
                code, result = self.cli(['hana', 'corporate', 'session', 'extend', '--send'], versioned)
            self.assertEqual(code, 0)
            self.assertTrue(result['accepted'])
