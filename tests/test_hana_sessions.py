"""Synthetic Hana session flow. A fake transport answers; no socket is ever opened."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from finance_cli.cli.main import main
from finance_cli.credentials.joint import crypto
from finance_cli.credentials.registry import Registry
from finance_cli.services.hana import compat, inquiry, ledger_protocol, store, transport
from finance_cli.services.hana.hana_protocol import encode_header

sys.path.insert(0, str(Path(__file__).parent / 'hometax'))
from test_certificate import synthetic_material

PATHS = {'nonce': '/certsMgnt/createDelfinoNonce', 'login': '/lginMgnt/loginOfclCerts',
         'accounts': '/mainInfoMgnt/retrieveMainAcctInfo'}
ACCOUNT = '12345678901234'


def business(payload, extra=None, code='0'):
    headers = {'hana-sys-header': encode_header({'CHNL_SYS_HDPT': {'PROC_RSLT_DV_CD': code}}),
               'hana-com-header': encode_header({'CNL_HDPT': {'SCRN_ID': 'X'}, 'STD_MSGPT': [{}]})}
    headers.update(extra or {})
    return 200, headers, json.dumps(payload).encode()


class Response:
    def __init__(self, status, headers, body):
        self.code, self.body = status, body
        self.headers = type('Headers', (), {'items': lambda _: list(headers.items())})()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, limit=-1):
        return self.body


class FakeBank:
    """Answers by URL suffix and records every request that would have been sent."""
    def __init__(self):
        self.requests, self.overrides = [], {}

    def opener(self, jar):
        return self

    def open(self, req, timeout=None):
        self.requests.append((req.get_method(), req.full_url, {k.lower(): v for k, v in req.header_items()}, req.data))
        url = req.full_url
        for suffix, answer in self.overrides.items():
            if url.endswith(suffix):
                return Response(*answer)
        if url.endswith('/app_public_key'):
            return Response(200, {'key-save-status': 'Successful'}, b'{}')
        if url.endswith('/app_first_access'):
            return Response(200, {'nonce': 'SERVER-NONCE'}, b'{}')
        if url.endswith('/get_access_token'):
            return Response(200, {'access-token': 'ACCESS-TOKEN'}, b'{}')
        if url.endswith(PATHS['nonce']):
            return Response(*business({'nnce': 'LOGIN NONCE'}))
        if url.endswith(PATHS['login']):
            return Response(*business({'custNo': '1', 'lginCertMethCd': '2'}, {'one-access-token': 'USER-TOKEN'}))
        if url.endswith(PATHS['accounts']):
            return Response(*business({'lginYn': 'Y', 'mainAcctList': [
                {'acctNo': ACCOUNT, 'curCd': 'KRW', 'acctBal': 1000, 'acctSeqNo': ''}]}))
        if url.endswith('/retrievetxnOurTrns'):
            rows = [{'eChnlTrscAcpnNo': 'A1', 'chnlSvcCd': 'B1', 'eChnlTrscUnqNo': 'C1'}]
            return Response(*business({'rec': rows, 'recNcnt': '1'}))
        if url.endswith('/retrieveCurrDtm'):
            return Response(*business({'dt': inquiry.today_kst().strftime('%Y%m%d'), 'tm': '120000', 'bussDdYn': 'Y'}))
        if url.endswith('/retrieveSessAcctInfo'):
            return Response(*business({'acctInfo': {'acctNo': ACCOUNT, 'curCd': 'KRW', 'tailNo': '01'}}))
        if url.endswith('/retrievetxnNrstTrsc'):
            return Response(*business({'grid1': [{'trscDt': '20260929', 'trscAmt': 10}], 'recNcnt1': 1,
                                       'nextTrscYn1': 'N'}))
        if url.endswith('/retrieveTrnsLim'):
            return Response(*business({'dd1TrnsLimAmt': 1, 'bot1TrnsLimAmt': 1, 'scrtMdclDvCd': '1'}))
        if url.endswith('/extendLgin'):
            return Response(*business({}))
        raise AssertionError('Unexpected request: ' + url)


class HanaSessions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.private, _ = synthetic_material()
        cls.password = 'Synthetic-Password!'
        cls.encrypted = crypto.encrypt(cls.private, cls.password)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name).resolve()
        self.root = root
        self.bank = FakeBank()
        for start in (patch.dict(os.environ, {'FINANCE_HOME': str(root / 'state')}),
                      patch('socket.socket', side_effect=AssertionError('No real network')),
                      patch.object(transport, 'opener', self.bank.opener),
                      patch('getpass.getpass', return_value=self.password)):
            start.start()
            self.addCleanup(start.stop)
        Registry().import_npki('personal', self.cert, self.encrypted, self.password.encode())
        (root / 'profile.json').write_text(json.dumps({
            'system_header': {'CHNL_SYS_HDPT': {'TRMS_SYS_CD': 'OQF'}},
            'channel_header': {'CNL_HDPT': {'MBLE_OS': 'AOS'}},
            'secure_token': 'SYNTHETIC-TOKEN', 'profile_provenance': {'source': 'synthetic'}}))
        (root / 'login-input.json').write_text(json.dumps({
            'push_token': 'push', 'fakefinder_install_id': 'install', 'input_provenance': {'source': 'synthetic'}}))
        today = inquiry.today_kst().strftime('%Y%m%d')
        (root / 'query.json').write_text(json.dumps({'account_index': 1, 'start_date': today, 'end_date': today}))
        self.addCleanup(self.temp.cleanup)

    def run_cli(self, *argv, versioned=False):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main((['--format', 'json-v1'] if versioned else []) + ['hana', *argv])
        return code, json.loads(output.getvalue())

    def logged_in(self, session='s1'):
        self.run_cli('session', 'new', '--session', session)
        code, result = self.run_cli('session', 'authenticate', '--session', session,
                                    '--profile-file', str(self.root / 'profile.json'), '--send')
        self.assertEqual((code, result['accepted']), (0, True))
        code, result = self.run_cli('login', '--session', session, '--credential', 'personal',
                                    '--login-input', str(self.root / 'login-input.json'), '--send')
        self.assertEqual((code, result['accepted'], result['user_login_verified']), (0, True, True))
        return session

    def test_prepare_only_commands_never_reach_the_bank(self):
        self.run_cli('session', 'new', '--session', 's1')
        code, result = self.run_cli('session', 'authenticate', '--session', 's1',
                                    '--profile-file', str(self.root / 'profile.json'))
        self.assertEqual((code, result['network_used']), (0, False))
        self.assertEqual(self.bank.requests, [])

    def test_identity_is_random_private_and_never_a_device_value(self):
        self.run_cli('session', 'new', '--session', 's1')
        session = store.session_path('s1')
        identity = store.read_json(session / 'identity.json')
        self.assertEqual(len(identity['android_id']), 16)
        self.assertIn('not the Android ID', identity['provenance'])
        for path in (session / 'identity.json', session / 'app-key.der'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        code, result = self.run_cli('session', 'new', '--session', 's1')
        self.assertEqual(code, 2)

    def test_joint_login_accounts_and_records(self):
        session = store.session_path(self.logged_in())
        # App-auth requests carry the profile headers and a signed token; the login is signed locally.
        methods = [(m, u.rsplit('/', 1)[1]) for m, u, _, _ in self.bank.requests]
        self.assertEqual([name for _, name in methods],
                         ['app_public_key', 'app_first_access', 'get_access_token', 'createDelfinoNonce',
                          'loginOfclCerts'])
        login_body = json.loads(self.bank.requests[-1][3])
        cms = base64.b64decode(login_body['elecSignVluDat'], validate=True)
        self.assertIn(self.cert, cms)
        self.assertEqual(login_body['lginCertMethDtlCd'], '02')
        state = store.read_json(session / 'login-session.json')
        self.assertEqual((state['user_login_verified'], state['login_method']), (True, 'joint certificate'))
        code, result = self.run_cli('accounts', '--session', 's1', '--send')
        self.assertEqual((code, result['accepted'], result['account_count']), (0, True, 1))
        self.assertEqual(self.bank.requests[-1][2]['one-access-token'], 'USER-TOKEN')
        selection = store.read_json(session / 'account-selection.json')
        self.assertEqual(selection['accounts'][0]['index'], 1)
        # A recorded attempt is never sent again.
        code, result = self.run_cli('accounts', '--session', 's1', '--send')
        self.assertEqual(code, 2)
        self.assertEqual(sum(u.endswith(PATHS['accounts']) for _, u, _, _ in self.bank.requests), 1)
        for path in session.rglob('*'):
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600, path)
                self.assertNotIn(self.password.encode(), path.read_bytes())

    def test_a_refusal_stops_the_chain_and_is_not_retried(self):
        self.run_cli('session', 'new', '--session', 's1')
        self.bank.overrides['/app_first_access'] = (200, {}, b'{}')
        code, result = self.run_cli('session', 'authenticate', '--session', 's1',
                                    '--profile-file', str(self.root / 'profile.json'), '--send')
        self.assertEqual((code, result['accepted'], result['stopped_at']), (1, False, 'first-access'))
        self.assertEqual(len(self.bank.requests), 2)
        code, _ = self.run_cli('session', 'authenticate', '--session', 's1',
                               '--profile-file', str(self.root / 'profile.json'), '--send')
        self.assertEqual(code, 2)
        self.assertEqual(len(self.bank.requests), 2)

    def test_unfinished_request_leaves_an_unknown_outcome_marker(self):
        self.run_cli('session', 'new', '--session', 's1')
        with patch.object(self.bank, 'open', side_effect=OSError('timeout')):
            code, _ = self.run_cli('session', 'authenticate', '--session', 's1',
                                   '--profile-file', str(self.root / 'profile.json'), '--send')
        self.assertEqual(code, 2)
        failure = store.read_json(store.session_path('s1') / 'register' / 'failure.json')
        self.assertIn('no automatic replay', failure['outcome'])

    def test_transfer_history_query_uses_the_draft_and_paginates_only_on_request(self):
        self.logged_in()
        self.run_cli('accounts', '--session', 's1', '--send')
        query = str(self.root / 'query.json')
        code, result = self.run_cli('inquiry', 'history', '--session', 's1', '--input', query)
        self.assertEqual((code, result['network_used']), (0, False))
        sent = len(self.bank.requests)
        code, result = self.run_cli('inquiry', 'history', '--session', 's1', '--input', query, '--send')
        self.assertEqual((code, result['accepted'], result['row_count']), (0, True, 1))
        self.assertEqual(len(self.bank.requests), sent + 1)
        body = json.loads(self.bank.requests[-1][3])
        self.assertEqual(body['wdrwAcctNo'], ACCOUNT)
        code, next_page = self.run_cli('inquiry', 'history', '--session', 's1', '--input', query,
                                       '--previous', result['receipt_directory'])
        self.assertEqual(code, 2)  # one complete page: no next page is invented
        code, detail = self.run_cli('inquiry', 'detail', '--session', 's1', '--input', query,
                                    '--previous', result['receipt_directory'], '--row', '1')
        self.assertEqual((code, detail['network_used']), (0, False))

    def test_a_changed_draft_is_not_sent(self):
        self.logged_in()
        self.run_cli('accounts', '--session', 's1', '--send')
        query = str(self.root / 'query.json')
        self.run_cli('inquiry', 'history', '--session', 's1', '--input', query)
        draft = next(store.session_path('s1').glob('inquiry-history-*-prepared.json'))
        value = json.loads(draft.read_text())
        value['body']['srchWdNm'] = 'changed'
        draft.chmod(0o600)
        draft.write_text(json.dumps(value))
        sent = len(self.bank.requests)
        code, _ = self.run_cli('inquiry', 'history', '--session', 's1', '--input', query, '--send')
        self.assertEqual(code, 2)
        self.assertEqual(len(self.bank.requests), sent)

    def test_ledger_chain_and_offline_export(self):
        self.logged_in()
        self.run_cli('accounts', '--session', 's1', '--send')
        query = str(self.root / 'query.json')

        def step(stage, *extra, send=True):
            args = ['history', stage, '--session', 's1', '--input', query, *extra]
            self.run_cli(*args)
            code, result = self.run_cli(*args, '--send') if send else (0, None)
            self.assertEqual((code, result['accepted']), (0, True))
            return result['receipt_directory']
        clock, info = step('clock'), step('account')
        page = step('page', '--clock', clock, '--account-info', info)
        sent = len(self.bank.requests)
        output = self.root / 'history.json'
        code, exported = self.run_cli('history', 'export', '--session', 's1', '--previous', page,
                                      '--output', str(output))
        self.assertEqual((code, exported['row_count'], exported['network_used']), (0, 1, False))
        self.assertEqual(len(self.bank.requests), sent)
        self.assertTrue(output.with_suffix('.csv').read_bytes().startswith('﻿'.encode()))
        code, detail = self.run_cli('history', 'detail', '--session', 's1', '--input', query, '--clock', clock,
                                    '--account-info', info, '--previous', page, '--row', '1')
        self.assertEqual((code, detail['network_used']), (0, False))

    def unified_history(self, **options):
        args = ['history', '--session', 's1', '--account', ACCOUNT,
                '--start', options.pop('start', '20241001'), '--end', options.pop('end', '20241020')]
        for key, value in options.items():
            args.extend(['--' + key, value])
        return self.run_cli(*args, '--send')

    def unified_setup(self):
        self.logged_in()
        self.run_cli('accounts', '--session', 's1', '--send')
        self.bank.overrides['/retrieveCurrDtm'] = business({'dt': '20261010', 'tm': '120000', 'bussDdYn': 'Y'})
        self.bank.overrides['/retrievetxnInoAmtPst'] = business({
            'r01': [{'trscDt': '20241010', 'trscAmt': 5}], 'r01Rowcount': 1})

    def test_unified_history_routes_and_merges_both_orders(self):
        self.unified_setup()
        for order, expected in [('latest', ['recent', 'past']), ('oldest', ['past', 'recent'])]:
            with self.subTest(order=order):
                before = len(self.bank.requests)
                code, result = self.unified_history(order=order)
                self.assertEqual((code, result['complete'], result['accepted']), (0, True, True), result)
                self.assertEqual([row['kind'] for row in result['transactions']], expected)
                calls = self.bank.requests[before:]
                self.assertEqual(len(calls), 4)
                bodies = {r[1].split('/')[-1]: json.loads(r[3]) for r in calls}
                self.assertEqual(bodies['retrievetxnNrstTrsc']['inqStrDt'], '20241011')
                self.assertEqual(bodies['retrievetxnInoAmtPst']['inqEndDt'], '20241010')
                self.assertNotIn('USER-TOKEN', json.dumps(result))

    def test_unified_history_only_requests_needed_period(self):
        self.unified_setup()
        for start, end, kind in [('20241011', '20241020', 'recent'), ('20241001', '20241010', 'past')]:
            before = len(self.bank.requests)
            _, result = self.unified_history(start=start, end=end)
            self.assertTrue(result['complete'], result)
            self.assertEqual([p['kind'] for p in result['pages']], [kind])
            self.assertEqual(len(self.bank.requests) - before, 3)

    def test_unified_history_keeps_rows_after_rejection_and_storage_error(self):
        self.unified_setup()
        self.bank.overrides['/retrievetxnInoAmtPst'] = (500, {}, b'{}')
        _, result = self.unified_history()
        self.assertTrue(result['accepted'])
        self.assertFalse(result['complete'])
        self.assertEqual(len(result['transactions']), 1)
        self.assertFalse(result['stages'][-1]['accepted'])
        original = store.write_new
        def broken(path, value):
            if path.name == 'body.bin' and 'account-history-recent-' in str(path):
                raise OSError('SYNTHETIC-SECRET')
            return original(path, value)
        with patch.object(store, 'write_new', side_effect=broken):
            _, result = self.unified_history(start='20241011')
        self.assertTrue(result['accepted'], result)
        self.assertFalse(result['complete'])
        self.assertNotIn('SYNTHETIC-SECRET', json.dumps(result))

    def test_unified_history_repeated_cursor_stops_preserving_duplicates(self):
        self.unified_setup()
        self.bank.overrides['/retrievetxnNrstTrsc'] = business({
            'grid1': [{'trscDt': '20241012', 'trscAmt': 10}] * 20,
            'recNcnt1': 20, 'nextTrscYn1': 'Y', 'trscSeqNo1': 9})
        before = len(self.bank.requests)
        _, result = self.unified_history()
        self.assertTrue(result['accepted'], result)
        self.assertFalse(result['complete'])
        self.assertEqual(len(result['transactions']), 40)
        self.assertEqual(len(self.bank.requests) - before, 4)
        self.assertIn('continuation_cursor_requires_review', result['warnings'])

    def test_unified_history_plan_does_not_open_store_or_prompt(self):
        from finance_cli.services.hana import onesign_cli
        with patch.object(store, 'session_path', side_effect=AssertionError('store accessed')), \
             patch.object(onesign_cli, 'password', side_effect=AssertionError('secret requested')):
            code, result = self.run_cli('history', '--name', 'missing', '--account', ACCOUNT, versioned=True)
        self.assertEqual(code, 0)
        self.assertFalse(result['result']['network_used'])
        self.assertEqual(self.bank.requests, [])

    def test_security_query_is_two_step_and_reports_from_saved_bytes(self):
        self.logged_in()
        code, result = self.run_cli('security', 'limits', '--session', 's1', '--run', 'limits-1')
        self.assertEqual((code, result['network_used']), (0, False))
        code, result = self.run_cli('security', 'limits', '--session', 's1', '--run', 'limits-1', '--send')
        self.assertEqual((code, result['accepted'], result['state_change_requested']), (0, True, False))
        observation = store.read_json(store.run_path('limits-1') / 'observation.json')
        self.assertEqual(observation['observation']['display']['medium'], 'card')
        code, _ = self.run_cli('security', 'limits', '--session', 's1', '--run', 'limits-1', '--send')
        self.assertEqual(code, 2)

    def test_security_limits_keep_bank_values_separate_from_guidance_in_both_formats(self):
        self.logged_in()
        for versioned in (False, True):
            for index, fields in enumerate((
                {'bot1TrnsLimAmt': '145678901', 'dd1TrnsLimAmt': 650000001,
                 'scrtMdclDvCd': '2', 'mbphOtpYn': 'N', 'trnsLimRslt': False},
                {'bot1TrnsLimAmt': 0, 'dd1TrnsLimAmt': None},
                {},
            )):
                with self.subTest(versioned=versioned, case=index):
                    run = f'limits-{versioned}-{index}'
                    args = ('security', 'limits', '--session', 's1', '--run', run)
                    self.bank.overrides['/retrieveTrnsLim'] = business(fields)
                    sent = len(self.bank.requests)
                    self.run_cli(*args, versioned=versioned)
                    self.assertEqual(len(self.bank.requests), sent)
                    code, output = self.run_cli(*args, '--send', versioned=versioned)
                    result = output['result'] if versioned else output
                    self.assertEqual((code, result['accepted']), (0, True))
                    self.assertEqual(len(self.bank.requests), sent + 1)
                    if versioned:
                        self.assertEqual((output['schema_version'], output['exit_code']), (1, code))
                    report = store.read_json(store.run_path(run) / 'observation.json')
                    observed = report['observation']
                    self.assertEqual(observed['fields'], fields)
                    self.assertEqual(observed['display'], {
                        'medium': 'otp', 'once_ceiling_text': '100,000,000',
                        'daily_ceiling_text': '500,000,000', 'exception_prompt': False})
                    self.assertEqual(observed['diagnostics'], [] if fields else ['display_fields_absent'])
                    self.assertTrue(report['assessment']['accepted'])
                    self.assertNotIn('observation', result)  # stdout stays a summary, not a merged field list.

    def test_login_extension_sends_once_and_keeps_the_login_proof(self):
        session = store.session_path(self.logged_in())
        before = (session / 'login-session.json').read_bytes()
        code, result = self.run_cli('session', 'extend', '--session', 's1', '--run', 'extend-1', '--send')
        self.assertEqual((code, result['accepted'], result['native_client_timer_reset_ms']), (0, True, 600000))
        self.assertEqual((session / 'login-session.json').read_bytes(), before)
        sent = len(self.bank.requests)
        code, _ = self.run_cli('session', 'extend', '--session', 's1', '--run', 'extend-1', '--send')
        self.assertEqual(code, 2)
        self.assertEqual(len(self.bank.requests), sent)

    def test_session_listing_reads_only_metadata(self):
        self.logged_in()
        code, result = self.run_cli('session', 'list')
        self.assertEqual(code, 0)
        self.assertEqual(result['sessions'][0]['user_login_verified'], True)
        self.assertNotIn('USER-TOKEN', json.dumps(result))


class Semantics(unittest.TestCase):
    def test_business_header_rules_differ_for_web_and_native(self):
        ok = business({})[1]
        self.assertEqual(compat.bank_business_headers(list(ok.items()), web=False), '0')
        failed = business({}, code='1')[1]
        with self.assertRaises(compat.ProtocolError):
            compat.bank_business_headers(list(failed.items()), web=True)
        other = business({}, code='9')[1]
        self.assertEqual(compat.bank_business_headers(list(other.items()), web=True), '9')
        with self.assertRaises(compat.ProtocolError):
            compat.bank_business_headers(list(other.items()), web=False)

    def test_native_literals_and_web_values(self):
        self.assertEqual(compat.kotlin_object(b'{a: 1, "b": x, c: null}'), {'a': 1, 'b': 'x', 'c': None})
        self.assertEqual(compat.web_value(b'{"a": 1}'), {'a': 1})
        self.assertEqual(compat.web_value(b'not json'), 'not json')
        self.assertFalse(compat.truthy(0) or compat.truthy('') or compat.truthy(float('nan')))
        self.assertTrue(compat.truthy('0') and compat.truthy([]))

    def test_ledger_plan_splits_at_the_two_year_boundary_and_follows_the_cursor(self):
        config = {'start_date': '20240101', 'end_date': '20260929'}
        plan = ledger_protocol.plan(config, '20260929', ACCOUNT)
        self.assertEqual([s['kind'] for s in plan['segments']], ['recent', 'past'])
        self.assertEqual(ledger_protocol.cursor('recent', {'recNcnt1': 20, 'nextTrscYn1': 'Y', 'trscSeqNo1': '5'}),
                         {'wdrwDstnDt': '', 'dtlsSeqNo': 0, 'trscSeqNo': 5, 'nextTrscYn': 'Y'})
        self.assertIsNone(ledger_protocol.cursor('recent', {'recNcnt1': 19, 'nextTrscYn1': 'Y'}))
        with self.assertRaises(ValueError):
            ledger_protocol.plan({'start_date': '20200101', 'end_date': '20260929'}, '20260929', ACCOUNT)

    def test_inquiry_period_is_limited_to_two_recent_years(self):
        today = inquiry.today_kst().strftime('%Y%m%d')
        inquiry.check_period(today, today)
        with self.assertRaises(ValueError):
            inquiry.check_period('20000101', today)


if __name__ == '__main__':
    unittest.main()
