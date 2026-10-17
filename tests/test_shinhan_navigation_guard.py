"""Native notice/account navigation using synthetic bank replies only."""
import base64
import json
from pathlib import Path
from unittest.mock import Mock, patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.core import storage
from finance_cli.services.shinhan import account_protocol, loan_detail, menu_protocol, navigation_guard as guard, netfunnel_http, setup, transport
from test_shinhan import PrivateHome, response
from test_shinhan_loan_detail import menu


class NavigationTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.install()
        self.settings = setup.load() | {'menu': menu()}
        storage.atomic_json(setup.root()/'settings.json', self.settings)
        rows = account_protocol.decode(json.dumps({'assetList': [{'assetRefKey': 'SYN', 'assetCtgrId': 'C15', 'assetOrgC': '088',
            'assetPrgId': 'BM0302S0404F01', 'assetPrgParam': '{"P":{"acno":"SYN-ACCOUNT"}}'}],
            'mainCtgrList': [{'ctgrId': 'C15', 'assetRefKeyList': [{'assetRefKey': 'SYN'}]}]}))
        self.state = {'cookie': 'JSESSIONID=SYN', 'credential': 'SYN', 'authenticated': True,
            'login': {'user': {'ipjiAmtAcntN5': 1}},
            'intro': {'programNotiList': [{'prId': 'BM0302S0404F01', 'notiSeq': 7}]},
            'accounts': {'attempt': 'SYN-LIST', 'credential': 'SYN', 'categories': account_protocol.categories(rows)}}
        self.save()
        self.replies, self.calls = [], []
        def send(payload, cookie, **options):
            value = json.loads(payload); key = bytes.fromhex(self.settings['bank_key'])
            body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(value['dataBody'])), 16))
            self.calls.append((value['dataHeader']['trxCd'], body, options))
            return self.replies.pop(0)
        self.enterContext(patch.object(transport, 'post', side_effect=send))
        self.enterContext(patch.object(transport, 'post_web', side_effect=send))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))

    def save(self):
        storage.atomic_json(setup.root()/'session.json', self.state)

    def reply(self, body=None, result='SUCCESS', **fields):
        self.replies.append(transport.Reply(200, [], response(result, body, **fields)))

    def detail(self):
        self.reply({'acno': 'SYN-ACCOUNT', 'dcTamt': '100'})
        self.reply({'getCurrentDateFmt': {'valueS20': '20261017'}})

    def test_notice_confirm_rechecks_and_fetches_again_before_account_detail(self):
        self.reply({'notiTitle': 'SYN-PRIVATE', 'notiMsg1': '1', 'notiMsg3': ' 3 ', 'notiMsg6': '6'})
        self.reply({'notiType': 'BLOCK'})
        self.detail()
        acknowledge = Mock(return_value=True)
        result = loan_detail.run(acknowledge=acknowledge)
        self.assertEqual(result['detail_result'], 'success')
        self.assertEqual([c[0] for c in self.calls], ['RSMCM9007A11']*2+['RSMLO1002A01', 'RSMCM9000A03'])
        self.assertEqual([c[1] for c in self.calls[:2]], [{'notiSeq': 7}]*2)
        self.assertTrue(all(c[2]['path'] == '/serviceEndpoint/httpDigital' for c in self.calls[:2]))
        acknowledge.assert_called_once()
        self.assertEqual(acknowledge.call_args.args[0], 'SYN-PRIVATE\n1  3  6\n')
        path = Path(result['notice_file'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result['notice_navigation'], 'allowed')
        self.assertNotIn('SYN-PRIVATE', json.dumps(result))
        self.assertNotIn('SYN-PRIVATE', (path.parent/'report.json').read_text())

    def test_network_and_native_parse_errors_allow_navigation_without_confirmation(self):
        replies = [transport.Reply(503, [], b'unavailable'), transport.Reply(error='transport_error'),
                   transport.Reply(204), transport.Reply(200, [], b'null'),
                   transport.Reply(200, [], b'not json'), transport.Reply(200, [], b'{}'),
                   transport.Reply(200, [], b'{"dataHeader":null,"dataHeader":{"result":"SUCCESS"}}'),
                   transport.Reply(200, [], b'{"dataHeader":{"result":"SUCCESS"},"dataHeader":null}'),
                   transport.Reply(200, [], response('OTHER', {})), transport.Reply(200, [], response('FAIL', {})),
                   transport.Reply(200, [], response('SUCCESS', {'notiMsg1': []}))]
        for reply in replies:
            with self.subTest(reply=reply):
                self.calls.clear(); self.replies = [reply]; self.detail()
                acknowledge = Mock(side_effect=AssertionError('Unexpected confirmation'))
                result = loan_detail.run(acknowledge=acknowledge)
                self.assertEqual(result['detail_result'], 'success')
                self.assertEqual(result['notice_result'], 'error')
                self.assertEqual(len(self.calls), 3)

    def test_success_null_notice_body_is_not_repository_error_or_empty_notice(self):
        self.reply()
        result = loan_detail.run()
        self.assertEqual(result['bank_result'], 'success')
        self.assertEqual(result['required_action'], 'loan_program_notice_unverified')
        self.assertEqual(len(self.calls), 1)

    def test_local_size_limit_does_not_imply_native_error_allows_navigation(self):
        self.replies.append(transport.Reply(200, [], b'', 'response_too_large'))
        result = loan_detail.run()
        self.assertEqual(result['required_action'], 'loan_program_notice_unverified')
        self.assertEqual(len(self.calls), 1)

    def test_block_exact_case_stops_even_when_confirmed(self):
        self.reply({'notiType': 'BLOCK'})
        result = loan_detail.run(acknowledge=lambda *args: True)
        self.assertEqual(result['required_action'], 'loan_program_notice_blocks_service')
        self.assertEqual(result['notice_navigation'], 'blocked')
        self.assertEqual(len(self.calls), 1)
        self.calls.clear(); self.reply({'notiType': 'block'}); self.reply({}, 'FAIL'); self.detail()
        self.assertEqual(loan_detail.run(acknowledge=lambda *args: True)['detail_result'], 'success')
        self.assertEqual(len(self.calls), 4)

    def test_noninteractive_pending_dismissal_and_interruption_do_not_query_detail(self):
        for acknowledge, action in [(None, 'loan_program_notice_confirmation_required'),
                                    (lambda *a: False, 'loan_program_notice_dismissed')]:
            self.calls.clear(); self.reply({})
            result = loan_detail.run(acknowledge=acknowledge)
            self.assertEqual(result['required_action'], action)
            self.assertEqual(len(self.calls), 1)
        self.calls.clear(); self.reply({})
        result = loan_detail.run(acknowledge=Mock(side_effect=KeyboardInterrupt))
        self.assertEqual((result['bank_result'], result['error']), ('success', 'interrupted'))
        self.assertEqual(len(self.calls), 1)

    def test_notice_file_failure_does_not_change_confirmation_or_native_result(self):
        self.reply({'notiTitle': 'SYN-PRIVATE'}); self.reply({}); self.detail()
        write = storage.write_new
        def fail_notice(path, content):
            if Path(path).name == 'program-notice.txt':
                raise OSError('SYN-PRIVATE')
            return write(path, content)
        acknowledge = Mock(return_value=True)
        with patch.object(storage, 'write_new', side_effect=fail_notice):
            result = loan_detail.run(acknowledge=acknowledge)
        self.assertEqual(result['detail_result'], 'success')
        self.assertIn('program_notice_save_error', result['warnings'])
        self.assertEqual(acknowledge.call_args.args, ('SYN-PRIVATE\n\n', None, False))

    def test_recheck_earlier_guards_before_second_notice_request(self):
        from finance_cli.services.shinhan.exchange import Exchange
        exchange = Exchange(self.settings, self.state, 'loan_detail')
        self.reply({})
        def confirm(*args):
            self.state['emergency'] = True
            return True
        row = {'programId': 'BM0302S0404F01'}
        with self.assertRaises(guard.Pending) as caught:
            loan_detail.program(self.settings, self.state, row, exchange, confirm)
        self.assertEqual(caught.exception.action, 'loan_banking_login_required')
        self.assertEqual(len(self.calls), 1)

    def test_account_guard_uses_login_counts_even_with_existing_loan_row(self):
        self.settings['menu']['R'][0]['ACCOUNT_CHECK_YN'] = 'Y'
        storage.atomic_json(setup.root()/'settings.json', self.settings)
        self.state['intro'] = {}; self.state['login']['user'] = {}; self.save()
        self.assertEqual(loan_detail.run()['required_action'], 'loan_account_required')
        self.assertEqual(self.calls, [])
        self.state['login']['user']['opbAcnoCnt'] = '1'; self.save(); self.detail()
        result = loan_detail.run()
        self.assertEqual((result['account_guard'], result['detail_result']), ('passed', 'success'))

    def test_group_agreement_follows_notice_and_account_guard_precedes_it(self):
        self.settings['menu']['R'][0]['GRP_AGREE_YN'] = '1'
        storage.atomic_json(setup.root()/'settings.json', self.settings)
        self.reply({}); self.reply({})
        result = loan_detail.run(acknowledge=lambda *args: True)
        self.assertEqual(result['required_action'], 'loan_group_agreement_required')
        self.assertEqual([c[0] for c in self.calls], ['RSMCM9007A11']*2)
        self.settings['menu']['R'][0]['ACCOUNT_CHECK_YN'] = 'Y'
        storage.atomic_json(setup.root()/'settings.json', self.settings)
        self.state['menu'] = {'value': menu_protocol.decode(json.dumps(self.settings['menu'])), 'loaded': True, 'source': 'synthetic'}
        self.state['login']['user'] = {}; self.save(); self.calls.clear()
        self.assertEqual(loan_detail.run()['required_action'], 'loan_account_required')
        self.assertEqual(self.calls, [])

    def test_account_counts_preserve_native_integer_coercion_and_overflow(self):
        for values, expected in [({}, False), ({'ipjiAmtAcntN5': None}, False),
                                 ({'opbAcnoCnt': '1e1'}, True), ({'ipjiAmtAcntN5': -1, 'opbAcnoCnt': 1}, False),
                                 ({'ipjiAmtAcntN5': 2**31-1, 'opbAcnoCnt': 1}, False),
                                 ({'ipjiAmtAcntN5': -2**31, 'opbAcnoCnt': -1}, True)]:
            self.assertEqual(guard.has_account(values), expected)
        for value in (True, [], {}, '1.0', 2**31):
            with self.assertRaises(guard.Pending) as caught:
                guard.account({'ACCOUNT_CHECK_YN': 'Y'}, {'ipjiAmtAcntN5': value})
            self.assertEqual(caught.exception.action, 'loan_account_state_unverified')

    def test_duplicate_intro_last_wins_and_netfunnel_does_not_query_ordinary_notice(self):
        self.state['intro']['programNotiList'].append({'prId': 'BM0302S0404F01', 'popType': '99', 'popLinkId': 'SYN-ACTION'})
        self.save()
        self.detail()
        result = loan_detail.run()
        self.assertEqual(result['detail_result'], 'success')
        self.assertEqual(result['netfunnel'][0]['state'], 'END')
        self.assertEqual(result['netfunnel'][0]['action'], 'SYN-ACTION')
        self.assertEqual([call[0] for call in self.calls], ['RSMLO1002A01', 'RSMCM9000A03'])

    def test_program_queue_block_does_not_open_detail_or_prompt_intro_continue(self):
        self.state['intro']['programNotiList'] = [{'prId': 'BM0302S0404F01', 'popType': '99', 'popLinkId': 'SYN-ACTION'}]
        self.save()
        with patch.object(netfunnel_http, 'get', side_effect=['301:', '{}']):
            result = loan_detail.run(acknowledge=Mock(side_effect=AssertionError('Unexpected prompt')))
        self.assertEqual(result['required_action'], 'loan_netfunnel_blocked')
        self.assertEqual(self.calls, [])

    def test_program_queue_end_directly_opens_destination_without_group_recheck(self):
        self.state['intro']['programNotiList'] = [{'prId': 'BM0302S0404F01', 'popType': '99'}]
        self.settings['menu']['R'][0]['GRP_AGREE_YN'] = '1'
        storage.atomic_json(setup.root()/'settings.json', self.settings)
        self.save(); self.detail()
        self.assertEqual(loan_detail.run()['detail_result'], 'success')

    def test_cli_notice_auto_acknowledges_with_or_without_terminal_and_keeps_stdout_redacted(self):
        self.reply({'notiTitle': 'SYN-PRIVATE'}); self.reply({}); self.detail()
        with patch('sys.stdin.isatty', return_value=True), patch('getpass.getpass', return_value='y') as prompt:
            code, out, err = self.call(['loan-detail', '--send'])
        self.assertEqual(code, 0); prompt.assert_not_called()
        self.assertNotIn('SYN-PRIVATE', out+err)
        self.reply({}); self.reply({}); self.detail()
        with patch('sys.stdin.isatty', return_value=False), patch('getpass.getpass', side_effect=AssertionError('TTY prompt')):
            code, out, err = self.call(['loan-detail', '--send'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['result']['detail_result'], 'success')
