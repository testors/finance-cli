"""Selected native history over a synthetic encrypted HTTP boundary."""
import base64
import copy
from datetime import datetime
import json
from pathlib import Path
from unittest.mock import Mock, patch
from zoneinfo import ZoneInfo

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.core import storage
from finance_cli.services.shinhan import account_protocol, accounts, history, history_protocol, history_screen, setup, transport
from test_shinhan import PrivateHome, response
from test_shinhan_loan_detail import menu


class HistoryTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.install()
        self.settings = setup.load() | {'menu': menu()}
        self.settings['menu']['R'].append({'B': history_screen.PROGRAM, 'PR_TYPE': 'N',
            'MOVE_URL': history_screen.PROGRAM, 'LOGIN_LEVEL': '2', 'ID_USABLE_YN': 'N'})
        storage.atomic_json(setup.root()/'settings.json', self.settings)
        self.state = {'cookie': 'JSESSIONID=SYN-COOKIE', 'authenticated': True, 'credential': 'SYN-CERT',
                      'login': {'user': {'membGdS2': '02', 'loginLevS2': '8'}}}
        row = {'assetRefKey': 'SYN-ROW', 'assetCtgrId': 'C1', 'assetOrgC': '088',
               'assetPrgId': history_screen.PROGRAM, 'assetAcno': 'SYN-DISPLAY',
               'assetPrgParam': '{P:{acnoS12:"SYN-AC-1",bnkCdS3:"088",assetK:"1"}}'}
        self.graph = {'assetList': [row], 'mainCtgrList': [{'ctgrId': 'C1', 'assetRefKeyList': [{'assetRefKey': 'SYN-ROW'}]}]}
        self.state['accounts'] = {'attempt': 'SYN-LIST', 'credential': 'SYN-CERT',
            'selection_scope': 'visible_shinhan_accounts',
            'categories': account_protocol.categories(account_protocol.decode(json.dumps(self.graph)))}
        self.save()
        self.calls, self.replies = [], []
        def send(payload, cookie, **options):
            document = json.loads(payload); key = bytes.fromhex(self.settings['bank_key'])
            body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(document['dataBody'])), 16))
            self.calls.append((document['dataHeader'], body, cookie, options))
            return self.replies.pop(0)
        self.enterContext(patch.object(transport, 'post', side_effect=send))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))

    def save(self):
        storage.atomic_json(setup.root()/'session.json', self.state)

    def row(self):
        return self.state['accounts']['categories'][0]['assetList'][0]

    def answer(self, body=None, result='SUCCESS'):
        self.replies.append(transport.Reply(200, [], response(result, body)))

    def page(self, *, more=False, atm='Y', date='2026.10.17'):
        self.answer({'rstCL1': 2 if more else 0, 'nxtTrxnoL10': 17, 'nxtSubTrxnoL10': 2**40,
            'masJan': 'SYN-BALANCE', 'grd12': [{'trxdt': date, 'trxTime': '12:34:56', 'ipjiG': 1,
                'ipamt_originalValue': 12345.5, 'jan_originalValue': 45678.5,
                'trxCmmtCtntS24': 'SYN-PRIVATE-TITLE', 'atmYn': atm}]})

    def start(self, *, more=False, **options):
        self.answer({'acno': 'SYN-HEADER', 'acNmS100': 'SYN-PRIVATE-NAME'})
        self.page(more=more)
        return history.run(**options)

    def test_shortest_cli_uses_selected_parameters_default_period_and_private_output(self):
        self.answer({'acno': 'SYN-HEADER'}); self.page()
        clock = Mock(return_value=datetime(2026, 10, 17, 12, tzinfo=ZoneInfo('Asia/Seoul')))
        period = history_screen.period
        with patch.object(history_screen, 'period', side_effect=lambda *args: period(*args, now=clock)):
            code, out, err = self.call(['transactions', '--send'])
        result = json.loads(out)['result']; data = storage.read_json(result['data_file'])
        self.assertEqual((code, result['bank_result'], result['count']), (0, 'success', 1))
        self.assertEqual([call[0]['trxCd'] for call in self.calls], ['RSMDE0105A21', 'RSMDE0105A20'])
        self.assertEqual(self.calls[0][1], {'acno': 'SYNAC1', 'bnkCdS3': '088', 'assetK': '1'})
        query = self.calls[1][1]
        self.assertEqual((query['acno'], query['inqrSjdt'], query['inqrEndt']), ('SYNAC1', '2026.07.17', '2026.10.17'))
        self.assertEqual(clock.call_count, 2)
        self.assertTrue(all(call[3]['path'] == '/serviceEndpoint/httpDigital/' for call in self.calls))
        self.assertTrue(all(call[2] == 'JSESSIONID=SYN-COOKIE' for call in self.calls))
        self.assertTrue(all((call[0]['appG'], call[0]['encG'], call[0]['uuid']) ==
                            ('supersol', '1', self.settings['device']['device_id']) for call in self.calls))
        self.assertEqual(data['header']['accountNumber'], 'SYN-HEADER')
        self.assertEqual(data['pages'][0]['data'][1]['amount'], 12345.5)
        self.assertEqual(Path(result['data_file']).stat().st_mode & 0o777, 0o600)
        public = out+err+(Path(result['data_file']).parent/'report.json').read_text()
        for secret in ('SYNAC1', 'SYN-HEADER', 'SYN-PRIVATE-TITLE', '12345.5', 'SYN-COOKIE'):
            self.assertNotIn(secret, public)

    def test_explicit_filters_next_page_reuses_query_and_long_cursor_without_header(self):
        self.answer({}); self.page(more=True, atm='N')
        args = ['transactions', '--send', '--type', 'atm', '--sort', 'oldest', '--min-amount', '10',
                '--max-amount', '20', '--keyword', 'SYN-KEYWORD', '--start-date', '2026-01-01', '--end-date', '2026-10-17']
        code, out, _ = self.call(args)
        result = json.loads(out)['result']
        self.assertEqual((code, result['count'], result['has_next']), (0, 0, True))
        first = self.calls[-1][1]
        self.page()
        result = json.loads(self.call(['transactions', '--next', '--send'])[1])['result']
        second = self.calls[-1][1]
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(second, first | {'trxno': 17, 'subTrxnoL10': 2**40, 'sttGN1': 1})
        self.assertEqual((result['count'], result['pages_available'], result['has_next']), (1, 2, False))
        data = storage.read_json(result['data_file'])
        self.assertEqual([len(p['data']) for p in data['pages']], [1, 2])
        again = history.run(next_page=True)
        self.assertEqual((again['bank_result'], again['page_result'], again['count']), ('success', 'not_requested', 1))
        self.assertEqual(len(self.calls), 3)

    def test_header_failure_or_unknown_does_not_prevent_page(self):
        for reply, verdict in [(transport.Reply(200, [], response('FAIL', {})), 'failure'),
                               (transport.Reply(error='transport_error'), 'unknown')]:
            with self.subTest(verdict=verdict):
                self.calls.clear(); self.replies.append(reply); self.page()
                result = history.run()
                self.assertEqual((result['bank_result'], result['header_result'], result['page_result']), ('partial_success', verdict, 'success'))
                self.assertEqual((len(self.calls), result['count']), (2, 1))
                self.assertIsNone(storage.read_json(result['data_file'])['header'])

    def test_header_success_decode_error_keeps_acceptance_and_page_data(self):
        for body in (None, {'acJan_originalValue': 'bad'}):
            self.answer(body); self.page()
            result = history.run()
            self.assertEqual((result['bank_result'], result['processing_status'], result['count']), ('success', 'incomplete', 1))
            self.assertEqual(result['header_processing_status'], 'incomplete')

    def test_failed_next_keeps_saved_pages_and_cursor(self):
        for reply, verdict in [(transport.Reply(200, [], response('FAIL', {})), 'failure'),
                               (transport.Reply(error='transport_error'), 'unknown')]:
            self.start(more=True)
            prior = storage.read_json(setup.root()/'session.json')['history']
            self.replies.append(reply); before = len(self.calls)
            result = history.run(next_page=True)
            after = storage.read_json(setup.root()/'session.json')['history']
            self.assertEqual((result['bank_result'], result['page_result'], result['count']), ('partial_success', verdict, 1))
            self.assertEqual(after['cursor'], prior['cursor'])
            self.assertEqual(after['pages'], prior['pages'])
            self.assertEqual(len(self.calls)-before, 1)

    def test_mapping_error_after_acceptance_does_not_advance_cursor(self):
        self.start(more=True)
        prior = storage.read_json(setup.root()/'session.json')['history']
        self.page(date='1800.01.01')
        result = history.run(next_page=True)
        after = storage.read_json(setup.root()/'session.json')['history']
        self.assertEqual((result['bank_result'], result['page_result'], result['processing_status']), ('success', 'success', 'incomplete'))
        self.assertEqual((after['pages'], after['cursor']), (prior['pages'], prior['cursor']))
        self.assertEqual(len(self.calls), 3)

    def test_first_page_failure_is_not_an_exhausted_successful_query(self):
        self.answer({}); self.answer({}, 'FAIL')
        first = history.run()
        self.assertEqual(first['bank_result'], 'partial_success')
        result = history.run(next_page=True)
        self.assertEqual((result['bank_result'], result['required_action']), ('partial_success', 'history_first_page_required'))
        self.assertEqual(result['processing_status'], 'incomplete')
        self.assertNotIn('count', result)
        self.assertEqual(len(self.calls), 2)

    def test_private_file_session_and_final_report_errors_keep_bank_success(self):
        write = storage.atomic_json
        for failing in ('history.json', 'session.json', 'report.json'):
            self.answer({}); self.page()
            def fail(path, value):
                if Path(path).name == failing and (failing != 'report.json' or 'count' in value):
                    raise OSError('SYN-PRIVATE-ERROR')
                return write(path, value)
            with patch.object(storage, 'atomic_json', side_effect=fail):
                result = history.run()
            self.assertEqual((result['bank_result'], result['processing_status'], result['local_status']), ('success', 'complete', 'incomplete'))
            self.assertNotIn('SYN-PRIVATE-ERROR', json.dumps(result))
        self.assertEqual(len(self.calls), 6)

    def test_account_scope_selection_and_credential_boundaries(self):
        baseline = copy.deepcopy(self.state)
        for scope in (None, 'visible_shinhan_loans'):
            self.state['accounts']['selection_scope'] = scope; self.save()
            self.assertEqual(history.run()['required_action'], 'history_account_list_required')
        self.state = copy.deepcopy(baseline)
        row = self.row(); category = self.state['accounts']['categories'][0]
        category['assetList'] = [dict(row, isHide=True), dict(row, orgCode='999'), row]
        self.assertEqual(history.select(self.state, None)[0], row)
        category['assetList'].append(dict(row)); self.save()
        self.assertEqual(history.run()['required_action'], 'history_account_selection_required')
        self.state = copy.deepcopy(baseline); self.state['credential'] = 'SYN-OTHER'; self.save()
        self.assertEqual(history.run()['required_action'], 'history_account_list_required')
        self.assertEqual(self.calls, [])

    def test_new_list_invalidates_next_and_assigns_visible_indices(self):
        self.start(more=True)
        self.answer(self.graph)
        result = accounts.run()
        data = storage.read_json(result['data_file'])
        self.assertEqual(data['categories'][0]['assetList'][0]['index'], 1)
        self.assertEqual(result['selection_scope'], 'visible_shinhan_accounts')
        self.assertEqual(history.run(next_page=True)['required_action'], 'history_query_required')
        self.assertEqual(len(self.calls), 3)

    def test_only_visible_first_button_can_supply_destination_without_popup(self):
        row = self.row(); row['programId'] = ''
        button = account_protocol.button(account_protocol.decode('{"assetBtnPrgId":"BM1509S0011F01","assetBtnParam":"SYN-PARAM"}', account_protocol.BUTTON))
        row['buttonList'] = [button]
        self.assertEqual(history.destination(row), (history_screen.PROGRAM, 'SYN-PARAM'))
        button['isShowPopup'] = True
        with self.assertRaisesRegex(history.Pending, 'history_account_button_confirmation_required'):
            history.destination(row)
        row['buttonList'].insert(0, dict(button, programId='SYN-OTHER'))
        with self.assertRaisesRegex(history.Pending, 'history_destination_unavailable'):
            history.destination(row)
        self.assertEqual(self.calls, [])

    def test_shortcut_and_missing_account_stop_without_using_display_number(self):
        for text, action in [('{shortcutID:"SYN"}', 'history_shortcut_lookup_required'),
                             ('{acno:"SYN-DISPLAY"}', 'history_account_parameters_required')]:
            self.row()['programParam'] = text; self.save()
            self.assertEqual(history.run()['required_action'], action)
        self.assertEqual(self.calls, [])

    def test_notice_confirmation_rechecks_before_both_history_requests(self):
        self.state['intro'] = {'programNotiList': [{'prId': history_screen.PROGRAM, 'notiSeq': 7}]}; self.save()
        self.answer({'notiTitle': 'SYN-PRIVATE-NOTICE'}); self.answer({})
        acknowledge = Mock(return_value=True)
        result = self.start(acknowledge=acknowledge)
        self.assertEqual(result['bank_result'], 'success')
        acknowledge.assert_called_once()
        self.assertEqual([c[0]['trxCd'] for c in self.calls], ['RSMCM9007A11']*2+['RSMDE0105A21', 'RSMDE0105A20'])
        self.assertEqual(result['stages'][0]['stage'], 'history_program_notice')

    def test_blocking_notice_or_login_guard_stops_before_history(self):
        self.row()['programParam'] = '{}'
        self.state['emergency'] = True; self.save()
        self.assertEqual(history.run()['required_action'], 'history_banking_login_required')
        self.assertEqual(self.calls, [])
        del self.state['emergency']
        self.state['intro'] = {'programNotiList': [{'prId': history_screen.PROGRAM, 'notiSeq': 7}]}; self.save()
        self.answer({'notiType': 'BLOCK'})
        self.assertEqual(history.run()['required_action'], 'history_program_notice_blocks_service')
        self.assertEqual(len(self.calls), 1)

    def test_customer_verification_notice_keeps_both_independent_results(self):
        self.state['login']['user']['checkCddDsynS1'] = 'Y'; self.save()
        result = self.start()
        self.assertEqual((result['bank_result'], result['required_action'], result['count']), ('success', 'history_customer_verification_notice', 1))
        self.assertEqual(len(self.calls), 2)

    def test_no_send_invalid_dates_options_and_no_login_never_query(self):
        with patch.object(setup, 'load', side_effect=AssertionError('Settings read')):
            self.assertEqual(json.loads(self.call(['transactions'])[1])['result']['error'], 'send_required')
            for extra in (['--account', '0'], ['--next', '--account', '1'], ['--start-date', '2026-10-17'],
                          ['--start-date', '2026-02-30', '--end-date', '2026-10-17'], ['--min-amount', str(2**63)]):
                self.assertEqual(self.call(['transactions', '--send', *extra])[0], 2)
        self.state['authenticated'] = False; self.save()
        self.assertEqual(json.loads(self.call(['transactions', '--send'])[1])['result']['error'], 'login_required')
        self.assertEqual(self.calls, [])
