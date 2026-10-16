"""Synthetic account graphs and encrypted HTTP boundary; no bank traffic."""
import base64
import json
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from finance_cli.core import storage
from finance_cli.services.shinhan import account_protocol as protocol, accounts, setup, transport
from test_shinhan import PrivateHome, response, settings


def graph():
    def row(key, category='C15', org='088', **fields):
        return {'assetRefKey': key, 'assetCtgrId': category, 'assetOrgC': org,
                'assetNm': 'SYN-NAME-'+key, 'assetNo_originalValue': 'SYN-PRIVATE-'+key, **fields}
    return {'assetList': [row('deposit', 'C1'), row('parent', assetSno=8,
                subAssetRefKeyList=[{'assetRefKey': key} for key in ('loan', 'loan', 'parent', 'other', 'absent')]),
                row('loan', assetSno=2, assetAmt=-123.5, assetPrgId='SYN-DETAIL', assetPrgParam='{"SYN":"PARAM"}'),
                row('loan', assetSno=-99, assetNm='SYN-LATER'), row('hidden', assetHideYn='Y'),
                row('other', org='999', assetHideYn='Y')],
            'mainCtgrList': [{'ctgrId': 'C15', 'ctgrCustomSno': 2,
                'assetRefKeyList': [{'assetRefKey': key} for key in ('parent', 'loan', 'loan', 'hidden', 'other')]},
                {'ctgrId': 'C1', 'ctgrCustomSno': 1, 'assetRefKeyList': [{'assetRefKey': 'deposit'}]}]}


class ProtocolTests(PrivateHome):
    def test_reference_order_first_match_duplicates_and_bounded_cycles(self):
        categories = protocol.categories(protocol.decode(json.dumps(graph())))
        visible = protocol.visible(categories, loans=True)
        self.assertEqual(len(visible), 1)
        rows = visible[0]['assetList']
        self.assertEqual([row['key'] for row in rows], ['loan', 'loan', 'parent'])
        self.assertEqual(rows[0]['accountName'], 'SYN-NAME-loan')
        self.assertEqual(rows[0]['amount'], -123.5)
        children = rows[-1]['subAccountList']
        self.assertEqual([row['key'] for row in children], ['other', 'loan', 'loan', 'parent'])
        self.assertTrue(all(not row['subAccountList'] for row in children))
        self.assertTrue(children[0]['isHide'])  # No recursive filtering.
        self.assertEqual([item['categoryType'] for item in protocol.visible(categories)], ['CHECKING_ACCOUNT', 'LOAN'])

    def test_optional_null_duplicate_order_and_all_rows_are_decoded(self):
        decoded = protocol.decode('{assetList:[{assetCalcG:"2",assetCalcG:null,assetOrgC:88,assetSno:1e2}],unknown:[1,]}')
        row = protocol.row(decoded['assetList'][0])
        self.assertEqual((row['assetCalcG'], row['orgCode'], row['seqNum']), ('2', '88', 100))
        self.assertEqual(row['balanceUpdate']['kind'], 'Loading')
        self.assertEqual(protocol.decode('{assetList:[{}],assetList:null}')['assetList'], protocol.decode('{assetList:[{}]}')['assetList'])
        self.assertEqual(protocol.decode('{assetList:null}')['assetList'], [])
        for value in ('{assetList:[null]}', '{assetList:[{assetRefKey:{}}]}', '{assetList:[{assetSno:12.0}]}',
                      '{assetList:[{assetAmt:NaN}]}', '{assetList:[{assetSno:2147483648}]}', '{assetList:[],}', 'null'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                protocol.decode(value)

    def test_initial_balance_popup_and_summary(self):
        for org in ('088', '021', '026'):
            row = protocol.row(protocol.decode(json.dumps({'assetOrgC': org}), protocol.ROW))
            self.assertEqual(row['balanceUpdate']['kind'], 'Success')
        for char, popup in (('\xa0', False), ('\x85', True), ('\x1c', False), ('\u200b', True)):
            button = protocol.button(protocol.decode(json.dumps({'assetBtnPopYn': 'Y', 'assetBtnPopMsg': char}), protocol.BUTTON))
            self.assertEqual(button['isShowPopup'], popup)
        self.assertEqual(protocol.summary(protocol.decode('{}', protocol.SUMMARY))['notiMsgContent'], '')

    def test_body_error_preserves_header_verdict_lenient_header_and_duplicates(self):
        for raw in (b'{dataHeader:{result:SUCCESS},dataBody:null}',
                    b'{dataHeader:{result:SUCCESS},dataBody:{assetList:[null]}}'):
            verdict, document = protocol.parse_reply(transport.Reply(200, [], raw))
            self.assertEqual(verdict['bank_result'], 'success')
            self.assertEqual(verdict['processing_status'], 'incomplete')
        verdict, document = protocol.parse_reply(transport.Reply(200, [], b'{dataHeader:{result:SUCCESS,result:FAIL},dataBody:{}}'))
        self.assertEqual(verdict['bank_result'], 'failure')


class AccountWorkflowTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))

    def authenticated(self):
        self.install()
        storage.atomic_json(setup.root()/'session.json', {'cookie': 'JSESSIONID=SYN-SECRET', 'authenticated': True})

    def test_missing_send_does_not_read_settings_or_prompt_and_login_is_explicit(self):
        with patch.object(setup, 'load', side_effect=AssertionError('Settings read')):
            for command in ('accounts', 'loans'):
                code, output, _ = self.call([command])
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(output)['result']['error'], 'send_required')
                self.assertEqual(self.call([command, '--help'])[0], 0)
        self.install()
        storage.atomic_json(setup.root()/'session.json', {'cookie': 'JSESSIONID=SYN'})
        with patch.object(transport, 'post', side_effect=AssertionError('Unexpected HTTP')):
            self.assertEqual(json.loads(self.call(['loans', '--send'])[1])['result']['error'], 'login_required')

    def test_cli_encrypted_request_private_selection_and_redacted_report(self):
        self.authenticated()
        calls = []
        def send(payload, cookie, *, path):
            envelope = json.loads(payload)
            key = bytes.fromhex(settings()['bank_key'])
            body = json.loads(unpad(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(base64.b64decode(envelope['dataBody'])), 16))
            calls.append((path, envelope['dataHeader']['trxCd'], body, cookie))
            return transport.Reply(200, [], response(body=graph()))
        with patch.object(transport, 'post', side_effect=send):
            code, output, _ = self.call(['loans', '--refresh', '--send'])
        result = json.loads(output)['result']
        self.assertEqual(code, 0)
        self.assertEqual(calls, [('/serviceEndpoint/httpDigital/', 'RSMDE0101A20', {'inqrGN2': 9, 'refreshYn': 1}, 'JSESSIONID=SYN-SECRET')])
        self.assertEqual((result['bank_result'], result['count']), ('success', 3))
        from pathlib import Path
        data = Path(result['data_file'])
        self.assertEqual(data.stat().st_mode & 0o777, 0o600)
        rows = storage.read_json(data)['categories'][0]['assetList']
        self.assertEqual(rows[0]['programId'], 'SYN-DETAIL')
        for secret in ('SYN-SECRET', 'SYN-NAME', 'SYN-PRIVATE', 'SYN-DETAIL', 'PARAM'):
            self.assertNotIn(secret, output)
            self.assertNotIn(secret, (data.parent/'report.json').read_text())

    def test_empty_success_failure_unknown_and_body_error_are_distinct(self):
        self.authenticated()
        for reply, bank, count in ((transport.Reply(200, [], response(body={})), 'success', 0),
                (transport.Reply(200, [], response('FAIL', {})), 'failure', None),
                (transport.Reply(error='transport_error'), 'unknown', None),
                (transport.Reply(200, [], response(body=None)), 'success', None)):
            with self.subTest(bank=bank, count=count), patch.object(transport, 'post', return_value=reply) as send:
                result = accounts.run(loans=True)
                self.assertEqual(result['bank_result'], bank)
                self.assertEqual(result.get('count'), count)
                self.assertEqual(send.call_count, 1)
                if count is None:
                    self.assertNotIn('count', result)
                    self.assertNotIn('accounts', storage.read_json(setup.root()/'session.json'))

    def test_data_write_error_does_not_erase_success_or_repeat_request(self):
        self.authenticated()
        original = storage.write_new
        def write(path, data):
            if path.name == 'accounts.json':
                raise OSError('SYN-PRIVATE')
            return original(path, data)
        with patch.object(storage, 'write_new', side_effect=write), patch.object(transport, 'post', return_value=transport.Reply(200, [], response(body=graph()))) as send:
            result = accounts.run(loans=True)
        self.assertEqual((result['bank_result'], result['count'], result['local_status']), ('success', 3, 'incomplete'))
        self.assertNotIn('SYN-PRIVATE', json.dumps(result))
        self.assertEqual(send.call_count, 1)
