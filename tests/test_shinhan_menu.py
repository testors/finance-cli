"""Synthetic menu recovery, selected-row routing and native lookup; no bank IO."""
import base64
import copy
import json
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from finance_cli.core import storage
from finance_cli.services.shinhan import menu, menu_protocol as protocol, loan_detail, session, setup, transport
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, settings, response
from test_shinhan_loan_detail import menu as default_menu


def document(version='SYN-DEFAULT', programs=None):
    value = default_menu() | {'VERSION': version}
    if programs is not None:
        value['R'] = programs
    return value


def reply(value=None, status=200):
    return transport.Reply(status, [], json.dumps(document() if value is None else value).encode())


class MenuTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.install()
        self.settings = setup.load() | {'menu': document()}
        storage.atomic_json(setup.root()/'settings.json', self.settings)
        self.state = {'cookie':'JSESSIONID=SYN-PRIVATE'}
        self.exchange = Exchange(self.settings, self.state, 'synthetic-menu')
        self.loader = menu.Store(self.settings, self.state, self.exchange.report, self.exchange.run)
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))

    def load(self, replies, *, download=True):
        with patch.object(menu, 'get_file', side_effect=replies) as get:
            self.loader.load({'menuDownlYnS1':'Y' if download else 'N', 'menuFileNmS100':'SYN-CURRENT.json'})
        return [call.args[0] for call in get.call_args_list]

    def test_download_and_next_start_use_new_version_without_default_reset(self):
        self.assertEqual(self.load([reply(document('SYN-NEW'))]), ['SYN-CURRENT.json'])
        self.assertEqual(self.state['menu']['value']['VERSION'], 'SYN-NEW')
        self.assertEqual(self.loader.before_start(), 'SYN-NEW')
        self.assertNotIn('menu', self.state)
        self.assertEqual(self.load([], download=False), [])
        self.assertEqual(self.state['menu']['value']['VERSION'], 'SYN-NEW')
        for name in (menu.ACTIVE, menu.BACKUP):
            self.assertEqual((setup.root()/name).stat().st_mode & 0o777, 0o600)

    def test_network_failure_uses_server_default_once_then_backup(self):
        storage.atomic_json(setup.root()/menu.BACKUP, document('SYN-BACKUP'))
        calls = self.load([reply(status=503), transport.Reply(error='menu_transport_error')])
        self.assertEqual(calls, ['SYN-CURRENT.json', menu.DEFAULT])
        self.assertEqual(self.state['menu']['value']['VERSION'], 'SYN-BACKUP')
        self.assertEqual(self.state['menu']['source'], 'backup')
        self.assertTrue(self.state['menu_refresh_needed'])
        self.assertEqual(self.loader.before_start(), 'SYN-DEFAULT')
        self.assertFalse((setup.root()/menu.ACTIVE).exists())

    def test_no_backup_recovers_to_bundled_default_in_order(self):
        self.load([reply(status=404), reply(status=500)])
        parsed = [e for e in self.loader.events if e['action']=='parse']
        self.assertEqual([(e['source'], e['result']) for e in parsed], [('backup','error'), ('default','success')])
        self.assertEqual(self.state['menu']['value']['VERSION'], 'SYN-DEFAULT')

    def test_server_default_success_stops_before_backup(self):
        storage.atomic_json(setup.root()/menu.BACKUP, document('SYN-STALE'))
        self.load([reply(status=403), reply(document('SYN-SERVER-DEFAULT'))])
        self.assertEqual(self.state['menu']['value']['VERSION'], 'SYN-SERVER-DEFAULT')
        self.assertEqual([e['source'] for e in self.loader.events if e['action']=='parse'], ['server_default'])

    def test_invalid_download_parser_result_is_not_download_failure(self):
        storage.atomic_json(setup.root()/menu.BACKUP, document('SYN-OLD'))
        self.assertEqual(self.load([reply({'VERSION':'SYN-INVALID'})]), ['SYN-CURRENT.json'])
        self.assertEqual(self.loader.events[0]['result'], 'success')
        self.assertEqual(self.loader.events[1]['result'], 'error')
        self.assertEqual(self.state['menu']['value']['VERSION'], 'SYN-DEFAULT')
        self.assertFalse((setup.root()/menu.BACKUP).exists())
        self.assertIn('menu_file_copy_error', self.exchange.report['warnings'])

    def test_invalid_server_default_consumes_backup_then_returns_download_success(self):
        storage.atomic_json(setup.root()/menu.BACKUP, document('SYN-BACKUP'))
        self.load([reply(status=500), reply({})])
        self.assertEqual(self.state['menu']['value']['VERSION'], 'SYN-BACKUP')
        self.assertEqual([e['source'] for e in self.loader.events if e['action']=='parse'], ['server_default','backup'])
        self.assertFalse((setup.root()/menu.BACKUP).exists())

    def test_default_copy_and_local_decode_do_not_download(self):
        self.assertEqual(self.load([], download=False), [])
        self.assertTrue(self.state['menu_refresh_needed'])
        self.assertEqual(self.state['menu']['value']['VERSION'], 'SYN-DEFAULT')
        storage.atomic_json(setup.root()/menu.ACTIVE, {'bad':True})
        self.state.pop('menu');self.loader.value=None
        self.assertEqual(self.load([], download=False), [])
        self.assertEqual(self.state['menu']['value']['VERSION'], 'SYN-DEFAULT')

    def test_copy_storage_failure_retains_loaded_menu_and_no_extra_get(self):
        write = storage.write_new
        def fail(path, data):
            if Path(path).name in (menu.ACTIVE,menu.BACKUP):
                raise OSError('SYN-PRIVATE')
            return write(path,data)
        with patch.object(storage,'write_new',side_effect=fail):
            self.assertEqual(self.load([reply(document('SYN-NEW'))]), ['SYN-CURRENT.json'])
        self.assertEqual(self.state['menu']['value']['VERSION'], 'SYN-NEW')
        self.assertEqual(self.exchange.report['menu']['status'],'available')
        self.assertNotIn('SYN-PRIVATE', json.dumps(self.exchange.report))

    def test_updated_program_flags_restrict_selected_row_before_financial_query(self):
        value=document(programs=[{'B':'BM0302S0404F01','PR_TYPE':'W','AND_MIN_APP_VER':'99.0.99','MOVE_URL':'/web/pages/BM/BM03/BM0302/BM0302S0404F01.html'}])
        self.load([reply(value)])
        with self.assertRaises(loan_detail.Pending) as error:
            loan_detail.program(self.settings,self.state,{'programId':'BM0302S0404F01'},self.exchange)
        self.assertEqual(error.exception.action,'loan_program_version_required')

    def lookup(self, body, result='SUCCESS', raw=None):
        self.load([],download=False)
        calls=[]
        def send(payload, cookie, *, path):
            wire=json.loads(payload);key=bytes.fromhex(self.settings['bank_key'])
            data=json.loads(unpad(AES.new(key,AES.MODE_CBC,key[:16]).decrypt(base64.b64decode(wire['dataBody'])),16))
            calls.append((wire['dataHeader'],data,cookie,path))
            return transport.Reply(200,[],response(result,body) if raw is None else raw)
        with patch.object(transport,'post',side_effect=send):
            try: value=menu.resolve(self.exchange,'SYN-UNKNOWN')
            except loan_detail.Pending as error: value=error.action
        return value,calls

    def test_lookup_required_fields_header_encryption_and_trailing_slash(self):
        body=dict.fromkeys(protocol.REMOTE_FIELDS,'') | {'prId':'BM0302S0404F01','prType':'W','loginLevel':'2'}
        value,calls=self.lookup(body)
        self.assertEqual(value['PR_ID'],'BM0302S0404F01')
        self.assertEqual(calls[0][1:],({'prId':'SYN-UNKNOWN'},'JSESSIONID=SYN-PRIVATE','/serviceEndpoint/httpDigital/'))
        self.assertEqual(calls[0][0]['trxCd'],'RSMCM9000H06')
        self.assertEqual(calls[0][0]['uuid'],self.settings['device']['device_id'])
        self.assertEqual(self.exchange.report['program_lookup_result'],'success')

    def test_unknown_rejected_null_and_malformed_body_are_separate(self):
        for body,bank,action in [(None,'SUCCESS','loan_destination_unavailable'), ({},'FAIL','loan_destination_unavailable'),
                ({},'SUCCESS','loan_program_lookup_unverified'), (dict.fromkeys(protocol.REMOTE_FIELDS,''),'SUCCESS','loan_destination_unavailable')]:
            with self.subTest(body=body,bank=bank):
                value,calls=self.lookup(body,bank)
                self.assertEqual(value,action)
                self.assertEqual(len(calls),1)
                self.assertEqual(self.exchange.report['program_lookup_result'],'success' if bank=='SUCCESS' else 'failure')

    def test_local_alias_duplicates_and_length_never_make_server_request(self):
        value=document(programs=[{'B':'BM0302S0404F01','PR_TYPE':'N'}, {'B':'BM0302S0404F01','PR_TYPE':'W'},
                                 {'B':'BM0310S0402F01','PR_TYPE':'W'}])
        self.load([reply(value)])
        with patch.object(transport,'post',side_effect=AssertionError('Unexpected lookup')):
            self.assertEqual(menu.resolve(self.exchange,'BM0302S0404F01')['PR_TYPE'],'W')
            self.assertEqual(menu.resolve(self.exchange,'SYN-OLD-PAGE')['PR_ID'],'BM0310S0402F01')
            with self.assertRaises(loan_detail.Pending):menu.resolve(self.exchange,'😀'*11)

    def test_startup_saves_menu_and_preserves_bank_success_on_menu_error(self):
        storage.atomic_json(setup.root()/'session.json',self.state)
        body={'menuDownlYnS1':'Y','menuFileNmS100':'SYN.json'}
        with patch.object(transport,'post',return_value=transport.Reply(200,[],response('SUCCESS',body))), \
             patch.object(menu,'get_file',return_value=reply(document('SYN-NEW'))):
            result=session.execute('start')
        self.assertEqual((result['bank_result'],result['menu']['status']),('success','available'))
        self.assertEqual(storage.read_json(setup.root()/'session.json')['menu']['value']['VERSION'],'SYN-NEW')
        with patch.object(transport,'post',return_value=transport.Reply(200,[],response('SUCCESS',body))), \
             patch.object(menu.Store,'load',side_effect=OSError('SYN-PRIVATE')):
            result=session.execute('start')
        self.assertEqual(result['bank_result'],'success')
        self.assertEqual(result['menu']['status'],'unavailable')
        self.assertNotIn('SYN-PRIVATE',json.dumps(result))

    def test_menu_parser_required_optional_recursive_keys_and_duplicate_order(self):
        source=document();value=protocol.decode(json.dumps(source))
        self.assertEqual(value['PROGRAM_LIST'][0]['PR_ID'],'BM0302S0404F01')
        self.assertEqual(value['PROGRAM_LIST'][0]['PR_NM'],'')
        source['R']=[{'PR_ID':'SYN-FIRST','B':'SYN-LAST','PR_TYPE':None}]
        self.assertEqual(protocol.decode(json.dumps(source))['PROGRAM_LIST'][0]['PR_ID'],'SYN-LAST')
        for modified in [source|{'VERSION':None},source|{'VERSION':7},source|{'P':[{}]},source|{'R':[None]},source|{'LIGHT_PRG_KEY_DATA':None}]:
            with self.assertRaises(ValueError):protocol.decode(json.dumps(modified))

    def test_anonymous_get_uses_menu_base_and_decodes_gzip_without_bank_cookie(self):
        import gzip
        import io
        from email.message import Message
        class Response(io.BytesIO):
            status=200
            headers=Message()
        value=Response(gzip.compress(json.dumps(document()).encode()))
        value.headers['Content-Encoding']='gzip'
        with patch.object(menu.urllib.request,'urlopen',return_value=value) as send:
            result=menu.get_file('SYN.json')
        request=send.call_args.args[0]
        self.assertEqual(request.full_url,'https://nssol.shinhan.com/images/menu/SYN.json')
        self.assertEqual(request.get_method(),'GET')
        self.assertIsNone(request.get_header('Cookie'))
        self.assertEqual(json.loads(result.body),document())

    def test_lookup_null_first_duplicate_is_not_recovered_by_later_valid_value(self):
        body=dict.fromkeys(protocol.REMOTE_FIELDS,'')
        raw=('{"dataHeader":{"result":"SUCCESS"},"dataBody":{"prId":null,'+json.dumps(body)[1:]+'}').encode()
        value,calls=self.lookup(body,raw=raw)
        self.assertEqual(value,'loan_program_lookup_unverified')
        self.assertEqual(self.exchange.report['bank_result'],'success')
        self.assertEqual(len(calls),1)

    def test_menu_report_error_does_not_change_download_or_recovery_order(self):
        write=storage.atomic_json
        def fail(path, value):
            if Path(path).name=='report.json':raise OSError('SYN-PRIVATE')
            return write(path,value)
        with patch.object(storage,'atomic_json',side_effect=fail):
            self.assertEqual(self.load([reply(document('SYN-NEW'))]),['SYN-CURRENT.json'])
        self.assertEqual(self.state['menu']['value']['VERSION'],'SYN-NEW')
        self.assertEqual(self.exchange.report['menu']['status'],'available')
        self.assertEqual(self.exchange.report['warnings'],['menu_report_save_error'])

    def test_interrupting_menu_download_keeps_received_startup_success(self):
        body={'menuDownlYnS1':'Y','menuFileNmS100':'SYN.json'}
        with patch.object(transport,'post',return_value=transport.Reply(200,[],response('SUCCESS',body))),              patch.object(menu,'get_file',side_effect=KeyboardInterrupt()):
            result=session.execute('start')
        self.assertEqual(result['bank_result'],'success')
        self.assertEqual(result['menu']['status'],'interrupted')
        self.assertEqual(result['processing_status'],'incomplete')
        self.assertTrue(result['session_saved'])
        self.assertEqual(storage.read_json(setup.root()/'session.json')['intro'],body)
