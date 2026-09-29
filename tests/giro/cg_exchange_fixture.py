"""Synthetic observation adapter ONLY FOR TESTS, never a live CodeGuard client.

json.loads and the placeholder certificate/native observations below model
test replies, NOT Android/SDK/platform equivalence or clean device evidence.
"""
import base64
import json
from urllib.parse import parse_qs, urlsplit

from giro.codeguard_effects import JavaFault
from giro.codeguard_exchange import UpdaterState
from giro.codeguard_updater import AgentMaterial, UpdaterRuntime
from giro.codeguard_platform import ReadOnce
import test_codeguard_response as response_support

drive = response_support.drive
fault = response_support.fault
sample_state = response_support.sample_state


class Transcript:
    def __init__(self, documents=(), *, overrides=None, cert='c3ludGhldGlj', context='test-context'):
        self.main = sample_state()
        self.runtime = UpdaterRuntime(UpdaterState(),context,'https://synthetic.invalid/',5000,'APP','1')
        self.agent = AgentMaterial(cert,None,'synthetic-engine',False,'synthetic-agent-cookie')
        self.documents = iter(documents)
        self.overrides = overrides or {}
        self.effects, self.requests, self.writes = [],[],[]
        self.responses, self.readers = {},{}
        self.preferences = {'user_agent':'synthetic-UA','GETMODE':False,'ENGINE_VERSION':'cached','CERT':cert}
        self.next_key, self.tick = 1,0

    def reply(self, effect):
        self.effects.append(effect)
        if effect.kind in self.overrides:
            value = self.overrides[effect.kind]
            return value(effect) if callable(value) else value
        return self.default(effect)

    def default(self,e):
        kind,args = e.kind,e.args
        if kind=='clock_ms':
            self.tick += 1
            return self.tick
        if kind=='cpu_abi': return 'arm64-v8a'
        if kind=='native_library_dir': return '/synthetic/arm64'
        if kind=='new_java_random': return 'SYNTHETIC-random-instance'
        if kind=='java_random_seed_and_bytes':
            value = bytes([self.next_key])*16
            self.next_key += 1
            return value
        if kind=='android_parse_x509': return 'SYNTHETIC-cert-object'
        if kind=='certificate_public_key': return 'SYNTHETIC-public-key'
        if kind=='rsa_cipher_instance': return 'SYNTHETIC-cipher'
        if kind=='rsa_cipher_init': return None
        if kind=='rsa_cipher_final': return b'SYNTHETIC-wrapped-'+args[1]
        if kind=='preference_read': return self.preferences.get(args[1],args[2])
        if kind=='preference_write':
            self.preferences[args[1]] = args[2]
            return False if args[3]=='commit' else None
        if kind=='application_info': return 'SYNTHETIC-application-info'
        if kind=='application_native_library_dir': return '/synthetic/lib'
        if kind=='file_exists': return True  # explicit test observation, no disk IO
        if kind=='open_file_input': return 'SYNTHETIC-file-stream'
        if kind=='file_available': return 3
        if kind=='file_read_once': return ReadOnce(3,b'abc')
        if kind=='close_file_input': return None
        if kind=='http_open':
            url = args[0]
            command = int(parse_qs(urlsplit(url).query)['CODEGUARD_CMD'][0])
            expected,fields = next(self.documents)  # missing observations must fail
            assert command == expected, (command,expected)
            connection = 'synthetic-connection-'+str(len(self.requests))
            self.requests.append((command,url,connection))
            self.responses[connection] = fields
            return connection
        if kind=='http_call':
            connection,method,params = args
            if method=='getResponseCode': return 200
            if method in ('getInputStream','getOutputStream'): return connection
            if method in ('setReadTimeout','setConnectTimeout','setRequestMethod','setDoInput',
                          'setDoOutput','setRequestProperty','connect'): return None
            raise AssertionError('unexpected HTTP method '+method)
        if kind=='input_stream_reader':
            reader = args[0]
            self.readers[reader] = iter((json.dumps(self.responses[reader]),None))
            return reader
        if kind=='read_line': return next(self.readers[args[0]])
        if kind in ('close_reader','headers_for_logging','flush_output','close_output'): return None
        if kind=='write_bytes':
            self.writes.append(args)
            return None
        if kind=='set_cookie_header_values': return None
        if kind=='json_object': return json.loads(args[0])
        if kind=='json_string_field':
            obj,name,default = args
            return default if obj.get(name) is None else obj[name]
        if kind=='java_decode_default_charset': return args[0].decode('utf-8')
        if kind=='java_runtime_fault': return fault(args[0],message='SYNTHETIC '+args[1])
        if kind=='oscheck_future': return 'SYNTHETIC-OS-OBSERVATION'
        if kind=='native_start': return 'SYNTHETIC-NATIVE-OBSERVATION'
        if kind=='native_get_nonce': return 'SYNTHETIC-NONCE-OBSERVATION'
        if kind=='read_detail_enabled': return False  # explicit test observation
        if kind=='location_text': return ''
        if kind in ('check_zip_os14','check_fingerprint'): return True  # explicit test observations
        if kind=='split_metadata_boolean': return None  # observed absent test bundle
        if kind=='zip_error_message': return 'synthetic zip detail'
        if kind=='fingerprint_error_message': return 'synthetic fingerprint detail'
        if kind=='format_local_error': return 'SYNTHETIC-LOCAL-ERROR:'+args[1]
        if kind=='returned_token_decode_fault': return fault(message='synthetic decrypt exception')
        raise AssertionError('unhandled synthetic effect '+kind)

    def run(self,generator): return drive(generator,self.reply)
    def kinds(self): return [e.kind for e in self.effects]
    def calls(self,method): return [e for e in self.effects if e.kind=='http_call' and e.args[1]==method]
