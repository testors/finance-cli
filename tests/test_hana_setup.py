"""Synthetic user packages only: extraction never executes their contents."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from Crypto.PublicKey import ECC
from finance_cli.services.hana import onesign_setup as setup
from finance_cli.services.hana import onesign_bundle as bundle
from finance_cli.services.hana.onesign_state import State
from test_hana_onesign import certificate, PASSWORD


def manifest(version='1.0.27'):
    strings=['manifest','package','com.hanabank.oqf','versionName',version,'versionCode']
    raw=b''
    offsets=[]
    for text in strings:
        data=text.encode()
        offsets.append(len(raw))
        raw+=bytes([len(text),len(data)])+data+b'\0'
    start=28+4*len(strings)
    pool=struct.pack('<HHIIIIII',1,28,start+len(raw),len(strings),0,256,start,0)
    pool+=struct.pack('<'+'I'*len(offsets),*offsets)+raw
    attrs=b''.join(struct.pack('<IIIHBBI',0xffffffff,name,value,8,0,kind,value)
        for name,value,kind in ((1,2,3),(3,4,3),(5,62,16)))
    # Typed numeric attribute has no string-pool raw value.
    attrs=attrs[:-20]+struct.pack('<IIIHBBI',0xffffffff,5,0xffffffff,8,0,16,62)
    element=struct.pack('<HHIII',0x102,16,36+len(attrs),1,0xffffffff)
    element+=struct.pack('<IIHHHHHH',0xffffffff,0,20,20,3,0,0,0)+attrs
    return struct.pack('<HHI',3,8,8+len(pool)+len(element))+pool+element


def lp(data):
    return struct.pack('<I',len(data))+data


def add_signer(archive, cert):
    signed=lp(b'')+lp(lp(cert))+lp(b'')
    signer=lp(signed)+lp(b'')+lp(b'')
    value=lp(lp(signer))
    entry=struct.pack('<QI',4+len(value),0x7109871a)+value
    size=len(entry)+24
    block=struct.pack('<Q',size)+entry+struct.pack('<Q',size)+b'APK Sig Block 42'
    end=archive.rfind(b'PK\x05\x06')
    directory=struct.unpack_from('<I',archive,end+16)[0]
    raw=bytearray(archive[:directory]+block+archive[directory:])
    struct.pack_into('<I',raw,end+len(block)+16,directory+len(block))
    return raw


class SetupTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='finance-setup-test-')
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve()
        self.enterContext(patch.dict(os.environ,{'FINANCE_HOME':str(self.root/'home')}))
        self.cert=certificate(ECC.construct(curve='P-256',d=29))
        self.values={'token':b'SYNTHETIC-TOKEN','ca':base64.b64encode(self.cert),'mac':bytes(range(20))}
        recipes={k:(k+'.data',hashlib.sha256(v).hexdigest(),0,len(v),()) for k,v in self.values.items()}
        self.enterContext(patch.object(setup,'RECIPES',recipes))
        self.enterContext(patch.object(setup,'SIGNER_SHA256',hashlib.sha256(self.cert).hexdigest()))
        self.enterContext(patch.object(setup,'CA_SHA256',hashlib.sha256(self.cert).hexdigest()))
        self.base,self.split=self.root/'base.apk',self.root/'split.apk'
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w') as z:
            z.writestr('token.data',self.values['token'])
            z.writestr('ca.data',self.values['ca'])
            z.writestr('AndroidManifest.xml',manifest())
            z.writestr('executable.sh',b'exit 9')
        self.base.write_bytes(add_signer(raw.getvalue(),self.cert))
        with zipfile.ZipFile(self.split,'w') as z:
            z.writestr('mac.data',self.values['mac'])

    def test_install_and_device_profile_without_execution_or_network(self):
        with patch('subprocess.Popen',side_effect=AssertionError),patch('socket.socket.connect',side_effect=AssertionError):
            result=setup.install([self.base,self.split],'service')
            self.assertFalse(result['network_used'])
            setup.configure('service',android_sdk=35,model='SYNTHETIC',width=1080,height=2400,
                webview_user_agent='SYNTHETIC-WEBVIEW',timezone='Asia/Seoul')
        value=setup.load('service')
        self.assertEqual(value['secure_token'],'SYNTHETIC-TOKEN')
        self.assertEqual(value['build_version'],'62')
        self.assertEqual(value['service_profile']['system_header']['CHNL_SYS_HDPT']['LNGG_DV_CD'],'KR')
        self.assertEqual(base64.b64decode(value['keypad_mac']),self.values['mac'])
        for path in (self.root/'home').rglob('*'):
            self.assertEqual(path.stat().st_mode&0o077,0)
        with self.assertRaises(FileExistsError):
            setup.install([self.base,self.split],'service')

    def test_changed_missing_duplicate_entries_rejected_before_install(self):
        for packages in ([self.base],[self.base,self.base,self.split]):
            with self.assertRaises(ValueError):
                setup.install(packages,'bad')
        with zipfile.ZipFile(self.split,'w') as z:
            z.writestr('mac.data',b'changed')
        with self.assertRaisesRegex(ValueError,'unsupported_service_data_version'):
            setup.install([self.base,self.split],'bad')
        self.assertFalse((self.root/'home').exists())

    def test_manifest_and_signer_identity_are_checked(self):
        self.assertEqual(setup.manifest_version(manifest()),'62')
        for raw in (b'',b'bad header',manifest()[:-1]):
            with self.assertRaisesRegex(ValueError,'invalid_manifest'):
                setup.manifest_version(raw)
        with self.assertRaisesRegex(ValueError,'unsupported_package_version'):
            setup.manifest_version(manifest('9.9.9'))
        with patch.object(setup,'SIGNER_SHA256','0'*64):
            with self.assertRaisesRegex(ValueError,'unsupported_package_signer'):
                setup.extract([self.base,self.split])

    def test_malformed_signing_block_and_symlink_are_rejected(self):
        self.base.write_bytes(b'not a package')
        with self.assertRaises(ValueError):
            setup.signer_certificate(self.base)
        alias=self.root/'alias.apk'
        alias.symlink_to(self.split)
        with self.assertRaisesRegex(ValueError,'symlink_not_allowed'):
            setup.extract([alias])


class StateTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='finance-state-test-')
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve()
        self.enterContext(patch.dict(os.environ,{'FINANCE_HOME':str(self.root/'home')}))

    def test_reopen_tamper_and_wrong_password(self):
        with State('x',PASSWORD,{'runs':{},'secret':'SYNTHETIC'}) as state:
            state.begin_run('r','check')
            state.record('r','a',{'value':'SYNTHETIC'})
            self.assertEqual(state.read_record('r','a')['value'],'SYNTHETIC')
            with self.assertRaises(FileExistsError):
                state.begin_run('r','check')
            path=state.path
        with State('x',PASSWORD) as state:
            self.assertEqual(state.snapshot()['secret'],'SYNTHETIC')
        with self.assertRaisesRegex(ValueError,'store_authentication_failed'):
            with State('x','wrong password'):pass
        value=json.loads(path.read_bytes())
        ciphertext=bytearray(bundle.unb64url(value['sealed']))
        ciphertext[-1]^=1
        value['sealed']=bundle.b64url(ciphertext)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'store_authentication_failed'):
            with State('x',PASSWORD):pass

    def test_exclusive_identity_lock(self):
        with State('x',PASSWORD,{'runs':{}}):
            with self.assertRaises(BlockingIOError):
                with State('x',PASSWORD):pass


if __name__=='__main__':
    unittest.main()
