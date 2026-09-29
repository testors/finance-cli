"""Scoped macOS Keychain access; certificate service is the default.

Uses Security.framework directly; password bytes never enter subprocess argv,
environment variables, stdout or a repository file. macOS may require access
approval. Python strings and framework buffers temporarily hold plaintext.
"""
import ctypes as C
import re
import sys

SERVICE='local.finance-cli.credential-password.v1'
NOT_FOUND=-25300


class Keychain:
    def __init__(self, fingerprint, *, service=SERVICE, label='Finance CLI credential'):
        if sys.platform!='darwin':
            raise ValueError('Password storage requires macOS Keychain')
        if re.fullmatch('[0-9a-f]{64}',fingerprint or '') is None:
            raise ValueError('Invalid credential fingerprint')
        self.fingerprint=fingerprint
        self.service,self.label=service,label
        self.security=C.CDLL('/System/Library/Frameworks/Security.framework/Security')
        self.cf=C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        pointer=C.c_void_p;length=C.c_long
        signatures={
            'CFStringCreateWithBytes':([pointer,pointer,length,C.c_uint32,C.c_bool],pointer),
            'CFDataCreate':([pointer,pointer,length],pointer),
            'CFDataGetLength':([pointer],length),
            'CFDataGetBytePtr':([pointer],pointer),
            'CFDictionaryCreate':([pointer,pointer,pointer,length,pointer,pointer],pointer),
            'CFRelease':([pointer],None),
        }
        for name,(arguments,result) in signatures.items():
            fn=getattr(self.cf,name);fn.argtypes=arguments;fn.restype=result
        for name in ('SecItemCopyMatching','SecItemAdd'):
            fn=getattr(self.security,name);fn.argtypes=[pointer,C.POINTER(pointer)];fn.restype=C.c_int32
        self.security.SecItemDelete.argtypes=[pointer]
        self.security.SecItemDelete.restype=C.c_int32

    def constant(self,name):
        library=self.cf if name.startswith('kCF') else self.security
        return C.c_void_p.in_dll(library,name).value

    def call(self, operation, password=None):
        owned=[]
        def string(value):
            raw=value.encode('utf-8')
            result=self.cf.CFStringCreateWithBytes(None,raw,len(raw),0x08000100,False)
            if not result:raise ValueError('Cannot allocate Keychain query')
            owned.append(result);return result
        values={
            'kSecClass':self.constant('kSecClassGenericPassword'),
            'kSecAttrService':string(self.service),
            'kSecAttrAccount':string(self.fingerprint),
        }
        output=C.c_void_p()
        try:
            if operation=='store':
                if not isinstance(password,str) or not password:
                    raise ValueError('Password must not be empty')
                raw=password.encode('utf-8')
                data=self.cf.CFDataCreate(None,raw,len(raw));del raw
                if not data:raise ValueError('Cannot allocate Keychain data')
                owned.append(data)
                values.update(kSecValueData=data,kSecAttrLabel=string(self.label),
                              kSecAttrSynchronizable=self.constant('kCFBooleanFalse'))
            elif operation=='load':
                values.update(kSecReturnData=self.constant('kCFBooleanTrue'),
                              kSecMatchLimit=self.constant('kSecMatchLimitOne'))
            elif operation!='delete':
                raise ValueError('Unsupported Keychain operation')
            keys=(C.c_void_p*len(values))(*(self.constant(k) for k in values))
            items=(C.c_void_p*len(values))(*values.values())
            callbacks=lambda n:C.addressof((C.c_byte*1).in_dll(self.cf,n))
            query=self.cf.CFDictionaryCreate(None,keys,items,len(values),
                callbacks('kCFTypeDictionaryKeyCallBacks'),callbacks('kCFTypeDictionaryValueCallBacks'))
            if not query:raise ValueError('Cannot allocate Keychain dictionary')
            owned.append(query)
            if operation=='load':status=self.security.SecItemCopyMatching(query,C.byref(output))
            elif operation=='store':status=self.security.SecItemAdd(query,None)
            else:status=self.security.SecItemDelete(query)
            if status==NOT_FOUND and operation in ('load','delete'):return None
            if status!=0:
                raise ValueError('Keychain operation failed (OSStatus '+str(status)+')')
            if operation=='load':
                length=self.cf.CFDataGetLength(output)
                if not 0<length<=65536:raise ValueError('Invalid Keychain password length')
                try:
                    return C.string_at(self.cf.CFDataGetBytePtr(output),length).decode('utf-8')
                except UnicodeError:
                    raise ValueError('Invalid Keychain password encoding') from None
            return True
        finally:
            if output.value:self.cf.CFRelease(output)
            for pointer in reversed(owned):self.cf.CFRelease(pointer)


def load(fingerprint):
    if sys.platform!='darwin':return None
    return Keychain(fingerprint).call('load')


def store(fingerprint,password):
    # Duplicate items are rejected. Replacement requires explicit deletion.
    return Keychain(fingerprint).call('store',password)


def forget(fingerprint):
    return Keychain(fingerprint).call('delete')


def obtain(fingerprint,prompt):
    value=load(fingerprint)
    return value if value is not None else prompt()
