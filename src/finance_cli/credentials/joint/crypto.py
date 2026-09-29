"""Offline NPKI metadata and Delfino-compatible key protection; no transport.

Local management supports PBES2 SEED/AES/3DES and legacy Korean SEED keys.
Existing login/signing code and its narrower supported profile are unchanged.
"""
import ctypes as ct
import hashlib
import secrets
import unicodedata
from contextlib import ExitStack
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.asn1 import DerOctetString
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtensionOID

from .cms import sequence, seq, oid, oid_der, octets
from .openssl import OpenSSL

PBES2 = '1.2.840.113549.1.5.13'
PBKDF2 = '1.2.840.113549.1.5.12'
SEED = '1.2.410.200004.1.4'
LEGACY_SEED = '1.2.410.200004.1.15'
CIPHERS = {SEED: (16,16), '2.16.840.1.101.3.4.1.2': (16,16),
           '2.16.840.1.101.3.4.1.22': (24,16), '2.16.840.1.101.3.4.1.42': (32,16),
           '1.2.840.113549.3.7': (24,8)}


def java_chars(value):
    b = value.encode('utf-16-be', errors='surrogatepass')
    return [chr(int.from_bytes(b[i:i+2], 'big')) for i in range(0,len(b),2)]


def password_policy(old, new, *, browser=False):
    """com.unboundid.g.s.a: >=40 UTF-16 units skip composition, not exclusions."""
    chars = java_chars(new)
    if old is not None and java_chars(old) == chars:
        raise ValueError('password_unchanged')
    if len(chars) < 40:
        if (len(chars) < 10 or not any(unicodedata.category(c)=='Nd' for c in chars)
                or not any(unicodedata.category(c).startswith('L') for c in chars)
                or not browser and not any(c in " ~`!@#$%^&*()-_+={[}]:;<,>./?|\\'\"" for c in chars)):
            raise ValueError('password_policy')
    if any(c in "|\\'\"" for c in chars):
        raise ValueError('password_policy')


def protection(encoded):
    outer = sequence(encoded)
    if len(outer) != 2: raise ValueError('encrypted_private_key_required')
    alg = sequence(outer[0]); kind = oid(alg[0]); ciphertext = octets(outer[1])
    if kind == PBES2:
        params = sequence(alg[1]); kdf, cipher = map(sequence, params)
        if oid(kdf[0]) != PBKDF2: raise ValueError('unsupported_kdf')
        values = sequence(kdf[1]); name = oid(cipher[0])
        if name not in CIPHERS: raise ValueError('unsupported_cipher')
        salt, count, iv = octets(values[0]), values[1], octets(cipher[1])
        # SDK p.f/a ignores optional keyLength/PRF declarations and uses SHA1.
        key_size, block_size = CIPHERS[name]
    elif kind in (LEGACY_SEED, SEED):
        salt_der, count = sequence(alg[1]); salt = octets(salt_der)
        name, key_size, block_size, iv = SEED, 16, 16, None
    else: raise ValueError('unsupported_key_protection')
    if type(count) is not int or not 1 <= count <= 10_000_000:
        raise ValueError('invalid_iteration_count')
    if not salt or not ciphertext or len(ciphertext)%block_size or (iv is not None and len(iv)!=block_size):
        raise ValueError('invalid_key_parameters')
    return dict(algorithm=kind, cipher=name, salt=salt, iterations=count, iv=iv,
                ciphertext=ciphertext, key_size=key_size, block_size=block_size)


def seed(data, key, iv, encrypt):
    lib = OpenSSL().lib
    ptr, integer = ct.c_void_p, ct.c_int
    for name, result, args in [
        ('EVP_seed_cbc',ptr,[]),
        ('EVP_CipherInit_ex',integer,[ptr,ptr,ptr,ct.c_char_p,ct.c_char_p,integer]),
        ('EVP_CipherUpdate',integer,[ptr,ptr,ct.POINTER(integer),ct.c_char_p,integer]),
        ('EVP_CipherFinal_ex',integer,[ptr,ptr,ct.POINTER(integer)])]:
        fn=getattr(lib,name);fn.restype=result;fn.argtypes=args
    with ExitStack() as stack:
        ctx=OpenSSL.resource(stack,lib.EVP_CIPHER_CTX_new(),lib.EVP_CIPHER_CTX_free)
        out=ct.create_string_buffer(len(data)+32);first,last=integer(),integer()
        try:
            if lib.EVP_CipherInit_ex(ctx,lib.EVP_seed_cbc(),None,key,iv,int(encrypt))!=1:
                raise ValueError('seed_initialization_failed')
            if lib.EVP_CipherUpdate(ctx,out,ct.byref(first),data,len(data))!=1 or lib.EVP_CipherFinal_ex(ctx,ct.byref(out,first.value),ct.byref(last))!=1:
                raise ValueError('incorrect_password_or_damaged_key')
            return out.raw[:first.value+last.value]
        finally: ct.memset(out,0,len(out))


def decrypt(encoded, password):
    p=protection(encoded)
    chars=password.encode('utf-16-be',errors='surrogatepass')[1::2]
    if p['algorithm']==PBES2:
        key=hashlib.pbkdf2_hmac('sha1',chars,p['salt'],p['iterations'],p['key_size']);iv=p['iv']
    else:
        derived=hashlib.sha1(chars+p['salt']).digest()
        for _ in range(1,p['iterations']): derived=hashlib.sha1(derived).digest()
        key=derived[:16]
        iv=hashlib.sha1(derived[16:]).digest()[:16] if p['algorithm']==LEGACY_SEED else b'0123456789012345'
    if p['cipher']==SEED: plain=seed(p['ciphertext'],key,iv,False)
    else:
        cipher=DES3 if p['block_size']==8 else AES
        plain=unpad(cipher.new(key,cipher.MODE_CBC,iv).decrypt(p['ciphertext']),p['block_size'])
    serialization.load_der_private_key(plain,password=None)
    return plain


def encrypt(material, password, *, salt=None, iv=None):
    """SDK n.a(char[]) uses PBES2/SEED, salt8, iterations1024, random IV16."""
    serialization.load_der_private_key(material,password=None)
    salt=secrets.token_bytes(8) if salt is None else salt
    iv=secrets.token_bytes(16) if iv is None else iv
    if len(salt)!=8 or len(iv)!=16: raise ValueError('invalid_encryption_parameters')
    chars=password.encode('utf-16-be',errors='surrogatepass')[1::2]
    key=hashlib.pbkdf2_hmac('sha1',chars,salt,1024,16)
    octet=lambda b:DerOctetString(b).encode()
    params=seq(seq(oid_der(PBKDF2),seq(octet(salt),1024)),seq(oid_der(SEED),octet(iv)))
    return seq(seq(oid_der(PBES2),params),octet(seed(material,key,iv,True)))


def check_pair(cert, encrypted, password):
    material=decrypt(encrypted,password)
    key=serialization.load_der_private_key(material,password=None)
    pub=lambda k:k.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    if pub(key.public_key())!=pub(x509.load_der_x509_certificate(cert).public_key()):
        raise ValueError('certificate_key_mismatch')
    return material


def metadata(encoded, now=None):
    cert=x509.load_der_x509_certificate(encoded)
    def values(name, key): return [a.value for a in name.get_attributes_for_oid(key)]
    def first(name,key): return next(iter(values(name,key)),'')
    try: policies=[p.policy_identifier.dotted_string for p in cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value]
    except x509.ExtensionNotFound: policies=[]
    now=now or datetime.now(timezone.utc)
    if now.tzinfo is None: raise ValueError('timezone_required')
    expiry=cert.not_valid_after_utc
    days=(expiry.astimezone(ZoneInfo('Asia/Seoul')).date()-now.astimezone(ZoneInfo('Asia/Seoul')).date()).days
    status='EXPIRED' if expiry<=now else 'EXPIRE_IMMINENT' if days<=30 else 'VALID'
    policy=next(iter(policies),'');ous=values(cert.subject,NameOID.ORGANIZATIONAL_UNIT_NAME)
    browser=policy=='1.2.410.200005.1.1.1' and 'personalB' in ous or policy=='1.2.410.200005.1.1.5' and 'corporation4ECB' in ous
    return {'sha256':hashlib.sha256(encoded).hexdigest(),'serialNumber':str(cert.serial_number),
            'subject':cert.subject.rfc4514_string(),'issuer':cert.issuer.rfc4514_string(),
            'subjectCN':first(cert.subject,NameOID.COMMON_NAME),'subjectOU':first(cert.subject,NameOID.ORGANIZATIONAL_UNIT_NAME),
            'issuerCN':first(cert.issuer,NameOID.COMMON_NAME),'policyOID':policy,'policies':policies,
            'issueDate':cert.not_valid_before_utc.astimezone(ZoneInfo('Asia/Seoul')).strftime('%Y%m%d'),
            'expireDate':expiry.astimezone(ZoneInfo('Asia/Seoul')).strftime('%Y%m%d'),'not_after':expiry.isoformat(),
            'status':status,'browser_certificate':bool(browser),'revocation_checked':False}
