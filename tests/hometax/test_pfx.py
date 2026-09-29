"""Synthetic PFX fixtures; independent KDF/encryption, no original server."""
import contextlib
import hashlib
import hmac
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from asn1crypto import algos, cms, keys, pkcs12, x509 as asn_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.serialization import pkcs12 as crypto_pkcs12

from hometax_cli.__main__ import main
from hometax_cli.certificate import CertificateError, vid_random
from hometax_cli.pfx import read_pfx, prepare_pfx
from test_certificate import synthetic_material


def kdf(password, salt, ident, rounds, size):
    # RFC 7292 Appendix B, independent of the OpenSSL reader.
    expand = lambda b: (b * ((64*((len(b)+63)//64)+len(b)-1)//len(b)))[:64*((len(b)+63)//64)] if b else b''
    state = bytearray(expand(salt) + expand(password.decode().encode('utf-16-be') + b'\0\0'))
    result = b''
    while len(result) < size:
        block = bytes([ident])*64 + state
        for _ in range(rounds):
            block = hashlib.sha1(block).digest()
        result += block
        amount = int.from_bytes((block*4)[:64], 'big') + 1
        for i in range(0,len(state),64):
            updated = (int.from_bytes(state[i:i+64],'big') + amount) % (1 << 512)
            state[i:i+64] = updated.to_bytes(64,'big')
    return result[:size]


def encrypted(data, password, profile):
    salt, rounds = b'12345678', 20
    if profile == '3des':
        key, iv = kdf(password,salt,1,rounds,24), kdf(password,salt,2,rounds,8)
        cipher, width = TripleDES(key), 8
        algorithm = algos.EncryptionAlgorithm({'algorithm':'pkcs12_sha1_tripledes_3key',
            'parameters':{'salt':salt,'iterations':rounds}})
    else:
        iv, width = b'0123456789abcdef', 16
        key = hashlib.pbkdf2_hmac('sha256',password,salt,rounds,32)
        cipher = algorithms.AES(key)
        algorithm = algos.EncryptionAlgorithm({'algorithm':'pbes2','parameters':{
            'key_derivation_func':{'algorithm':'pbkdf2','parameters':{'salt':{'specified':salt},
                'iteration_count':rounds,'prf':{'algorithm':'sha256'}}},
            'encryption_scheme':{'algorithm':'aes256_cbc','parameters':iv}}})
    padding = width - len(data)%width
    enc = Cipher(cipher,modes.CBC(iv)).encryptor()
    return algorithm, enc.update(data + bytes([padding])*padding) + enc.finalize()


def synthetic_pfx(certificates, private_keys, password=b'synthetic password', profile='3des', mac=True):
    safes = []
    for private in private_keys:
        algorithm, value = encrypted(private,password,profile)
        bag = pkcs12.SafeBag({'bag_id':'pkcs8_shrouded_key_bag','bag_value':
            keys.EncryptedPrivateKeyInfo({'encryption_algorithm':algorithm,'encrypted_data':value})})
        safes.append({'content_type':'data','content':pkcs12.SafeContents([bag]).dump()})
    cert_bags = pkcs12.SafeContents([{'bag_id':'cert_bag','bag_value':{
        'cert_id':'x509','cert_value':asn_x509.Certificate.load(cert)}} for cert in certificates])
    algorithm, value = encrypted(cert_bags.dump(),password,profile)
    safes.append({'content_type':'encrypted_data','content':{'version':'v0',
        'encrypted_content_info':{'content_type':'data','content_encryption_algorithm':algorithm,
                                  'encrypted_content':value}}})
    encoded = pkcs12.AuthenticatedSafe(safes).dump()
    pfx = pkcs12.Pfx({'version':'v3','auth_safe':{'content_type':'data','content':encoded}})
    if mac:
        salt, rounds = b'abcdefgh', 17
        digest = hmac.new(kdf(password,salt,3,rounds,20),encoded,hashlib.sha1).digest()
        pfx['mac_data'] = {'mac':{'digest_algorithm':{'algorithm':'sha1'},'digest':digest},
                           'mac_salt':salt,'iterations':rounds}
    return pfx.dump()


class PfxContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.private, cls.random = synthetic_material()

    def test_3des_and_pbes2_preserve_der_vid_and_validate_independent_export(self):
        for profile in ['3des','aes']:
            password = '한글 PFX + password'.encode()
            data = synthetic_pfx([self.cert],[self.private],password,profile)
            pair, warnings = read_pfx(data,password)
            self.assertEqual(pair,[(self.cert,self.private)])
            self.assertEqual(vid_random(pair[0][1]),self.random)
            self.assertEqual(prepare_pfx(data,password).random,self.random)
            self.assertFalse(warnings)
            # A separate library also accepts the independently built PFX/MAC.
            key, certificate, _ = crypto_pkcs12.load_key_and_certificates(data,password)
            self.assertEqual(certificate.public_bytes(serialization.Encoding.DER),self.cert)

    def test_real_library_export_and_wrong_password_or_tampering(self):
        private = serialization.load_der_private_key(self.private,None)
        data = crypto_pkcs12.serialize_key_and_certificates(b'fixture',private,
            x509.load_der_x509_certificate(self.cert),None,
            serialization.BestAvailableEncryption(b'password'))
        pairs, warnings = read_pfx(data,b'password')
        self.assertEqual(pairs[0][0],self.cert)
        with self.assertRaises(CertificateError):
            prepare_pfx(data,b'password')  # Export discarded VID; never invent it.
        with self.assertRaises(CertificateError):
            read_pfx(data,b'wrong')
        parsed = pkcs12.Pfx.load(data)
        parsed['mac_data']['mac']['digest'] = b'\0'*len(parsed['mac_data']['mac']['digest'].native)
        with self.assertRaises(CertificateError):
            read_pfx(parsed.dump(),b'password')

    def test_optional_mac_and_multiple_identity_selection(self):
        cert2, private2, _ = synthetic_material()
        data = synthetic_pfx([self.cert,cert2],[self.private,private2],mac=False)
        pairs, warnings = read_pfx(data,b'synthetic password')
        self.assertEqual(len(pairs),2)
        self.assertTrue(warnings)
        with self.assertRaises(CertificateError):
            prepare_pfx(data,b'synthetic password')
        selected = prepare_pfx(data,b'synthetic password',1)
        self.assertEqual(cms.SignedData.load(selected.signed_data)['certificates'][0].chosen.dump(),cert2)

    def test_signing_and_encryption_pair_selects_signing_certificate(self):
        cert2, private2, _ = synthetic_material()
        original = x509.load_der_x509_certificate(cert2)
        key = serialization.load_der_private_key(private2,None)
        encryption_cert = (x509.CertificateBuilder().subject_name(original.subject)
            .issuer_name(original.issuer).public_key(key.public_key()).serial_number(123)
            .not_valid_before(original.not_valid_before_utc).not_valid_after(original.not_valid_after_utc)
            .add_extension(x509.KeyUsage(False,False,True,True,False,False,False,False,False),critical=True)
            .sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.DER))
        data = synthetic_pfx([encryption_cert,self.cert],[private2,self.private])
        prepared = prepare_pfx(data,b'synthetic password')
        signed = cms.SignedData.load(prepared.signed_data)
        self.assertEqual(signed['certificates'][0].chosen.dump(),self.cert)

    def test_cli_pfx_stays_offline_and_does_not_print_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            source, target = Path(temp)/'source.pfx',Path(temp)/'result.json'
            source.write_bytes(synthetic_pfx([self.cert],[self.private]))
            out = io.StringIO()
            with patch('getpass.getpass',return_value='synthetic password'), \
                 patch('socket.socket',side_effect=AssertionError('No network')), contextlib.redirect_stdout(out):
                self.assertEqual(main(['auth','prepare-cert','--pfx',str(source),'--output',str(target)]),0)
            self.assertNotIn('synthetic password',out.getvalue())
            self.assertNotIn('signData',out.getvalue())
            self.assertEqual(target.stat().st_mode&0o777,0o600)


if __name__ == '__main__':
    unittest.main()
