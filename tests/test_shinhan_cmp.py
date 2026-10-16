"""Synthetic CMP server messages and independent RSA verification; no network."""
from datetime import datetime, timezone
import hashlib
import hmac
import unittest

from asn1crypto import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from finance_cli.services.shinhan import cmp
from finance_cli.credentials.joint.cms import seq, sequence, der, oid, algorithm, oid_der, octets
from test_shinhan_login import certificate


def server_message(body, password=b'SYN-AUTH', *, signer=None, extra=None, protected=True):
    salt = b'SYN-SERVER-SALT'
    alg = cmp.pbm_algorithm(salt, 2) if signer is None else algorithm(cmp.RSA_SHA256)
    header = seq(2, der(0x81, b'SYN-SERVER'), der(0x81, b'SYN-CLIENT'),
                 der(0xa1, alg) if protected else b'', cmp.optional(0xa2, b'SERVER-KID'),
                 cmp.optional(0xa3, b'CLIENT-KID'), cmp.optional(0xa4, b'TRANSACTION'),
                 cmp.optional(0xa5, b'SENDER-NONCE'), cmp.optional(0xa6, b'RECIPIENT-NONCE'))
    if not protected:
        return seq(header, body)
    part = seq(header, body)
    if signer is None:
        key = hashlib.sha256(hashlib.sha256(password+salt).digest()).digest()
        signature = hmac.new(key, part, hashlib.sha256).digest()
    else:
        signature = serialization.load_der_private_key(signer, None).sign(part, padding.PKCS1v15(), hashes.SHA256())
    return seq(header, body, der(0xa0, cmp.bits(signature)), der(0xa1, seq(*extra)) if extra is not None else b'')


def genp(cert, types=(2048,), **kwargs):
    body = der(0xb6, seq(seq(oid_der(cmp.KEY_TYPES), seq(*(seq(oid_der(cmp.RSA), n) for n in types))),
                         seq(oid_der(cmp.CA_CERT), cert)))
    return server_message(body, **kwargs)


def ip(cert, statuses=(0,), **kwargs):
    body = der(0xa1, seq(seq(*(seq(cmp.REQUEST_ID, seq(status), seq(der(0xa0, cert))) for status in statuses))))
    return server_message(body, **kwargs)


class CMPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca, cls.ca_private = certificate()
        cls.cert, cls.private = certificate()

    def context(self):
        return cmp.Context(b'SYN-REF', b'SYN-AUTH')

    def test_genm_mac_and_transport_encoding(self):
        context = self.context()
        message = context.genm()
        header, body, protection = sequence(message)
        self.assertEqual(cmp.unwire(cmp.wire(message)), message)
        values = sequence(header)
        self.assertEqual(values[:3], [2, der(0x81, b' '), der(0x81, b'Aton-CA')])
        self.assertEqual([oid(sequence(v)[0]) for v in sequence(cmp.content(body, 0xb5))], [cmp.KEY_TYPES, cmp.CA_CERT, cmp.CIPHER])
        key = b'SYN-AUTH'+bytes(20)
        for _ in range(1024):
            key = hashlib.sha256(key).digest()
        self.assertEqual(cmp.bit_value(cmp.content(protection, 0xa0)), hmac.new(key, seq(header, body), hashlib.sha256).digest())

    def test_genp_protection_before_state_and_body_after_state(self):
        context = self.context()
        context.genp(genp(self.ca, types=(4096, 1024, 3072, 3072)))
        self.assertEqual(context.key_types, [4096, 3072, 3072])
        self.assertTrue(context.protection_verified)
        self.assertEqual(context.recipient_nonce, b'RECIPIENT-NONCE')
        self.assertEqual(context.sender_kid, b'CLIENT-KID')
        fresh = self.context()
        broken = genp(self.ca)
        with self.assertRaises(cmp.ProtocolError):
            fresh.genp(broken[:-1]+bytes([broken[-1] ^ 1]))
        self.assertEqual(fresh.sender, der(0x81, b''))
        with self.assertRaises(cmp.ProtocolError):
            fresh.genp(genp(self.ca, types=()))
        self.assertEqual(fresh.sender, der(0x81, b'SYN-CLIENT'))
        self.assertEqual(fresh.ca_certificate, self.ca)
        self.assertEqual(fresh.key_types, [2048, 3072, 4096])

    def test_signature_uses_only_first_extra_certificate(self):
        context = self.context()
        context.genp(genp(self.ca, signer=self.ca_private, extra=[self.ca, self.cert]))
        self.assertTrue(context.protection_verified)
        with self.assertRaises(cmp.ProtocolError):
            context.genp(genp(self.ca, signer=self.ca_private, extra=[self.cert, self.ca]))
        with self.assertRaises(cmp.ProtocolError):
            context.genp(genp(self.ca, signer=self.ca_private, extra=[]))

    def test_ir_signature_vid_encryption_and_header(self):
        context = self.context()
        context.genp(genp(self.ca))
        random, customer = bytes(range(32)), b'SYN-CUSTOMER'
        message = context.ir(self.private, random, customer, now=datetime(2050, 1, 2, tzinfo=timezone.utc))
        header, body, _ = sequence(message)
        tags = {v[0]: v for v in sequence(header)[3:]}
        self.assertNotIn(0xa4, tags)
        self.assertEqual(octets(cmp.content(tags[0xa6], 0xa6)), b'RECIPIENT-NONCE')
        self.assertEqual(cmp.content(cmp.content(tags[0xa0], 0xa0), 0x18), b'20500102000000Z')
        request, pop, reg = sequence(sequence(cmp.content(body, 0xa0))[0])
        self.assertEqual(sequence(request)[0], 24948)
        pop_values = sequence(b'\x30'+pop[1:])
        signed_input = b'\x30'+pop_values[0][1:]
        spki = sequence(signed_input)[1]
        public = serialization.load_der_public_key(spki)
        public.verify(cmp.bit_value(pop_values[2]), signed_input, padding.PKCS1v15(), hashes.SHA256())
        encrypted_vid = sequence(sequence(sequence(reg)[0])[1])
        encrypted = octets(cmp.content(encrypted_vid[-1], 0xa4))
        key = serialization.load_der_private_key(self.ca_private, None)
        plain = key.decrypt(encrypted, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        vid, r = sequence(plain)
        self.assertEqual(cmp.bit_value(r), random)
        hashed = hashlib.sha256(hashlib.sha256(seq(der(0x13, customer), der(3, b'\0'+random))).digest()).digest()
        self.assertEqual(octets(cmp.content(sequence(vid)[1], 0xa0)), hashed)
        self.assertEqual(sequence(cmp.content(encrypted_vid[1], 0xa2))[1], b'\x05\0')

    def test_ip_first_matching_status_and_confirm_null(self):
        context = self.context()
        context.genp(genp(self.ca))
        cert, alias = context.ip(ip(self.cert, statuses=(0, 2)))
        self.assertEqual(cert, self.cert)
        self.assertEqual(alias, str(x509.Certificate.load(cert).serial_number).zfill(12))
        confirm = sequence(context.confirm())[1]
        self.assertEqual(confirm, b'\xb3\x02\x05\0')
        for status in (1, 2, 3):
            fresh = self.context()
            with self.assertRaises(cmp.ProtocolError) as error:
                fresh.ip(ip(self.cert, statuses=(status, 0)))
            self.assertEqual(error.exception.issuance, 'failure')
            self.assertEqual(fresh.certificate, b'')
            self.assertEqual(fresh.sender, der(0x81, b'SYN-CLIENT'))

    def test_no_protection_algorithm_and_unresolved_encrypted_response(self):
        context = self.context()
        context.ip(ip(self.cert, protected=False))
        self.assertIsNone(context.protection_verified)
        body = der(0xa1, seq(seq(seq(cmp.REQUEST_ID, seq(0), seq(der(0xa1, seq()))))))
        with self.assertRaises(cmp.ProtocolError) as error:
            self.context().ip(server_message(body))
        self.assertEqual(error.exception.code, 'cmp_encrypted_certificate_unresolved')
        self.assertEqual(error.exception.issuance, 'unknown')


if __name__ == '__main__':
    unittest.main()
