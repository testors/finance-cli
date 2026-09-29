from dataclasses import replace
from datetime import timedelta
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from giro.cms import _tlv
from giro.cms_signed import SignedData, Signer, SIGNED_DATA, CONTENT_TYPE, MESSAGE_DIGEST, SIGNING_TIME, RSA, verify_signer, digest_bytes, attribute_table
from giro.cms_signed import single_signer_certificate
from giro.cert_ctl import CTL, CIVIL_USAGE, TrustList, ctl_trust_steps, select_path_anchor_steps, ObservedCTLException, ObservedCTLIOException, ObservedCTLStoreException
from giro.cert_ctl import inspect_ctl_candidate
from giro.cert_acquisition import LDAPValues
from giro.cert_factory import CertificateBackendLimit, _node
from giro.cert_material import CertificateMaterial
from giro.cert_rules import CertificateRuleError
from giro.cert_path import validate_path_with_anchor_steps, CRLContext, PathRuleError
import test_cert_path as path_support
import test_ldap_codec as ldap_support
from giro.ldap_codec import replay_responses
SHA256 = '2.16.840.1.101.3.4.2.1'
DP = 'ldap://synthetic.invalid/cn=ctl?certificateTrustList'

def number(value):
    from asn1crypto.core import Integer
    return Integer(value).dump()

def oid(value):
    from asn1crypto.core import ObjectIdentifier
    return ObjectIdentifier(value).dump()

def date(value):
    return _tlv(24, value.strftime('%Y%m%d%H%M%SZ').encode())

def seq(*values):
    return _tlv(48, b''.join(values))

def aset(*values):
    return _tlv(49, b''.join(values))

def attribute(key, *values):
    return seq(oid(key), aset(*values))

def algorithm(value):
    return seq(oid(value), b'\x05\x00')

def drive(generator, reply):
    effects = []
    try:
        effect = next(generator)
    except StopIteration as done:
        return (done.value, effects)
    while True:
        effects.append(effect)
        answer = reply(effect)
        try:
            effect = generator.throw(answer) if isinstance(answer, BaseException) else generator.send(answer)
        except StopIteration as done:
            return (done.value, effects)

class Fixtures:
    cert = path_support.SuppliedPathTests.cert
    crl = path_support.SuppliedPathTests.crl

    @classmethod
    def setUpClass(cls):
        path_support.SuppliedPathTests.setUpClass()
        for attr in ('keys', 'names', 'at', 'policy'):
            setattr(cls, attr, getattr(path_support.SuppliedPathTests, attr))

    def content(self, target=None, *, version=None, usage=None, entries=None, algorithm_oid=SHA256, this_update=None, next_update=None, identifier=False):
        target = target or self.cert(1)
        fields = [] if version is None else [number(version)]
        fields.append(seq(*(usage if usage is not None else [oid(CIVIL_USAGE)])))
        if identifier:
            fields.append(_tlv(4, b'synthetic list identifier'))
        fields.extend([number(-7), date(this_update or self.at - timedelta(days=1)), date(next_update or self.at + timedelta(days=1)), algorithm(algorithm_oid), seq(*(entries if entries is not None else [seq(_tlv(4, digest_bytes(algorithm_oid, target.data)))]))])
        return b''.join(fields)

    def raw_signed(self, content, *, attrs='default', signer=None, sd_version=1, signer_version=1, content_type=CTL, outer_type=SIGNED_DATA, certs=None, crls=(), wrapped_content=False, digest=SHA256, signature_oid=RSA, signers_extra=(), corrupt=False):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        signer = signer or self.cert(0)
        if attrs == 'default':
            attrs = [attribute(MESSAGE_DIGEST, _tlv(4, digest_bytes(digest, content))), attribute(CONTENT_TYPE, oid(content_type))]
        signed_bytes = content if attrs is None else aset(*attrs)
        signature = self.keys[0].sign(signed_bytes, padding.PKCS1v15(), hashes.SHA256())
        if corrupt:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        fields = [number(signer_version), seq(signer.issuer_der, number(signer.serial)), algorithm(digest)]
        if attrs is not None:
            fields.append(_tlv(160, b''.join(attrs)))
        fields += [algorithm(signature_oid), _tlv(4, signature)]
        certs = (signer.data,) if certs is None else certs
        content_der = seq(content) if wrapped_content else _tlv(4, content)
        body = seq(number(sd_version), aset(), seq(oid(content_type), _tlv(160, content_der)), _tlv(160, b''.join(certs)), _tlv(161, b''.join(crls)), aset(seq(*fields), *signers_extra))
        return seq(oid(outer_type), _tlv(160, body))

    def signed(self, content=None, **kwargs):
        return SignedData.parse(self.raw_signed(self.content() if content is None else content, **kwargs))

    def run_ctl(self, values=None, *, target=None, anchors=None, overrides=None, parse=SignedData.parse):
        target = target or self.cert(1)
        if values is None:
            values = (self.raw_signed(self.content(target)),)
        anchors = (self.cert(0),) if anchors is None else anchors
        answers = {'ldap_ctl': LDAPValues(1, values), 'ctl_first_signer_index': 0, 'ctl_create_trust_directory': False, 'ctl_open_trust_cache': 'synthetic stream', 'ctl_write_trust_cache': None, 'ctl_close_trust_cache': None, 'ctl_global_trust_contains': False, 'ctl_global_trust_add': False}
        answers.update(overrides or {})

        def reply(effect):
            if effect.kind in answers:
                value = answers[effect.kind]
                return value(effect) if callable(value) else value
            if effect.kind == 'ctl_signer_certificates':
                return effect.candidate[0]
            raise AssertionError('unexpected effect ' + effect.kind)
        self.reply = reply
        return drive(ctl_trust_steps(target, anchors, distribution_point=DP, at=self.at, locale_language='ko', parse=parse), reply)
CRYPTO = importlib.util.find_spec('asn1crypto') and importlib.util.find_spec('cryptography')

@unittest.skipUnless(CRYPTO, 'optional crypto/ASN.1 unavailable')
class CMSCTLTests(Fixtures, unittest.TestCase):

    def test_actual_signature_with_and_without_attributes(self):
        for attrs in ('default', None):
            signed = self.signed(attrs=attrs)
            self.assertTrue(verify_signer(signed, signed.signers()[0], self.cert(0)))

    def test_unsorted_attributes_preserved_and_independent_crypto_verifies(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        signed = self.signed()
        signer = signed.signers()[0]
        data = [n.encoded for n in signer.attributes]
        self.assertNotEqual(data, sorted(data))
        self.keys[0].public_key().verify(signer.signature, aset(*data), padding.PKCS1v15(), hashes.SHA256())
        self.assertTrue(verify_signer(signed, signer, self.cert(0)))

    def test_content_type_and_hash_mandatory_only_with_attributes(self):
        content = self.content()
        md = attribute(MESSAGE_DIGEST, _tlv(4, hashlib.sha256(content).digest()))
        ct = attribute(CONTENT_TYPE, oid(CTL))
        for (attrs, rule) in (([], 'hash_missing'), ([md], 'type_missing'), ([ct, attribute(MESSAGE_DIGEST, _tlv(4, b'wrong'))], 'hash_mismatch'), ([md, attribute(CONTENT_TYPE, oid('1.2.3'))], 'type_mismatch')):
            signed = self.signed(content, attrs=attrs)
            with self.assertRaisesRegex(CertificateRuleError, rule):
                verify_signer(signed, signed.signers()[0], self.cert(0))

    def test_duplicate_last_attribute_and_first_value_are_used(self):
        content = self.content()
        attrs = [attribute(MESSAGE_DIGEST, _tlv(4, b'wrong')), attribute(CONTENT_TYPE, oid(CTL), oid('1.2.3')), attribute(MESSAGE_DIGEST, _tlv(4, hashlib.sha256(content).digest()), _tlv(4, b'ignored'))]
        signed = self.signed(content, attrs=attrs)
        self.assertTrue(verify_signer(signed, signed.signers()[0], self.cert(0)))

    def test_signingtime_only_validity_and_first_value(self):
        cert = self.cert(0, valid=False)
        signed = self.signed(signer=cert, attrs=None)
        self.assertTrue(verify_signer(signed, signed.signers()[0], cert))
        content = self.content()
        base = [attribute(MESSAGE_DIGEST, _tlv(4, hashlib.sha256(content).digest())), attribute(CONTENT_TYPE, oid(CTL))]
        for (when, ok) in ((self.at - timedelta(days=2), True), (self.at, False)):
            signed = self.signed(content, signer=cert, attrs=base + [attribute(SIGNING_TIME, date(when), date(self.at))])
            if ok:
                self.assertTrue(verify_signer(signed, signed.signers()[0], cert))
            else:
                with self.assertRaisesRegex(CertificateRuleError, 'expired'):
                    verify_signer(signed, signed.signers()[0], cert)

    def test_digest_set_not_required_to_contain_signer_algorithm(self):
        signed = self.signed()
        self.assertTrue(verify_signer(signed, signed.signers()[0], self.cert(0)))

    def test_content_getobjectbytes_sequence_and_octets_agree(self):
        content = self.content()
        for wrapped in (False, True):
            signed = self.signed(content, wrapped_content=wrapped)
            self.assertEqual(signed.content, content)
            self.assertTrue(verify_signer(signed, signed.signers()[0], self.cert(0)))

    def test_trailing_outer_bytes_ignored_but_unknown_ber_not_bad_signature(self):
        raw = self.raw_signed(self.content())
        self.assertEqual(SignedData.parse(raw + b'ignored').content, SignedData.parse(raw).content)
        with self.assertRaises(CertificateBackendLimit):
            SignedData.parse(b'0\x80' + _node(raw).contents + b'\x00\x00')

    def test_bad_unused_crl_not_skipped_for_good_signer(self):
        signed = self.signed(crls=(b'0\x00',))
        with self.assertRaises(CertificateBackendLimit):
            signed.store_material()

    def test_unknown_algorithm_not_fallback_or_success(self):
        signed = self.signed()
        signer = replace(signed.signers()[0], digest_algorithm='1.2.3.4')
        with self.assertRaises(CertificateBackendLimit):
            verify_signer(signed, signer, self.cert(0))

    def test_digest_mismatch_is_false_but_rsa_structure_error_is_exception(self):
        signed = self.signed()
        self.assertFalse(verify_signer(replace(signed, content=b'changed'), replace(signed.signers()[0], attributes=None), self.cert(0)))
        with self.assertRaises(CertificateRuleError):
            verify_signer(signed, replace(signed.signers()[0], signature=b'\x00'), self.cert(0))

    def test_signed_content_absence_does_not_create_empty_message(self):
        for attrs in (None, 'default'):
            signed = replace(self.signed(attrs=attrs), content=None)
            with self.assertRaises(CertificateRuleError):
                verify_signer(signed, signed.signers()[0], self.cert(0))

    def test_single_signer_serial_is_checked_before_issuer(self):
        signer = self.signed().signers()[0]
        self.assertEqual(single_signer_certificate(signer, (self.cert(0), self.cert(1))), (self.cert(0),))
        self.assertEqual(single_signer_certificate(signer, (self.cert(1),)), ())

    def test_distinct_multiple_matches_require_order_but_duplicates_do_not(self):
        signer = self.signed().signers()[0]
        self.assertEqual(len(single_signer_certificate(signer, (self.cert(0), self.cert(0)))), 1)
        with self.assertRaisesRegex(CertificateBackendLimit, 'HashSet'):
            single_signer_certificate(signer, (self.cert(0), self.cert(0, valid=False)))

    def test_different_principal_not_assumed_mismatch(self):
        signer = self.signed().signers()[0]
        cert = replace(self.cert(0), issuer_der=self.cert(2).issuer_der)
        with self.assertRaises(CertificateBackendLimit):
            single_signer_certificate(signer, (cert,))

    def test_android_ski_selector_uses_encoded_inner_octets_not_payload(self):
        cert = self.cert(0)
        encoded = cert.extensions.values['2.5.29.14'][1]
        signer = self.signed().signers()[0]
        self.assertEqual(single_signer_certificate(replace(signer, sid=_node(_tlv(128, encoded))), (cert,)), (cert,))
        self.assertEqual(single_signer_certificate(replace(signer, sid=_node(_tlv(128, _node(encoded).contents))), (cert,)), ())

@unittest.skipUnless(CRYPTO, 'optional crypto/ASN.1 unavailable')
class TrustListTests(Fixtures, unittest.TestCase):

    def test_versions_default_and_java_int_wrap(self):
        for version in (None, 0, 2 ** 32):
            ctl = TrustList.from_content(self.content(version=version, identifier=True))
            self.assertEqual((ctl.version, ctl.sequence_number), (1, -7))
            ctl.check(self.cert(1), signer_version=2 ** 32 + 1, at=self.at)

    def test_signer_version_precedes_ctl_and_time(self):
        ctl = TrustList.from_content(self.content(version=2, next_update=self.at - timedelta(days=1)))
        with self.assertRaisesRegex(CertificateRuleError, 'signer_version'):
            ctl.check(self.cert(1), signer_version=3, at=self.at)
        with self.assertRaisesRegex(CertificateRuleError, 'ctl_version'):
            ctl.check(self.cert(1), signer_version=1, at=self.at)

    def test_time_bounds_inclusive_and_no_extra_sequence_number_rule(self):
        for at in (self.at - timedelta(days=1), self.at + timedelta(days=1)):
            TrustList.from_content(self.content()).check(self.cert(1), signer_version=1, at=at)
        for (at, rule) in ((self.at - timedelta(days=2), 'not_yet'), (self.at + timedelta(days=2), 'expired')):
            with self.assertRaisesRegex(CertificateRuleError, rule):
                TrustList.from_content(self.content()).check(self.cert(1), signer_version=1, at=at)

    def test_usage_and_entries_shortcircuit(self):
        content = self.content(usage=[oid(CIVIL_USAGE), number(4)], entries=[seq(_tlv(4, hashlib.sha256(self.cert(1).data).digest())), number(3)])
        TrustList.from_content(content).check(self.cert(1), signer_version=1, at=self.at)

    def test_missing_usage_precedes_unrecognized_hash_algorithm(self):
        content = self.content(usage=[], entries=[], algorithm_oid='1.2.3')
        with self.assertRaisesRegex(CertificateRuleError, 'usage_missing'):
            TrustList.from_content(content).check(self.cert(1), signer_version=1, at=self.at)

    def test_full_certificate_digest_not_spki_or_suffix(self):
        for value in (hashlib.sha256(self.cert(1).spki).digest(), hashlib.sha256(self.cert(1).data).digest()[-3:]):
            with self.assertRaisesRegex(CertificateRuleError, 'not_listed'):
                TrustList.from_content(self.content(entries=[seq(_tlv(4, value))])).check(self.cert(1), signer_version=1, at=self.at)

    def test_all_registered_standard_digests(self):
        from giro.cms_signed import DIGESTS
        for algorithm_oid in DIGESTS:
            TrustList.from_content(self.content(algorithm_oid=algorithm_oid)).check(self.cert(1), signer_version=1, at=self.at)

    def test_original_wrap_does_not_accept_complete_sequence_as_body(self):
        with self.assertRaises(CertificateBackendLimit):
            TrustList.from_content(seq(self.content()))

@unittest.skipUnless(CRYPTO, 'optional crypto/ASN.1 unavailable')
class CTLFlowTests(Fixtures, unittest.TestCase):

    def test_trusted_signed_ctl_membership_completes_without_io(self):
        raw = self.raw_signed(self.content())
        with patch('socket.socket', side_effect=AssertionError('no socket')), patch('builtins.open', side_effect=AssertionError('no files')), patch('ctypes.CDLL', side_effect=AssertionError('no SDK')):
            (result, effects) = self.run_ctl((raw,))
        self.assertEqual(result.candidate_index, 0)
        self.assertFalse(result.certificate_validation_performed)
        self.assertEqual([e.kind for e in effects], ['ldap_ctl', 'ctl_signer_certificates'])
        self.assertNotIn('synthetic', repr(result) + repr(effects))

    def test_candidate_headers_skip_and_last_error_preserved(self):
        cases = (dict(outer_type='1.2.3'), dict(sd_version=3), dict(content_type='1.2.3'))
        for kwargs in cases:
            (result, _) = self.run_ctl((self.raw_signed(self.content(), **kwargs), self.raw_signed(self.content())))
            self.assertEqual(result.candidate_index, 1)
        with self.assertRaisesRegex(CertificateRuleError, 'content_type'):
            self.run_ctl(tuple((self.raw_signed(self.content(), **kwargs) for kwargs in cases)))

    def test_actual_io_parse_failure_continues_unknown_backend_does_not(self):

        def parse(raw):
            if raw == b'observed-failure':
                raise ObservedCTLIOException()
            return SignedData.parse(raw)
        (result, _) = self.run_ctl((b'observed-failure', self.raw_signed(self.content())), parse=parse)
        self.assertEqual(result.candidate_index, 1)
        with self.assertRaises(CertificateBackendLimit):
            self.run_ctl((b'unknown', self.raw_signed(self.content())))

    def test_non_byte_vector_entry_is_not_ignored_as_io_failure(self):
        for entry in (None, 'not bytes'):
            with self.assertRaisesRegex(CertificateRuleError, 'cast_or_null'):
                self.run_ctl((entry, self.raw_signed(self.content())))

    def test_signature_failure_stops_instead_of_trying_next_ctl(self):
        with self.assertRaisesRegex(CertificateRuleError, 'signature_error'):
            self.run_ctl((self.raw_signed(self.content(), corrupt=True), self.raw_signed(self.content())))

    def test_trusted_signature_but_wrong_membership_stops(self):
        with self.assertRaisesRegex(CertificateRuleError, 'not_listed'):
            self.run_ctl((self.raw_signed(self.content(entries=[])), self.raw_signed(self.content())))

    def test_ctl_times_not_signer_current_validity(self):
        signer = self.cert(0, valid=False)
        (result, _) = self.run_ctl((self.raw_signed(self.content(), signer=signer),), anchors=(signer,))
        self.assertEqual(result.candidate_index, 0)

    def test_trust_equality_is_whole_cert_not_same_key_or_subject(self):
        with self.assertRaisesRegex(CertificateRuleError, 'no_trusted_signer'):
            self.run_ctl(anchors=(self.cert(0, valid=False),))

    def test_null_anchor_cert_is_not_skipped_like_normal_anchor_search(self):
        with self.assertRaisesRegex(CertificateRuleError, 'null_trusted_cert'):
            self.run_ctl(anchors=(None, self.cert(0)))

    def test_selector_empty_fatal_but_store_exception_continues(self):
        with self.assertRaisesRegex(CertificateRuleError, 'iterator_empty'):
            self.run_ctl(overrides={'ctl_signer_certificates': ()})
        with self.assertRaisesRegex(CertificateRuleError, 'store_failed'):
            self.run_ctl(overrides={'ctl_signer_certificates': ObservedCTLStoreException()})

    def test_first_matched_certificate_only(self):
        with self.assertRaisesRegex(CertificateRuleError, 'no_trusted_signer'):
            self.run_ctl(overrides={'ctl_signer_certificates': (self.cert(1), self.cert(0))})

    def test_multisigner_requires_hashmap_first_observation_not_wire_order(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        alternative = CertificateMaterial.from_der(x509.CertificateBuilder().subject_name(self.names[0]).issuer_name(self.names[0]).public_key(self.keys[0].public_key()).serial_number(99).not_valid_before(self.at - timedelta(days=1)).not_valid_after(self.at + timedelta(days=1)).sign(self.keys[0], hashes.SHA256()).public_bytes(serialization.Encoding.DER))
        one = self.signed(signer=alternative).signer_nodes[0].encoded
        raw = self.raw_signed(self.content(), signer_version=3, signers_extra=(one,), certs=(self.cert(0).data, alternative.data))

        def matches(e):
            serial = int.from_bytes(e.target.sid.children()[1].contents, 'big')
            return tuple((c for c in e.candidate[0] if c.serial == serial))
        overrides = {'ctl_first_signer_index': 1, 'ctl_signer_certificates': matches}
        (result, _) = self.run_ctl((raw,), anchors=(self.cert(0), alternative), overrides=overrides)
        self.assertEqual(result.candidate_index, 0)
        with self.assertRaises(CertificateBackendLimit):
            self.run_ctl((raw,), overrides={'ctl_first_signer_index': None})
        with self.assertRaisesRegex(CertificateRuleError, 'signer_version'):
            self.run_ctl((raw,), overrides={**overrides, 'ctl_first_signer_index': 0})

    def test_ldap_wrapper_nonzero_and_empty_vector_rules(self):
        raw = self.raw_signed(self.content())
        (result, _) = self.run_ctl(overrides={'ldap_ctl': LDAPValues(-1, (raw,))})
        self.assertEqual(result.candidate_index, 0)
        for (reply, rule) in ((LDAPValues(0, ()), 'ldap_failed'), (LDAPValues(1, ()), 'ldap_empty'), (LDAPValues(1, None, True), 'vector_failed')):
            with self.assertRaisesRegex(CertificateRuleError, rule):
                self.run_ctl(overrides={'ldap_ctl': reply})

    def test_raw_ldap_replay_connects_to_actual_signed_data_verifier(self):
        raw = self.raw_signed(self.content())
        data = ldap_support.result() + ldap_support.entry([(b'certificateTrustList;binary', [raw])]) + ldap_support.result(9, 49)

        def ldap(e):
            reply = replay_responses(data, e.location, message_id=1, locale_language='ko')
            return LDAPValues(reply.code, reply.values)
        (result, _) = self.run_ctl(overrides={'ldap_ctl': ldap})
        self.assertEqual(result.candidate_index, 0)

    def kisa(self, *, ski=True):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        name = x509.Name([x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'KISA'), x509.NameAttribute(x509.NameOID.COMMON_NAME, 'synthetic CTL target')])
        builder = x509.CertificateBuilder().issuer_name(name).subject_name(name).public_key(self.keys[1].public_key()).serial_number(42).not_valid_before(self.at - timedelta(days=1)).not_valid_after(self.at + timedelta(days=1))
        if ski:
            builder = builder.add_extension(x509.SubjectKeyIdentifier(b'\xab\xcd'), False)
        return CertificateMaterial.from_der(builder.sign(self.keys[1], hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def test_kisa_write_sequence_only_described(self):
        (result, effects) = self.run_ctl(target=self.kisa())
        self.assertEqual([e.kind for e in effects][-4:], ['ctl_create_trust_directory', 'ctl_open_trust_cache', 'ctl_write_trust_cache', 'ctl_close_trust_cache'])
        self.assertEqual(effects[-3].cache_key, 'abcd_42.der')
        self.assertFalse(result.certificate_validation_performed)

    def test_kisa_mkdir_exception_and_close_io_ignored(self):
        (result, _) = self.run_ctl(target=self.kisa(), overrides={'ctl_create_trust_directory': ObservedCTLException(), 'ctl_close_trust_cache': ObservedCTLIOException()})
        self.assertEqual(result.candidate_index, 0)

    def test_kisa_missing_ski_and_write_failure_are_not_diagnostic_only(self):
        with self.assertRaisesRegex(CertificateRuleError, 'ski_missing'):
            self.run_ctl(target=self.kisa(ski=False))
        with self.assertRaisesRegex(CertificateRuleError, 'write_failed'):
            self.run_ctl(target=self.kisa(), overrides={'ctl_write_trust_cache': ObservedCTLIOException()})
        with self.assertRaises(ObservedCTLException):
            self.run_ctl(target=self.kisa(), overrides={'ctl_close_trust_cache': ObservedCTLException()})

    def test_unknown_errors_do_not_become_trust_success(self):
        for error in (CertificateBackendLimit('unknown'), TypeError('bug')):
            with self.assertRaises(type(error)):
                self.run_ctl(target=self.kisa(), overrides={'ctl_create_trust_directory': error})

    def test_anchor_selection_no_ctl_if_anchor_found_or_matching_anchor_fails(self):

        def reply(e):
            self.assertEqual(e.kind, 'anchor_match')
            return True
        (selected, effects) = drive(select_path_anchor_steps((self.cert(1),), (self.cert(0),), at=self.at, locale_language='ko', distribution_point=DP), reply)
        self.assertFalse(selected.via_ctl)
        self.assertEqual(len(effects), 1)
        with self.assertRaisesRegex(CertificateRuleError, 'matching_anchor_failed'):
            drive(select_path_anchor_steps((self.cert(1),), (self.cert(0, valid=False),), at=self.at, locale_language='ko', distribution_point=DP), reply)

    def test_ctl_anchor_promotion_describes_global_set_before_path_removal(self):
        self.run_ctl()

        def reply(e):
            return False if e.kind == 'anchor_match' else self.reply(e)
        (selected, effects) = drive(select_path_anchor_steps((self.cert(2), self.cert(1)), (self.cert(0),), at=self.at, locale_language='ko', distribution_point=DP), reply)
        self.assertTrue(selected.via_ctl)
        self.assertEqual(len(selected.path), 1)
        self.assertEqual(selected.anchor.data, self.cert(1).data)
        self.assertEqual([e.kind for e in effects][-2:], ['ctl_global_trust_contains', 'ctl_global_trust_add'])
        self.assertFalse(selected.certificate_validation_performed)

    def path_generator(self, *, crls=None, target=None):
        return validate_path_with_anchor_steps((target or self.cert(2), self.cert(1)), (self.cert(0),), crls=(CRLContext((self.crl(1),)), CRLContext((self.crl(0),))) if crls is None else crls, at=self.at, locale_language='ko', distribution_point=DP)

    def test_ctl_composes_with_actual_remaining_path_and_crl_verification(self):
        from cryptography import x509
        names = [x509.UniformResourceIdentifier('ldap://synthetic.invalid/crl')]
        target = self.cert(2, extra=((x509.CRLDistributionPoints([x509.DistributionPoint(names, None, None, None)]), False),))
        idp = x509.IssuingDistributionPoint(names, None, True, False, None, False, False)
        self.run_ctl()
        (result, _) = drive(self.path_generator(target=target, crls=(CRLContext((self.crl(1, extra=(idp,)),)), None)), lambda e: False if e.kind == 'anchor_match' else self.reply(e))
        self.assertTrue(result['path_rules_completed'])
        self.assertTrue(result['revocation_checked'])
        self.assertTrue(result['anchor_via_ctl'])
        self.assertEqual(result['supplied_path_length'], 1)
        self.assertFalse(result['certificate_validation_performed'])
        self.assertFalse(result['live_login_ready'])

    def test_ctl_top_removal_recomputes_licensedca_mode_not_old_top(self):
        self.run_ctl()
        with self.assertRaisesRegex(PathRuleError, 'rfc3280_crl_idp_missing'):
            drive(self.path_generator(), lambda e: False if e.kind == 'anchor_match' else self.reply(e))

    def test_ctl_does_not_waive_revoked_leaf_or_missing_crl(self):
        self.run_ctl()
        reply = lambda e: False if e.kind == 'anchor_match' else self.reply(e)
        with self.assertRaisesRegex(PathRuleError, 'certificate_revoked'):
            drive(self.path_generator(crls=(CRLContext((self.crl(1, revoked=True),)), None)), reply)
        with self.assertRaises(CertificateBackendLimit):
            drive(self.path_generator(crls=(CRLContext(), None)), reply)

    def test_normal_anchor_composition_preserves_full_path_checks(self):
        (result, effects) = drive(self.path_generator(), lambda e: True if e.kind == 'anchor_match' else self.fail('unexpected CTL'))
        self.assertTrue(result['path_rules_completed'])
        self.assertFalse(result['anchor_via_ctl'])
        self.assertEqual(result['supplied_path_length'], 2)

    def test_target_validity_precedes_even_ctl_download(self):
        with self.assertRaisesRegex(CertificateRuleError, 'certificate_expired'):
            drive(self.path_generator(target=self.cert(2, valid=False)), lambda e: self.fail('unexpected effect'))

@unittest.skipUnless(CRYPTO, 'optional crypto/ASN.1 unavailable')
class InspectCTLTests(Fixtures, unittest.TestCase):

    def inspect(self, raw=None, anchors=None):
        return inspect_ctl_candidate(raw or self.raw_signed(self.content()), self.cert(1).data, [self.cert(0).data] if anchors is None else anchors, at=self.at, locale_language='ko')

    def test_public_material_completes_without_observed_selector_substitution(self):
        import json
        with patch('socket.socket', side_effect=AssertionError('offline')):
            result = self.inspect()
        self.assertTrue(result['ctl_rules_completed'])
        for key in ('network_attempted', 'certificate_validation_performed', 'trust_installed', 'live_login_ready'):
            self.assertFalse(result[key])
        self.assertNotIn('synthetic', json.dumps(result))

    def test_untrusted_and_corrupt_signed_data_not_accepted(self):
        self.assertEqual(self.inspect(anchors=[])['rule_error'], 'ctl_no_trusted_signer')
        result = self.inspect(self.raw_signed(self.content(), corrupt=True))
        self.assertEqual(result['analysis_status'], 'ctl_rule_failed')

    def test_multiple_signers_diagnostic_not_first_wire_member(self):
        raw = self.raw_signed(self.content(), signers_extra=(self.signed().signer_nodes[0].encoded,))
        self.assertEqual(self.inspect(raw)['analysis_status'], 'unmodeled')

    def test_cli_reads_only_explicit_public_files_and_hides_paths(self):
        import contextlib, io, json
        from giro.__main__ import main
        files = {'PRIVATE-ctl': self.raw_signed(self.content()), 'PRIVATE-target': self.cert(1).data, 'PRIVATE-anchor': self.cert(0).data}
        output = io.StringIO()
        with patch.object(Path, 'read_bytes', lambda p: files[str(p)]), patch('socket.socket', side_effect=AssertionError('offline')), patch('getpass.getpass', side_effect=AssertionError('no PIN')), contextlib.redirect_stdout(output):
            code = main(['auth', 'inspect-ctl', '--input', 'PRIVATE-ctl', '--target', 'PRIVATE-target', '--trust-anchor', 'PRIVATE-anchor', '--at', self.at.isoformat(), '--locale', 'ko'])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())['ctl_rules_completed'])
        self.assertNotIn('PRIVATE', output.getvalue())

    def test_cli_requires_timezone_before_any_read(self):
        import contextlib, io, json
        from giro.__main__ import main
        output = io.StringIO()
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('no read')), contextlib.redirect_stdout(output):
            code = main(['auth', 'inspect-ctl', '--input', 'x', '--target', 'y', '--trust-anchor', 'z', '--at', '2026-09-28', '--locale', 'ko'])
        self.assertEqual(code, 2)
