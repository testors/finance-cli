from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from giro.cert_material import CertificateMaterial, CRLMaterial
from giro.cert_path import validate_supplied_path, CRLContext, PathRuleError, PolicySequence
from giro.cert_factory import CertificateBackendLimit, _node
from giro.cert_rules import PolicyState, DEFAULT_POLICIES
from giro.cms import _tlv

@unittest.skipUnless(importlib.util.find_spec('asn1crypto') and importlib.util.find_spec('cryptography'), 'optional crypto/ASN.1 unavailable')
class SuppliedPathTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        cls.keys = [rsa.generate_private_key(public_exponent=65537, key_size=1024) for _ in range(3)]
        cls.at = datetime(2026, 9, 28, tzinfo=timezone.utc)
        cls.names = [x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'synthetic root')]), x509.Name([x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, 'LicensedCA'), x509.NameAttribute(x509.NameOID.COMMON_NAME, 'synthetic issuer')]), x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'synthetic target')])]
        cls.policy = '1.2.410.200004.2.1'

    def cert(self, index, *, extra=(), policy=True, ca=True, usage=True, ski=True, aki=True, critical_aki=False, valid=True, path_length=None):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        issuer_index = max(index - 1, 0)
        builder = x509.CertificateBuilder().subject_name(self.names[index]).issuer_name(self.names[issuer_index]).public_key(self.keys[index].public_key()).serial_number(index + 1).not_valid_before(self.at - timedelta(days=2)).not_valid_after(self.at + timedelta(days=2) if valid else self.at - timedelta(days=1))
        if ski:
            builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(self.keys[index].public_key()), False)
        if aki:
            builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.keys[issuer_index].public_key()), critical_aki)
        if policy and index:
            builder = builder.add_extension(x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(self.policy), None)]), False)
        if index != 2:
            builder = builder.add_extension(x509.BasicConstraints(ca, path_length), True)
        if usage:
            builder = builder.add_extension(x509.KeyUsage(False, False, index == 2, False, False, index != 2, index != 2, False, False), True)
        for (value, critical) in extra:
            builder = builder.add_extension(value, critical)
        return CertificateMaterial.from_der(builder.sign(self.keys[issuer_index], hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def crl(self, issuer_index, *, extra=(), revoked=False, valid=True, wrong_key=False):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        builder = x509.CertificateRevocationListBuilder().issuer_name(self.names[issuer_index]).last_update(self.at - timedelta(days=2)).next_update(self.at + timedelta(days=1) if valid else self.at - timedelta(days=1)).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.keys[issuer_index].public_key()), False)
        if revoked:
            entry = x509.RevokedCertificateBuilder().serial_number(issuer_index + 2).revocation_date(self.at - timedelta(days=1)).build()
            builder = builder.add_revoked_certificate(entry)
        for value in extra:
            builder = builder.add_extension(value, False)
        key = self.keys[2] if wrong_key else self.keys[issuer_index]
        return CRLMaterial.from_der(builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def run_path(self, *, target=None, intermediate=None, anchor=None, crls=None):
        path = (target or self.cert(2), intermediate or self.cert(1))
        if crls is None:
            crls = (CRLContext((self.crl(1),)), CRLContext((self.crl(0),)))
        return validate_supplied_path(path, trust_anchor=anchor or self.cert(0), crls=crls, at=self.at, locale_language='ko')

    def test_full_supplied_path_rules_with_mandatory_crls(self):
        with patch('socket.socket', side_effect=AssertionError('offline')), patch('getpass.getpass', side_effect=AssertionError('no PIN')):
            result = self.run_path()
        self.assertTrue(result['path_rules_completed'])
        self.assertTrue(result['revocation_checked'])
        self.assertEqual([x['certificate_index'] for x in result['completed']], [1, 0])
        self.assertEqual([x['revocation_attribute'] for x in result['completed']], ['authorityrevocationlist', 'certificaterevocationlist'])
        self.assertFalse(result['certificate_validation_performed'])
        self.assertFalse(result['trust_discovery_performed'])
        self.assertFalse(result['live_login_ready'])
        self.assertNotIn('synthetic', json.dumps(result))

    def test_missing_crl_requires_original_acquisition_not_skip(self):
        with self.assertRaisesRegex(CertificateBackendLimit, 'cache/LDAP'):
            self.run_path(crls=(CRLContext(), CRLContext((self.crl(0),))))

    def test_invalid_store_crls_do_not_trigger_online_fallback(self):
        with self.assertRaises(PathRuleError) as caught:
            self.run_path(crls=(CRLContext((self.crl(1, valid=False),)), CRLContext((self.crl(0),))))
        self.assertEqual(caught.exception.rule, 'stored_crls_present_but_invalid')
        self.assertEqual(caught.exception.stage, 'revocation')
        self.assertEqual(caught.exception.certificate_index, 0)

    def test_revocation_enforced_for_ca_and_target(self):
        for revoked_index in (0, 1):
            contexts = [CRLContext((self.crl(1, revoked=revoked_index == 0),)), CRLContext((self.crl(0, revoked=revoked_index == 1),))]
            with self.assertRaises(PathRuleError) as caught:
                self.run_path(crls=contexts)
            self.assertEqual(caught.exception.rule, 'certificate_revoked')
            self.assertEqual(caught.exception.certificate_index, revoked_index)

    def test_revocation_precedes_delta_number_error(self):
        from cryptography import x509
        contexts = [CRLContext((self.crl(1, revoked=True, extra=(x509.DeltaCRLIndicator(5),)),)), CRLContext((self.crl(0),))]
        with self.assertRaises(PathRuleError) as caught:
            self.run_path(crls=contexts)
        self.assertEqual(caught.exception.rule, 'certificate_revoked')

    def test_anchor_validity_checked_before_highest_signature(self):
        with self.assertRaises(PathRuleError) as caught:
            self.run_path(anchor=self.cert(0, valid=False))
        self.assertEqual(caught.exception.rule, 'certificate_expired')
        self.assertEqual(caught.exception.stage, 'supplied_anchor')

    def test_target_validity_is_first_builder_gate(self):
        with self.assertRaises(PathRuleError) as caught:
            self.run_path(target=self.cert(2, valid=False), anchor=self.cert(0, valid=False))
        self.assertEqual(caught.exception.stage, 'builder_target_validity')

    def test_missing_policy_and_ca_constraint_are_observed_failures(self):
        for (cert, stage) in ((self.cert(1, policy=False), 'certificate_policies'), (self.cert(1, ca=False), 'ca_constraints')):
            with self.assertRaises(PathRuleError) as caught:
                self.run_path(intermediate=cert)
            self.assertEqual(caught.exception.stage, stage)

    def test_missing_recipient_usage_checked_after_path(self):
        with self.assertRaises(PathRuleError) as caught:
            self.run_path(target=self.cert(2, usage=False))
        self.assertEqual(caught.exception.stage, 'recipient_key_usage')

    def test_missing_ski_leaf_allowed_but_issuer_required(self):
        self.assertTrue(self.run_path(target=self.cert(2, ski=False))['path_rules_completed'])
        with self.assertRaises(PathRuleError) as caught:
            self.run_path(intermediate=self.cert(1, ski=False))
        self.assertEqual(caught.exception.stage, 'issuer_link')
        self.assertEqual(caught.exception.rule, 'issuer_key_identifier_missing')

    def test_aki_ski_link_not_waived_by_valid_signature(self):
        with self.assertRaises(PathRuleError) as caught:
            self.run_path(anchor=self.cert(0, ski=False))
        self.assertEqual(caught.exception.rule, 'issuer_key_identifier_missing')

    def test_unknown_critical_extension_and_critical_aki_not_silently_accepted(self):
        from cryptography import x509
        for cert in (self.cert(2, critical_aki=True), self.cert(2, extra=((x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.3.4'), b'\x05\x00'), True),))):
            with self.assertRaises(PathRuleError) as caught:
                self.run_path(target=cert)
            self.assertEqual(caught.exception.rule, 'unhandled_critical_extension')

    def test_eku_uses_original_all_oid_mask_not_only_serverauth(self):
        from cryptography import x509
        cert = self.cert(2, extra=((x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), False),))
        with self.assertRaises(PathRuleError) as caught:
            self.run_path(target=cert)
        self.assertEqual(caught.exception.rule, 'extended_key_usage_mismatch')

    def test_name_constraints_applied_to_target_san(self):
        from cryptography import x509
        inter = self.cert(1, extra=((x509.NameConstraints([x509.DNSName('example.test')], None), True),))
        for (name, good) in (('a.example.test', True), ('wrong.test', False)):
            target = self.cert(2, extra=((x509.SubjectAlternativeName([x509.DNSName(name)]), False),))
            if good:
                self.assertTrue(self.run_path(target=target, intermediate=inter)['path_rules_completed'])
            else:
                with self.assertRaises(PathRuleError) as caught:
                    self.run_path(target=target, intermediate=inter)
                self.assertEqual(caught.exception.rule, 'name_not_permitted_2')

    def test_target_name_constraints_not_applied_to_itself(self):
        from cryptography import x509
        cert = self.cert(2, extra=((x509.NameConstraints(None, [x509.DNSName('example.test')]), True), (x509.SubjectAlternativeName([x509.DNSName('example.test')]), False)))
        self.assertTrue(self.run_path(target=cert)['path_rules_completed'])

    def test_signature_overload_uses_no_provider_only_for_anchor_candidate(self):
        from asn1crypto import x509

        def mutate(cert):
            parsed = x509.Certificate.load(cert.data)
            parsed['signature_algorithm']['algorithm'] = 'sha1_rsa'
            return CertificateMaterial.from_der(parsed.dump())
        self.assertTrue(self.run_path(target=mutate(self.cert(2)))['path_rules_completed'])
        with self.assertRaises(PathRuleError) as caught:
            self.run_path(intermediate=mutate(self.cert(1)))
        self.assertEqual(caught.exception.stage, 'supplied_anchor')
        self.assertEqual(caught.exception.rule, 'outer_tbs_signature_algorithm_mismatch')

    def test_delta_base_number_bounds_are_enforced_by_adapter(self):
        from cryptography import x509
        delta = self.crl(1, extra=(x509.DeltaCRLIndicator(5), x509.CRLNumber(7)))
        for (number, good) in ((4, False), (5, True), (6, True), (7, False)):
            base = self.crl(1, extra=(x509.CRLNumber(number),))
            contexts = [CRLContext((delta,), (base,)), CRLContext((self.crl(0),))]
            if good:
                self.assertTrue(self.run_path(crls=contexts)['path_rules_completed'])
            else:
                with self.assertRaisesRegex(PathRuleError, 'delta_base_crl_not_found'):
                    self.run_path(crls=contexts)

    def test_policy_decode_remains_lazy_after_any_policy(self):
        from asn1crypto.core import ObjectIdentifier
        any_policy = _node(_tlv(48, ObjectIdentifier('2.5.29.32.0').dump()))
        malformed_later = _node(_tlv(4, b'not-policy'))
        values = PolicySequence((any_policy, malformed_later))
        state = PolicyState.initial(1, licensed_ca=False)
        self.assertEqual(state.select(values).allowed, DEFAULT_POLICIES)

    def manifest(self):
        return {'path': ['target', 'intermediate'], 'trust_anchor': 'anchor', 'crls': [{'candidates': ['crl1']}, {'candidates': ['crl0']}], 'at': self.at.isoformat(), 'locale': 'ko'}

    def test_path_cli_no_socket_no_pin_and_no_global_trust(self):
        from giro.__main__ import parser, run
        materials = {'target': self.cert(2).data, 'intermediate': self.cert(1).data, 'anchor': self.cert(0).data, 'crl1': self.crl(1).data, 'crl0': self.crl(0).data}

        def read(path):
            return materials[path.name]
        with patch('giro.__main__._load', return_value=self.manifest()), patch.object(Path, 'read_bytes', read), patch('socket.socket', side_effect=AssertionError('offline')), patch('getpass.getpass', side_effect=AssertionError('no PIN')):
            (result, status) = run(parser().parse_args(['auth', 'inspect-path', '--input', 'manifest.json']))
        self.assertEqual(status, 0)
        self.assertTrue(result['path_rules_completed'])
        self.assertFalse(result['certificate_validation_performed'])
        self.assertFalse(result['network_attempted'])
        self.assertNotIn('synthetic', json.dumps(result))

    def test_path_cli_missing_material_is_diagnostic_not_app_failure(self):
        from giro.cert_path import inspect_path_manifest
        materials = {'target': self.cert(2).data, 'intermediate': self.cert(1).data, 'anchor': self.cert(0).data, 'crl1': self.crl(1).data, 'crl0': self.crl(0).data}

        def read(path):
            return materials[path.name]
        document = self.manifest()
        document['crls'][0]['candidates'] = []
        with patch.object(Path, 'read_bytes', read):
            result = inspect_path_manifest(document)
        self.assertEqual(result['analysis_status'], 'unmodeled_or_material_needed')
        self.assertNotIn('app_success', result)
        self.assertFalse(result['path_rules_completed'])

    def test_manifest_shape_and_timezone_are_local_input_errors(self):
        from giro.cert_path import inspect_path_manifest
        from giro.errors import GiroError
        for doc in (None, {}, dict(self.manifest(), at='2026-09-28'), dict(self.manifest(), crls=[])):
            with self.assertRaises(GiroError):
                inspect_path_manifest(doc)
