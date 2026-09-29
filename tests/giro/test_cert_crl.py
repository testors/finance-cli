from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from giro.cert_material import CertificateMaterial, CRLMaterial, Extensions, _date
from giro.cert_factory import _node, CertificateBackendLimit
from giro.cert_crl import AuthorityKeyIdentifier, check_issuer_candidate, check_crl_candidate, select_crl_from_candidates, check_selected_crl, delta_bounds, inspect_crl_candidate
from giro.cert_rules import CertificateRuleError
from giro.cms import _tlv

@unittest.skipUnless(importlib.util.find_spec('cryptography') and importlib.util.find_spec('asn1crypto'), 'optional crypto/ASN.1 unavailable')
class CRLTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        cls.wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        cls.at = datetime(2026, 9, 1, tzinfo=timezone.utc)
        cls.root_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'synthetic root')])
        cls.issuer_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'synthetic issuer')])
        cls.target_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'synthetic target')])
        cls.ski = x509.SubjectKeyIdentifier.from_public_key(cls.key.public_key())
        cls.aki = x509.AuthorityKeyIdentifier(cls.ski.digest, None, None)
        cls.url = 'ldap://offline.invalid/synthetic'

    def cert(self, *, issuer=False, extra=(), aki=True, crl_sign=True, ca=None, subject=None):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        builder = x509.CertificateBuilder().serial_number(2 if issuer else 3).subject_name(subject or (self.issuer_name if issuer else self.target_name)).issuer_name(self.root_name if issuer else self.issuer_name).public_key(self.key.public_key()).not_valid_before(self.at - timedelta(days=1)).not_valid_after(self.at + timedelta(days=30))
        if issuer:
            builder = builder.add_extension(self.ski, False)
            builder = builder.add_extension(x509.KeyUsage(False, False, False, False, False, True, crl_sign, False, False), True)
        elif aki:
            builder = builder.add_extension(self.aki, False)
        if ca is not None:
            builder = builder.add_extension(x509.BasicConstraints(ca, None), True)
        for value in extra:
            builder = builder.add_extension(value, False)
        return CertificateMaterial.from_der(builder.sign(self.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def crl(self, *, extra=(), aki=True, name=None, key=None, entries=(), current=None, next_update=None):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        builder = x509.CertificateRevocationListBuilder().issuer_name(name or self.issuer_name).last_update(current or self.at - timedelta(days=1)).next_update(next_update or self.at + timedelta(days=1))
        if aki:
            builder = builder.add_extension(self.aki, False)
        for (serial, date) in entries:
            builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(date).build())
        for value in extra:
            builder = builder.add_extension(value, False)
        return CRLMaterial.from_der(builder.sign(key or self.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def dp(self, url=None, **kwargs):
        from cryptography import x509
        return x509.DistributionPoint([x509.UniformResourceIdentifier(url or self.url)], None, None, kwargs.get('crl_issuer'))

    def idp(self, *, full=True, user=False, ca=False, attr=False, indirect=False):
        from cryptography import x509
        return x509.IssuingDistributionPoint([x509.UniformResourceIdentifier(self.url)] if full else None, None, user, ca, None, indirect, attr)

    def check(self, target=None, issuer=None, crl=None, **kwargs):
        issuer = issuer or self.cert(issuer=True)
        options = dict(at=self.at, locale_language='ko', trust_anchor=issuer, licensed_ca=True)
        options.update(kwargs)
        return check_selected_crl(target or self.cert(), issuer, crl or self.crl(), **options)

    def test_parsed_materials_signature_aki_and_crl_subchecks(self):
        (target, issuer, crl) = (self.cert(), self.cert(issuer=True), self.crl())
        self.assertIsNone(check_issuer_candidate(target, issuer, at=self.at, locale_language='ko'))
        self.assertIsNone(self.check(target, issuer, crl))
        self.assertNotIn('synthetic issuer', repr(issuer))
        self.assertNotIn('synthetic', repr(crl))

    def test_candidate_checks_do_not_substitute_for_path_validation(self):
        (target, issuer) = (self.cert(), self.cert(issuer=True, ca=False))
        self.assertIsNone(check_issuer_candidate(target, issuer, at=self.at, locale_language='ko'))

    def test_wrong_signature_is_not_swallowed_as_success(self):
        with self.assertRaises(CertificateRuleError):
            self.check(crl=self.crl(key=self.wrong_key))

    def test_original_window_boundaries_and_missing_next(self):
        crl = self.crl()
        for date in crl.update_dates():
            self.assertIsNone(self.check(crl=crl, at=date))
        with self.assertRaisesRegex(CertificateRuleError, 'update_time_missing'):
            self.check(crl=replace(crl, updates=(crl.updates[0], None)))
        with self.assertRaisesRegex(CertificateRuleError, 'crl_expired'):
            self.check(crl=crl, at=self.at + timedelta(days=2))

    def test_dn_and_aki_failures_separate(self):
        with self.assertRaisesRegex(CertificateRuleError, 'issuer_name_mismatch'):
            self.check(crl=self.crl(name=self.root_name))
        with self.assertRaisesRegex(CertificateRuleError, 'aki_missing'):
            self.check(crl=self.crl(aki=False))
        with self.assertRaisesRegex(CertificateRuleError, 'aki_missing'):
            self.check(target=self.cert(aki=False))

    def test_store_candidates_first_valid_and_no_invalid_store_fallback(self):
        (target, issuer, good) = (self.cert(), self.cert(issuer=True), self.crl())
        bad = self.crl(key=self.wrong_key)
        opts = dict(at=self.at, locale_language='ko')
        self.assertIs(select_crl_from_candidates(target, issuer, [bad, good], **opts), good)
        self.assertIsNone(select_crl_from_candidates(target, issuer, [], **opts))
        with self.assertRaisesRegex(CertificateRuleError, 'stored_crls_present_but_invalid'):
            select_crl_from_candidates(target, issuer, [bad], **opts)

    def test_aki_serial_without_issuer_not_equivalent_even_to_itself(self):
        aki = AuthorityKeyIdentifier(b'key', None, 7)
        self.assertFalse(aki.equals(aki, locale_language='ko'))
        self.assertTrue(AuthorityKeyIdentifier(b'key', None, None).equals(AuthorityKeyIdentifier(b'key', None, None), locale_language='ko'))

    def test_aki_first_directory_name_and_serial_null_error(self):
        names = _node(_tlv(161, _tlv(134, b'ldap://offline.invalid') + _tlv(164, self.root_name.public_bytes()) + _tlv(164, self.issuer_name.public_bytes())))
        aki = AuthorityKeyIdentifier(b'key', names, 2)
        self.assertIn('synthetic root', aki.cert_issuer().render(locale_language='ko'))
        self.assertTrue(aki.equals(aki, locale_language='ko'))
        with self.assertRaisesRegex(CertificateRuleError, 'serial_null'):
            replace(aki, serial=None).equals(aki, locale_language='ko')
        names_without_dn = _node(_tlv(161, _tlv(134, b'offline')))
        with self.assertRaisesRegex(CertificateRuleError, 'directory_name_missing'):
            replace(aki, issuer_names=names_without_dn).cert_issuer()

    def test_aki_directory_lookup_stops_before_later_unsupported_name(self):
        names = _node(_tlv(161, _tlv(164, self.root_name.public_bytes()) + _tlv(131, b'unknown')))
        aki = AuthorityKeyIdentifier(b'key', names, 2)
        self.assertIn('synthetic root', aki.cert_issuer().render(locale_language='ko'))

    def test_issuer_aki_names_issuer_issuer_not_subject(self):
        from cryptography import x509
        issuer = self.cert(issuer=True)
        for (dn, success) in ((self.root_name, True), (self.issuer_name, False)):
            aki = x509.AuthorityKeyIdentifier(self.ski.digest, [x509.DirectoryName(dn)], issuer.serial)
            target = self.cert(aki=False, extra=(aki,))
            if success:
                self.assertIsNone(check_issuer_candidate(target, issuer, at=self.at, locale_language='ko'))
            else:
                with self.assertRaisesRegex(CertificateRuleError, 'cert_issuer_mismatch'):
                    check_issuer_candidate(target, issuer, at=self.at, locale_language='ko')

    def test_issuer_candidate_ignores_serial_when_cert_issuer_absent(self):
        (target, issuer) = (self.cert(), self.cert(issuer=True))
        values = dict(target.extensions.values)
        values['2.5.29.35'] = (False, _tlv(48, _tlv(128, self.ski.digest) + _tlv(130, b'\t')))
        target = replace(target, extensions=Extensions(values))
        self.assertIsNone(check_issuer_candidate(target, issuer, at=self.at, locale_language='ko'))

    def test_exact_anchor_certificate_exempts_issuer_crl_key_usage(self):
        issuer = self.cert(issuer=True, crl_sign=False)
        self.assertIsNone(self.check(issuer=issuer, trust_anchor=issuer))
        other = self.cert(issuer=True, crl_sign=True)
        with self.assertRaisesRegex(CertificateRuleError, 'issuer_crl_sign_required'):
            self.check(issuer=issuer, trust_anchor=other)

    def test_anchor_does_not_parse_bad_usage_and_boolean_array_masks_pad_bits(self):
        issuer = self.cert(issuer=True)
        values = dict(issuer.extensions.values)
        values['2.5.29.15'] = (True, b'unparseable')
        issuer = replace(issuer, extensions=Extensions(values))
        self.assertIsNone(self.check(issuer=issuer, trust_anchor=issuer))
        values['2.5.29.15'] = (True, _tlv(3, b'\x02\x02'))
        usage = Extensions(values)
        self.assertEqual(usage.key_usage(), 2)
        self.assertEqual(usage.key_usage(boolean_array=True), 0)

    def test_matching_revocation_entry_always_fails_including_future(self):
        for (delta, rule) in ((-1, 'certificate_revoked'), (1, 'revocation_date_in_future')):
            with self.assertRaisesRegex(CertificateRuleError, rule):
                self.check(crl=self.crl(entries=((3, self.at + timedelta(hours=delta)),)))
        self.assertIsNone(self.check(crl=self.crl(entries=((999, self.at),))))

    def test_revocation_lookup_uses_first_duplicate(self):
        crl = self.crl(entries=((3, self.at + timedelta(hours=1)), (3, self.at - timedelta(hours=1))))
        with self.assertRaisesRegex(CertificateRuleError, 'revocation_date_in_future'):
            self.check(crl=crl)

    def test_missing_idp_nonlicensed_rule(self):
        with self.assertRaisesRegex(CertificateRuleError, 'idp_missing'):
            self.check(licensed_ca=False)

    def test_idp_name_and_usage_pass_with_real_der(self):
        from cryptography import x509
        target = self.cert(extra=(x509.CRLDistributionPoints([self.dp()]),))
        self.assertIsNone(self.check(target=target, crl=self.crl(extra=(self.idp(user=True),)), licensed_ca=False))

    def test_only_first_distribution_point_used(self):
        from cryptography import x509
        target = self.cert(extra=(x509.CRLDistributionPoints([self.dp('ldap://different.invalid'), self.dp()]),))
        with self.assertRaisesRegex(CertificateRuleError, 'point_mismatch'):
            self.check(target=target, crl=self.crl(extra=(self.idp(user=True),)))

    def test_crl_issuer_fallback_only_when_distribution_point_absent(self):
        from cryptography import x509
        matching = [x509.UniformResourceIdentifier(self.url)]
        point = x509.DistributionPoint(None, None, None, matching)
        target = self.cert(extra=(x509.CRLDistributionPoints([point]),))
        crl = self.crl(extra=(self.idp(user=True),))
        self.assertIsNone(self.check(target=target, crl=crl))
        target = self.cert(extra=(x509.CRLDistributionPoints([self.dp('ldap://different.invalid', crl_issuer=matching)]),))
        with self.assertRaisesRegex(CertificateRuleError, 'point_mismatch'):
            self.check(target=target, crl=crl)

    def test_idp_distribution_point_null_not_silently_accepted(self):
        from cryptography import x509
        target = self.cert(extra=(x509.CRLDistributionPoints([self.dp()]),))
        with self.assertRaisesRegex(CertificateRuleError, 'idp_distribution_point_missing'):
            self.check(target=target, crl=self.crl(extra=(self.idp(full=False, user=True),)))

    def test_idp_ca_user_attribute_restrictions(self):
        from cryptography import x509
        for (ca, idp, rule) in ((True, self.idp(user=True), 'user_only'), (None, self.idp(ca=True), 'ca_only'), (False, self.idp(attr=True), 'attribute_certificates')):
            target = self.cert(ca=ca, extra=(x509.CRLDistributionPoints([self.dp()]),))
            with self.assertRaisesRegex(CertificateRuleError, rule):
                self.check(target=target, crl=self.crl(extra=(idp,)))

    def test_indirect_flag_not_added_as_rejection(self):
        from cryptography import x509
        target = self.cert(extra=(x509.CRLDistributionPoints([self.dp()]),))
        self.assertIsNone(self.check(target=target, crl=self.crl(extra=(self.idp(indirect=True),))))

    def test_delta_base_required_and_original_loop_does_not_merge(self):
        from cryptography import x509
        delta = self.crl(extra=(x509.DeltaCRLIndicator(5), x509.CRLNumber(7)))
        self.assertEqual(delta_bounds(delta), (5, 6))
        with self.assertRaisesRegex(CertificateRuleError, 'base_crl_not_found'):
            self.check(crl=delta)
        base = self.crl(extra=(x509.CRLNumber(5),), key=self.wrong_key, current=self.at - timedelta(days=5), next_update=self.at - timedelta(days=2), entries=((3, self.at - timedelta(days=3)),))
        self.assertIsNone(self.check(crl=delta, base_candidates=[base]))

    def test_delta_idp_must_match_and_number_required(self):
        from cryptography import x509
        delta = self.crl(extra=(x509.DeltaCRLIndicator(5),))
        with self.assertRaisesRegex(CertificateRuleError, 'number_missing'):
            self.check(crl=delta)
        delta = self.crl(extra=(x509.DeltaCRLIndicator(5), x509.CRLNumber(7)))
        base = self.crl(extra=(x509.CRLNumber(5), self.idp(user=True)))
        with self.assertRaisesRegex(CertificateRuleError, 'base_crl_not_found'):
            self.check(crl=delta, base_candidates=[base])

    def test_date_noncanonical_representation_is_analysis_limit(self):
        with self.assertRaises(CertificateBackendLimit):
            _date(_node(_tlv(23, b'2609010000Z')))
        self.assertEqual(_date(_node(_tlv(23, b'490901000000Z'))).year, 2049)
        self.assertEqual(_date(_node(_tlv(23, b'500901000000Z'))).year, 1950)

    def test_extensions_last_duplicate_and_first_object(self):
        from asn1crypto.core import ObjectIdentifier

        def ext(value):
            return _tlv(48, ObjectIdentifier('2.5.29.14').dump() + _tlv(4, _tlv(4, value) + b'trailing'))
        extensions = Extensions.parse(_node(_tlv(48, ext(b'one') + ext(b'two'))))
        self.assertEqual(extensions.get('2.5.29.14').contents, b'two')

    def test_candidate_report_never_announces_trust_or_prints_identity(self):
        report = inspect_crl_candidate(self.cert().data, self.cert(issuer=True).data, self.crl().data, at=self.at, locale_language='ko')
        self.assertTrue(all((r['rule_completed'] for r in report['subchecks'].values())))
        self.assertFalse(report['certificate_validation_performed'])
        self.assertFalse(report['live_login_ready'])
        self.assertFalse(report['network_attempted'])
        self.assertNotIn('synthetic', json.dumps(report))
        self.assertNotIn('app_success', report)

    def test_crl_cli_offline_no_pin_and_subrule_failure_not_giro_code(self):
        from giro.__main__ import parser, run
        data = {'target': self.cert().data, 'issuer': self.cert(issuer=True).data, 'crl': self.crl(key=self.wrong_key).data}

        def read(path):
            return data[path.name]
        args = parser().parse_args(['auth', 'inspect-crl', '--target', 'target', '--issuer', 'issuer', '--crl', 'crl', '--locale', 'ko', '--at', self.at.isoformat()])
        with patch.object(Path, 'read_bytes', read), patch('socket.socket', side_effect=AssertionError('offline')), patch('getpass.getpass', side_effect=AssertionError('no PIN')):
            (report, status) = run(args)
        self.assertEqual(status, 0)
        self.assertFalse(report['subchecks']['crl_candidate']['rule_completed'])
        self.assertNotIn('response_code', report)

    def test_cli_backend_gap_is_diagnostic_and_timezone_is_required(self):
        from giro.__main__ import parser, run
        from giro.errors import GiroError
        args = parser().parse_args(['auth', 'inspect-crl', '--target', 'target', '--issuer', 'issuer', '--crl', 'crl', '--locale', 'ko', '--at', self.at.isoformat()])
        with patch.object(Path, 'read_bytes', return_value=b'0\x82\xff'):
            (report, status) = run(args)
        self.assertEqual(status, 0)
        self.assertEqual(report['analysis_status'], 'unmodeled_material')
        args.at = self.at.replace(tzinfo=None)
        with self.assertRaises(GiroError):
            run(args)
