from dataclasses import replace
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import test_cert_path as path_support
from giro.cert_acquisition import AcquisitionEffect, LDAPValues, ObservedReadFailure, ObservedStoreFailure, ObservedMaterialParseFailure, issuer_location, crl_location, issuer_steps, crl_steps, anchor_steps, build_path_steps, _ca_key
from giro.cert_factory import CertificateBackendLimit
from giro.cert_rules import CertificateRuleError
from giro.cert_path import validate_supplied_path, CRLContext
from giro.ldap_codec import LdapLocation, replay_responses
from giro.cms import _tlv
import test_ldap_codec as ldap_support

def drive(generator, replies):
    effects = []
    try:
        effect = next(generator)
    except StopIteration as done:
        return (done.value, effects)
    while True:
        effects.append(effect)
        try:
            reply = replies(effect) if callable(replies) else next(replies)
        except StopIteration:
            raise AssertionError('missing synthetic observation') from None
        try:
            effect = generator.send(reply)
        except StopIteration as done:
            return (done.value, effects)

@unittest.skipUnless(importlib.util.find_spec('asn1crypto') and importlib.util.find_spec('cryptography'), 'optional crypto/ASN.1 unavailable')
class AcquisitionTests(unittest.TestCase):
    cert = path_support.SuppliedPathTests.cert
    crl = path_support.SuppliedPathTests.crl

    @classmethod
    def setUpClass(cls):
        path_support.SuppliedPathTests.setUpClass()
        for attr in ('keys', 'at', 'names', 'policy'):
            setattr(cls, attr, getattr(path_support.SuppliedPathTests, attr))

    def target(self, *, aia=True, dp=True, **kwargs):
        from cryptography import x509
        extra = []
        if aia:
            uri = 'ldap://issuer.invalid:123/cn=ignored?wrong' if aia is True else aia
            value = x509.AuthorityInformationAccess([x509.AccessDescription(x509.AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(uri))])
            extra.append((value, False))
        if dp:
            uri = 'ldap://crl.invalid/cn=list?customAttribute' if dp is True else dp
            value = x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier(uri)], None, None, None)])
            extra.append((value, False))
        return self.cert(2, extra=extra, **kwargs)

    def issuer_generator(self, target=None, stores=0, **kwargs):
        return issuer_steps(target or self.target(), store_count=stores, at=self.at, locale_language='ko', **kwargs)

    def crl_generator(self, target=None, candidates=(), **kwargs):
        return crl_steps(target or self.target(), self.cert(1), candidates=candidates, at=self.at, locale_language='ko', attribute='certificaterevocationlist', save_crl=kwargs.pop('save_crl', True), **kwargs)

    def test_aia_overwrites_dn_attribute_but_preserves_scheme_host_port(self):
        target = self.target()
        loc = issuer_location(target, locale_language='ko')
        self.assertEqual((loc.host, loc.port, loc.attribute), ('issuer.invalid', '123', 'cacertificate'))
        self.assertEqual(loc.dn, target.issuer.render(locale_language='ko'))

    def test_aia_no_matching_method_uses_crldp(self):
        from cryptography import x509
        ocsp = x509.AuthorityInformationAccess([x509.AccessDescription(x509.AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier('http://ocsp.invalid/'))])
        target = self.target(aia=False)
        values = dict(target.extensions.values)
        values['1.3.6.1.5.5.7.1.1'] = (False, ocsp.public_bytes())
        target = replace(target, extensions=replace(target.extensions, values=values))
        self.assertEqual(issuer_location(target, locale_language='ko').host, 'crl.invalid')

    def test_present_bad_aia_not_fallback(self):
        with self.assertRaisesRegex(CertificateRuleError, 'aia_ca_issuers_parse_failed'):
            issuer_location(self.target(aia='invalid'), locale_language='ko')

    def test_aia_derstring_cast_does_not_require_uri_tag(self):
        from asn1crypto.core import ObjectIdentifier
        target = self.target(aia=False)
        values = dict(target.extensions.values)
        aia = _tlv(48, _tlv(48, ObjectIdentifier('1.3.6.1.5.5.7.48.2').dump() + _tlv(130, b'ldap://dns.invalid/dn')))
        values['1.3.6.1.5.5.7.1.1'] = (False, aia)
        target = replace(target, extensions=replace(target.extensions, values=values))
        self.assertEqual(issuer_location(target, locale_language='ko').host, 'dns.invalid')

    def test_bad_first_crldp_uri_stops_instead_of_trying_second(self):
        from cryptography import x509
        dp = x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier('invalid'), x509.UniformResourceIdentifier('ldap://good.invalid/dn')], None, None, None)])
        target = self.cert(2, extra=((dp, False),))
        self.assertIsNone(crl_location(target))

    def test_missing_distribution_point_is_original_null_dereference(self):
        from cryptography import x509
        dp = x509.CRLDistributionPoints([x509.DistributionPoint(None, None, None, [x509.DirectoryName(self.names[1])])])
        target = self.cert(2, extra=((dp, False),))
        with self.assertRaisesRegex(CertificateRuleError, 'null_dereference'):
            crl_location(target)

    def test_issuer_store_exceptions_and_invalid_candidates_continue(self):
        valid = self.cert(1)
        replies = iter([ObservedStoreFailure(), (None, self.cert(1, valid=False), valid)])
        (result, effects) = drive(self.issuer_generator(stores=2), replies)
        self.assertIs(result.material, valid)
        self.assertEqual(result.source, 'store')
        self.assertEqual([e.kind for e in effects], ['issuer_store', 'issuer_store'])

    def test_unknown_store_is_not_assumed_empty(self):
        with self.assertRaises(CertificateBackendLimit):
            drive(self.issuer_generator(stores=1), iter([None]))

    def test_missing_aki_fails_only_after_store_attempts(self):
        gen = self.issuer_generator(target=self.target(aki=False), stores=1)
        self.assertEqual(next(gen).kind, 'issuer_store')
        with self.assertRaisesRegex(CertificateRuleError, 'acquisition_aki_missing'):
            gen.send(())

    def test_cache_key_uses_signed_decimal_serial_even_without_certissuer(self):
        target = self.target()
        key = _ca_key(target)
        self.assertTrue(key.endswith('.der'))
        values = dict(target.extensions.values)
        values['2.5.29.35'] = (False, _tlv(48, _tlv(128, b'\xab\xcd') + _tlv(130, b'\xff')))
        target = replace(target, extensions=replace(target.extensions, values=values))
        self.assertEqual(_ca_key(target), 'abcd_-1.der')
        values['2.5.29.35'] = (False, _tlv(48, b''))
        self.assertEqual(_ca_key(target), 'null.der')

    def test_good_cache_shortcircuits_ldap_and_write(self):
        (result, effects) = drive(self.issuer_generator(), iter([self.cert(1).data]))
        self.assertEqual(result.source, 'cache')
        self.assertEqual([e.kind for e in effects], ['read_certificate_cache'])

    def test_invalid_cache_and_parse_failures_fall_through_to_ldap(self):
        for cache in (ObservedReadFailure(), b'not-pem', self.cert(1, valid=False).data):
            (result, effects) = drive(self.issuer_generator(), iter([cache, LDAPValues(1, (b'not-pem', self.cert(1).data)), 'written']))
            self.assertEqual(result.source, 'ldap')
            self.assertEqual([e.kind for e in effects], ['read_certificate_cache', 'ldap_certificate', 'write_certificate_cache'])

    def test_first_parsed_invalid_issuer_not_replaced_by_later_valid_value(self):
        replies = iter([ObservedReadFailure(), LDAPValues(1, (self.cert(1, valid=False).data, self.cert(1).data))])
        with self.assertRaisesRegex(CertificateRuleError, 'expired'):
            drive(self.issuer_generator(), replies)

    def test_parse_backend_gap_not_swallowed_like_original_exception(self):

        def unresolved(_):
            raise CertificateBackendLimit('not modeled')
        with self.assertRaises(CertificateBackendLimit):
            drive(self.issuer_generator(parse=unresolved), iter([b'X']))
        replies = iter([ObservedReadFailure(), LDAPValues(1, (b'X', self.cert(1).data))])
        with self.assertRaises(CertificateBackendLimit):
            drive(self.issuer_generator(parse=unresolved), replies)

    def test_cache_write_io_nonfatal_but_encoding_failure_fatal(self):
        (result, _) = drive(self.issuer_generator(), iter([ObservedReadFailure(), LDAPValues(1, (self.cert(1).data,)), 'io_error']))
        self.assertTrue(result.cache_io_warning)
        with self.assertRaisesRegex(CertificateRuleError, 'cache_encoding_failed'):
            drive(self.issuer_generator(), iter([ObservedReadFailure(), LDAPValues(1, (self.cert(1).data,)), 'encoding_error']))

    def test_ldap_nonzero_not_only_one_is_caller_success(self):
        (result, _) = drive(self.issuer_generator(), iter([ObservedReadFailure(), LDAPValues(-1, (self.cert(1).data,)), 'written']))
        self.assertEqual(result.source, 'ldap')

    def test_ldap_failure_empty_vector_and_parse_exhaustion_are_distinct(self):
        cases = ((LDAPValues(0, None), 'ldap_failed'), (LDAPValues(1, None, True), 'vector_failed'), (LDAPValues(1, ()), 'ldap_empty'), (LDAPValues(1, (b'not-pem',)), 'no_parsable'))
        for (reply, error) in cases:
            with self.subTest(error=error), self.assertRaisesRegex(CertificateRuleError, error):
                drive(self.issuer_generator(), iter([ObservedReadFailure(), reply]))

    def test_unknown_wrapper_observation_not_success_or_original_failure(self):
        for reply in (LDAPValues(None, ()), LDAPValues(1, 'not a vector'), LDAPValues(1, (), None)):
            with self.assertRaises(CertificateBackendLimit):
                drive(self.issuer_generator(), iter([ObservedReadFailure(), reply]))

    def test_issuer_selection_does_not_add_signature_check_prematurely(self):
        from asn1crypto import x509
        cert = self.cert(1)
        obj = x509.Certificate.load(cert.data)
        obj['signature_algorithm']['algorithm'] = 'sha1_rsa'
        from giro.cert_material import CertificateMaterial
        invalid_signature_header = CertificateMaterial.from_der(obj.dump())
        (result, _) = drive(self.issuer_generator(stores=1), iter([(invalid_signature_header,)]))
        self.assertEqual(result.source, 'store')

    def test_crl_store_present_invalid_does_not_request_cache_or_ldap(self):
        gen = self.crl_generator(candidates=(self.crl(1, valid=False),))
        with self.assertRaisesRegex(CertificateRuleError, 'stored_crls_present_but_invalid'):
            next(gen)

    def test_crl_store_success_needs_no_distribution_point(self):
        (result, effects) = drive(self.crl_generator(target=self.target(dp=False), candidates=(self.crl(1),)), iter([]))
        self.assertEqual((result.source, effects), ('store', []))

    def test_crl_uri_selected_before_cache_and_does_not_use_aia(self):
        gen = self.crl_generator(target=self.target(dp=False))
        with self.assertRaisesRegex(CertificateRuleError, 'crl_distribution_point_parse_failed'):
            next(gen)
        (result, effects) = drive(self.crl_generator(), iter([self.crl(1).data]))
        self.assertEqual(result.source, 'cache')
        self.assertEqual(effects[0].cache_key, 'cn=list.crl')

    def test_crl_preserves_uri_attribute_and_default_only_when_null(self):
        for (uri, attribute) in (('ldap://crl.invalid/cn=list?custom', 'custom'), ('ldap://crl.invalid/cn=list', 'certificaterevocationlist')):
            replies = iter([ObservedReadFailure(), LDAPValues(1, (self.crl(1).data,)), 'written'])
            (result, effects) = drive(self.crl_generator(target=self.target(dp=uri)), replies)
            self.assertEqual(effects[1].location.attribute, attribute)
            self.assertEqual(result.source, 'ldap')

    def test_savecrl_false_skips_write_but_not_cache_read_or_validation(self):
        (result, effects) = drive(self.crl_generator(save_crl=False), iter([ObservedReadFailure(), LDAPValues(1, (self.crl(1).data,))]))
        self.assertEqual([e.kind for e in effects], ['read_crl_cache', 'ldap_crl'])
        self.assertEqual(result.source, 'ldap')
        with self.assertRaisesRegex(CertificateRuleError, 'crl_expired'):
            drive(self.crl_generator(save_crl=False), iter([ObservedReadFailure(), LDAPValues(1, (self.crl(1, valid=False).data, self.crl(1).data))]))

    def test_raw_ldap_reply_connects_to_issuer_parser_without_java_deserialization(self):
        issuer = self.cert(1)
        response = ldap_support.result() + ldap_support.entry([(b'CACERTIFICATE;binary', [issuer.data])]) + ldap_support.result(5, 49)

        def observations(effect):
            if effect.kind == 'read_certificate_cache':
                return ObservedReadFailure()
            if effect.kind == 'ldap_certificate':
                replay = replay_responses(response, effect.location, message_id=123, locale_language='ko')
                return LDAPValues(replay.code, replay.values)
            if effect.kind == 'write_certificate_cache':
                return 'io_error'
            self.fail('unexpected effect')
        with patch('socket.socket', side_effect=AssertionError('offline')):
            (result, _) = drive(self.issuer_generator(), observations)
        self.assertEqual(result.material.data, issuer.data)
        self.assertTrue(result.cache_io_warning)

    def test_anchor_failure_continues_and_later_success_wins(self):
        good = self.cert(0)
        (anchor, effects) = drive(anchor_steps(self.cert(1), (None, self.cert(0, valid=False), good), at=self.at), iter([True, True]))
        self.assertIs(anchor, good)
        self.assertEqual([e.index for e in effects], [1, 2])

    def test_anchor_no_match_returns_none_but_failed_match_throws(self):
        (anchor, _) = drive(anchor_steps(self.cert(1), (self.cert(0),), at=self.at), iter([False]))
        self.assertIsNone(anchor)
        with self.assertRaisesRegex(CertificateRuleError, 'matching_anchor_failed:certificate_expired'):
            drive(anchor_steps(self.cert(1), (self.cert(0, valid=False), self.cert(0)), at=self.at), iter([True, False]))

    def test_anchor_unknown_selector_not_guessed(self):
        with self.assertRaises(CertificateBackendLimit):
            drive(anchor_steps(self.cert(1), (self.cert(0),), at=self.at), iter([None]))

    def test_builder_then_supplied_path_validation_all_offline(self):
        (root, inter, target) = (self.cert(0), self.cert(1), self.cert(2))

        def observations(effect):
            if effect.kind == 'anchor_match':
                return effect.target.issuer_der == effect.candidate.subject_der
            if effect.kind == 'issuer_store':
                return (inter,)
            self.fail('unexpected effect')
        with patch('socket.socket', side_effect=AssertionError('offline')):
            (built, effects) = drive(build_path_steps(target, anchors=(root,), store_count=1, at=self.at, locale_language='ko'), observations)
            result = validate_supplied_path(built.path, trust_anchor=built.anchor, crls=(CRLContext((self.crl(1),)), CRLContext((self.crl(0),))), at=self.at, locale_language='ko')
        self.assertEqual([e.kind for e in effects], ['anchor_match', 'issuer_store', 'anchor_match'])
        self.assertTrue(result['path_rules_completed'])
        self.assertFalse(built.certificate_validation_performed)
        self.assertFalse(result['live_login_ready'])

    def test_builder_self_issued_without_anchor_requires_ctl_not_automatic_trust(self):
        gen = build_path_steps(self.cert(0), anchors=(), store_count=0, at=self.at, locale_language='ko')
        with self.assertRaisesRegex(CertificateBackendLimit, 'CTL'):
            next(gen)

    def test_raw_ldap_issuer_and_crls_connect_to_all_supplied_path_rules(self):
        from cryptography import x509
        (root, target) = (self.cert(0), self.target())
        point = x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier('ldap://root-crl.invalid/cn=root')], None, None, None)])
        inter = self.cert(1, extra=((point, False),))
        lists = {'root-crl.invalid': self.crl(0), 'crl.invalid': self.crl(1)}
        events = []

        def observations(effect):
            events.append(effect.kind)
            if effect.kind == 'anchor_match':
                return effect.target.issuer_der == effect.candidate.subject_der
            if effect.kind == 'issuer_store':
                return ()
            if effect.kind.startswith('read_'):
                return ObservedReadFailure()
            if effect.kind.startswith('write_'):
                return 'io_error'
            material = inter if effect.kind == 'ldap_certificate' else lists[effect.location.host]
            data = ldap_support.result() + ldap_support.entry([(effect.location.attribute.encode(), [material.data])]) + ldap_support.result(5, 49)
            replay = replay_responses(data, effect.location, message_id=19, locale_language='ko')
            return LDAPValues(replay.code, replay.values)
        with patch('socket.socket', side_effect=AssertionError('offline')):
            (built, _) = drive(build_path_steps(target, anchors=(root,), store_count=1, at=self.at, locale_language='ko'), observations)
            contexts = [None, None]
            for (index, cert, issuer) in ((1, inter, root), (0, target, inter)):
                (acquired, _) = drive(crl_steps(cert, issuer, candidates=(), at=self.at, locale_language='ko', attribute='authorityrevocationlist' if index else 'certificaterevocationlist', save_crl=True), observations)
                contexts[index] = CRLContext((acquired.material,))
            output = validate_supplied_path(built.path, trust_anchor=built.anchor, crls=contexts, at=self.at, locale_language='ko')
        self.assertTrue(output['path_rules_completed'])
        self.assertTrue(output['revocation_checked'])
        self.assertEqual(events.count('ldap_certificate'), 1)
        self.assertEqual(events.count('ldap_crl'), 2)
        self.assertFalse(output['live_login_ready'])

    def test_builder_target_validity_before_any_effect(self):
        gen = build_path_steps(self.cert(2, valid=False), anchors=(self.cert(0),), store_count=1, at=self.at, locale_language='ko')
        with self.assertRaisesRegex(CertificateRuleError, 'expired'):
            next(gen)

    def test_builder_budget_is_diagnostic_not_invented_sdk_cycle_failure(self):
        gen = build_path_steps(self.cert(2), anchors=(), store_count=0, at=self.at, locale_language='ko', step_budget=0)
        with self.assertRaisesRegex(CertificateBackendLimit, 'budget'):
            next(gen)

    def test_effects_and_results_hide_identifiers_and_bytes(self):
        effect = AcquisitionEffect('read_certificate_cache', cache_key='PRIVATE', data=b'PRIVATE')
        self.assertNotIn('PRIVATE', repr(effect))
        (result, _) = drive(self.issuer_generator(), iter([self.cert(1).data]))
        self.assertNotIn('synthetic', repr(result))
