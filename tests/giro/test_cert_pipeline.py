import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from giro.cert_acquisition import ObservedStoreFailure, LDAPValues
from giro.cert_factory import CertificateBackendLimit
from giro.cert_path import PathRuleError
from giro.cert_rules import CertificateRuleError
from giro.cert_pipeline import build_and_validate_steps, public_store_steps
from giro.cert_selectors import MaterialStore, select_material_effect
from giro.public_material_io import PublicCache, PublicLdapClient, PublicMaterialExecutor, MaterialAccessLimit
import test_cert_acquisition as acquisition
import test_ldap_codec as wire
import test_public_material_io as io_support
import test_cert_ctl as ctl_support

def drive(generator, reply):
    (value, error) = (None, None)
    while True:
        try:
            effect = generator.throw(error) if error is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        error = None
        try:
            value = reply(effect)
        except Exception as exc:
            error = exc

@unittest.skipUnless(importlib.util.find_spec('asn1crypto') and importlib.util.find_spec('cryptography'), 'crypto unavailable')
class PipelineTests(unittest.TestCase):
    cert = acquisition.AcquisitionTests.cert
    crl = acquisition.AcquisitionTests.crl
    target = acquisition.AcquisitionTests.target
    setUpClass = classmethod(acquisition.AcquisitionTests.setUpClass.__func__)

    def generator(self, *, target=None, anchors=None, stores=1, **kwargs):
        return build_and_validate_steps(target or self.target(), anchors=(self.cert(0),) if anchors is None else anchors, store_count=stores, at=self.at, locale_language='ko', ctl_distribution_point=None, save_crl=True, **kwargs)

    def store(self, *, issuer=None, root_crl=None, leaf_crl=None):
        return MaterialStore((issuer or self.cert(1),), (root_crl or self.crl(0), leaf_crl or self.crl(1)))

    def run_store(self, *, store=None, **kwargs):
        executor = PublicMaterialExecutor(stores=(store or self.store(),))
        with patch('socket.socket', side_effect=AssertionError('offline')), patch('getpass.getpass', side_effect=AssertionError('no PIN')):
            return executor.run(self.generator(**kwargs))

    def test_discovery_through_mandatory_validation_without_supplied_path(self):
        result = self.run_store()
        for flag in ('path_acquisition_completed', 'anchor_selection_completed', 'path_rules_completed', 'revocation_checked'):
            self.assertTrue(result[flag])
        self.assertFalse(result['anchor_via_ctl'])
        self.assertFalse(result['certificate_validation_performed'])
        self.assertFalse(result['live_login_ready'])
        self.assertFalse(result['network_attempted'])
        self.assertTrue(result['offline'])
        self.assertEqual([x['certificate_index'] for x in result['completed']], [1, 0])
        self.assertEqual([x['revocation_attribute'] for x in result['completed']], ['authorityrevocationlist', 'certificaterevocationlist'])
        self.assertNotIn('synthetic', json.dumps(result))

    def test_builder_and_validator_each_find_anchor_then_crls_root_down(self):
        effects = []
        stores = (self.store(),)

        def reply(effect):
            effects.append((effect.kind, effect.target.serial))
            return select_material_effect(effect, stores)
        result = drive(self.generator(), reply)
        self.assertEqual(effects, [('anchor_match', 3), ('issuer_store', 3), ('anchor_match', 2), ('anchor_match', 2), ('crl_store', 2), ('crl_store', 3)])
        self.assertTrue(result['revocation_checked'])

    def test_invalid_target_before_any_store_or_anchor_effect(self):
        with self.assertRaisesRegex(CertificateRuleError, 'certificate_expired'):
            drive(self.generator(target=self.target(valid=False)), lambda _: self.fail('premature effect'))

    def test_matching_bad_anchor_never_tries_ctl_or_crls(self):
        stores = (self.store(),)
        effects = []

        def reply(effect):
            effects.append(effect.kind)
            return select_material_effect(effect, stores)
        with self.assertRaisesRegex(CertificateRuleError, 'matching_anchor_failed'):
            drive(self.generator(anchors=(self.cert(0, valid=False),)), reply)
        self.assertNotIn('ldap_ctl', effects)
        self.assertNotIn('crl_store', effects)

    def test_revoked_intermediate_stops_before_leaf_lookup(self):
        stores = (self.store(root_crl=self.crl(0, revoked=True)),)
        seen = []

        def reply(effect):
            if effect.kind == 'crl_store':
                seen.append(effect.target.serial)
            return select_material_effect(effect, stores)
        with self.assertRaises(PathRuleError) as caught:
            drive(self.generator(), reply)
        self.assertEqual((caught.exception.rule, caught.exception.certificate_index), ('certificate_revoked', 1))
        self.assertEqual(seen, [2])

    def test_policy_failure_precedes_leaf_crl_acquisition(self):
        stores = (self.store(issuer=self.cert(1, policy=False)),)
        seen = []

        def reply(effect):
            if effect.kind == 'crl_store':
                seen.append(effect.target.serial)
            return select_material_effect(effect, stores)
        with self.assertRaises(PathRuleError) as caught:
            drive(self.generator(), reply)
        self.assertEqual(caught.exception.stage, 'certificate_policies')
        self.assertEqual(seen, [2])

    def test_invalid_present_crl_not_replaced_by_online_crl(self):
        with self.assertRaises(PathRuleError) as caught:
            self.run_store(store=self.store(leaf_crl=self.crl(1, valid=False)))
        self.assertEqual((caught.exception.rule, caught.exception.stage), ('stored_crls_present_but_invalid', 'revocation'))

    def test_unknown_io_configuration_is_not_app_failure_or_empty_store(self):
        with self.assertRaises(MaterialAccessLimit):
            self.run_store(store=MaterialStore((self.cert(1),), (self.crl(0),)))

    def test_store_exception_is_skipped_but_python_fault_not_forged(self):
        stores = (ObservedStoreFailure(), self.store())
        result = PublicMaterialExecutor(stores=stores).run(self.generator(stores=2))
        self.assertTrue(result['path_rules_completed'])
        with patch('giro.cert_pipeline.select_material_effect', side_effect=TypeError('synthetic bug')):
            with self.assertRaises(TypeError):
                self.run_store()

    def test_distinct_crls_across_stores_require_actual_hashset_order(self):
        stores = (MaterialStore((self.cert(1),), (self.crl(0),)), MaterialStore(crls=(self.crl(0, valid=False),)))
        with self.assertRaisesRegex(CertificateBackendLimit, 'HashSet'):
            PublicMaterialExecutor(stores=stores).run(self.generator(stores=2))

    def test_duplicates_across_stores_are_not_ambiguous(self):
        store = self.store()
        result = PublicMaterialExecutor(stores=(store, store)).run(self.generator(stores=2))
        self.assertTrue(result['path_rules_completed'])

    def test_delta_lookup_does_not_precede_revocation(self):
        from cryptography import x509
        delta = self.crl(1, revoked=True, extra=(x509.DeltaCRLIndicator(5), x509.CRLNumber(7)))
        stores = (self.store(leaf_crl=delta),)
        seen = []

        def reply(effect):
            seen.append(effect.kind)
            return select_material_effect(effect, stores)
        with self.assertRaisesRegex(PathRuleError, 'certificate_revoked'):
            drive(self.generator(), reply)
        self.assertNotIn('delta_crl_store', seen)

    def test_delta_base_lookup_is_lazy_and_missing_base_fails(self):
        from cryptography import x509
        delta = self.crl(1, extra=(x509.DeltaCRLIndicator(5), x509.CRLNumber(7)))
        stores = (self.store(leaf_crl=delta),)
        seen = []

        def reply(effect):
            seen.append(effect.kind)
            return select_material_effect(effect, stores)
        with self.assertRaisesRegex(PathRuleError, 'delta_base_crl_not_found'):
            drive(self.generator(), reply)
        self.assertEqual(seen[-1], 'delta_crl_store')

    def test_bad_leaf_signature_fails_before_leaf_crl_lookup(self):
        from asn1crypto import x509
        from giro.cert_material import CertificateMaterial
        obj = x509.Certificate.load(self.target().data)
        raw = obj['signature_value'].native
        obj['signature_value'] = bytes([raw[0] ^ 1]) + raw[1:]
        target = CertificateMaterial.from_der(obj.dump())
        stores = (self.store(),)
        seen = []

        def reply(effect):
            if effect.kind == 'crl_store':
                seen.append(effect.target.serial)
            return select_material_effect(effect, stores)
        with self.assertRaises(PathRuleError) as caught:
            drive(self.generator(target=target), reply)
        self.assertEqual(caught.exception.stage, 'signature')
        self.assertEqual(seen, [2])

    def test_self_issued_stop_does_not_declare_trust(self):
        target = self.cert(0)
        with self.assertRaisesRegex(CertificateRuleError, 'ctl_distribution_point_invalid'):
            PublicMaterialExecutor(stores=()).run(self.generator(target=target, anchors=(), stores=0))

    def test_local_public_cache_connects_missing_issuer_and_leaf_crl(self):
        from giro.cert_acquisition import _ca_key
        target = self.target()
        with tempfile.TemporaryDirectory() as folder, PublicCache(folder, max_bytes=65536) as cache:
            cache.write(_ca_key(target), self.cert(1).data)
            cache.write('cn=list.crl', self.crl(1).data)
            executor = PublicMaterialExecutor(stores=(MaterialStore(crls=(self.crl(0),)),), cache=cache)
            with patch('socket.socket', side_effect=AssertionError('offline')):
                result = executor.run(self.generator(target=target))
        self.assertTrue(result['path_rules_completed'])
        self.assertFalse(executor.network_attempted)

    def test_mock_wire_to_real_cache_to_full_mandatory_path(self):
        (issuer, leaf_crl) = (self.cert(1), self.crl(1))

        def response(attribute, value):
            return wire.result() + wire.entry([(attribute, [value])]) + wire.result(5, 49)
        sockets = [io_support.FakeSocket(response(b'cacertificate;binary', issuer.data)), io_support.FakeSocket(response(b'customAttribute', leaf_crl.data))]
        ldap = PublicLdapClient(allowed_endpoints=(('issuer.invalid', 123), ('crl.invalid', 389)), timeout_ms=100, max_bytes=65536, locale_language='ko')
        with tempfile.TemporaryDirectory() as folder, PublicCache(folder, max_bytes=65536) as cache:
            executor = PublicMaterialExecutor(stores=(MaterialStore(crls=(self.crl(0),)),), cache=cache, ldap=ldap)
            with patch('socket.socket', side_effect=AssertionError('no real network')), patch('socket.create_connection', side_effect=sockets) as connect:
                first = executor.run(self.generator())
            self.assertEqual(connect.call_count, 2)
            self.assertEqual(cache.read('cn=list.crl'), leaf_crl.data)
            with patch('socket.create_connection', side_effect=AssertionError('second run uses cache')):
                second = executor.run(self.generator())
        self.assertTrue(first['path_rules_completed'] and second['path_rules_completed'])
        self.assertFalse(first['offline'])
        self.assertTrue(first['network_attempted'])
        self.assertEqual(second['io_observation_scope'], 'executor_lifetime')
        self.assertFalse(second['transport_equivalence_verified'])
        self.assertTrue(all((s.closed for s in sockets)))
        self.assertTrue(executor.network_attempted)

    def test_cache_write_io_warns_without_reversing_original_success(self):
        crl = self.crl(1)

        class SyntheticLdap:
            network_attempted = False

            def fetch(self, location):
                from giro.public_material_io import PublicLdapResult
                from giro.ldap_codec import LdapReplay
                return PublicLdapResult(LdapReplay(1, (crl.data,), ()), False)
        with tempfile.TemporaryDirectory() as folder, PublicCache(folder, max_bytes=65536) as cache:
            executor = PublicMaterialExecutor(stores=(MaterialStore((self.cert(1),), (self.crl(0),)),), cache=cache, ldap=SyntheticLdap())
            with patch('os.write', side_effect=OSError('synthetic')):
                result = executor.run(self.generator())
        self.assertTrue(result['path_rules_completed'])
        self.assertEqual(executor.cache_io_warnings, 1)
        self.assertEqual(result['cache_io_warnings'], 1)

@unittest.skipUnless(importlib.util.find_spec('asn1crypto') and importlib.util.find_spec('cryptography'), 'crypto unavailable')
class RecipientCLITests(unittest.TestCase):
    cert = PipelineTests.cert
    crl = PipelineTests.crl
    setUpClass = classmethod(acquisition.AcquisitionTests.setUpClass.__func__)

    def inspect(self, *, target=None, issuers=None, crls=None, anchors=None):
        from giro.cert_pipeline import inspect_recipient_material
        return inspect_recipient_material(target or self.cert(2).data, [self.cert(0).data] if anchors is None else anchors, [self.cert(1).data] if issuers is None else issuers, [self.crl(0).data, self.crl(1).data] if crls is None else crls, at=self.at, locale_language='ko')

    def test_success_has_no_giro_success_or_trust_install_claim(self):
        with patch('socket.socket', side_effect=AssertionError('offline')):
            result = self.inspect()
        self.assertEqual(result['analysis_status'], 'acquired_path_rules_completed')
        self.assertTrue(result['path_rules_completed'])
        self.assertFalse(result['certificate_validation_performed'])
        self.assertFalse(result['live_login_ready'])
        self.assertNotIn('app_success', result)

    def test_missing_issuer_reports_pending_effect_without_making_up_cache_miss(self):
        result = self.inspect(issuers=[])
        self.assertEqual(result['analysis_status'], 'material_or_io_needed')
        self.assertEqual(result['pending_effect'], 'read_certificate_cache')

    def test_ambiguous_issuer_order_stays_diagnostic(self):
        result = self.inspect(issuers=[self.cert(1, valid=False).data, self.cert(1).data])
        self.assertEqual(result['analysis_status'], 'unmodeled')
        self.assertNotIn('app_success', result)

    def test_revoked_certificate_retains_original_rule_and_stage(self):
        result = self.inspect(crls=[self.crl(0).data, self.crl(1, revoked=True).data])
        self.assertEqual((result['rule_error'], result['stage'], result['certificate_index']), ('certificate_revoked', 'revocation', 0))

    def test_target_expiration_is_acquisition_error(self):
        result = self.inspect(target=self.cert(2, valid=False).data)
        self.assertEqual((result['analysis_status'], result['rule_error']), ('acquisition_rule_failed', 'certificate_expired'))

    def test_explicit_bad_certificate_and_unmodeled_crl_differ(self):
        self.assertEqual(self.inspect(target=b'not-pem')['analysis_status'], 'certificate_input_failed')
        self.assertEqual(self.inspect(crls=[b'not-pem'])['analysis_status'], 'unmodeled')

    def test_ctl_uses_configured_default_without_implicitly_contacting_it(self):
        result = self.inspect(target=self.cert(0).data, anchors=[])
        self.assertEqual((result['analysis_status'], result['pending_effect']), ('material_or_io_needed', 'ldap_ctl'))

    def test_cli_hides_filenames_and_reads_only_explicit_files(self):
        from giro.__main__ import parser, run
        files = {'PRIVATE-target': self.cert(2).data, 'PRIVATE-root': self.cert(0).data, 'PRIVATE-issuer': self.cert(1).data, 'PRIVATE-crl0': self.crl(0).data, 'PRIVATE-crl1': self.crl(1).data}
        with patch.object(Path, 'read_bytes', lambda p: files[str(p)]), patch('socket.socket', side_effect=AssertionError('offline')), patch('getpass.getpass', side_effect=AssertionError('no PIN')):
            (result, code) = run(parser().parse_args(['auth', 'inspect-recipient', '--input', 'PRIVATE-target', '--trust-anchor', 'PRIVATE-root', '--issuer', 'PRIVATE-issuer', '--crl', 'PRIVATE-crl0', '--crl', 'PRIVATE-crl1', '--at', self.at.isoformat(), '--locale', 'ko']))
        self.assertEqual(code, 0)
        self.assertTrue(result['path_rules_completed'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_cli_timezone_required_before_file_read(self):
        from giro.__main__ import parser, run
        from giro.errors import GiroError
        args = parser().parse_args(['auth', 'inspect-recipient', '--input', 'target', '--trust-anchor', 'root', '--at', '2026-09-28T12:00:00', '--locale', 'ko'])
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('no read')), self.assertRaises(GiroError):
            run(args)

    def test_cli_file_error_does_not_disclose_path(self):
        from giro.__main__ import parser, run
        from giro.errors import GiroError
        args = parser().parse_args(['auth', 'inspect-recipient', '--input', 'PRIVATE', '--trust-anchor', 'PRIVATE', '--at', self.at.isoformat(), '--locale', 'ko'])
        with patch.object(Path, 'read_bytes', side_effect=OSError('PRIVATE')):
            with self.assertRaises(GiroError) as caught:
                run(args)
        self.assertNotIn('PRIVATE', str(caught.exception))

@unittest.skipUnless(importlib.util.find_spec('asn1crypto') and importlib.util.find_spec('cryptography'), 'crypto unavailable')
class BuiltCTLTests(ctl_support.Fixtures, unittest.TestCase):

    def self_signed_issuer(self):
        from asn1crypto import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from giro.cert_material import CertificateMaterial
        obj = x509.Certificate.load(self.cert(1).data)
        obj['tbs_certificate']['issuer'] = obj['tbs_certificate']['subject']
        obj['signature_value'] = self.keys[1].sign(obj['tbs_certificate'].dump(), padding.PKCS1v15(), hashes.SHA256())
        return CertificateMaterial.from_der(obj.dump())

    def context(self, *, revoked=False, bad_ctl=False):
        from cryptography import x509
        issuer = self.self_signed_issuer()
        names = [x509.UniformResourceIdentifier('ldap://synthetic.invalid/crl')]
        target = self.cert(2, extra=((x509.CRLDistributionPoints([x509.DistributionPoint(names, None, None, None)]), False),))
        idp = x509.IssuingDistributionPoint(names, None, True, False, None, False, False)
        store = MaterialStore((issuer,), (self.crl(1, extra=(idp,), revoked=revoked),))
        raw = self.raw_signed(self.content(issuer), corrupt=bad_ctl)
        generator = build_and_validate_steps(target, anchors=(self.cert(0),), store_count=1, at=self.at, locale_language='ko', ctl_distribution_point=ctl_support.DP, save_crl=True)
        return (generator, store, raw)

    def test_real_builder_to_ctl_to_remaining_crl_checks(self):
        (generator, store, raw) = self.context()
        effects = []

        def reply(effect):
            effects.append(effect.kind)
            if effect.kind == 'ldap_ctl':
                return LDAPValues(1, (raw,))
            if effect.kind == 'ctl_global_trust_contains':
                return True
            self.fail('unexpected unmodeled operation ' + effect.kind)
        result = drive(public_store_steps(generator, (store,)), reply)
        self.assertEqual(effects, ['ldap_ctl', 'ctl_global_trust_contains'])
        self.assertEqual(result['supplied_path_length'], 1)
        self.assertTrue(result['anchor_via_ctl'] and result['revocation_checked'])
        self.assertFalse(result['certificate_validation_performed'])

    def test_ctl_still_does_not_waive_revoked_leaf(self):
        (generator, store, raw) = self.context(revoked=True)
        with self.assertRaisesRegex(PathRuleError, 'certificate_revoked'):
            drive(public_store_steps(generator, (store,)), lambda effect: LDAPValues(1, (raw,)) if effect.kind == 'ldap_ctl' else True)

    def test_bad_ctl_stops_before_trust_or_crl_lookup(self):
        (generator, store, raw) = self.context(bad_ctl=True)
        effects = []

        def reply(effect):
            effects.append(effect.kind)
            if effect.kind == 'ldap_ctl':
                return LDAPValues(1, (raw,))
            self.fail('premature state effect')
        with self.assertRaisesRegex(CertificateRuleError, 'ctl_signature_error'):
            drive(public_store_steps(generator, (store,)), reply)
        self.assertEqual(effects, ['ldap_ctl'])

    def test_actual_executor_does_not_invent_global_trust_state(self):
        (generator, store, raw) = self.context()

        class SyntheticLdap:
            network_attempted = False

            def fetch(self, location):
                from giro.public_material_io import PublicLdapResult
                from giro.ldap_codec import LdapReplay
                return PublicLdapResult(LdapReplay(1, (raw,), ()), False)
        executor = PublicMaterialExecutor(stores=(store,), ldap=SyntheticLdap())
        with self.assertRaises(MaterialAccessLimit):
            executor.run(generator)
        self.assertFalse(executor.network_attempted)
