from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from giro.cert_rules import ANY_POLICY, DEFAULT_POLICIES, EKU_MASKS, HANDLED_CRITICAL, CertificateRuleError, PolicyState, check_extended_key_usage, check_recipient_key_usage, check_ca_constraints, unhandled_critical, check_crl_window, check_crl_signer_usage, check_revocation_entry, crl_attribute, crl_source_action, check_missing_idp

class PolicyTests(unittest.TestCase):

    def state(self, licensed=False, **kwargs):
        return PolicyState.initial(3, initial_policies={'1.2.3', '1.2.4'}, licensed_ca=licensed, **kwargs)

    def test_normal_path_narrows_policies_between_certificates(self):
        ca = self.state().step(['1.2.3'])
        self.assertEqual(ca.allowed, {'1.2.3'})
        with self.assertRaises(CertificateRuleError):
            ca.step(['1.2.4'], target=True)

    def test_licensed_path_retains_initial_allow_set(self):
        ca = self.state(True).step(['1.2.3'])
        self.assertEqual(ca.allowed, {'1.2.3', '1.2.4'})
        self.assertEqual(ca.step(['1.2.4'], target=True).allowed, ca.allowed)

    def test_licensed_requires_all_policies_not_just_one_intersection(self):
        self.state().step(['1.2.3', '9.9'])
        with self.assertRaisesRegex(CertificateRuleError, 'licensed_policy_count_mismatch'):
            self.state(True).step(['1.2.3', '9.9'])

    def test_duplicate_policy_sequence_count_is_not_set_count(self):
        self.state().step(['1.2.3', '1.2.3'])
        with self.assertRaisesRegex(CertificateRuleError, 'count_mismatch'):
            self.state(True).step(['1.2.3', '1.2.3'])

    def test_any_policy_breaks_early_and_keeps_previous_allow_set(self):
        self.assertEqual(self.state().step(['1.2.3', ANY_POLICY, '9.9']).allowed, self.state().allowed)
        with self.assertRaisesRegex(CertificateRuleError, 'count_mismatch'):
            self.state(True).step([ANY_POLICY])
        self.state(True).step([ANY_POLICY, '9.9'])

    def test_any_inhibited_can_still_match_literal_initial_policy(self):
        with self.assertRaises(CertificateRuleError):
            self.state(any_inhibited=True).step([ANY_POLICY])
        state = PolicyState.initial(1, initial_policies={ANY_POLICY}, licensed_ca=False, any_inhibited=True)
        self.assertEqual(state.step([ANY_POLICY], target=True).allowed, {ANY_POLICY})

    def test_missing_empty_and_unaccepted_policies_fail_explicit_rule(self):
        for policies in (None, [], ['9.9']):
            with self.subTest(policies=policies), self.assertRaises(CertificateRuleError):
                self.state().step(policies)

    def test_self_issued_ca_does_not_decrement_or_apply_constraints(self):
        state = self.state(explicit_required=False)
        after = state.step(['1.2.3'], self_issued=True, require_explicit=0, inhibit_any=0)
        self.assertEqual((after.explicit, after.inhibit_any), (4, 4))

    def test_leaf_applies_explicit_constraint_even_when_self_issued(self):
        state = self.state(explicit_required=False)
        after = state.step(['1.2.3'], target=True, self_issued=True, require_explicit=0, inhibit_any=0)
        self.assertEqual((after.explicit, after.inhibit_any), (0, 4))

    def test_ca_counter_updates_use_java_intvalue_and_minus_one_sentinel(self):
        state = self.state(explicit_required=False)
        after = state.step(['1.2.3'], require_explicit=2 ** 32 + 1, inhibit_any=2 ** 32)
        self.assertEqual((after.explicit, after.inhibit_any), (1, 0))
        after = state.step(['1.2.3'], require_explicit=2 ** 32 - 1)
        self.assertEqual(after.explicit, 3)

class UsageAndCrlTests(unittest.TestCase):

    def test_all_six_eku_masks_all_low_byte_values(self):
        for (oid, mask) in EKU_MASKS.items():
            for ku in range(256):
                if ku & mask:
                    check_extended_key_usage(ku, [oid])
                else:
                    with self.assertRaises(CertificateRuleError):
                        check_extended_key_usage(ku, [oid])

    def test_unknown_eku_not_silently_accepted_including_anyeku(self):
        for unknown in ('1.2.3', '2.5.29.37.0'):
            with self.assertRaises(CertificateRuleError):
                check_extended_key_usage(255, ['1.3.6.1.5.5.7.3.1', unknown])

    def test_absent_and_empty_eku_do_not_invent_serverauth_requirement(self):
        for (ku, eku) in ((None, ['unknown']), (32, None), (0, [])):
            check_extended_key_usage(ku, eku)
        check_recipient_key_usage(32)
        for mask in (None, 0, 128):
            with self.assertRaises(CertificateRuleError):
                check_recipient_key_usage(mask)

    def test_ca_pathlen_decrement_and_limit(self):
        args = dict(version=3, is_ca=True, path_length=0, self_issued=False, remaining_path=3, key_usage_mask=4)
        self.assertEqual(check_ca_constraints(**args), 0)
        with self.assertRaisesRegex(CertificateRuleError, 'exhausted'):
            check_ca_constraints(**{**args, 'remaining_path': 0})
        self.assertEqual(check_ca_constraints(**{**args, 'remaining_path': 0, 'self_issued': True}), 0)

    def test_ca_actual_required_fields_and_v1_rejection(self):
        args = dict(version=3, is_ca=True, path_length=None, self_issued=False, remaining_path=3, key_usage_mask=4)
        for change in ({'version': 1}, {'is_ca': None}, {'is_ca': False}, {'key_usage_mask': None}, {'key_usage_mask': 2}):
            with self.assertRaises(CertificateRuleError):
                check_ca_constraints(**{**args, **change})

    def test_critical_list_does_not_treat_aki_ski_as_implicitly_handled(self):
        self.assertEqual(unhandled_critical(HANDLED_CRITICAL), set())
        self.assertEqual(unhandled_critical(['2.5.29.14', '2.5.29.35']), {'2.5.29.14', '2.5.29.35'})
        self.assertEqual(unhandled_critical(['unknown'], version=1), set())

    def test_crl_window_inclusive_endpoints_but_both_dates_required(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        end = now + timedelta(days=1)
        check_crl_window(now, end, now)
        check_crl_window(now, end, end)
        for args in ((None, end, now), (now, None, now), (end, end, now), (now, now, end)):
            with self.assertRaises(CertificateRuleError):
                check_crl_window(*args)

    def test_revocation_date_future_is_error_not_future_validity(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        check_revocation_entry(None, now)
        for (offset, error) in ((1, 'revocation_date_in_future'), (0, 'certificate_revoked'), (-1, 'certificate_revoked')):
            with self.assertRaisesRegex(CertificateRuleError, error):
                check_revocation_entry(now + timedelta(seconds=offset), now)

    def test_trust_anchor_crlsign_exemption_does_not_apply_to_ca(self):
        check_crl_signer_usage(None, is_trust_anchor=True)
        check_crl_signer_usage(2, is_trust_anchor=False)
        with self.assertRaises(CertificateRuleError):
            check_crl_signer_usage(4, is_trust_anchor=False)

    def test_existing_bad_store_crls_do_not_fall_back_to_network(self):
        self.assertEqual(crl_source_action(store_had_candidates=False, valid_store_candidate=False), 'find_crl')
        self.assertEqual(crl_source_action(store_had_candidates=True, valid_store_candidate=True), 'use_store')
        with self.assertRaises(CertificateRuleError):
            crl_source_action(store_had_candidates=True, valid_store_candidate=False)

    def test_crl_attribute_leaf_directly_under_root_uses_arl(self):
        self.assertEqual(crl_attribute(target=True, issuer_name_equals_root_name=True), 'authorityrevocationlist')
        self.assertEqual(crl_attribute(target=False, issuer_name_equals_root_name=False), 'authorityrevocationlist')
        self.assertEqual(crl_attribute(target=True, issuer_name_equals_root_name=False), 'certificaterevocationlist')

    def test_idp_absent_rule_is_mode_and_rendered_name_sensitive(self):
        check_missing_idp(licensed_ca=True, issuer_name_lower='cn=synthetic')
        check_missing_idp(licensed_ca=False, issuer_name_lower='o=kisa-synthetic')
        with self.assertRaises(CertificateRuleError):
            check_missing_idp(licensed_ca=False, issuer_name_lower='o = kisa')
ROOT = Path(__file__).resolve().parents[1] / 'analysis'
