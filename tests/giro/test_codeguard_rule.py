import hashlib
from pathlib import Path
import unittest
from giro.codeguard_rule import AnalysisLimit, HASHES, OPERATIONS, NativeRuleError, RulePlan, parse_rule, parsing_positions

class CodeGuardRuleTests(unittest.TestCase):

    def test_odd_challenge_uses_floor_length_tail(self):
        expected = tuple((b % 10 for b in hashlib.sha1(b'appDEversion').digest()[:3]))
        self.assertEqual(parsing_positions(b'ABCDE', b'app', b'version'), expected)

    def test_native_string_lengths_but_binary_challenge(self):
        expected = tuple((b % 10 for b in hashlib.sha1(b'a\x00Zv').digest()[:3]))
        self.assertEqual(parsing_positions(b'AB\x00Z', b'a\x00ignored', b'v\x00ignored'), expected)

    def test_empty_challenge_is_not_an_added_gate(self):
        expected = tuple((b % 10 for b in hashlib.sha1(b'av').digest()[:3]))
        self.assertEqual(parsing_positions(b'', b'a', b'v'), expected)

    def test_explicit_native_error_codes(self):
        for (action, code) in ((lambda : parsing_positions(b'', None, None), 40), (lambda : parsing_positions(b'', b'', None), 41), (lambda : parse_rule(None, (0, 0, 0)), 50), (lambda : parse_rule(b'\x7f', (0, 0, 0)), 51), (lambda : parse_rule(b'\xff', (0, 0, 0)), 51)):
            with self.subTest(code=code), self.assertRaises(NativeRuleError) as caught:
                action()
            self.assertEqual(caught.exception.native_code, code)

    def test_wrap_and_distinct_hashes(self):
        plan = parse_rule(bytes([2]), (9, 9, 9))
        self.assertEqual(plan.hash_ids, (2, 0))
        self.assertEqual(plan.operation_ids, (2,) * 5)
        self.assertEqual(plan.selected_offsets, (0,) * 8)

    def test_skipped_high_bytes_are_not_rejected(self):
        rule = bytes([0, 1, 255, 127, 0, 255, 127, 2, 3, 6])
        plan = parse_rule(rule, (0, 2, 2))
        self.assertEqual(plan.selected_offsets, (0, 1, 4, 7, 8, 9))
        self.assertEqual(plan.hash_ids, (0, 1))
        self.assertEqual(plan.operation_ids, (2, 3, 6))

    def test_all_selector_values_and_counts(self):
        for byte in range(127):
            plan = parse_rule(bytes([byte]), (0, 0, 0))
            self.assertEqual(plan.hash_ids, (byte % 3, (byte % 3 + 1) % 3))
            self.assertEqual(plan.operation_ids, (byte % 7,) * (byte % 3 + 3))

    def test_unmodeled_memory_is_not_native_failure(self):
        for (data, positions) in ((b'', (0, 0, 0)), (b'a', (-1, 0, 0)), (b'a', (10, 0, 0)), (b'a', (0, 0))):
            with self.subTest(data=data, positions=positions), self.assertRaises(AnalysisLimit):
                parse_rule(data, positions)

    def test_symbolic_plan_order_and_optional_extra(self):
        plan = RulePlan((0, 2), (2, 0, 6), ())
        description = plan.describe(extra_present=True)
        self.assertEqual(description['steps'][1]['right'], 'extra')
        self.assertEqual(description['steps'][2]['left'], 'SHA-1(s0_extra)')
        self.assertEqual(description['steps'][2]['right'], 'SHA-256(s0_extra)')
        self.assertEqual(description['steps'][3]['left'], 'SHA-256(s1)')
        self.assertFalse(description['response_generated'])
        self.assertEqual(len(plan.describe()['steps']), 3)
