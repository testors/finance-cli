import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest
from giro.codeguard_flow import ChallengeState, JavaStageError, ObservedCertificateParseFailure, ObservedJavaException, ReturnedTokenDecodeError, challenge_should_continue, effective_split, submission_responses, returned_token_key_iv, decode_returned_token, java_substring
from giro.codeguard_codec import java_seed_encrypt
from giro.codeguard_rule import AnalysisLimit

class FlowTests(unittest.TestCase):

    def test_null_challenge_is_exception_before_guard_and_prefix_only_shortcircuits(self):
        with self.assertRaises(JavaStageError):
            challenge_should_continue(None)
        self.assertFalse(challenge_should_continue('E101_NET_ERROR_006&&detail'))
        self.assertTrue(challenge_should_continue('xE101_NET_ERROR::rule'))
        self.assertTrue(challenge_should_continue(''))

    def test_challenge_two_fields_preserve_previous_cert_fourth_and_suffix(self):
        state = ChallengeState('old', 'rule', 'cert', 'object', 'fourth', 'suffix')
        state.consume('new::new-rule')
        self.assertEqual((state.challenge, state.rule), ('new', 'new-rule'))
        self.assertEqual((state.certificate_text, state.certificate, state.fourth, state.rcl_suffix), ('cert', 'object', 'fourth', 'suffix'))
        state.consume('single')
        self.assertEqual(state.challenge, 'new')

    def test_challenge_java_split_trailing_empty_and_more_than_four_fields(self):
        state = ChallengeState(fourth='old')
        state.consume('c::r::YQ==::four', decode_certificate=lambda b: b)
        self.assertEqual((state.certificate, state.fourth), (b'a', 'four'))
        state.consume('d::s::Yg==::ignored::extra', decode_certificate=lambda b: b)
        self.assertEqual((state.challenge, state.certificate, state.fourth), ('d', b'b', 'four'))
        state.consume('e::t::')
        self.assertEqual((state.challenge, state.certificate_text), ('e', 'Yg=='))

    def test_observed_certificate_failure_retains_old_object_but_not_text(self):

        def failed(_):
            raise ObservedCertificateParseFailure()
        state = ChallengeState(certificate='prior-object')
        state.consume('c::r::YQ==::four', decode_certificate=failed)
        self.assertEqual((state.certificate_text, state.certificate, state.fourth), ('YQ==', 'prior-object', 'four'))

    def test_null_base64_throws_before_factory_and_retains_old_certificate(self):

        def unused(_):
            self.fail('ByteArrayInputStream(null) fails first')
        state = ChallengeState(certificate='prior-object')
        state.consume('c::r::bad::four', decode_certificate=unused)
        self.assertEqual((state.certificate_text, state.certificate, state.fourth), ('bad', 'prior-object', 'four'))

    def test_missing_android_parser_not_faked_as_caught_error(self):
        state = ChallengeState()
        with self.assertRaises(AnalysisLimit):
            state.consume('c::r::YQ==')
        self.assertEqual((state.challenge, state.rule, state.certificate_text), ('c', 'r', None))

    def test_rcl_java_units_and_empty_retention(self):
        state = ChallengeState(challenge='😀', rcl_suffix='old')
        state.apply_rcl('')
        self.assertEqual(state.rcl_suffix, 'old')
        state.apply_rcl('ABsuffix')
        self.assertEqual(state.rcl_suffix, 'suffix')
        with self.assertRaises(JavaStageError):
            ChallengeState().apply_rcl('nonempty')

    def test_split_uses_observed_metadata_outcome_and_updater_or(self):
        for (status, value, updater, want) in (('value', True, False, True), ('value', False, True, True), ('absent_bundle', None, False, False), ('exception', None, True, True)):
            self.assertEqual(effective_split(metadata_status=status, metadata_value=value, updater_split=updater), want)
        with self.assertRaises(AnalysisLimit):
            effective_split(metadata_status='unknown', metadata_value=None, updater_split=False)

    def test_response_override_order_and_nonce_unchanged(self):
        calls = []

        def formatter(*args):
            calls.append(args)
            return 'local-error-' + str(len(calls))
        (response, nonce) = submission_responses('original', 'native-return', zip_status='failed', zip_error='zip', fingerprint_status='failed', fingerprint_error='finger', format_error=formatter)
        self.assertEqual((response, nonce), ('local-error-2', 'native-return'))
        self.assertEqual(calls, [('CG_CONN_ENGINE01', 'unZip error : zip', 'CG_CONN_ENGINE'), ('CG_CONN_ENGINE01', 'FingerPrint error(finger)', 'CG_CONN_ENGINE')])

    def test_fingerprint_exception_retains_response_and_no_extra_engine_error_gate(self):

        def unused(*_):
            self.fail('formatter must not be called')
        for response in ('normal', 'E101_ENGINE_LOAD_ERROR0_120'):
            self.assertEqual(submission_responses(response, 'nonce', zip_status='passed', zip_error=None, fingerprint_status='exception', fingerprint_error=None, format_error=unused), (response, 'nonce'))

    def test_unknown_check_results_not_defaulted_and_null_response_logging_throws(self):
        for (zip_status, fingerprint) in (('unknown', 'passed'), ('passed', 'unknown')):
            with self.assertRaises(AnalysisLimit):
                submission_responses('r', 'n', zip_status=zip_status, zip_error=None, fingerprint_status=fingerprint, fingerprint_error=None, format_error=None)
        with self.assertRaises(JavaStageError):
            submission_responses(None, 'n', zip_status='passed', zip_error=None, fingerprint_status='passed', fingerprint_error=None, format_error=None)

    def test_fingerprint_formatter_java_exception_is_swallowed_but_zip_is_not(self):

        def failed(*_):
            raise ObservedJavaException()
        self.assertEqual(submission_responses('prior', 'n', zip_status='passed', zip_error=None, fingerprint_status='failed', fingerprint_error=None, format_error=failed), ('prior', 'n'))
        with self.assertRaises(ObservedJavaException):
            submission_responses('prior', 'n', zip_status='failed', zip_error=None, fingerprint_status='passed', fingerprint_error=None, format_error=failed)

    def test_local_formatter_gap_not_faked_as_swallowed_java_exception(self):

        def unresolved(*_):
            raise AnalysisLimit('original JSONObject adapter required')
        with self.assertRaises(AnalysisLimit):
            submission_responses('prior', 'n', zip_status='passed', zip_error=None, fingerprint_status='failed', fingerprint_error=None, format_error=unresolved)

    def test_return_stage_null_and_passthrough(self):
        self.assertIsNone(decode_returned_token(None, challenge='c', encrypted_token=False))
        with self.assertRaises(JavaStageError):
            decode_returned_token(None, challenge='c', encrypted_token=True)
        self.assertEqual(decode_returned_token('ordinary', challenge='c', encrypted_token=True), 'ordinary')
        self.assertEqual(decode_returned_token('[ETOKEN]x', challenge='c', encrypted_token=False), '[ETOKEN]x')

    def test_utf16_substring_not_unicode_codepoint(self):
        self.assertEqual(java_substring('😀abcd', 2), 'abcd')
        self.assertEqual(java_substring('😀', 1), '\ude00')

    def test_repr_no_private_fields(self):
        self.assertNotIn('PRIVATE', repr(ChallengeState(challenge='PRIVATE', certificate='PRIVATE')))

@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto unavailable')
class ReturnedTokenTests(unittest.TestCase):

    def test_key_schedule_matches_explicit_1024_and_1025_rounds(self):
        data = b'BTW::SSLSIGN::KS-PASSWD::synthetic'
        for _ in range(1024):
            data = hashlib.sha1(data).digest()
        self.assertEqual(returned_token_key_iv('synthetic'), (data[:16], hashlib.sha1(data).digest()[:16]))

    def test_synthetic_encrypted_return_not_server_token_generation(self):
        (key, iv) = returned_token_key_iv('synthetic')
        encoded = base64.b64encode(java_seed_encrypt(b'synthetic offline text', key, iv)).decode()
        self.assertEqual(decode_returned_token('[ETOKEN]' + encoded, challenge='synthetic', encrypted_token=True), 'synthetic offline text')

    def test_decode_failure_maps_retry_branch_without_inventing_exception_message(self):
        with self.assertRaises(ReturnedTokenDecodeError) as caught:
            decode_returned_token('[ETOKEN]bad', challenge='synthetic', encrypted_token=True)
        self.assertEqual(caught.exception.sdk_error, 'CG_RETRY01')

    def test_marker_later_in_text_does_not_strip_at_marker(self):
        with self.assertRaises(ReturnedTokenDecodeError):
            decode_returned_token('prefix[ETOKEN]bad', challenge='synthetic', encrypted_token=True)
