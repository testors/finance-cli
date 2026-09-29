import base64
import hashlib
from pathlib import Path
import unittest
from giro.codeguard_codec import RULE_KEY, RULE_IV, java_seed_decrypt
from giro.codeguard_effects import JavaFault, LinkFault, java_length
from giro.codeguard_first import java_response_frame
from giro.codeguard_flow import ChallengeState
from giro.codeguard_response import ResponseState, response_steps, encrypted_response_steps, os_status_digest, oscheck_steps
from giro.codeguard_rule import AnalysisLimit

def drive(generator, reply):
    """Only generator StopIteration signals completion; missing replies fail."""
    try:
        effect = next(generator)
    except StopIteration as done:
        return done.value
    while True:
        value = reply(effect)
        try:
            effect = generator.throw(value) if isinstance(value, BaseException) else generator.send(value)
        except StopIteration as done:
            return done.value

def fault(kind='Exception', message='synthetic message'):
    return JavaFault(kind, message=message, java_string='java.synthetic.' + kind + ': ' + message)

def sample_state(**changes):
    values = dict(challenge=ChallengeState('challenge', 'rule'), app_info='APP', version='1', pid='42', build_string='MODEL/ID/RELEASE', etc_data=None, status_log='E0', updater_engine_version='u-version', native_error_detail='native detail')
    values.update(changes)
    return ResponseState(**values)

class ResponseTests(unittest.TestCase):

    def run_response(self, state=None, *, overrides=None, root_check=True, rooting_info=False, encrypted=None):
        self.effects = []
        clock = iter((100, 107))
        replies = dict(oscheck_future='synthetic OS return', native_start='synthetic native return', engine_version='engine', read_detail_enabled=False, location_text='', clock_ms=lambda _: next(clock))
        replies.update(overrides or {})

        def reply(effect):
            self.effects.append(effect)
            value = replies[effect.kind]
            return value(effect) if callable(value) else value
        gen = response_steps if encrypted is None else encrypted_response_steps
        kwargs = {} if encrypted is None else {'encrypted_token': encrypted}
        return drive(gen(state or sample_state(), root_check=root_check, rooting_info=rooting_info, **kwargs), reply)

    def kinds(self):
        return [e.kind for e in self.effects]

    def test_plain_frame_matches_existing_pure_serializer(self):
        result = self.run_response()
        expected = java_response_frame(app_info='APP', version='1', engine_version='engine', cached_engine_version=None, build_string='MODEL/ID/RELEASE', elapsed_ms=7, etc_data=None, detail_enabled=False, rcl='', device_detail=None, device_detail_ex=None, os_status='synthetic OS return', native_return='synthetic native return', location_text='')
        self.assertEqual(result, expected)
        self.assertEqual(self.kinds(), ['oscheck_future', 'clock_ms', 'native_start', 'clock_ms', 'engine_version', 'read_detail_enabled', 'location_text'])

    def test_first_refresh_before_oscheck_and_native(self):
        state = sample_state(challenge=ChallengeState())
        self.run_response(state, overrides={'request_challenge': 'new::rule', 'read_rcl': 'newRCL'})
        self.assertEqual(self.kinds()[:3], ['request_challenge', 'read_rcl', 'oscheck_future'])
        self.assertEqual(self.effects[2].args, ('new', True, False, None, 'RCL', 5000))
        self.assertEqual(state.status_log, 'E0,E32,E32.5.2')

    def test_missing_rule_refreshes_after_os_without_repeating_os(self):
        state = sample_state(challenge=ChallengeState('old', ''))
        self.run_response(state, overrides={'request_challenge': 'new::rule', 'read_rcl': None})
        self.assertEqual(self.kinds()[:3], ['oscheck_future', 'request_challenge', 'read_rcl'])
        self.assertEqual(self.effects[0].args[0], 'old')
        native = next((e for e in self.effects if e.kind == 'native_start'))
        self.assertEqual(native.args, ('new', 'rule', 'APP', '1', '42'))
        self.assertEqual(state.os_status, 'synthetic OS return')

    def test_null_or_network_first_refresh_still_permits_second_refresh(self):
        for first in (None, 'E101_NET_ERROR_000'):
            values = iter((first, 'new::rule'))
            self.run_response(sample_state(challenge=ChallengeState()), overrides={'request_challenge': lambda _: next(values), 'read_rcl': ''})
            self.assertEqual(self.kinds().count('request_challenge'), 2)
            self.assertEqual(self.kinds().count('read_rcl'), 1)

    def test_first_refresh_exception_escapes_second_is_engine_error2(self):
        with self.assertRaises(JavaFault):
            self.run_response(sample_state(challenge=ChallengeState()), overrides={'request_challenge': fault()})
        result = self.run_response(sample_state(challenge=ChallengeState('old', '')), overrides={'request_challenge': fault(message='refresh#failure')})
        self.assertIn('E101_ENGINE_LOAD_ERROR2', result)
        self.assertIn('(refresh#failure)', result)
        self.assertNotIn('native_start', self.kinds())

    def test_rcl_runtime_text_not_invented(self):
        with self.assertRaises(AnalysisLimit):
            self.run_response(sample_state(challenge=ChallengeState()), overrides={'request_challenge': 'longchallenge::rule', 'read_rcl': 'short'})

    def test_rooting_flag_effective_only_with_nonempty_main_etc_data(self):
        for (data, effective) in ((None, False), ('', False), ('encoded', True)):
            self.run_response(sample_state(etc_data=data), rooting_info=True)
            self.assertIs(self.effects[0].args[2], effective)

    def test_null_future_return_is_literal_null_not_cli_rejection(self):
        result = self.run_response(overrides={'oscheck_future': None})
        self.assertIn('*null##', result)

    def test_three_observed_future_failures_use_same_challenge_digest(self):
        for kind in ('InterruptedException', 'ExecutionException', 'TimeoutException'):
            state = sample_state()
            self.run_response(state, overrides={'oscheck_future': fault(kind)})
            self.assertEqual(state.os_status, os_status_digest('challenge'))
            self.assertNotIn('E32.5(', state.status_log)
            self.assertNotIn('cancel', self.kinds())

    def test_other_future_exception_becomes_os_error_string_then_native_runs(self):
        state = sample_state()
        result = self.run_response(state, overrides={'oscheck_future': fault('SecurityException')})
        self.assertIn('OS_CHECK_ERR001(java.synthetic.SecurityException:', result)
        self.assertIn(',E32.5(synthetic message)', state.status_log)
        self.assertIn('native_start', self.kinds())

    def test_os_link_error_not_caught_by_exception_region(self):
        with self.assertRaises(LinkFault):
            self.run_response(overrides={'oscheck_future': LinkFault()})

    def test_backend_limit_and_python_bug_not_converted_to_app_error(self):
        for error in (AnalysisLimit('unresolved'), ValueError('local bug')):
            with self.assertRaises(type(error)):
                self.run_response(overrides={'native_start': error})

    def test_timeout_shared_detail_can_be_written_later(self):
        state = sample_state(challenge=ChallengeState('challenge', 'rule', rcl_suffix='RCL'))
        result = self.run_response(state, overrides={'oscheck_future': fault('TimeoutException'), 'read_detail_enabled': True, 'device_detail': 'late observation'})
        self.assertIn('!' + base64.b64encode(b'late observation').decode() + '*', result)
        detail = next((e for e in self.effects if e.kind == 'device_detail'))
        self.assertEqual(detail.args, ('extended',))
        self.assertTrue(state.detail_enabled)

    def test_detail_uses_refreshed_rcl_not_old_oscheck_rcl(self):
        state = sample_state(challenge=ChallengeState('old', '', rcl_suffix=''))
        self.run_response(state, overrides={'request_challenge': 'new::rule', 'read_rcl': 'newEX', 'read_detail_enabled': True, 'device_detail': 'observed'})
        self.assertEqual(self.effects[0].args[4], '')
        self.assertEqual(next((e for e in self.effects if e.kind == 'device_detail')).args, ('extended',))

    def test_empty_etc_still_writes_bang_and_avoids_detail_read(self):
        result = self.run_response(sample_state(etc_data=''))
        self.assertIn('@7!*', result)
        self.assertNotIn('read_detail_enabled', self.kinds())

    def test_empty_engine_uses_preference_verbatim(self):
        result = self.run_response(overrides={'engine_version': '', 'read_engine_version_preference': ''})
        self.assertIn('APP::1##/MODEL', result)

    def test_native_null_checks_metadata_before_error4(self):
        result = self.run_response(overrides={'native_start': None})
        self.assertIn('E101_ENGINE_LOAD_ERROR4', result)
        self.assertIn('native detail', result)
        self.assertIn('engine_version', self.kinds())
        result = self.run_response(overrides={'native_start': None, 'engine_version': fault(message='metadata')})
        self.assertIn('E101_ENGINE_LOAD_ERROR2', result)
        self.assertNotIn('native detail', result)

    def test_native_exception_and_link_error_different_suffix_and_message(self):
        for (error, suffix, text) in ((fault(message='oops'), '2', 'oops'), (LinkFault(), '3', '()')):
            result = self.run_response(overrides={'native_start': error})
            self.assertIn('E101_ENGINE_LOAD_ERROR' + suffix, result)
            self.assertIn(text, result)
            self.assertNotIn('engine_version', self.kinds())

    def test_error120_annotation_first_matching_pid_and_null_process_name(self):
        result = self.run_response(overrides={'native_start': 'E101_ENGINE_LOAD_ERROR0_120', 'running_app_processes': [(41, 'other'), (42, None), (42, 'later')]})
        self.assertIn('E101_ENGINE_LOAD_ERROR0_120_null##', result)

    def test_error120_only_security_exception_swallowed(self):
        for (kind, suffix) in (('SecurityException', '0_120'), ('Exception', '2')):
            result = self.run_response(overrides={'native_start': 'E101_ENGINE_LOAD_ERROR0_120', 'running_app_processes': fault(kind)})
            self.assertIn('E101_ENGINE_LOAD_ERROR' + suffix, result)

    def test_unsatisfied_link_substring_anywhere_triggers_preference_effect(self):
        for outcome in (False, fault()):
            state = sample_state(build_string='UnsatisfiedLinkError-in-build')
            result = self.run_response(state, overrides={'write_engine_version_preference': outcome})
            self.assertIn('synthetic native return', result)
            self.assertEqual(self.effects[-1].kind, 'write_engine_version_preference')
            self.assertTrue(state.status_log.endswith(',E32.6'))

    def test_clock_difference_uses_signed_long_not_clamped_to_zero(self):
        for (times, expected) in (((10, 2), -8), ((2 ** 63 - 1, -2 ** 63), 1)):
            ticks = iter(times)
            result = self.run_response(overrides={'clock_ms': lambda _: next(ticks)})
            self.assertIn('@' + str(expected) + '*', result)

    def test_error_log_truncation_counts_utf16_and_mutates_log(self):
        state = sample_state(status_log='#' + '😀' * 600)
        self.run_response(state, overrides={'native_start': fault(message='tail#')})
        self.assertEqual(java_length(state.status_log), 1002 + len('(tail#)'))
        self.assertTrue(state.status_log.startswith('_'))
        self.assertTrue(state.status_log.endswith('(tail#)'))

    def test_encrypted_wrapper_and_engine_error_passthrough(self):
        for encrypted in (False, True):
            result = self.run_response(encrypted=encrypted)
            decoded = java_seed_decrypt(base64.b64decode(result), RULE_KEY, RULE_IV).decode()
            self.assertEqual(decoded.startswith('[ETOKEN]'), encrypted)
        result = self.run_response(encrypted=True, overrides={'native_start': None})
        self.assertIn('##E101_ENGINE_LOAD_ERROR4', result)

    def test_setters_encode_etc_and_keep_old_challenge_os_fields(self):
        state = sample_state(os_status='old')
        state.set_etc_data('phone/root^task')
        self.assertEqual(base64.b64decode(state.etc_data), b'phone/root^task')
        state.set_app_info(999, 'NEW', '2')
        self.assertEqual((state.pid, state.app_identity, state.challenge.challenge, state.os_status), ('999', 'NEW::2', 'challenge', 'old'))
        self.assertEqual(state.status_log, 'E0,E30')

    def test_private_values_not_in_representations(self):
        state = sample_state(etc_data='PRIVATE', status_log='PRIVATE')
        error = fault(message='PRIVATE')
        self.assertNotIn('PRIVATE', repr(state) + str(error) + repr(error))

class OSCheckTests(unittest.TestCase):

    def run_os(self, *, replies=(), **changes):
        state = sample_state()
        args = dict(challenge='challenge', root_check=True, rooting_info=False, fourth='fourth', rcl='')
        args.update(changes)
        self.effects = []
        answers = iter(replies)

        def reply(e):
            self.effects.append(e)
            return next(answers)
        result = drive(oscheck_steps(state, **args), reply)
        return (state, result)

    def test_observed_false_result_hashes_challenge_true_hashes_detail(self):
        for (values, text) in (((False,), 'challenge'), ((True, 'detail'), 'detail')):
            (state, result) = self.run_os(replies=values)
            decoded = java_seed_decrypt(base64.b64decode(result), RULE_KEY, RULE_IV)
            self.assertEqual(decoded, hashlib.sha1(text.encode()).digest())
            self.assertIs(state.detail_enabled, values[0])
        self.assertEqual(self.effects[0].args, ('standard', 'fourth'))

    def test_nonempty_rcl_selects_extended_manager(self):
        self.run_os(rcl='policy', replies=(False,))
        self.assertEqual(self.effects[0].args, ('extended', 'policy'))

    def test_actual_rooting_info_flag_precedes_root_check(self):
        (_, result) = self.run_os(rooting_info=True)
        self.assertEqual(self.effects, [])
        self.assertEqual(result, os_status_digest('OS_modification_by_rooting_info'))

    def test_flag_false_is_explicit_observation_not_default(self):
        (_, result) = self.run_os(root_check=False)
        self.assertEqual(self.effects, [])
        self.assertEqual(result, os_status_digest('challenge'))
        with self.assertRaises(AnalysisLimit):
            self.run_os(root_check=None)
        with self.assertRaises(AnalysisLimit):
            self.run_os(replies=(None,))

    def test_java_check_exception_preserves_source_and_sets_log(self):
        (state, result) = self.run_os(replies=(fault(),))
        self.assertEqual(result, os_status_digest('challenge'))
        self.assertEqual(state.status_log, 'E0,E32.4')

    def test_detail_read_exception_keeps_already_assigned_true(self):
        (state, result) = self.run_os(replies=(True, fault()))
        self.assertTrue(state.detail_enabled)
        self.assertEqual(result, os_status_digest('challenge'))

    def test_unknown_native_and_backend_errors_not_swallowed(self):
        for error in (LinkFault(), AnalysisLimit('unknown'), TypeError('bug')):
            with self.assertRaises(type(error)):
                self.run_os(replies=(error,))
