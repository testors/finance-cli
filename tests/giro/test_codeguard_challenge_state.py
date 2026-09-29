from pathlib import Path
import unittest
from unittest.mock import patch
from giro.codeguard_flow import ChallengeState
from giro.codeguard_effects import JavaFault, LinkFault
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_service import generate_token_steps
from test_codeguard_response import drive, fault
from cg_exchange_fixture import Transcript

class ChallengeEffectTests(unittest.TestCase):

    def consume(self, state, text, overrides=None):
        self.effects = []
        replies = dict(x509_certificate_factory='synthetic-factory', x509_generate_certificate='synthetic-cert', cast_x509_certificate='synthetic-x509', log_codeguard_certificate=None)
        replies.update(overrides or {})

        def reply(e):
            self.effects.append(e)
            return replies[e.kind]
        return drive(state.consume_steps(text), reply)

    def test_three_parts_full_factory_parse_cast_assignment_logging_order(self):
        state = ChallengeState(fourth='old')
        with patch('socket.socket', side_effect=AssertionError('offline')):
            self.consume(state, 'c::r::YQ==')
        self.assertEqual([e.kind for e in self.effects], ['x509_certificate_factory', 'x509_generate_certificate', 'cast_x509_certificate', 'log_codeguard_certificate'])
        self.assertEqual(self.effects[1].args, ('synthetic-factory', b'a'))
        self.assertEqual((state.challenge, state.rule, state.certificate_text, state.certificate, state.fourth), ('c', 'r', 'YQ==', 'synthetic-x509', 'old'))

    def test_factory_exception_retains_old_text_object_but_updates_fourth(self):
        state = ChallengeState(certificate_text='old-text', certificate='old-cert')
        self.consume(state, 'c::r::YQ==::new-fourth', {'x509_certificate_factory': fault('CertificateException')})
        self.assertEqual(len(self.effects), 1)
        self.assertEqual((state.challenge, state.rule, state.certificate_text, state.certificate, state.fourth), ('c', 'r', 'old-text', 'old-cert', 'new-fourth'))

    def test_parse_exception_retains_object_but_changes_text_and_fourth(self):
        state = ChallengeState(certificate='old')
        self.consume(state, 'c::r::YQ==::fourth', {'x509_generate_certificate': fault('CertificateException')})
        self.assertEqual(len(self.effects), 2)
        self.assertEqual((state.certificate_text, state.certificate, state.fourth), ('YQ==', 'old', 'fourth'))

    def test_cast_exception_is_before_new_object_assignment(self):
        state = ChallengeState(certificate='old')
        self.consume(state, 'c::r::YQ==::fourth', {'cast_x509_certificate': fault('ClassCastException')})
        self.assertEqual(state.certificate, 'old')
        self.assertEqual(state.fourth, 'fourth')
        self.assertEqual(len(self.effects), 3)

    def test_logging_exception_does_not_roll_back_new_object(self):
        state = ChallengeState(certificate='old')
        self.consume(state, 'c::r::YQ==::fourth', {'log_codeguard_certificate': fault('Exception')})
        self.assertEqual((state.certificate, state.fourth), ('synthetic-x509', 'fourth'))

    def test_null_base64_after_factory_does_not_invoke_parser(self):
        state = ChallengeState(certificate='old')
        self.consume(state, 'c::r::bad::fourth')
        self.assertEqual(len(self.effects), 1)
        self.assertEqual((state.certificate_text, state.certificate, state.fourth), ('bad', 'old', 'fourth'))

    def test_two_parts_no_provider_lookup_and_old_optional_fields(self):
        state = ChallengeState(certificate_text='old-text', certificate='old', fourth='fourth')
        self.consume(state, 'c::r::')
        self.assertEqual(self.effects, [])
        self.assertEqual((state.challenge, state.rule, state.certificate, state.fourth), ('c', 'r', 'old', 'fourth'))

    def test_one_part_no_assignment_and_more_than_four_no_fourth_assignment(self):
        state = ChallengeState('old', 'rule', fourth='old-fourth')
        self.consume(state, 'one')
        self.assertEqual((state.challenge, state.rule), ('old', 'rule'))
        self.consume(state, 'c::r::YQ==::not-set::extra')
        self.assertEqual(state.fourth, 'old-fourth')

    def test_unknown_provider_and_link_fault_not_caught_as_parse_failure(self):
        for error in (AnalysisLimit('unknown'), LinkFault(), ValueError('local backend')):
            state = ChallengeState(certificate_text='old', fourth='old-fourth')
            with self.assertRaises(type(error)):
                self.consume(state, 'c::r::YQ==::new', {'x509_certificate_factory': error})
            self.assertEqual(state.certificate_text, 'old')
            self.assertEqual(state.fourth, 'old-fourth')

    def test_legacy_explicit_parser_projection_still_available(self):
        state = ChallengeState()
        generator = state.consume_steps('c::r::YQ==', decode_certificate=lambda raw: raw)
        with self.assertRaises(StopIteration):
            next(generator)
        self.assertEqual(state.certificate, b'a')

class PipelineTests(unittest.TestCase):

    def test_initial_and_refresh_three_part_challenge_use_new_effects(self):
        for refresh in (False, True):
            documents = [(200, {'CODE_CHALLENGE': 'only-one'})] if refresh else []
            documents += [(200, {'CODE_CHALLENGE': 'new::rule::YQ==::fourth'}), (300, {'CODE_TOKEN': 'SYNTHETIC'})]
            t = Transcript(documents, overrides={'x509_certificate_factory': fault('CertificateException')})
            t.main.challenge = ChallengeState()
            with patch('socket.socket', side_effect=AssertionError('no IO')):
                result = t.run(generate_token_steps(t.main, t.runtime, t.agent, server_url='https://synthetic.invalid/', timeout=500, root_check=True, rooting_info=False, encrypted_token=False))
            self.assertEqual(result, 'SYNTHETIC')
            self.assertEqual(t.kinds().count('x509_certificate_factory'), 1)
            self.assertEqual(t.main.challenge.fourth, 'fourth')
            native = next((e for e in t.effects if e.kind == 'native_start'))
            self.assertEqual(native.args[:2], ('new', 'rule'))

    def test_missing_real_provider_observation_leaves_effect_not_clean_default(self):
        state = ChallengeState()
        generator = state.consume_steps('c::r::YQ==')
        self.assertEqual(next(generator).kind, 'x509_certificate_factory')
        self.assertIsNone(state.certificate_text)
        generator.close()
