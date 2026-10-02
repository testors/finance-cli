import unittest
from unittest.mock import patch

from giro.codeguard_app import (build_string_steps, giro_task_checks,
                                giro_task_settings, phone_number_steps)
from giro.codeguard_effects import JavaFault, LinkFault
from giro.codeguard_rule import AnalysisLimit
from giro.codeguard_task import TaskTokenState
from giro.codeguard_worker import worker_steps
from giro.protocol import ENDPOINTS
import test_codeguard_response as support


class AppInputTests(unittest.TestCase):
    def run_steps(self, generator, replies):
        self.effects = []
        def respond(effect):
            self.effects.append(effect)
            value = replies[effect.kind]
            return value(effect) if callable(value) else value
        return support.drive(generator, respond)

    def test_phone_number_null_empty_and_all_replacements(self):
        for raw, expected in ((None, None), ('', ''), ('+82-test-+82', '0-test-0')):
            result = self.run_steps(phone_number_steps('synthetic-context'), {
                'telephony_service': 'synthetic-service', 'telephony_line1_number': raw})
            self.assertEqual(result, expected)
            self.assertEqual([e.kind for e in self.effects],
                             ['telephony_service', 'telephony_line1_number'])

    def test_only_observed_security_exception_becomes_empty(self):
        security = support.fault('SecurityException')
        for site in ('telephony_service', 'telephony_line1_number'):
            replies = dict(telephony_service='service', telephony_line1_number='value',
                           phone_security_log=None)
            replies[site] = security
            self.assertEqual(self.run_steps(phone_number_steps('context'), replies), '')
            self.assertIs(self.effects[-1].args[0], security)
        for fault in (support.fault('NullPointerException'), AnalysisLimit('unobserved'), LinkFault()):
            with self.assertRaises(type(fault)):
                self.run_steps(phone_number_steps('context'), {'telephony_service': fault})

    def test_null_service_is_not_null_number(self):
        with self.assertRaises(JavaFault):
            self.run_steps(phone_number_steps('context'), {'telephony_service': None,
                'telephony_line1_number': support.fault('NullPointerException')})
        self.assertEqual(self.effects[-1].args, (None,))

    def test_logger_failure_does_not_complete_phone_fallback(self):
        with self.assertRaises(JavaFault):
            self.run_steps(phone_number_steps('context'), {
                'telephony_service': support.fault('SecurityException'),
                'phone_security_log': support.fault('IOException')})

    def test_build_order_null_append_and_discarded_replacement(self):
        values = dict(MODEL='MODEL#synthetic', ID=None, RELEASE='release')
        result = self.run_steps(build_string_steps(), {
            'build_string_field': lambda effect: values[effect.args[0]]})
        self.assertEqual(result, 'MODEL#synthetic/null/release')
        self.assertEqual([e.args for e in self.effects], [('MODEL',), ('ID',), ('RELEASE',)])

    def test_build_exception_discards_partial_string_but_unknown_propagates(self):
        def read(effect):
            return 'model' if effect.args == ('MODEL',) else support.fault()
        self.assertEqual(self.run_steps(build_string_steps(), {
            'build_string_field': read, 'build_exception_log': None}), '')
        self.assertEqual([e.kind for e in self.effects].count('build_string_field'), 2)
        for fault in (AnalysisLimit('unknown'), LinkFault()):
            with self.assertRaises(type(fault)):
                self.run_steps(build_string_steps(), {'build_string_field': fault})

    def test_task_configuration_does_not_request_optional_checks(self):
        settings = giro_task_settings(etc_data=None)
        self.assertEqual(settings.max_timeout, 100000)
        self.assertEqual((settings.app_info, settings.version), ('IGIROMOBILE', '4.9.5_209'))
        state = TaskTokenState(None, -1, '', '', '', None, None, 'https://synthetic.invalid/')
        self.run_steps(worker_steps(state, settings, context='synthetic-context'), {
            'clock_ms': 100, 'set_agent_context': None, 'set_agent_encrypted_token': None,
            'agent_generate_token': 'synthetic-token'})
        self.assertEqual([e.kind for e in self.effects], ['clock_ms', 'set_agent_context',
            'set_agent_encrypted_token', 'agent_generate_token'])
        self.assertEqual(state.get_token(check_flags=giro_task_checks(),
            observed_check=lambda _: self.fail('optional task check unexpectedly enabled'),
            format_error=lambda *_: self.fail('unexpected local formatter')), 'synthetic-token')

    def test_unknown_phone_input_is_not_a_default_or_a_clean_check(self):
        with self.assertRaises(TypeError):
            giro_task_settings()
        with self.assertRaises(AnalysisLimit):
            giro_task_settings(etc_data=object())
        with self.assertRaises(AnalysisLimit):
            self.run_steps(phone_number_steps('context'), {'telephony_service': 'service',
                'telephony_line1_number': object()})

    def test_settings_and_effects_hide_values_and_do_not_read_host(self):
        with patch('socket.socket', side_effect=AssertionError('network')), \
             patch('builtins.open', side_effect=AssertionError('file')), \
             patch('os.getpid', side_effect=AssertionError('host identity')):
            settings = giro_task_settings(etc_data='synthetic-private-value')
            generator = phone_number_steps('synthetic-private-context')
            effect = next(generator)
        self.assertNotIn('synthetic-private', repr(settings) + repr(effect))

    def test_supported_token_requirements_include_link_detail(self):
        self.assertEqual({name for name, ep in ENDPOINTS.items() if ep.codeguard_required},
                         {'auth.pin', 'hometax.detail', 'registration.user-info'})
        self.assertFalse(ENDPOINTS['hometax.detail'].session_required)
        self.assertEqual(ENDPOINTS['hometax.detail'].mode, 'ENCRYPT')


if __name__ == '__main__':
    unittest.main()
