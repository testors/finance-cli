import unittest
from unittest.mock import patch

from giro.codeguard_effects import JavaFault
from giro.codeguard_rule import AnalysisLimit
from giro.device_identity import DeviceIdentityState, device_id_steps


def security():
    return JavaFault('SecurityException', message='SYNTHETIC', java_string='SYNTHETIC')


class DeviceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.state = DeviceIdentityState()
        self.effects = []
        self.values = dict(device_preferences='SYNTHETIC-PREF', device_preference_string=None,
                           device_telephony_service='SYNTHETIC-PHONE', device_telephony_id='SYNTHETIC-ID',
                           device_content_resolver='SYNTHETIC-RESOLVER', device_secure_string='SYNTHETIC-SECURE',
                           device_preference_store=True)

    def run_steps(self):
        gen = device_id_steps(self.state, 'SYNTHETIC-CONTEXT')
        effect = next(gen)
        while True:
            self.effects.append(effect)
            value = self.values[effect.kind]
            if isinstance(value, list):
                value = value.pop(0)
            try:
                effect = gen.throw(value) if isinstance(value, Exception) else gen.send(value)
            except StopIteration as done:
                return done.value

    def kinds(self):
        return [e.kind for e in self.effects]

    def test_cached_identity_avoids_platform_reads_and_keeps_whitespace(self):
        self.values['device_preference_string'] = '  '
        self.assertEqual(self.run_steps(), '  ')
        self.assertEqual(self.kinds(), ['device_preferences', 'device_preference_string'])
        self.effects.clear()
        self.run_steps()
        self.assertEqual(self.kinds(), ['device_preference_string'])

    def test_missing_preference_object_is_not_an_empty_cache(self):
        self.values['device_preferences'] = None
        with self.assertRaises(AnalysisLimit):
            self.run_steps()
        self.assertIsNone(self.state.preferences)
        self.assertEqual(self.kinds(), ['device_preferences'])

    def test_empty_cache_reads_phone_and_ignores_false_commit(self):
        self.values.update(device_preference_string='', device_preference_store=False)
        self.assertEqual(self.run_steps(), 'SYNTHETIC-ID')
        self.assertEqual(self.effects[-1].args, ('SYNTHETIC-PREF', 'deviceId', 'SYNTHETIC-ID'))
        self.assertNotIn('device_secure_string', self.kinds())

    def test_empty_phone_id_is_not_replaced_by_secure_id(self):
        self.values['device_telephony_id'] = ''
        self.assertEqual(self.run_steps(), '')
        self.assertNotIn('device_secure_string', self.kinds())

    def test_null_phone_service_selects_secure_id_without_phone_call(self):
        self.values['device_telephony_service'] = None
        self.assertEqual(self.run_steps(), 'SYNTHETIC-SECURE')
        self.assertNotIn('device_telephony_id', self.kinds())

    def test_null_phone_result_and_security_exception_select_secure_id(self):
        for value in (None, security()):
            with self.subTest(value=value):
                self.values['device_telephony_id'] = value
                self.assertEqual(self.run_steps(), 'SYNTHETIC-SECURE')

    def test_secure_null_is_preserved_and_passed_to_store(self):
        self.values.update(device_telephony_id=None, device_secure_string=None)
        self.assertIsNone(self.run_steps())
        self.assertIsNone(self.effects[-1].args[-1])

    def test_security_during_phone_value_store_falls_back(self):
        self.values['device_preference_store'] = [security(), False]
        self.assertEqual(self.run_steps(), 'SYNTHETIC-SECURE')
        stored = [e.args[-1] for e in self.effects if e.kind == 'device_preference_store']
        self.assertEqual(stored, ['SYNTHETIC-ID', 'SYNTHETIC-SECURE'])

    def test_security_in_null_phone_fallback_enters_catch_once(self):
        self.values.update(device_telephony_id=None,
                           device_secure_string=[security(), 'SYNTHETIC-SECOND'])
        self.assertEqual(self.run_steps(), 'SYNTHETIC-SECOND')
        self.assertEqual(self.kinds().count('device_content_resolver'), 2)

    def test_fallback_catch_failure_propagates_without_retry(self):
        self.values.update(device_telephony_id=security(), device_secure_string=security())
        with self.assertRaises(JavaFault):
            self.run_steps()
        self.assertEqual(self.kinds().count('device_secure_string'), 1)

    def test_null_service_fallback_is_outside_catch(self):
        self.values.update(device_telephony_service=None, device_secure_string=security())
        with self.assertRaises(JavaFault):
            self.run_steps()
        self.assertEqual(self.kinds().count('device_secure_string'), 1)

    def test_service_acquisition_and_preference_cast_faults_propagate(self):
        for kind in ('device_preference_string', 'device_telephony_service'):
            with self.subTest(kind=kind):
                self.setUp()
                self.values[kind] = security()
                with self.assertRaises(JavaFault):
                    self.run_steps()
                self.assertNotIn('device_secure_string', self.kinds())

    def test_unknown_input_and_unrelated_fault_do_not_trigger_fallback(self):
        for value in (False, AnalysisLimit('unknown'), RuntimeError('SYNTHETIC'),
                      JavaFault('NullPointerException', message='SYNTHETIC', java_string='SYNTHETIC')):
            with self.subTest(value=value):
                self.setUp()
                self.values['device_telephony_id'] = value
                with self.assertRaises((AnalysisLimit, RuntimeError, JavaFault)):
                    self.run_steps()
                self.assertNotIn('device_secure_string', self.kinds())

    def test_model_never_reads_host_files_or_network_and_repr_hides_values(self):
        with patch('builtins.open', side_effect=AssertionError('no files')), \
             patch('socket.socket', side_effect=AssertionError('no network')):
            self.assertEqual(self.run_steps(), 'SYNTHETIC-ID')
        self.assertNotIn('SYNTHETIC', repr(self.state) + repr(self.effects))
