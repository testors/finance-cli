import unittest

from giro.errors import GiroError
from giro.user_agent import business_user_agent


class BusinessUserAgentTests(unittest.TestCase):
    def format(self, version='4.9.5', **changes):
        fields = dict(os_name='SyntheticOS', model='MODEL-X', release='17')
        return business_user_agent(version, **(fields | changes))

    def test_explicit_device_inputs_and_business_version(self):
        self.assertEqual(self.format(),
            'AndroidGiro/4.9.5 (SyntheticOS; MODEL-X AndroidGiro4.9.5; Android 17; ko-kr)')

    def test_version_helper_literal_condition_then_regex_replacement(self):
        self.assertEqual(self.format('4.9.5.test'), self.format())
        self.assertEqual(self.format('4.9.5.testXtest'), self.format())
        self.assertIn('AndroidGiro/.test', self.format('.test'))
        self.assertIn('AndroidGiro/4.9.5Xtest', self.format('4.9.5Xtest'))

    def test_missing_inputs_and_invalid_http_values_have_no_host_fallback(self):
        for field in ('os_name', 'model', 'release'):
            for value in (None, 17, 'bad\r\nheader', 'bad\x7f', '한글'):
                with self.subTest(field=field, value=value), self.assertRaises(GiroError):
                    self.format(**{field: value})
        self.assertIn('MODEL\tX', self.format(model='MODEL\tX'))
