import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from giro.auth_cli import enrollment_inputs, review_terms


class ConsentInputTests(unittest.TestCase):
    def test_registration_confirmation_accepts_the_same_words_with_optional_spaces(self):
        for text in ('기기등록', '기기 등록', '  기기  등록\t'):
            with self.subTest(text=text), patch('giro.auth_cli.answer', return_value=text), \
                 patch('giro.auth_cli.review_terms', return_value=True) as terms:
                self.assertTrue(enrollment_inputs(object(), None)['consent_provider']())
                terms.assert_called_once_with()

    def test_empty_or_negative_confirmation_does_not_fetch_terms(self):
        for text in ('', '   ', '취소', '기기등록 안함'):
            with self.subTest(text=text), patch('giro.auth_cli.answer', return_value=text), \
                 patch('giro.auth_cli.review_terms') as terms:
                self.assertFalse(enrollment_inputs(object(), None)['consent_provider']())
                terms.assert_not_called()

    def test_terms_whitespace_does_not_skip_any_individual_consent(self):
        response = Mock(status=200)
        response.read.return_value = b'<p>Synthetic terms</p>'
        response.headers.get_content_charset.return_value = 'utf-8'
        connection = Mock()
        connection.getresponse.return_value = response
        with patch('giro.auth_cli.http.client.HTTPSConnection', return_value=connection), \
             patch('giro.auth_cli.answer', side_effect=[' 동의 ', '동 의', '\t동의']) as answer:
            self.assertTrue(review_terms())
        self.assertEqual(answer.call_count, 3)
        self.assertEqual(connection.request.call_count, 3)
        self.assertEqual(connection.close.call_count, 3)


class IdentityInputTests(unittest.TestCase):
    def setUp(self):
        self.profile = SimpleNamespace(platform=SimpleNamespace(phone='+821000000000'))

    def test_numeric_carriers_and_visible_korean_name_reach_identity_fields(self):
        for choice, code in (('1', 'SKT'), ('2', 'SKM'), ('3', 'LGT'), ('4', 'LGM')):
            with self.subTest(choice=choice), \
                 patch('giro.auth_cli.answer', side_effect=[choice, ' 홍길동 ']) as answer, \
                 patch('giro.auth_cli.secret', side_effect=['19900101', '0', '0']) as secret:
                identity = enrollment_inputs(self.profile, None)['identity_provider']()
            self.assertEqual(identity.fields()['name'], '홍길동')
            self.assertEqual(identity.fields()['phoneCorp'], code)
            self.assertEqual(answer.call_args, call('이름: '))
            self.assertEqual(secret.call_args_list, [call('생년월일 8자리: '),
                call('내국인 0 / 외국인 1: '), call('남성 0 / 여성 1: ')])

    def test_invalid_menu_input_reprompts_and_trims_selection(self):
        with patch('giro.auth_cli.answer', side_effect=['SKT', '', '5', ' 1\t', '홍길동']) as answer, \
             patch('giro.auth_cli.secret', side_effect=['19900101', '0', '0']), \
             patch('giro.auth_cli.http.client.HTTPSConnection') as connection:
            identity = enrollment_inputs(self.profile, None)['identity_provider']()
        self.assertEqual(identity.phone_corp, 'SKT')
        self.assertEqual(answer.call_count, 5)
        connection.assert_not_called()

    def test_explicit_carrier_skips_menu_and_phone_still_uses_hidden_input(self):
        profile = SimpleNamespace(platform=SimpleNamespace(phone=None))
        with patch('giro.auth_cli.answer', return_value='홍길동') as answer, \
             patch('giro.auth_cli.secret', side_effect=['01000000000', '19900101', '0', '0']) as secret:
            identity = enrollment_inputs(profile, 'SKT')['identity_provider']()
        answer.assert_called_once_with('이름: ')
        self.assertEqual(identity.phone_corp, 'SKT')
        self.assertEqual(identity.phone_number, '01000000000')
        self.assertEqual(secret.call_args_list[0], call('본인 명의 휴대전화번호: '))
