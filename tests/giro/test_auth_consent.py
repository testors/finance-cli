import unittest
from unittest.mock import Mock, patch

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
