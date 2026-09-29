import json
import unittest
from giro.compat import JsonNumber, json_value, loads, read_model
from giro.errors import GiroError
from giro.response import receive

class JsonReaderTests(unittest.TestCase):

    def test_lenient_success_is_not_rejected(self):
        for text in ("/* prefix */ {responseCode:'000';paymentList:[]} ", "// prefix\n{responseCode = '000', paymentList=>[]}", "\ufeff)]}'\n{# comment\n responseCode:000, paymentList:[]}"):
            with self.subTest(text=text):
                self.assertTrue(receive('national.list', 200, [], text).app_success)

    def test_keyword_and_unquoted_rules(self):
        value = loads('[TrUe, FALSE, nUlL, NaN, Infinity, +1, 01, 1., .5, 1e, a"b]')
        self.assertEqual(value, [True, False, None, 'NaN', 'Infinity', '+1', '01', '1.', '.5', '1e', 'a"b'])
        self.assertTrue(all((not isinstance(item, JsonNumber) for item in value)))

    def test_array_omissions_are_null(self):
        for (text, expected) in (('[]', []), ('[,]', [None, None]), ('[;]', [None, None]), ('[1,]', ['1', None]), ('[1;;2]', ['1', None, '2'])):
            self.assertEqual(loads(text), expected)

    def test_object_and_escape_errors_remain_errors(self):
        for text in ('{a:1,}', '{a:}', '{a}', '[1 2]', '[', '{', '/* missing', '"\\v"', '"\\uZZZZ"', '"unterminated', '\x0c{}', '{} {}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                loads(text)

    def test_strings_and_utf16(self):
        self.assertEqual(loads("'x\\\ny'"), 'x\ny')
        self.assertEqual(loads('"raw\ncontrol\x00"'), 'raw\ncontrol\x00')
        self.assertEqual(loads('"\\ud83d\\ude00"'), '😀')
        self.assertEqual(loads('"\\ud800"'), '\ud800')
        self.assertEqual(loads('"\\u0000\\b\\f\\n\\r\\t\\"\\\'\\/\\\\"'), '\x00\x08\x0c\n\r\t"\'/\\')

    def test_number_length_and_spelling(self):
        for token in ('0', '-0', '1e+01', '9223372036854775808', '1.200', '9' * 1023):
            result = loads(token)
            self.assertIsInstance(result, JsonNumber)
            self.assertEqual(result, token)
        self.assertNotIsInstance(loads('9' * 1024), JsonNumber)

    def test_gson_restores_strict_mode_for_full_consumption(self):
        for text in ('{} // comment', '[] /* comment */', '{} # comment'):
            with self.assertRaises(ValueError):
                loads(text)
        self.assertIsNone(loads('null ignored trailing text'))
        self.assertIsNone(loads('/* empty */'))

    def test_each_duplicate_model_member_is_processed(self):
        document = loads('{responseCode:123,responseCode:"000",paymentList:[],paymentList:null}')
        model = read_model(document, 'national.list')
        self.assertEqual(model['responseCode'], '000')
        self.assertIsNone(model['paymentList'])
        for text in ('{responseCode:{},responseCode:"000"}', '{paymentList:false,paymentList:[]}', '{sessionInfo:{userId:[]},sessionInfo:null}'):
            with self.subTest(text=text), self.assertRaises(GiroError):
                read_model(loads(text), 'national.list')
        self.assertIsNotNone(read_model(loads('{unknown:[],unknown:{}}'), 'national.list'))

    def test_ordinary_json_matches_stdlib_values(self):
        for value in ({'x': ['가나다', '😀', None, True], 'y': {}}, [], {'a': '\n\r\t'}):
            self.assertEqual(loads(json.dumps(value)), value)
            self.assertEqual(json.loads(json_value(loads(json.dumps(value)))), value)
