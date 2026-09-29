import unittest
from giro.compat import json_value, loads, read_model, string_value
from giro.errors import GiroError
from giro.protocol import build_query, query_string

class CompatTests(unittest.TestCase):

    def test_numeric_lexemes_preserved(self):
        value = loads('{"a":1e+03,"b":1.2300,"c":-0,"d":9223372036854775808}')
        self.assertEqual([string_value(v) for v in value.values()], ['1e+03', '1.2300', '-0', '9223372036854775808'])
        self.assertEqual(query_string(value), 'a=1e+03&b=1.2300&c=-0&d=9223372036854775808')

    def test_numeric_arrays_not_quoted(self):
        self.assertEqual(json_value(loads('[1e2,1.20,-0]')), '[1e2,1.20,-0]')

    def test_gson_string_adapter(self):
        for (value, expected) in ((True, 'true'), (False, 'false'), (None, None), (123, '123'), ('', '')):
            self.assertEqual(string_value(value), expected)
        for value in ({}, []):
            with self.assertRaises(GiroError):
                string_value(value)

    def test_model_defaults_and_explicit_null(self):
        self.assertEqual(read_model({}, 'auth.pin')['작업구분'], '로그인')
        self.assertIsNone(read_model({'작업구분': None}, 'auth.pin')['작업구분'])

    def test_model_inheritance_and_unknown_fields(self):
        model = read_model({'responseCode': '000', 'unknown': [1, 2], 'paymentList': [{'payMny': 12.5}]}, 'national.list')
        self.assertEqual(model['responseCode'], '000')
        self.assertNotIn('unknown', model)
        self.assertEqual(model['paymentList'][0]['payMny'], '12.5')

    def test_request_model_uses_actual_field_names(self):
        result = build_query('auth.pin', {'pin': 'ANY-CIPHER', 'f31': 'ignored'}, device_id=None)
        self.assertIn('작업구분=로그인', result)
        self.assertIn('pin=ANY-CIPHER', result)
        self.assertNotIn('f31', result)
        self.assertNotIn('deviceId=', result)

    def test_unknown_field_invalid_shape_does_not_fail_model(self):
        self.assertIsNotNone(read_model({'neverSeen': [None, {}]}, 'auth.server-cert'))

    def test_all_model_fields_are_checked_not_only_normalized_subset(self):
        with self.assertRaises(GiroError):
            read_model({'responseCode': '000', 'isPayableDayTime': {}}, 'national.list')

    def test_request_arrays_keep_null_slots_but_omit_null_object_fields(self):
        self.assertEqual(query_string({'a': [{'x': None, 'y': '&='}, None]}), 'a=[{"y":"&="},null]')
