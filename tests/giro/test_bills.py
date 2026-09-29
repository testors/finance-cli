import copy
from datetime import date
import unittest
from giro.bills import due_bills, normalize_detail, normalize_pages, parse_date
from giro.errors import GiroError, ResponseError

def page(current=1, total=1, count=1, due='20260930'):
    return {'responseCode': '000', 'paymentList': [{'elecNo': f'TEST-{current}', 'companyName': '가상 테스트 기관', 'payMny': '12,340', 'payLimitDate': due}], 'pageNaviMap': {'currentPage': str(current), 'totalPage': str(total), 'totalCount': str(count)}}

class BillTests(unittest.TestCase):

    def test_three_tax_types(self):
        for kind in ('national', 'local', 'customs'):
            result = normalize_pages(page(), kind)
            self.assertTrue(result['complete'])
            self.assertEqual(result['bills'][0]['tax_type'], kind)
            self.assertEqual(result['bills'][0]['due_date'], '2026-09-30')
            self.assertEqual(result['bills'][0]['amount'], 12340)

    def test_all_pages_out_of_order(self):
        result = normalize_pages([page(2, 2, 2), page(1, 2, 2)], 'national')
        self.assertTrue(result['complete'])
        self.assertEqual(result['loaded_count'], 2)

    def test_missing_first_page_is_incomplete(self):
        result = normalize_pages(page(2, 2, 2), 'customs')
        self.assertFalse(result['complete'])
        self.assertEqual(result['missing_pages'], [1])

    def test_duplicate_and_inconsistent_pages_retained_with_diagnostics(self):
        for pages in ([page(), page()], [page(1, 2, 2), page(2, 3, 3)]):
            result = normalize_pages(pages, 'national')
            self.assertTrue(result['app_success'])
            self.assertFalse(result['complete'])
            self.assertEqual(result['loaded_count'], 2)

    def test_missing_nav_preserves_incomplete_data(self):
        data = page()
        del data['pageNaviMap']
        result = normalize_pages(data, 'local')
        self.assertFalse(result['complete'])
        self.assertEqual(result['loaded_count'], 1)

    def test_count_mismatch_not_successful_empty(self):
        data = page()
        data['paymentList'] = []
        self.assertFalse(normalize_pages(data, 'national')['complete'])

    def test_empty_success(self):
        data = page(0, 0, 0)
        data['paymentList'] = []
        self.assertTrue(normalize_pages(data, 'national')['complete'])

    def test_null_or_missing_list_not_zero_bills(self):
        for data in ({'responseCode': '000'}, {'responseCode': '000', 'paymentList': None}):
            result = normalize_pages(data, 'national')
            self.assertTrue(result['app_success'])
            self.assertIsNone(result['bills'])
            self.assertFalse(result['complete'])
        with self.assertRaises(GiroError):
            normalize_pages([], 'national')

    def test_error_code_not_zero_bills(self):
        for code in (None, '601', 'SESSION_EXPIRED', 0):
            with self.subTest(code=code), self.assertRaises(ResponseError):
                normalize_pages({'responseCode': code, 'paymentList': []}, 'national')

    def test_page_field_validation(self):
        for number in (True, '-1', 'NaN', '1.0', None):
            data = page()
            data['pageNaviMap']['currentPage'] = number
            result = normalize_pages(data, 'national')
            self.assertTrue(result['app_success'])
            self.assertFalse(result['complete'])

    def test_original_next_page_only_compares_current_with_total(self):
        data = page(-1, 2, 2)
        result = normalize_pages(data, 'national')
        self.assertEqual(result['pages'][0]['next_page'], 0)

    def test_signed_int_page_strings_accepted(self):
        data = page('+1', '+1', '+1')
        self.assertTrue(normalize_pages(data, 'national')['complete'])

    def test_huge_total_does_not_reject_success_or_expand_unboundedly(self):
        result = normalize_pages(page(1, 2147483647, 2147483647), 'national')
        self.assertTrue(result['app_success'])
        self.assertEqual(len(result['missing_pages']), 1000)
        self.assertTrue(result['missing_pages_truncated'])

    def test_gson_coerces_numeric_and_boolean_strings(self):
        data = page()
        data['paymentList'][0].update(payMny=1234, payLimitDate=20260930, companyName=True)
        bill = normalize_pages(data, 'national')['bills'][0]
        self.assertEqual((bill['amount_raw'], bill['due_date_raw'], bill['issuer']), ('1234', '20260930', 'true'))

    def test_unknown_fields_ignored_but_known_invalid_shapes_fail(self):
        data = page()
        data['newServerField'] = {'anything': [True]}
        self.assertTrue(normalize_pages(data, 'national')['app_success'])
        data['paymentList'][0]['payMny'] = {}
        with self.assertRaises(ResponseError) as caught:
            normalize_pages(data, 'national')
        self.assertEqual(caught.exception.callback_code, '605')
        self.assertEqual(caught.exception.origin, 'model_decode')

    def test_null_element_retained(self):
        data = page()
        data['paymentList'] = [None]
        result = normalize_pages(data, 'national')
        self.assertEqual(result['bills'], [None])
        self.assertTrue(result['app_success'])
        self.assertFalse(due_bills(result, today=date(2026, 9, 27), within_days=7)['filter_complete'])

    def test_dates_validated_without_guessing(self):
        for raw in ('20260930', '2026-09-30', '2026.09.30', '2026/09/30'):
            self.assertEqual(parse_date(raw), '2026-09-30')
        for raw in ('20260230', '30/09/2026', '2026-09.30', '별도 통보', ''):
            self.assertIsNone(parse_date(raw))

    def test_due_inclusive_boundaries_and_overdue(self):
        docs = [page(i, 4, 4, raw) for (i, raw) in enumerate(('20260926', '20260927', '20261004', '20261005'), 1)]
        result = normalize_pages(docs, 'national')
        filtered = due_bills(result, today=date(2026, 9, 27), within_days=7)
        self.assertEqual([b['days_until_due'] for b in filtered['bills']], [0, 7])
        filtered = due_bills(result, today=date(2026, 9, 27), within_days=7, include_overdue=True)
        self.assertEqual([b['days_until_due'] for b in filtered['bills']], [-1, 0, 7])

    def test_unknown_date_not_silently_dropped(self):
        result = normalize_pages(page(due='미정'), 'local')
        filtered = due_bills(result, today=date(2026, 9, 27), within_days=7)
        self.assertFalse(filtered['filter_complete'])
        self.assertEqual(filtered['unparsed_bills'][0]['due_date_raw'], '미정')

    def test_raw_amount_preserved(self):
        data = page()
        data['paymentList'][0]['payMny'] = '1,23'
        bill = normalize_pages(data, 'national')['bills'][0]
        self.assertIsNone(bill['amount'])
        self.assertEqual(bill['amount_raw'], '1,23')

    def test_detail_dates_not_assumed(self):
        data = {'responseCode': '000', 'paymentData': {'pay1date': '20260930', 'payMny': '0'}}
        result = normalize_detail(data, 'customs')
        self.assertIsNone(result['bill']['due_date'])
        self.assertEqual(result['detail_raw']['pay1date'], '20260930')

    def test_null_detail_is_still_query_success(self):
        result = normalize_detail({'responseCode': '000'}, 'customs')
        self.assertTrue(result['app_success'])
        self.assertIsNone(result['bill'])

    def test_success_not_overridden_by_errorinfo(self):
        data = page()
        data['errorInfo'] = {'errorCode': 'WHATEVER'}
        self.assertTrue(normalize_pages(data, 'national')['app_success'])

    def test_failure_keeps_response_and_callback_codes(self):
        data = {'responseCode': 'server code with spaces', 'errorInfo': {'errorCode': '', 'errorName': '실패', 'errorMessage': '서비스 메시지'}}
        with self.assertRaises(ResponseError) as caught:
            normalize_pages(data, 'national')
        self.assertEqual(caught.exception.code, 'server code with spaces')
        self.assertEqual(caught.exception.callback_code, '')
        self.assertEqual(caught.exception.error_info['errorMessage'], '서비스 메시지')

    def test_does_not_emit_session_or_mutate_input(self):
        data = page()
        data['sessionInfo'] = {'personal': 'MUST_NOT_OUTPUT'}
        original = copy.deepcopy(data)
        result = normalize_pages(data, 'national')
        self.assertEqual(data, original)
        self.assertNotIn('MUST_NOT_OUTPUT', str(result))
