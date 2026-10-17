import json
import unittest
from unittest.mock import patch

from finance_cli.services.shinhan import history_protocol as history, transport


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))

    def reply(self, body, result='SUCCESS'):
        return history.parse_reply(transport.Reply(200, [], json.dumps({
            'dataHeader': {'result': result}, 'dataBody': body}).encode()))

    def test_body_defaults_and_long_cursor_remain_distinct_from_row_int(self):
        body = history.decode('{nxtSubTrxnoL10:"1099511627776",grd12:[{trxno:"42"}]}')
        self.assertEqual(body['nxtSubTrxnoL10'], 2**40)
        self.assertEqual(body['grd12'][0]['trxno'], 42)
        self.assertEqual(body['grd12'][0]['subTrxnoL10'], 0)
        with self.assertRaises(ValueError):
            history.decode('{grd12:[{subTrxnoL10:1099511627776}]}')

    def test_unknown_fields_and_duplicate_null_skip(self):
        body = history.decode('{rstCL1:2,rstCL1:null,unknown:[{x:[1,]}],grd12:[],grd12:null}')
        self.assertEqual(body['rstCL1'], 2)
        self.assertEqual(body['grd12'], [])

    def test_empty_success_is_a_page_not_failure(self):
        verdict, document = self.reply({})
        cursor = history.Cursor()
        page = cursor.page(history.Query('SYN-ACCOUNT'), document['dataBody'])
        self.assertEqual(verdict['bank_result'], 'success')
        self.assertEqual(len(page['data']), 1)
        self.assertIsNone(page['nextKey'])

    def test_body_processing_errors_preserve_success_without_exposing_data(self):
        for body in (None, [], {'grd12': [None]}, {'nxtSubTrxnoL10': 2**63}, {'grd12': [{'ipamt_originalValue': 'SYN-SECRET'}]}):
            with self.subTest(body=body):
                verdict, document = self.reply(body)
                self.assertEqual(verdict['bank_result'], 'success')
                self.assertEqual(verdict['processing_status'], 'incomplete')
                self.assertIsNone(document['dataBody'])
                self.assertNotIn('SYN-SECRET', json.dumps(verdict))

    def test_failure_body_is_not_decoded_as_a_history_page(self):
        verdict, _ = self.reply({'grd12': [None]}, 'FAIL')
        self.assertEqual(verdict['bank_result'], 'failure')
        self.assertEqual(verdict['error'], 'bank_rejected')

    def test_unknown_header_is_not_inferred_from_plausible_history(self):
        verdict, _ = self.reply({'grd12': []}, 'OTHER')
        self.assertEqual(verdict['bank_result'], 'unknown')

    def test_filters_keep_amount_sentinels_and_whitespace_search(self):
        query = history.Query('SYN-01-02', keyword=' ', transaction_type='DEPOSIT', min_amount=0)
        request = history.Cursor().request(query)
        self.assertEqual((request['dtlGL1'], request['trxGL2'], request['upmuG']), (9, 15, 2))
        self.assertEqual(request['cmsNo'], ' ')
        self.assertEqual(request['acno'], 'SYN-01-02')
        self.assertEqual(request['dtlAmt2N12'], 2**63-1)

    def test_inverted_amounts_are_not_reordered(self):
        request = history.Cursor().request(history.Query('SYN', min_amount=50, max_amount=-10))
        self.assertEqual((request['dtlAmt1N12'], request['dtlAmt2N12']), (50, -10))

    def test_dates_and_page_keys_are_independent_of_request_cursor(self):
        query = history.Query('SYN', start='unchanged', end='', print_count=7)
        cursor = history.Cursor()
        self.assertEqual(cursor.request(query)['inqrSjdt'], 'unchanged')
        first = cursor.page(query, history.decode('{rstCL1:2,nxtTrxnoL10:55,nxtSubTrxnoL10:1099511627776}'), key=10)
        self.assertEqual((first['prevKey'], first['nextKey']), (9, 11))
        request = cursor.request(query)
        self.assertEqual((request['trxno'], request['subTrxnoL10'], request['sttGN1'], request['prntCntN8']), (55, 2**40, 1, 7))
        second = cursor.page(query, history.decode('{rstCL1:3}'), key=11)
        self.assertIsNone(second['nextKey'])

    def test_empty_atm_page_can_have_a_next_page(self):
        query = history.Query('SYN', transaction_type='SHINHAN_ATM')
        cursor = history.Cursor()
        page = cursor.page(query, history.decode('{rstCL1:2,grd12:[{atmYn:N}]}'))
        self.assertEqual(len(page['data']), 1)
        self.assertEqual(page['nextKey'], 2)
        self.assertTrue(cursor.has_next)

    def test_duplicate_and_cancelled_rows_preserve_order_amount_precision(self):
        row = {'trxno': 9, 'ipjiG': 1, 'ipamt_originalValue': 12.75, 'jan_originalValue': -3.5,
               'corrCancelYn': 'Y', 'atmYn': 'Y'}
        data = history.rows(history.decode(json.dumps({'grd12': [row, row | {'trxno': 3}, row]})))
        self.assertEqual([item['transactionNumber'] for item in data], [9, 3, 9])
        self.assertTrue(all(item['isCancelled'] for item in data))
        self.assertEqual(data[0]['amount'], 12.75)
        self.assertEqual(data[0]['balance'], -3.5)

    def test_mapper_failure_precedes_atm_filter_and_keeps_previous_cursor(self):
        cursor = history.Cursor(55, 2**40, True)
        def failed_observer():
            raise OSError('SYN-DIAGNOSTIC')
        with self.assertRaises(OSError):
            cursor.page(history.Query('SYN', transaction_type='SHINHAN_ATM'),
                        history.decode('{rstCL1:0,nxtTrxnoL10:99,grd12:[{atmYn:N}]}'),
                        on_date_error=failed_observer)
        self.assertEqual((cursor.transaction, cursor.subtransaction, cursor.has_next), (55, 2**40, True))

    def test_null_body_keeps_previous_cursor(self):
        cursor = history.Cursor(55, 66, True)
        with self.assertRaises(ValueError):
            cursor.page(history.Query('SYN'), None)
        self.assertEqual((cursor.transaction, cursor.subtransaction, cursor.has_next), (55, 66, True))

    def test_lenient_date_and_trailing_text(self):
        self.assertEqual(history.date_time('2026.09.47', '12:34:56 trailing'), 1792208096000)
        self.assertEqual(history.date_time('2026.10.18', '-12:34:56'), 1792208096000)
        self.assertEqual(history.date_time('invalid', 'time'), 0)

    def test_unestablished_calendar_range_is_not_replaced_by_zero(self):
        with self.assertRaisesRegex(ValueError, 'history_date_range_unverified'):
            history.date_time('1500.01.01', '00:00:00')

    def test_korean_clock_overlap_and_gap(self):
        self.assertEqual(history.date_time('1900.1.1', '00:00:00'), -2209021200000)
        self.assertEqual(history.date_time('1900.1.1', '08:27:52'), -2208988800000)
        self.assertEqual(history.date_time('1988.5.8', '02:30:00'), history.date_time('1988.5.8', '03:30:00'))

    def test_domain_input_repr_does_not_contain_account_search_or_cursor(self):
        self.assertNotIn('SYN-SECRET', repr(history.Query('SYN-SECRET', keyword='SYN-SECRET')))
        self.assertNotIn('987654321', repr(history.Cursor(987654321, 987654321, True)))


if __name__ == '__main__':
    unittest.main()
