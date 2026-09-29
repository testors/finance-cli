"""Synthetic checks of the transfer formatting port. No JavaScript runtime, network or credential."""
from pathlib import Path
import unittest

from finance_cli.services.hana import transfer_format as t

ROW = {'trnsTgb': '01', 'wdrwAcctNo': '12345678901234', 'wdrwBnkCd': '081', 'rcvBnkCd': '088',
       'rcvAcctNo': '110123456789', 'trnsAmt': 1234567, 'rduAfComm': 0, 'rmteNm': '수취인', 'rmtrNm': '송금인'}


def values(items):
    return {item['name']: item['value'] for item in items}


class FormattingPrimitives(unittest.TestCase):
    def test_source_has_no_javascript_runtime(self):
        source = Path(t.__file__).read_text()
        for word in ('subprocess', 'node', 'chromium', 'playwright'):
            self.assertNotIn(word, source.lower())

    def test_mark_replaces_entities_in_original_order(self):
        self.assertEqual(t.mark('a&yen;b&deg;c&rdquo;'), 'a¥b°c”')
        self.assertEqual(t.mark('&amp;&lt;'), '&amp;&lt;')
        # The original alternation matches "&#39" first, so the semicolon stays.
        self.assertEqual(t.mark('&#39;'), "';")
        self.assertEqual(t.mark('&#39'), "'")
        for value in (None, 5, ['&yen;'], {}):
            with self.assertRaises(ValueError):
                t.mark(value)

    def test_make_comma_follows_javascript_number_and_string_rules(self):
        cases = [(0, '0'), (-0.0, '0'), (999, '999'), (1234, '1,234'), (-1234567, '-1,234,567'),
                 (1234.5, '1,234.5'), (0.1 + 0.2, '0.30000000000000004'), (1e21, '1e+21'), (1e-7, '1e-7'),
                 (123456789012345680000, '123,456,789,012,345,680,000'), ('1234', '1,234'), ('1234abc', '1,234abc'),
                 ('1.2.3', '1.2'), ('abc', 'abc'), ('Infinity', 'Infinity'), ('', ''), (None, ''), (False, ''),
                 (True, 'true'), ([1234567], '1,234,567'), ({}, '[object Object]')]
        for value, expected in cases:
            self.assertEqual(t.make_comma(value), expected, value)

    def test_account_numbers_by_length_and_bank(self):
        self.assertEqual(t.to_acct_no('12345678901234', '081'), '123-456789-01234')
        self.assertEqual(t.to_acct_no('123456789012', '81'), '123-456789-012')
        self.assertEqual(t.to_acct_no('12345678901', '081'), '123-45-67890-1')
        self.assertEqual(t.to_acct_no('12345678901', '005'), '123-45-67890-1')
        self.assertEqual(t.to_acct_no('12345678901234', 5), '123-456789-01234')
        self.assertEqual(t.to_acct_no('12345678901234', '088'), '12345678901234')
        self.assertEqual(t.to_acct_no('12345678901234', None), '123-456789-01234')
        self.assertEqual(t.to_acct_no('12345678901234', ' '), '123-456789-01234')
        self.assertEqual(t.to_acct_no('1234567890', '081'), '1234567890')
        self.assertEqual(t.to_acct_no(None, '081'), '')
        self.assertEqual(t.to_acct_no(12345678901234, '081'), 12345678901234)

    def test_account_length_counts_utf16_units(self):
        self.assertEqual(t.to_acct_no('1234567890\U0001F600', '081'), '123-456789-0\U0001F600')
        self.assertEqual(t.to_acct_no('12\U0001F600345678901', '081'), '12\U0001F600345678901')
        self.assertEqual(t.to_acct_no('12\U0001F6000123456789', '081'), '12\ud83d-\ude0001234-56789')
        self.assertEqual(t.to_acct_no('\ud83d12345678901', '081'), '\ud83d12-345678-901')

    def test_unreproduced_account_inputs_are_refused(self):
        for args in ((['1'], '081'), ({}, '081'), ('12345678901234', ['081']), ('12345678901234', {})):
            with self.assertRaises(ValueError):
                t.to_acct_no(*args)
        with self.assertRaises(ValueError):
            t.to_keb_acct_no(['1'])

    def test_format_date_lengths(self):
        self.assertEqual(t.format_date('20240102'), '2024-01-02')
        self.assertEqual(t.format_date('202401'), '2024-01')
        self.assertEqual(t.format_date('20240102123456'), '2024-01-02 12:34:56')
        self.assertEqual(t.format_date('202401021234'), '2024-01-02 12:34')
        self.assertEqual(t.format_date(20240102), '2024-01-02')
        self.assertEqual(t.format_date('2024/01/02', '.'), '2024.01.02')
        for value in ('', None, 0, '2024', '２０２４０１０２', True):
            self.assertEqual(t.format_date(value), '', value)


class SignForm(unittest.TestCase):
    def test_account_form_order_and_defaults(self):
        items = t.form(ROW)
        self.assertEqual([item['name'] for item in items],
                         ['wdrwAcctNo', 'rcvBnkCd', 'rcvAcctNo', 'trnsAmt', 'rduAfComm', 'rcvPsbkMarkCtt',
                          'wdrwPsbkMarkCtt', 'rmteNm', 'rmtrNm', 'cshbUseYn', 'cshbUseAmt', 'slctDvCd'])
        self.assertEqual(items[0], {'name': 'wdrwAcctNo', 'signid': '출금계좌번호', 'value': '123-456789-01234'})
        self.assertEqual(values(items), {
            'wdrwAcctNo': '123-456789-01234', 'rcvBnkCd': '088', 'rcvAcctNo': '110123456789',
            'trnsAmt': '1,234,567', 'rduAfComm': '0', 'rcvPsbkMarkCtt': '', 'wdrwPsbkMarkCtt': '', 'rmteNm': '수취인',
            'rmtrNm': '송금인', 'cshbUseYn': '', 'cshbUseAmt': '', 'slctDvCd': ''})

    def test_account_form_passes_raw_values_and_stringifies_money_use(self):
        row = {**ROW, 'rcvBnkCd': 88, 'rcvPsbkMarkCtt': 0, 'cshbUseYn': 'N', 'cshbUseAmt': 100, 'slctDvCd': None}
        found = values(t.form(row))
        self.assertEqual((found['rcvBnkCd'], found['rcvPsbkMarkCtt'], found['cshbUseAmt'], found['slctDvCd']),
                         (88, 0, '100', ''))
        self.assertEqual(values(t.form({**ROW, 'cshbUseAmt': ' '}))['cshbUseAmt'], '')
        self.assertEqual(values(t.form({**ROW, 'cshbUseAmt': 0}))['cshbUseAmt'], '0')

    def test_scheduled_and_mmda_entries(self):
        items = t.form({**ROW, 'trnsScheDt': '20240102', 'trnsScheTm': '0900'})
        self.assertEqual(items[0], {'name': 'trnsScheDt', 'signid': '이체예정일시', 'value': '2024-01-02 0900시'})
        self.assertEqual(len(items), 13)
        self.assertEqual(len(t.form({**ROW, 'trnsScheTm': ' '})), 12)
        items = t.form({**ROW, 'mmdaHoldYn': 'Y', 'mmdaIntPaymCd': '1'})
        self.assertEqual([item['name'] for item in items[-2:]], ['mmdaIntPaymCd', 'mmdaIntRcvAcctNo'])
        self.assertEqual([item['value'] for item in items[-2:]], ['1', ''])
        self.assertEqual(len(t.form({**ROW, 'mmdaHoldYn': 'y'})), 12)

    def test_contact_and_national_tax_forms(self):
        contact = t.form({'trnsTgb': '03', 'rmteTelNo': '01012345678', 'wdrwAcctNo': '12345678901234',
                          'wdrwBnkCd': '081', 'trnsAmt': 5000})
        self.assertEqual([item['name'] for item in contact],
                         ['rmteTelNo', 'wdrwAcctNo', 'trnsAmt', 'rcvPsbkMarkCtt', 'wdrwPsbkMarkCtt', 'rmteNm', 'rmtrNm'])
        self.assertEqual(values(contact)['trnsAmt'], '5,000')
        tax = t.form({'trnsTgb': '02', 'levyInstNm': '세무서', 'fnncInpElecPayNo': '123', 'trnsAmt': 7})
        self.assertEqual([(item['name'], item['value']) for item in tax],
                         [('today', ''), ('levyInstNm', '세무서'), ('custNm', ''), ('BnkCd', '하나'),
                          ('fnncStdElecPayNo', '123'), ('rmndPayAmt', '7')])

    def test_unsupported_rows_are_refused(self):
        for row in ({**ROW, 'trnsTgb': '04'}, {**ROW, 'trnsTgb': None}, {**ROW, 'trnsTgb': 1}, {'trnsAmt': 1}):
            with self.assertRaisesRegex(ValueError, 'unsupported_transaction_type'):
                t.form(row)
        for row in (None, [], 'text', 5):
            with self.assertRaisesRegex(ValueError, 'row_object_required'):
                t.form(row)
        with self.assertRaisesRegex(ValueError, 'unsupported_account_value'):
            t.form({**ROW, 'rcvAcctNo': ['1']})
        with self.assertRaisesRegex(ValueError, 'unsupported_bank_code'):
            t.form({**ROW, 'wdrwBnkCd': {}})


if __name__ == '__main__':
    unittest.main()
