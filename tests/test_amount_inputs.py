"""Grouped user amounts at CLI boundaries; synthetic inputs and no network."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from finance_cli.cli.main import main
from finance_cli.services.hana import onesign_cli, onesign_transfer, onesign_multi_transfer
from finance_cli.services.hana_corporate import batch, transfers


class AmountInputTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(self.root / 'home')}))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))

    def call(self, args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(['--format', 'json-v1', *args])
        return code, json.loads(out.getvalue())['result']

    def test_corporate_amount_is_ungrouped_before_service_call(self):
        for raw, expected in [('3,000,000', '3000000'), ('3000000', '3000000'),
                              ('123,456,789,012,345,678', '123456789012345678'),
                              ('-1,000', '-1000'), ('1,000.50', '1000.50'), ('1e3', '1e3')]:
            with self.subTest(raw=raw), patch.object(transfers, 'prepare', return_value={'network_used': False}) as prepare:
                code, value = self.call(['hana', 'corporate', 'transfer', 'prepare', '--from-account', '000101',
                    '--to-bank', '081', '--to-account', '000201', '--amount', raw])
                self.assertEqual(code, 0)
                self.assertEqual(prepare.call_args.args[3], expected)
                self.assertFalse(prepare.call_args.kwargs['send'])
                self.assertFalse(value['network_used'])
        self.assertFalse((self.root / 'home').exists())

    def test_personal_json_preserves_integer_contract_after_group_removal(self):
        source = self.root / 'intent.json'
        intent = {'source_account': '000101', 'recipient_bank_code': '081',
                  'recipient_account_number': '000201', 'amount_krw': '3,000,000'}
        source.write_text(json.dumps(intent))
        with patch.object(onesign_cli, 'State'), patch.object(onesign_cli, 'password', return_value=b'synthetic'), \
                patch.object(onesign_transfer, 'operate', return_value={'network_used': False}) as operate:
            code, _ = self.call(['hana', 'transfer', 'prepare', '--name', 'synthetic', '--input', str(source), '--send'])
            self.assertEqual(code, 0)
            prepared = operate.call_args.kwargs['intent']
            self.assertEqual(prepared, {**intent, 'amount_krw': 3000000})
            self.assertEqual(onesign_transfer.checked_intent(prepared)['amount_krw'], 3000000)
        # Without --send, do not even read the input file or request a secret.
        with patch.object(onesign_cli, 'password', side_effect=AssertionError('Secret access forbidden')):
            code, value = self.call(['hana', 'transfer', 'prepare', '--name', 'synthetic', '--input', str(self.root / 'missing.json')])
            self.assertEqual(code, 0)
            self.assertFalse(value['network_used'])

    def test_both_batch_clis_accept_quoted_grouped_amounts_and_find_duplicates(self):
        path = self.root / 'items.csv'
        path.write_text('to_bank,to_account,amount\n081,000201,"3,000,000"\n081,000201,3000000\n')
        for args, total in [(['hana', 'transfer', 'check-batch', '--input'], 'amount_krw'),
                            (['hana', 'corporate', 'transfer', 'check-batch', '--file'], 'total_amount')]:
            code, result = self.call([*args, str(path)])
            self.assertEqual(code, 0)
            self.assertEqual(str(result[total]), '6000000')
            self.assertEqual(result['duplicate_rows'], [2])
            self.assertFalse(result['network_used'])
        for read in [batch.read_items, onesign_multi_transfer.read_items]:
            for invalid in ['0', '-1,000', '1,000.50', '1e3', '1,PRIVATE']:
                path.write_text(f'to_bank,to_account,amount\n081,000201,"{invalid}"\n')
                with self.subTest(reader=read.__module__, invalid=invalid), self.assertRaises(ValueError):
                    read(path)
