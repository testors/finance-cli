"""Input adapters use synthetic data and never contact a bank."""
import io
import json
from unittest.mock import patch

from finance_cli.services.shinhan import cli, issuance_input
from finance_cli.services.shinhan.enrollment import Pending
from finance_cli.services.shinhan.exchange import Exchange
from test_shinhan import PrivateHome, settings


class IssuanceInputTests(PrivateHome):
    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.exchange = Exchange(settings(), {}, 'certificate_issue')

    def test_consents_continue_without_prompt_and_cloud_keeps_issue_route(self):
        ask = issuance_input.factory(self.exchange, no_input=True)
        with patch('sys.stderr'), patch('builtins.input', side_effect=AssertionError('Prompt')), \
             patch('getpass.getpass', side_effect=AssertionError('Prompt')):
            for kind in ('terms', 'name_changed', 'phone_changed', 'account_security_route'):
                self.assertTrue(ask(kind, {}))
            self.assertFalse(ask('download_cloud_certificate', {}))

    def test_no_input_does_not_assert_sms_or_ars_completed(self):
        ask = issuance_input.factory(self.exchange, no_input=True)
        for kind, context, action in [
            ('send_phone_sms', {'destination': 'SYN-DEST', 'message': 'SYN-SMS'}, 'sms_sent_input_required'),
            ('additional_response', {'method': 'ars'}, 'ars_completed_input_required')]:
            with self.subTest(kind=kind), patch('sys.stderr', new_callable=io.StringIO) as error, \
                 patch('builtins.input', side_effect=AssertionError('Prompt')):
                with self.assertRaises(Pending) as stopped:
                    ask(kind, context)
                self.assertEqual(stopped.exception.action, action)
            if kind == 'send_phone_sms':
                self.assertIn('SYN-DEST', error.getvalue())
                self.assertIn('SYN-SMS', error.getvalue())
        self.assertNotIn('SYN-SMS', json.dumps(self.exchange.report))

    def test_pipe_can_acknowledge_sms_and_ars_after_their_challenges(self):
        ask = issuance_input.factory(self.exchange)
        with patch('sys.stdin', io.StringIO('\n\n')), patch('sys.stderr'):
            self.assertTrue(ask('send_phone_sms', {'destination': 'SYN-DEST', 'message': 'SYN-SMS'}))
            self.assertTrue(ask('additional_response', {'method': 'ars'}))

    def test_additional_authentication_uses_supplied_values_without_prompt(self):
        values = {'additional_method': 'ars', 'additional_phone_kind': '0', 'ars_completed': True,
                  'additional_sms_code': 'SYN-CODE'}
        ask = issuance_input.factory(self.exchange, values, no_input=True)
        with patch('sys.stderr'), patch('builtins.input', side_effect=AssertionError('Prompt')):
            self.assertEqual(ask('additional_select', {}), {'method': 'ars', 'kind': '0'})
            self.assertTrue(ask('additional_response', {'method': 'ars'}))
            self.assertEqual(ask('additional_response', {'method': 'sms'}), 'SYN-CODE')

    def test_eof_reports_missing_field_without_reading_controlling_terminal(self):
        ask = issuance_input.factory(self.exchange)
        with patch('sys.stdin', io.StringIO('')), patch('sys.stderr'), \
             patch('getpass.getpass', side_effect=AssertionError('Controlling terminal')):
            with self.assertRaises(Pending) as stopped:
                ask('identity_sms', {})
        self.assertEqual(stopped.exception.action, 'identity_sms_code_input_required')

    def test_unknown_or_nonstring_file_field_stops_before_network_without_echo(self):
        for data in ({'name': 42}, {'name': 'SYN-NAME', 'SYN-KEY': 'SYN-SECRET'}, {'sms_sent': 'yes'}):
            with self.subTest(data=data), patch.object(issuance_input.storage, 'read_json', return_value=data):
                code, output, error = self.call(['certificate', 'issue', '--send', '--input-file', 'synthetic.json'])
            self.assertEqual(code, 2)
            result = json.loads(output)['result']
            self.assertEqual(result['required_action'], 'issuance_input_file_invalid')
            self.assertFalse(result['network_used'])
            self.assertNotIn('SYN-SECRET', output+error)
            self.assertNotIn('SYN-NAME', output+error)

    def test_auto_notice_acknowledgment_preserves_block_and_unknown_button(self):
        with patch('sys.stderr'), patch('builtins.input', side_effect=AssertionError('Prompt')), \
             patch('getpass.getpass', side_effect=AssertionError('Prompt')):
            self.assertTrue(cli.acknowledge_program_notice('SYN', None, False))
            self.assertFalse(cli.acknowledge_program_notice('SYN', None, True))
            self.assertEqual(cli.queue_choice({'message': 'SYN', 'button': {'type': 'exit'}}, None), 'exit')
            self.assertIsNone(cli.queue_choice({'message': 'SYN', 'button': {'type': 'unknown'}}, None))
