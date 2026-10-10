"""CLI compatibility and machine framing; no credentials or institution traffic."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from finance_cli.cli.main import main


class CliContractTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(directory).resolve()
        self.home = self.root / 'home'
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(self.home)}))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))

    def call(self, args, stdin='', *, versioned=True):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), patch('sys.stdin', io.StringIO(stdin)):
            try:
                code = main((['--format', 'json-v1'] if versioned else []) + args)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def result(self, args, stdin='', **options):
        code, text, errors = self.call(args, stdin, **options)
        return code, json.loads(text), errors

    def test_framing_preserves_native_results_and_exit_codes(self):
        cases = [
            (['hana', 'transfer', 'prepare', '--name', 'synthetic', '--transaction', 't',
              '--session', 's', '--run', 'r', '--input', 'unused.json'], ''),
            (['hometax', 'tax', 'dues'], ''),
            (['hometax', 'auth', 'replay', 'cert-login'], '{}'),
            (['giro', 'auth', 'bootstrap'], ''),
            (['giro', 'auth', 'login'], ''),
            (['giro', 'bills', 'list', '--type', 'national', '--input', '-'], '{"responseCode":"999"}'),
        ]
        for args, stdin in cases:
            with self.subTest(command=args):
                legacy_code, legacy, _ = self.result(args, stdin, versioned=False)
                code, framed, _ = self.result(args, stdin)
                self.assertEqual(framed, {'schema_version': 1, 'service': args[0],
                                         'exit_code': code, 'result': legacy})
                self.assertEqual(code, legacy_code)
        self.assertFalse(self.home.exists())

    def test_unknown_is_not_inferred_success_from_zero_exit(self):
        code, value, _ = self.result(['hometax', 'auth', 'replay', 'cert-login'], '{}')
        self.assertEqual(code, 0)
        self.assertEqual(value['result']['branch'], 'no_action')
        self.assertNotIn('success', value)

    def test_capabilities_and_hana_plan_share_scoped_live_review(self):
        code, value, _ = self.result(['capabilities'])
        self.assertEqual(code, 0)
        capabilities = value['result']
        report = capabilities['services']['hana']['live_verification']
        self.assertEqual(report['verification'], 'live_partial')
        self.assertEqual(report['source'], 'reviewed_web_job_verdicts')
        code, plan, _ = self.result(['hana', 'plan'])
        self.assertEqual(code, 0)
        self.assertEqual(plan['result']['migration']['live_verification'], report)
        code, legacy, _ = self.result(['capabilities'], versioned=False)
        self.assertEqual(legacy, capabilities)
        self.assertFalse(capabilities['network_used'])
        self.assertFalse(capabilities['services']['hometax']['migration_live_tested'])
        self.assertFalse(self.home.exists())

    def test_service_success_survives_local_failure_and_reconciliation(self):
        original = {'accepted': True, 'processing_status': 'stopped',
                    'execution_result': {'original_result_success': True},
                    'reconciliation': {'candidate_complete': True, 'transfer_confirmed': False}}
        with patch('finance_cli.services.hana.cli.dispatch', return_value=original):
            code, value, _ = self.result(['hana', 'accounts', '--session', 'synthetic'])
        self.assertEqual(code, 2)
        self.assertEqual(value['result'], original)

    def test_argument_errors_are_json_without_echoing_values(self):
        for args in (['SYNTHETIC-PRIVATE'],
                     ['hana', 'accounts', '--session', 's', '--unexpected', 'SYNTHETIC-PRIVATE'],
                     ['hometax', 'auth', 'replay', 'SYNTHETIC-PRIVATE'],
                     ['giro', 'SYNTHETIC-PRIVATE']):
            with self.subTest(command=args):
                code, text, errors = self.call(args)
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(text)['result']['error'], 'invalid_arguments')
                self.assertNotIn('SYNTHETIC-PRIVATE', text + errors)

    def test_hometax_bad_input_is_json_in_both_formats(self):
        for versioned in (False, True):
            code, value, errors = self.result(['hometax', 'auth', 'replay', 'cert-login'],
                                               'SYNTHETIC-PRIVATE', versioned=versioned)
            result = value['result'] if versioned else value
            self.assertEqual(code, 2)
            self.assertEqual(result['error'], 'local_input_or_processing_error')
            self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(value) + errors)

    def test_conflicting_certificate_selection_never_reads_secret_or_profile(self):
        with patch('finance_cli.core.profiles.resolve', side_effect=AssertionError('Profile read')), \
             patch('getpass.getpass', side_effect=AssertionError('Secret read')):
            for selection in (['--profile', 'p', '--credential', 'c'],
                              ['--credential=c', '--profile=p']):
                for command in (['hana', 'sign-login', '--nonce', 'SYNTHETIC'],
                                ['hometax', 'auth', 'prepare-cert']):
                    code, value, _ = self.result(command + selection + ['--output', str(self.root / 'unused')])
                    self.assertEqual(code, 2)
                    self.assertEqual(value['result']['error'], 'invalid_arguments')
        self.assertFalse((self.root / 'unused').exists())

    def test_missing_send_and_help_never_resolve_profile(self):
        with patch('finance_cli.core.profiles.resolve', side_effect=AssertionError('Profile read')):
            code, result, _ = self.result(['hometax', 'login', '--profile=absent', '--output', 'unused'])
            self.assertEqual((code, result['result']['error']), (2, 'send_required'))
            code, help_text, _ = self.call(['hometax', 'login', '--profile=absent', '--help'])
            self.assertEqual(code, 0)
            self.assertIn('--profile', help_text)
        self.assertFalse(self.home.exists())

    def test_format_does_not_leak_to_later_invocations(self):
        self.result(['capabilities'])
        _, value, _ = self.result(['giro', 'auth', 'bootstrap'], versioned=False)
        self.assertNotIn('schema_version', value)

    def test_global_option_order_and_equals(self):
        for options in (['--home', str(self.home), '--format=json-v1'],
                        ['--format', 'json-v1', '--home=' + str(self.home)]):
            code, value, _ = self.result(options + ['paths'], versioned=False)
            self.assertEqual(code, 0)
            self.assertEqual(value['service'], 'fin')
            self.assertEqual(value['result']['data'], str(self.home))

    def test_node_summary_is_framed_without_reading_session_file(self):
        for branch, code in (('success', 0), ('failure', 1), ('no_action', 3)):
            original = {'branch': branch, 'session_file_saved': False, 'warning_count': 1}
            with patch('hometax_cli.__main__.subprocess.run', return_value=subprocess.CompletedProcess([], code, json.dumps(original))) as run:
                actual_code, value, _ = self.result(['hometax', 'tax', 'dues', '--session', 'nonexistent',
                                                    '--output', str(self.root / 'out.json'), '--send'])
            self.assertEqual(actual_code, code)
            self.assertEqual(value['result'], original)
            self.assertEqual(run.call_args.kwargs['stdout'], subprocess.PIPE)
            self.assertNotIn('stderr', run.call_args.kwargs)
            self.assertFalse((self.root / 'out.json').exists())

    def test_invalid_node_output_never_echoed_or_replayed(self):
        for stdout, code, reason in (('', 2, 'missing_result_json'),
                                     ('SYNTHETIC-PRIVATE', 0, 'invalid_result_json')):
            with patch('hometax_cli.__main__.subprocess.run', return_value=subprocess.CompletedProcess([], code, stdout)) as run:
                actual, value, errors = self.result(['hometax', 'session', 'resume', '--session', 'nonexistent',
                                                     '--output', str(self.root / 'out.json'), '--send'])
            self.assertEqual((actual, value['exit_code']), (code, code))
            self.assertIsNone(value['result'])
            self.assertEqual(value['output_error']['code'], reason)
            self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(value) + errors)
            run.assert_called_once()

    def test_hometax_tax_target_and_timing_options_share_one_child_and_keep_send_gate(self):
        for operation in ('dues', 'payments', 'refunds', 'notices'):
            for tin in ('B-SYNTHETIC', 'ORIGIN'):
                args = ['hometax', 'tax', operation, '--session', 'nonexistent',
                        '--output', str(self.root / 'out.json'), '--tin', tin, '--timings']
                with patch('hometax_cli.__main__.subprocess.run') as child:
                    code, value, _ = self.result(args)
                child.assert_not_called()
                self.assertNotEqual(code, 0)
                with patch('hometax_cli.__main__.subprocess.run', return_value=subprocess.CompletedProcess(
                        [], 0, '{"branch":"success","timings":[]}')) as child:
                    code, value, _ = self.result([*args, '--send'])
                self.assertEqual(code, 0)
                self.assertEqual(value['result'], {'branch': 'success', 'timings': []})
                child.assert_called_once()
                config = json.loads(child.call_args.kwargs['input'])
                self.assertEqual(config['target'], {'tin': tin, 'kind': 'personal' if tin == 'ORIGIN' else 'business'})
                self.assertTrue(config['timings'])
                self.assertFalse((self.root / 'out.json').exists())

    def test_hometax_session_extend_is_one_child_behind_the_send_gate(self):
        args = ['hometax', 'session', 'extend', '--session', 'nonexistent', '--output', str(self.root / 'out.json')]
        with patch('hometax_cli.__main__.subprocess.run') as child:
            code, value, _ = self.result(args)
        child.assert_not_called()
        self.assertEqual((code, value['result']['error'], value['result']['network_used']), (2, 'send_required', False))
        # The service did not state a verdict: exit 3 and an unverified extension, passed on as received.
        summary = {'operation': 'extend', 'branch': 'no_action', 'reason': 'unobserved', 'method': 'session-check',
                   'login_extension_accepted': None, 'extension_effect': 'unverified', 'session_ended': False,
                   'session_current_validity': 'unverified', 'server_expires_at': None, 'automatic_retry': False}
        with patch('hometax_cli.__main__.subprocess.run',
                   return_value=subprocess.CompletedProcess([], 3, json.dumps(summary))) as child:
            code, value, _ = self.result([*args, '--send'])
        self.assertEqual((code, value['exit_code']), (3, 3))
        self.assertEqual(value['result'], summary)
        child.assert_called_once()
        config = json.loads(child.call_args.kwargs['input'])
        self.assertEqual((config['command'], config['operation']), ('session', 'extend'))
        self.assertFalse((self.root / 'out.json').exists())
        extension = self.result(['capabilities'])[1]['result']['services']['hometax']['session_extension']
        self.assertEqual((extension['command'], extension['method'], extension['verification']),
                         ('fin hometax session extend', 'session-check', 'implemented_live_untested'))

    def test_keyboard_interrupt_has_no_assumed_business_verdict(self):
        with patch('finance_cli.services.hana.cli.dispatch', side_effect=KeyboardInterrupt):
            code, value, _ = self.result(['hana', 'accounts', '--session', 'synthetic'])
        self.assertEqual((code, value['exit_code']), (130, 130))
        self.assertEqual(value['result']['error'], 'interrupted')
        self.assertNotIn('accepted', value['result'])

    def test_missing_input_is_json_without_exception_text(self):
        with patch('finance_cli.services.hana.cli.dispatch', side_effect=EOFError('SYNTHETIC-PRIVATE')):
            code, value, errors = self.result(['hana', 'accounts', '--session', 'synthetic'])
        self.assertEqual(code, 2)
        self.assertEqual(value['result']['error'], 'input_required')
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(value) + errors)

    def test_real_child_pipe_preserves_summary_and_nonzero_exit(self):
        run = subprocess.run
        def local_child(command, **options):
            return run([sys.executable, '-c',
                        'import sys; sys.stdin.read(); print(\'{"branch":"no_action"}\'); sys.exit(3)'], **options)
        with patch('hometax_cli.__main__.subprocess.run', side_effect=local_child):
            code, value, _ = self.result(['hometax', 'session', 'resume', '--session', 'nonexistent',
                                          '--output', str(self.root / 'out.json'), '--send'])
        self.assertEqual((code, value['exit_code']), (3, 3))
        self.assertEqual(value['result'], {'branch': 'no_action'})

    def test_child_signal_preserves_posix_cli_status_without_claiming_failure(self):
        with patch('hometax_cli.__main__.subprocess.run', return_value=subprocess.CompletedProcess([], -9, '')):
            code, value, _ = self.result(['hometax', 'session', 'resume', '--session', 'nonexistent',
                                          '--output', str(self.root / 'out.json'), '--send'])
        self.assertEqual(code, -9)  # Existing return value; SystemExit exposes its low byte on POSIX.
        self.assertEqual(value['exit_code'], 247)
        self.assertIsNone(value['result'])


if __name__ == '__main__':
    unittest.main()
