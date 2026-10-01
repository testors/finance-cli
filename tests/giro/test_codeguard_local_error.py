"""Local error serialization on synthetic values and explicit failed checks."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from urllib.parse import parse_qs

from giro.codeguard_effects import Effect
from giro.codeguard_local_error import (format_local_error, local_error_fields,
    local_error_steps, project_local_error_steps)
from giro.codeguard_rule import AnalysisLimit
from cg_exchange_fixture import Transcript, drive, fault
from test_codeguard_service import service
from test_codeguard_lifecycle import LifecycleObservations


class LocalErrorTests(unittest.TestCase):
    def format(self, code='error', message='message', detail='detail', **options):
        return format_local_error(code, message, detail, **(dict(now_ms=7, map_profile='aosp-8') | options))

    def test_error_fields_are_not_server_success_or_normal_token_expiry(self):
        fields = json.loads(self.format())
        self.assertEqual(fields, {'CODE_APP_INFO':'error', 'CODE_RESPONSE':'message',
            'CODE_GUARD_OS_RESULT':'UNKNOWN', 'CG_VALIDTO':'1800007', 'CG_SIGNATURE':'detail'})
        self.assertNotIn('CODE_APP_HASH', fields)
        self.assertNotIn('CODE_TOKEN', fields)

    def test_map_profiles_change_order_but_preserve_values_including_nulls(self):
        legacy = self.format(None, None, map_profile='aosp-6-7')
        recent = self.format(None, None)
        self.assertEqual(json.loads(legacy), json.loads(recent))
        self.assertEqual(list(json.loads(legacy)), ['CODE_RESPONSE','CODE_GUARD_OS_RESULT',
            'CODE_APP_INFO','CG_SIGNATURE','CG_VALIDTO'])
        self.assertEqual(list(json.loads(recent)), ['CODE_APP_INFO','CODE_GUARD_OS_RESULT',
            'CODE_RESPONSE','CG_VALIDTO','CG_SIGNATURE'])
        self.assertIsNone(json.loads(legacy)['CODE_RESPONSE'])
        self.assertNotEqual(legacy, recent)

    def test_json_escaping_preserves_hash_unicode_and_null_vs_string_null(self):
        message = '/"\\\b\t\n\f\r\x00한글\u2028#'
        value = self.format('null', message, '#')
        self.assertEqual(json.loads(value)['CODE_APP_INFO'], 'null')
        self.assertEqual(json.loads(value)['CODE_RESPONSE'], message)
        self.assertIn('\\/', value)
        self.assertIn('\\u0000', value)
        self.assertIn('한글\u2028#', value)
        self.assertEqual(json.loads(value)['CG_SIGNATURE'], '#')

    def test_truncation_uses_two_hundred_utf16_units_and_keeps_split_surrogates(self):
        for size in (0, 199, 200, 201, 202, 1000):
            detail = 'A'*size
            fields = local_error_fields('code', 'message', detail, now_ms=0)
            self.assertEqual(fields['CG_SIGNATURE'], detail if size<=200 else 'A'*100+'--'+'A'*100)
        detail = 'A'*99+'😀'+'B'*200
        result = local_error_fields('code', 'message', detail, now_ms=0)['CG_SIGNATURE']
        self.assertEqual(result, 'A'*99+'\ud83d--'+'B'*100)

    def test_expiry_addition_wraps_signed_long_and_is_always_a_string(self):
        for now, expected in ((-1800000, '0'), (2**63-1, str(-2**63+1799999)),
                              (-2**63, str(-2**63+1800000))):
            self.assertEqual(json.loads(self.format(now_ms=now))['CG_VALIDTO'], expected)

    def test_unknown_values_remain_analysis_limits_without_disclosing_inputs(self):
        for value in (True, None, 2**63, -2**63-1, 1.5):
            with self.assertRaises(AnalysisLimit): self.format(now_ms=value)
        for profile in ('unknown', None):
            with self.assertRaises(AnalysisLimit): self.format(map_profile=profile)
        for code, message, detail in ((12, 'secret', 'detail'), ('code', False, 'detail'), ('code', 'message', None)):
            with self.assertRaises(AnalysisLimit) as error: self.format(code, message, detail)
            self.assertNotIn('secret', str(error.exception))

    def test_standard_jdk_order_long_and_utf16_values_match_selected_profile(self):
        java = shutil.which('java')
        if java is None: self.skipTest('JDK unavailable for development comparison')
        cases = [(0, ''), (2**63-1, 'A'*201), (-2**63, '한글'*200),
                 (11, 'A'*99+'😀'+'B'*200), (12, '😀'*99+'\ud800\udfff#')]
        def units(s): return s.encode('utf-16-be', 'surrogatepass').hex()
        result = subprocess.run([java, str(Path(__file__).parent/'java/LocalErrorValueVectors.java')],
            input=''.join(str(now)+' '+units(detail)+'\n' for now, detail in cases),
            capture_output=True, text=True, timeout=30, check=True)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], ','.join(json.loads(self.format())))
        self.assertEqual(len(lines), len(cases)+1)
        for (now, detail), actual in zip(cases, lines[1:]):
            fields = local_error_fields('code', 'message', detail, now_ms=now)
            self.assertEqual(actual, fields['CG_VALIDTO']+':'+units(fields['CG_SIGNATURE']))

    def test_null_detail_reads_clock_then_requires_actual_runtime_fault(self):
        events = []
        error = fault('NullPointerException', message='synthetic runtime text')
        def reply(e):
            events.append(e.kind)
            return 1 if e.kind == 'clock_ms' else error
        with self.assertRaises(type(error)) as caught:
            drive(local_error_steps('error', 'message', None, map_profile='aosp-8'), reply)
        self.assertIs(caught.exception, error)
        self.assertEqual(events, ['clock_ms', 'java_runtime_fault'])

    def test_clock_failure_and_python_limit_keep_the_callers_original_catch_scope(self):
        def body():
            try:
                return (yield Effect('format_local_error', ('code', 'message', 'detail')))
            except type(fault()):
                return 'caught-java-fault'
        self.assertEqual(drive(project_local_error_steps(body(), map_profile='aosp-8'), lambda _: fault()),
                         'caught-java-fault')
        with self.assertRaises(AnalysisLimit):
            drive(project_local_error_steps(body(), map_profile='aosp-8'), lambda _: None)

    def test_zip_and_fingerprint_error_json_reaches_cmd300_and_server_return_is_preserved(self):
        transcript = Transcript([(200, {'CODE_CHALLENGE':'c::r'}), (300, {'CODE_TOKEN':'synthetic-return'})],
            overrides={'check_zip_os14':False, 'check_fingerprint':False})
        result = transcript.run(project_local_error_steps(service(transcript), map_profile='aosp-8'))
        self.assertEqual(result, 'synthetic-return')
        form = parse_qs(transcript.writes[-1][1].decode())
        local = json.loads(form['CODE_RESPONSE'][0])
        self.assertEqual(local['CODE_RESPONSE'], 'FingerPrint error(synthetic fingerprint detail)')
        self.assertEqual(local['CODE_GUARD_OS_RESULT'], 'UNKNOWN')
        self.assertEqual(form['CODE_RESPONSE2'], ['SYNTHETIC-NONCE-OBSERVATION'])
        self.assertNotIn('format_local_error', transcript.kinds())
        self.assertEqual([r[0] for r in transcript.requests], [200, 300])

    def test_normal_token_path_has_no_error_formatter_or_extra_clock(self):
        def body():
            yield Effect('other')
            return 'synthetic-server-token'
        events = []
        result = drive(project_local_error_steps(body(), map_profile=None), lambda e: events.append(e.kind))
        self.assertEqual(result, 'synthetic-server-token')
        self.assertEqual(events, ['other'])

    def test_post_and_delivery_compute_separate_error_values_before_token_clear(self):
        obs = LifecycleObservations()
        task = obs.submit()
        task.state.status_code = 102
        project = lambda g: project_local_error_steps(g, map_profile='aosp-8')
        obs.run(project(task.finish_steps(True, cancelled=False)))
        handler, what, payload = obs.messages[0]
        obs.run(project(handler.message_steps(what, payload)))
        post, delivery = json.loads(payload), json.loads(obs.delivered[0][1])
        self.assertEqual(int(delivery['CG_VALIDTO']), int(post['CG_VALIDTO'])+1)
        self.assertEqual(post['CODE_APP_INFO'], 'CG_CONN_TIMEOUT01')
        self.assertIsNone(obs.guard.task)
        self.assertNotIn('format_local_error', obs.kinds())


if __name__ == '__main__': unittest.main()
