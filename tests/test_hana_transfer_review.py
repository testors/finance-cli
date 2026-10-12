"""Offline source-reference branches and no-send CLI contract."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch
from finance_cli.cli.main import main
from finance_cli.services.hana import transfer_review as review, onesign_cli


class TransferReviewTests(unittest.TestCase):
    def test_age_boundaries_and_missing_follow_javascript_number(self):
        for age, ids in [(None,'123'), ('','123'), ('29','123'), (30,'425'),
                         (39.99,'425'), (40,'243'), (59.99,'243'), (60,'467'), ('invalid','')]:
            with self.subTest(age=age):
                rows = review.questions(age)
                self.assertEqual(''.join(q['id'] for q in rows),ids)
                self.assertFalse(review.answers_complete(rows,{}))
                answers = {q['id']:q['continue_on'] for q in rows}
                self.assertEqual(review.answers_complete(rows,answers),bool(rows))
                if rows:
                    answers[rows[0]['id']] = 'yes' if answers[rows[0]['id']]=='no' else 'no'
                    self.assertFalse(review.answers_complete(rows,answers))

    def test_continue_without_send_never_opens_store_or_prompts(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as home, patch.dict(os.environ, {'FINANCE_HOME':home}), \
             patch.object(onesign_cli,'State',side_effect=AssertionError('store opened')), \
             patch.object(onesign_cli,'hidden',side_effect=AssertionError('prompted')),redirect_stdout(output):
            self.assertEqual(main(['--format','json-v1','hana','transfer','continue','--name','synthetic']),0)
        result = json.loads(output.getvalue())['result']
        self.assertEqual(result['operation'],'transfer-continue')
        self.assertFalse(result['network_used'])
