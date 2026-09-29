"""Synthetic response handling cases."""

import contextlib
import io
import json
import unittest

from hometax_cli import auth
from hometax_cli.__main__ import main


class ResponseBranches(unittest.TestCase):
    def test_certificate_registration_read_order_and_nonstandard_results(self):
        cases = [
            ({"RESULT": {"msg": "ok", "result": "S", "code": "unexpected"}}, "success"),
            ({"RESULT": {"msg": "ok", "result": "s"}}, "success"),
            ({"RESULT": {"result": "S", "code": "0"}}, "failure"),
            ({"RESULT": {"msg": None, "result": "S"}}, "success"),
            ({"RESULT": {"msg": 123, "result": "S", "code": None}}, "success"),
            ({"RESULT": {"msg": "pending", "result": "P", "code": "0"}}, "no_action"),
            ({"RESULT": {"msg": "ok", "result": True}}, "no_action"),
            ({"RESULT": {"msg": "ok", "result": None}}, "no_action"),
            ({"RESULT": {"msg": "ok", "result": {"status": "S"}}}, "no_action"),
            ({"RESULT": {"msg": "bad", "result": "f"}}, "failure"),
            ({"result": {"msg": "ok", "result": "S"}}, "failure"),
        ]
        for response, expected in cases:
            with self.subTest(response=response):
                self.assertEqual(auth.certificate_registration(response).branch, expected)

    def test_missing_code_warns_but_preserves_success(self):
        decision = auth.certificate_registration({"RESULT": {"msg": "ok", "result": "S"}})
        self.assertEqual(decision.branch, "success")
        self.assertEqual(decision.native["result"], "S")
        self.assertEqual(len(decision.warnings), 1)

    def test_logout_other_domains_cannot_override_primary(self):
        success = {"resultMsg": {"code": "S"}}
        failure = {"resultMsg": {"code": "F"}}
        decision = auth.logout([success, failure, {}, None, failure, failure])
        self.assertEqual(decision.branch, "success")
        self.assertTrue(decision.native["clear_cookies"])
        self.assertEqual(len(decision.warnings), 5)
        for primary in [failure, {"resultMsg": {"code": "s"}}, {}, None]:
            with self.subTest(primary=primary):
                self.assertEqual(auth.logout([primary] + [success] * 5).branch, "no_action")

    def test_qr_requires_both_exact_sentinels(self):
        for state, verified, expected in [("S", "Y", "success"), ("s", "Y", "failure"),
                                          ("S", "y", "failure"), ("S", True, "failure")]:
            self.assertEqual(auth.qr_confirmation({"transactionState": state,
                                                   "lbdyVrfYn": verified}).branch, expected)
        self.assertEqual(auth.qr_confirmation({"transactionState": "S"}).branch, "failure")

    def test_fido_token_absence_does_not_override_sdk_success(self):
        for token in [None, "", "synthetic-token"]:
            original = {"action": "FIDO_AUTH", "extra": {"keep": True}, "token": "old"}
            decision = auth.fido_auth_callback(original, 178, 0, "done", token)
            self.assertEqual(decision.branch, "success")
            self.assertIs(decision.native["result"], True)
            self.assertEqual(decision.native["extra"], {"keep": True})
            self.assertEqual(original["token"], "old")
            if token is None:
                self.assertNotIn("token", decision.native)
            else:
                self.assertEqual(decision.native["token"], token)

    def test_fido_failure_keeps_prior_token_and_null_removes_message(self):
        decision = auth.fido_auth_callback({"token": "synthetic-old", "message": "old"},
                                           178, 1009, None, "unused")
        self.assertEqual(decision.branch, "failure")
        self.assertFalse(decision.native["result"])
        self.assertEqual(decision.native["token"], "synthetic-old")
        self.assertNotIn("message", decision.native)
        self.assertEqual(auth.fido_auth_callback({}, 177, 0, "ok", "x").branch, "no_action")


class EncodingContracts(unittest.TestCase):
    def test_double_encoded_plus_and_base64_alphabet(self):
        output = auth.certificate_callback("+/8=", "A+B/C==")
        self.assertEqual(output["payload"]["signData"], "%252B%2F8%3D")
        self.assertEqual(output["payload"]["randomEnc"], "A%252BB%2FC%3D%3D")
        self.assertEqual(output["javascript"],
                         "javascript:nts_calledByNative({'certResult':'SUCC', "
                         "'signData':'%252B%2F8%3D', 'randomEnc':'A%252BB%2FC%3D%3D'})")

    def test_encoding_preserves_empty_or_unexpected_sdk_text(self):
        self.assertEqual(auth.certificate_callback("", "")["payload"]["signData"], "")
        self.assertEqual(auth.java_form_encode(" ~*_-.한글\n"), "+%7E*_-.%ED%95%9C%EA%B8%80%0A")

    def test_auth_context_case_and_null_policy(self):
        context = auth.fido_context("synthetic", "test device", "16")
        self.assertEqual(context, {"userName": "", "deviceModel": "test device",
                                   "deviceOS": "A|16", "authcode": "synthetic"})
        self.assertNotIn("authCode", context)
        self.assertNotIn("policyId", context)
        self.assertEqual(auth.fido_context("", "", "", "")["policyId"], "")


class CommandInterface(unittest.TestCase):
    def test_warning_is_stderr_and_exit_zero(self):
        output, logs = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(logs):
            from unittest.mock import patch
            with patch("sys.stdin", io.StringIO('{"RESULT":{"msg":"ok","result":"S"}}')):
                status = main(["auth", "replay", "cert-register"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["branch"], "success")
        self.assertIn("경고:", logs.getvalue())

    def test_neutral_branch_is_not_a_failed_process(self):
        from unittest.mock import patch
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with patch("sys.stdin", io.StringIO('{"RESULT":{"msg":"pending","result":"P"}}')):
                self.assertEqual(main(["auth", "replay", "cert-register"]), 0)

    def test_local_input_error_does_not_expose_input(self):
        from unittest.mock import patch
        output, logs = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(logs):
            with patch("sys.stdin", io.StringIO('synthetic-secret-not-json')):
                self.assertEqual(main(["auth", "replay", "cert-register"]), 2)
        self.assertNotIn("synthetic-secret", logs.getvalue())


if __name__ == "__main__":
    unittest.main()
