import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from finance_cli.credentials.registry import Registry
from hometax_cli import web_auth
from hometax_cli.__main__ import main
from test_certificate import synthetic_material, encrypt_test_key


class WebContracts(unittest.TestCase):
    def test_response_matches_javascript_including_coercion_and_exceptions(self):
        codes = ["S", "s", "F", "", None, 0, 1, True, False, ["S"], [["S"]], [],
                 {}, ["S", None], ["S", ""], {"toString": "S"}]
        responses = [{"result": {"resultMsg": {"code": code}}} for code in codes]
        responses += [None, {}, {"result": None}, {"result": {}},
                      {"result": {"resultMsg": {}}}, {"result": {"resultMsg": 7}},
                      {"result": {"resultMsg": None}}, {"result": []}]
        reference = subprocess.run(["node", "-e", """
let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{
 console.log(JSON.stringify(JSON.parse(s).map(data=>{
  try {return data.result.resultMsg.code != 'S' ? 'failure' : 'success';}
  catch (_) {return 'no_action';}
 })));
});
"""], input=json.dumps(responses), text=True, capture_output=True, check=True)
        self.assertEqual([web_auth.certificate_login(r).branch for r in responses],
                         json.loads(reference.stdout))

    def test_logical_body_matches_browser_encoding(self):
        request = web_auth.certificate_request("+/8=", "a+b/c==")
        self.assertEqual(request["params"]["signData"], "%2B/8=")
        reference = subprocess.run(["node", "-e", """
let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{
 console.log('datas='+encodeURIComponent(JSON.stringify(JSON.parse(s)))+'&m=');
});
"""], input=json.dumps(request["params"]), text=True, capture_output=True, check=True)
        self.assertEqual(request["body"], reference.stdout.strip())
        self.assertNotIn("dprtLoginYn", request["params"])
        self.assertEqual(web_auth.certificate_request("", "", department_id="")["params"]["dprtLoginYn"], "Y")

    def test_missing_followup_fields_do_not_cancel_success(self):
        decision = web_auth.certificate_login({"result": {"resultMsg": {"code": "S"}}})
        self.assertEqual(decision.branch, "success")
        self.assertTrue(decision.warnings)

    def import_credential(self, root, password=b"offline password"):
        cert, key, _ = synthetic_material()
        environment = patch.dict(os.environ, {"FINANCE_HOME": str(root / "state")})
        environment.start()
        self.addCleanup(environment.stop)
        Registry().import_npki("personal", cert, encrypt_test_key(key, password), password,
                               compatibility="hometax")

    def test_certificate_commands_accept_only_the_shared_credential(self):
        for operation in ("prepare-cert", "login-cert"):
            for removed in (["--cert", "cert.der", "--key", "key.der"], ["--pfx", "cert.pfx"], ["--pfx-index", "0"]):
                with self.subTest(operation=operation, removed=removed[0]), \
                     contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    main(["auth", operation, "--credential", "personal", *removed, "--output", "out.json"])
                self.assertEqual(raised.exception.code, 2)
            with self.subTest(operation=operation, removed="credential"), \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                main(["auth", operation, "--output", "out.json"])
            self.assertEqual(raised.exception.code, 2)
        for removed in (["--pfx", "cert.pfx"], ["--pfx-index", "0"]):
            with self.subTest(operation="invoice issue", removed=removed[0]), \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                main(["invoice", "issue", "--prepared", "prepared.json", "--output", "out.json",
                      "--credential", "personal", *removed])
            self.assertEqual(raised.exception.code, 2)

    def test_prepare_cli_writes_private_artifact_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.import_credential(root)
            args = ["auth", "prepare-cert", "--credential", "personal", "--output", str(root / "result.json")]
            out = io.StringIO()
            with patch("getpass.getpass", return_value="offline password"), \
                 patch("socket.socket", side_effect=AssertionError("No networking allowed")), \
                 contextlib.redirect_stdout(out):
                self.assertEqual(main(args), 0)
            self.assertEqual(json.loads(out.getvalue())["network_requests"], 0)
            self.assertEqual(stat.S_IMODE((root / "result.json").stat().st_mode), 0o600)
            artifact = json.loads((root / "result.json").read_text())
            self.assertEqual(artifact["logical_request"]["params"]["pkcLoginYn"], "Y")
            self.assertNotIn("offline password", (root / "result.json").read_text())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 2)  # No overwrite/no new password prompt.

    def test_login_defaults_to_node_http_and_keeps_explicit_cdp_option(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.import_credential(root)
            base = ["auth", "login-cert", "--credential", "personal", "--output", str(root / "session.json")]
            for options, adapter in (([], "browserless.mjs"),
                                     (["--cdp", "http://127.0.0.1:9222"], "browser.mjs")):
                with patch("getpass.getpass", return_value="offline password"), \
                     patch("hometax_cli.__main__.subprocess.run") as run:
                    run.return_value.returncode = 3
                    self.assertEqual(main(base + options), 3)
                    self.assertEqual(Path(run.call_args.args[0][-1]).name, adapter)
                    if not options:
                        self.assertEqual(run.call_args.args[0][1], "--require")
                        self.assertEqual(Path(run.call_args.args[0][2]).name, "jsdom_compat.cjs")
                    config = json.loads(run.call_args.kwargs["input"])
                    self.assertEqual(config["callback"]["payload"]["certResult"], "SUCC")
                    self.assertNotIn("offline password", run.call_args.kwargs["input"])
                    self.assertNotIn("signData", " ".join(run.call_args.args[0]))


if __name__ == "__main__":
    unittest.main()
