"""Readiness must fail closed when a submission's evidence is incomplete or inconsistent."""

import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import certification as cert


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / "report.json"
        self.module = {
            "name": "negative-test", "id": "module", "effective_variant": {"response_type": "code id_token"},
            "client_log": "client-logs/negative-test_code-id_token-1.log",
            "authorization": {"Err": {"message": "invalid issuer", "rejection": {"IdToken": {"ClaimMismatch": "iss"}}}},
            "client_check": {"Ok": None}, "harness_error": None,
            "suite": {"_id": "module", "status": "FINISHED", "result": "PASSED"},
        }
        self.report = {
            "run": {"schema_version": 2, "finished": True, "working_tree_dirty": False,
                    "plan_name": "plan", "plan_url": "https://suite.example/plan",
                    "revision": "revision", "suite_base": "https://suite.example", "started_at_unix_seconds": 1,
                    "variant": {}, "insecure_tls": False, "export": "suite-export.zip",
                    "plan": {"modules": [{"testModule": "negative-test", "variant": {"response_type": "code id_token"}}]}},
            "modules": [self.module], "counts": {"PASSED": 1},
            "expected_modules": 1, "recorded_modules": 1, "client_check_failures": 0,
        }
        with zipfile.ZipFile(self.directory / "suite-export.zip", "w") as archive:
            archive.writestr("suite.json", "{}")
        self.write_log()

    def write_log(self):
        run = self.report["run"]
        payload = {k: run[k] for k in ("plan_name", "plan_url", "revision", "working_tree_dirty")}
        payload.update(client_observations=self.module, outcome=self.module["suite"]["result"])
        log = self.directory / self.module["client_log"]
        log.parent.mkdir(exist_ok=True)
        log.write_text("Huskarl RP client evidence\n\n" + json.dumps(payload))

    def test_complete_negative_evidence_and_hybrid_filename(self):
        self.assertEqual(cert.audit(self.path, self.report), ([], []))

    def test_incremental_suite_artifacts_are_required_and_checked(self):
        self.report["run"]["incremental_suite_evidence"] = True
        self.module.update(suite_log="suite-logs/module-1.json", elapsed_seconds=1.5,
                           conditions={"counts": {"SUCCESS": 1}}, suite_evidence_error=None)
        raw = {"testInfo": dict(self.module["suite"], testName=self.module["name"]),
               "results": [{"result": "SUCCESS"}]}
        path = self.directory / self.module["suite_log"]
        path.parent.mkdir()
        path.write_text(json.dumps(raw))
        self.write_log()
        self.assertEqual(cert.audit(self.path, self.report), ([], []))
        for key, value in (("suite_evidence_error", "failed download"),
                           ("elapsed_seconds", -1), ("conditions", {"counts": {}})):
            original = self.module[key]
            self.module[key] = value
            self.write_log()
            self.assertTrue(cert.audit(self.path, self.report)[0])
            self.module[key] = original
        self.write_log()
        raw["testInfo"]["_id"] = "other-module"
        path.write_text(json.dumps(raw))
        self.assertTrue(cert.audit(self.path, self.report)[0])
        path.unlink()
        self.assertTrue(cert.audit(self.path, self.report)[0])

    def test_malformed_raw_evidence_reports_blockers(self):
        self.report["run"]["incremental_suite_evidence"] = True
        self.module.update(suite_log="raw.json", elapsed_seconds=1,
                           conditions={"counts": {}})
        self.write_log()
        info = dict(self.module["suite"], testName=self.module["name"])
        for raw in ([], None, {"testInfo": [], "results": []},
                    {"testInfo": info, "results": {}},
                    {"testInfo": info, "results": [None]}):
            with self.subTest(raw=raw):
                (self.directory / "raw.json").write_text(json.dumps(raw))
                self.assertTrue(cert.audit(self.path, self.report)[0])

    def test_malformed_report_shapes_do_not_crash_audit_or_readiness(self):
        for field, value in (("modules", [None]), ("modules", {}), ("counts", []),
                             ("run", {"suite_base": []})):
            report = copy.deepcopy(self.report)
            report[field] = value
            with self.subTest(field=field, value=value):
                self.assertTrue(cert.audit(self.path, report)[0])
                run_dir = self.directory / "run"
                run_dir.mkdir(exist_ok=True)
                (run_dir / "report.json").write_text(json.dumps(report))
                with redirect_stdout(io.StringIO()) as output:
                    status = cert.main(["ready", "--preset", "oidc-basic", "--revision", "revision",
                                        "--suite-base", "https://suite.example", "--evidence-dir", str(self.directory)])
                self.assertEqual(status, 1)
                self.assertIn("Unreadable evidence", output.getvalue())

    def test_acceptable_nonpass_requires_review(self):
        for verdict in ("SKIPPED", "WARNING", "REVIEW"):
            with self.subTest(verdict=verdict):
                self.module["suite"]["result"] = verdict
                self.report["counts"] = {verdict: 1}
                self.write_log()
                errors, reviews = cert.audit(self.path, self.report)
                self.assertEqual(errors, [])
                self.assertTrue(any(verdict in item for item in reviews))

    def test_suite_pass_cannot_hide_failed_client_check(self):
        self.module["client_check"] = {"Err": "wrong rejection reason"}
        self.write_log()
        errors, _ = cert.audit(self.path, self.report)
        self.assertTrue(any("client check" in item for item in errors))

    def test_duplicate_observation_cannot_replace_missing_test(self):
        self.report["run"]["plan"]["modules"].append({"testModule": "other-test"})
        self.report["modules"].append(copy.deepcopy(self.module))
        self.report.update(expected_modules=2, recorded_modules=2, counts={"PASSED": 2})
        errors, _ = cert.audit(self.path, self.report)
        self.assertTrue(any("complete plan" in item for item in errors))
        self.assertTrue(any("reused" in item for item in errors))

    def test_missing_or_stale_logs_and_invalid_export_block(self):
        log = self.directory / self.module["client_log"]
        log.unlink()
        self.assertTrue(cert.audit(self.path, self.report)[0])
        self.write_log()
        self.module["authorization"] = {"Ok": None}
        self.assertTrue(any("disagree" in e for e in cert.audit(self.path, self.report)[0]))
        self.write_log()
        (self.directory / "suite-export.zip").write_text("not a ZIP")
        self.assertTrue(any("suite export" in e for e in cert.audit(self.path, self.report)[0]))

    def test_artifact_path_cannot_escape_run(self):
        self.module["client_log"] = "../outside.log"
        self.assertTrue(any("escapes" in e for e in cert.audit(self.path, self.report)[0]))

    def test_dirty_or_unfinished_runs_block(self):
        for field, value in (("working_tree_dirty", True), ("finished", False)):
            report = copy.deepcopy(self.report)
            report["run"][field] = value
            self.assertTrue(cert.audit(self.path, report)[0])

    def test_selection_is_exact_and_never_falls_back_from_failure(self):
        preset = {"plan": "plan", "variant": {}}
        failed = copy.deepcopy(self.report)
        failed["run"]["started_at_unix_seconds"] = 2
        failed["modules"][0]["client_check"] = {"Err": "failed"}
        partial = copy.deepcopy(self.report)
        partial["run"].update(finished=False, started_at_unix_seconds=3)
        reports = [(self.path, self.report), (Path("failed.json"), failed), (Path("partial.json"), partial)]
        chosen, newer = cert.select(reports, preset, "revision", "https://suite.example/")
        self.assertIs(chosen[1], failed)
        self.assertEqual(newer, 1)
        for revision, suite, variant in [("other", "https://suite.example", {}),
                                          ("revision", "https://other.example", {}),
                                          ("revision", "https://suite.example", {"auth": "other"})]:
            self.assertIsNone(cert.select(reports, {"plan": "plan", "variant": variant}, revision, suite)[0])

    def test_cli_writes_blocked_index_when_no_matching_run_exists(self):
        output = self.directory / "index.md"
        with redirect_stdout(io.StringIO()):
            status = cert.main(["ready", "--preset", "oidc-basic", "--revision", "missing",
                                "--suite-base", "https://suite.example", "--evidence-dir", str(self.directory),
                                "--output", str(output)])
        self.assertEqual(status, 1)
        self.assertIn("no completed matching run", output.read_text())
        self.assertIn("Status: BLOCKED", output.read_text())

    def test_runner_refuses_empty_cargo_filter(self):
        with patch.object(cert.subprocess, "run") as run, redirect_stdout(io.StringIO()):
            run.return_value.stdout = "0 tests, 0 benchmarks\n"
            with self.assertRaisesRegex(ValueError, "exact test was not found"):
                cert.main(["run", "--preset", "oidc-basic", "--suite-base", "https://suite.example"])
            self.assertEqual(run.call_count, 1)

    def test_runner_uses_exact_test_and_explicit_tls_setting(self):
        test = "oidcc_client_basic_certification_test_plan_basic"
        with patch.object(cert.subprocess, "run") as run, redirect_stdout(io.StringIO()):
            run.return_value.stdout = f"{test}: test\n\n1 test, 0 benchmarks\n"
            with patch.dict(cert.os.environ, {"CONFORMANCE_INSECURE_TLS": "true"}):
                status = cert.main(["run", "--preset", "oidc-basic", "--suite-base", "https://suite.example"])
            self.assertEqual(status, 0)
            self.assertEqual(run.call_count, 2)
            call = run.call_args
            self.assertEqual(call.args[0][-4:], [test, "--", "--exact", "--nocapture"])
            self.assertEqual(call.kwargs["env"]["CONFORMANCE_INSECURE_TLS"], "false")


if __name__ == "__main__":
    unittest.main()
