#!/usr/bin/env python3
"""Run certification presets and audit saved RP evidence (Python 3.10+, stdlib only)."""

import argparse
from collections import Counter
import json
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ACCEPTED = {"PASSED", "WARNING", "REVIEW", "SKIPPED"}


def load_presets(path):
    presets = json.loads(path.read_text())
    for name, preset in presets.items():
        if not isinstance(preset["variant"], dict):
            raise ValueError(f"{name}: variant must be an object")
        for key in ("plan", "test_binary", "test"):
            if not isinstance(preset[key], str) or not preset[key]:
                raise ValueError(f"{name}: missing {key}")
    return presets


def artifact(directory, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("missing or non-relative artifact path")
    path = (directory / relative).resolve()
    if not path.is_relative_to(directory.resolve()):
        raise ValueError("artifact escapes run directory")
    if not path.is_file():
        raise ValueError(f"missing artifact: {relative}")
    return path


def module_key(name, variant):
    return name, json.dumps(variant, sort_keys=True)


def object_value(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def object_list(value, label):
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    for entry in value:
        object_value(entry, f"{label} entry")
    return value


def duration(value, label):
    if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be a finite nonnegative number")


def report_shape(report):
    """Validate shapes shared by selection, auditing, and checklist rendering."""
    object_value(report, "report")
    run = object_value(report["run"], "run")
    for field in ("plan_name", "revision", "suite_base"):
        if not isinstance(run.get(field), str):
            raise ValueError(f"run.{field} must be a string")
    duration(run["started_at_unix_seconds"], "run start time")
    object_value(run["variant"], "run.variant")
    plan = object_value(run["plan"], "plan")
    for entry in object_list(plan["modules"], "plan.modules"):
        if not isinstance(entry.get("testModule"), str):
            raise ValueError("plan module name must be a string")
        if entry.get("variant") is not None:
            object_value(entry["variant"], "plan module variant")
    object_value(report["counts"], "counts")
    for module in object_list(report["modules"], "modules"):
        if not isinstance(module.get("name"), str):
            raise ValueError("module name must be a string")
        object_value(module["effective_variant"], "effective variant")
        response = module["effective_variant"].get("response_type")
        if response is not None and not isinstance(response, str):
            raise ValueError("response_type must be a string")
        if module.get("id") is not None and not isinstance(module["id"], str):
            raise ValueError("module ID must be a string")
        if module.get("suite") is not None:
            suite = object_value(module["suite"], "module suite")
            for field in ("status", "result"):
                if suite.get(field) is not None and not isinstance(suite[field], str):
                    raise ValueError(f"suite {field} must be a string")
        if module.get("conditions") is not None:
            conditions = object_value(module["conditions"], "conditions")
            counts = object_value(conditions["counts"], "condition counts")
            if any(type(v) is not int or v < 0 for v in counts.values()):
                raise ValueError("condition counts must be nonnegative integers")


def audit(path, report):
    """Recompute readiness from observations, rather than trusting summary counts."""
    errors, reviews = [], []
    try:
        report_shape(report)
        run = report["run"]
        modules = report["modules"]
        expected = run["plan"]["modules"]
        if run.get("schema_version") != 2:
            errors.append("unsupported evidence schema (expected 2)")
        if run.get("finished") is not True:
            errors.append("run is incomplete")
        if run.get("working_tree_dirty") is not False:
            errors.append("run does not attest to a clean working tree")
        if not expected or len(modules) != len(expected):
            errors.append("module evidence is incomplete")
        if report["expected_modules"] != len(expected) or report["recorded_modules"] != len(modules):
            errors.append("module counts disagree with evidence")
        planned = Counter(module_key(m["testModule"], run["variant"] | (m.get("variant") or {})) for m in expected)
        observed = Counter(module_key(m["name"], m["effective_variant"]) for m in modules)
        if planned != observed:
            errors.append("recorded tests/variants do not match the complete plan")
        counts, seen_logs, seen_ids = Counter(), set(), set()
        for module in modules:
            name = module["name"]
            suite = module.get("suite") or {}
            verdict = suite.get("result")
            counts[verdict] += 1
            if suite.get("status") != "FINISHED" or verdict not in ACCEPTED:
                errors.append(f"{name}: unacceptable suite status/result")
            if module.get("harness_error") or module.get("client_check") != {"Ok": None}:
                errors.append(f"{name}: harness failure or unsuccessful client check")
            identity = module.get("id")
            if not identity or identity in seen_ids or suite.get("_id") != identity:
                errors.append(f"{name}: missing, duplicate, or inconsistent module ID")
            seen_ids.add(identity)
            if run.get("incremental_suite_evidence"):
                try:
                    if module.get("suite_evidence_error"):
                        raise ValueError("suite evidence collection failed")
                    raw = json.loads(artifact(path.parent, module.get("suite_log")).read_text())
                    object_value(raw, "raw suite evidence")
                    info = object_value(raw["testInfo"], "testInfo")
                    entries = object_list(raw["results"], "suite results")
                    if info.get("_id") != identity or info.get("testName") != name:
                        raise ValueError("raw suite log identity disagrees with module")
                    if info.get("status") != suite.get("status") or info.get("result") != verdict:
                        raise ValueError("raw suite verdict disagrees with module")
                    raw_counts = Counter(entry["result"] for entry in entries
                                         if isinstance(entry.get("result"), str))
                    if dict(raw_counts) != module["conditions"]["counts"]:
                        raise ValueError("condition counts disagree with raw suite logs")
                    duration(module.get("elapsed_seconds"), "module duration")
                except (OSError, ValueError, KeyError, TypeError) as error:
                    errors.append(f"{name}: {error}")
            if verdict in {"WARNING", "REVIEW", "SKIPPED"}:
                reviews.append(f"{name}: {verdict} — inspect suite explanation and client evidence")
            try:
                log = artifact(path.parent, module.get("client_log"))
                if log in seen_logs:
                    raise ValueError("client log reused by multiple tests")
                seen_logs.add(log)
                if not log.name.startswith(name):
                    raise ValueError("client filename lacks test name prefix")
                response = module["effective_variant"].get("response_type")
                if response and f"_{response.replace(' ', '-')}" not in log.name:
                    raise ValueError("client filename lacks response type")
                # Writer prepends a short human-readable header to JSON observations.
                contents = log.read_text()
                payload = object_value(json.loads(contents[contents.index("{"):]), "client log")
                if payload["client_observations"] != module:
                    raise ValueError("client log observations disagree with report")
                for key in ("plan_name", "plan_url", "revision", "working_tree_dirty"):
                    if payload.get(key) != run.get(key):
                        raise ValueError(f"client log {key} disagrees with report")
                if payload.get("outcome") != verdict:
                    raise ValueError("client log outcome disagrees with report")
            except (OSError, ValueError, KeyError, TypeError) as error:
                errors.append(f"{name}: {error}")
        if dict(counts) != report["counts"] or report.get("client_check_failures") != 0:
            errors.append("summary counts disagree or client checks failed")
        if run.get("export_error"):
            errors.append("suite export failed")
        try:
            export = artifact(path.parent, run.get("export"))
            with zipfile.ZipFile(export) as archive:
                if not archive.namelist() or archive.testzip() is not None:
                    errors.append("suite export is empty or corrupt")
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
            errors.append(f"suite export: {error}")
        if run.get("insecure_tls") is not False:
            reviews.append("TLS verification was disabled; this is local/development evidence")
        if not run.get("plan_url"):
            errors.append("missing suite plan URL")
    except (KeyError, TypeError, ValueError) as error:
        errors.append(f"malformed report: {error}")
    return errors, reviews


def select(reports, preset, revision, suite_base):
    matches = [(path, report) for path, report in reports
               if report["run"].get("plan_name") == preset["plan"]
               and report["run"].get("variant") == preset["variant"]
               and report["run"].get("revision") == revision
               and report["run"].get("suite_base", "").rstrip("/") == suite_base.rstrip("/")]
    completed = [(p, r) for p, r in matches if r["run"].get("finished") is True]
    if not completed:
        return None, len(matches)
    # Never hide a failed completed run by silently falling back to an older pass.
    chosen = max(completed, key=lambda pair: (pair[1]["run"]["started_at_unix_seconds"], str(pair[0])))
    newer = sum(r["run"]["started_at_unix_seconds"] > chosen[1]["run"]["started_at_unix_seconds"]
                for _, r in matches if not r["run"].get("finished"))
    return chosen, newer


def link(path):
    return f"[{path.name}]({path.resolve().as_uri()})"


def readiness(args, presets):
    reports, scan_errors = [], []
    for path in sorted(args.evidence_dir.glob("*/report.json")):
        try:
            report = json.loads(path.read_text())
            report_shape(report)
            reports.append((path, report))
        except (OSError, ValueError, KeyError, TypeError) as error:
            scan_errors.append(f"{path}: {error}")
    lines = ["# Certification evidence readiness", "", f"Revision: `{args.revision}`",
             f"Suite: {args.suite_base}", "",
             "This checks recorded evidence. It does not publish results or establish certification approval.", ""]
    blocked = bool(scan_errors)
    for name in args.preset:
        lines.extend([f"## {name}", "", f"Variant: `{json.dumps(presets[name]['variant'], sort_keys=True)}`", ""])
        chosen, incomplete = select(reports, presets[name], args.revision, args.suite_base)
        if chosen is None:
            blocked = True
            lines.extend([f"BLOCKED: no completed matching run ({incomplete} incomplete matching runs).", ""])
            continue
        path, report = chosen
        errors, reviews = audit(path, report)
        blocked |= bool(errors)
        run = report["run"]
        lines.extend(["BLOCKED" if errors else "Evidence checks passed; manual review and publishing remain.", "",
                      f"- Report: {link(path)}",
                      f"- Suite plan: {run.get('plan_url', '(missing)')}",
                      f"- RP upload directory: {link(path.parent / 'client-logs')}",
                      f"- Suite outcomes: `{json.dumps(report.get('counts', {}), sort_keys=True)}`"])
        if run.get("incremental_suite_evidence"):
            lines.append(f"- Raw suite logs: {link(path.parent / 'suite-logs')}")
            lines.append(f"- Run duration: {run.get('elapsed_seconds', '(incomplete)')} seconds")
            totals = Counter()
            for module in report.get("modules", []):
                totals.update((module.get("conditions") or {}).get("counts", {}))
            lines.append(f"- Suite condition outcomes: `{json.dumps(dict(totals), sort_keys=True)}`")
        if run.get("export") == "suite-export.zip":
            lines.append(f"- Ordinary export (not a certification ZIP): {link(path.parent / 'suite-export.zip')}")
        if incomplete:
            reviews.append(f"{incomplete} newer incomplete run(s) exist; this index selects the latest completed run")
        lines.extend(f"- BLOCKER: {error}" for error in errors)
        lines.extend(f"- REVIEW: {review}" for review in reviews)
        lines.extend(["", "- [ ] Inspect client evidence and resolve the review items above.",
                      "- [ ] Publish this plan for certification and upload its per-test client logs.",
                      "- [ ] Retain the ZIP returned by publishing for the submission.", ""])
    if scan_errors:
        lines.extend(["## Unreadable evidence", "", *[f"- BLOCKER: {e}" for e in scan_errors], ""])
    lines.extend(["Status: BLOCKED" if blocked else "Status: evidence checks passed; manual review/publishing pending.", ""])
    output = "\n".join(lines)
    if args.output:
        args.output.write_text(output)
        print(f"Wrote {args.output}")
    else:
        print(output)
    return int(blocked)


def cargo_command(preset, listing=False):
    return ["cargo", "test", "-p", "huskarl-conformance", "--features", "conformance-suite-tests",
            "--test", preset["test_binary"], preset["test"], "--", "--exact",
            "--list" if listing else "--nocapture"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--presets-file", type=Path, default=ROOT / "certification-presets.json")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="show named configurations and exact tests")
    for command in ("run", "ready"):
        child = sub.add_parser(command)
        child.add_argument("--preset", action="append", required=True, help="repeat to select multiple presets")
        child.add_argument("--suite-base", required=True, help="exact suite URL, e.g. https://www.certification.openid.net")
        child.add_argument("--evidence-dir", type=Path,
                           default=Path(os.environ.get("CONFORMANCE_EVIDENCE_DIR", ROOT.parent.parent / "target/conformance")))
        if command == "ready":
            child.add_argument("--revision", required=True, help="full revision recorded by the runner")
            child.add_argument("--output", type=Path, help="write a Markdown index; default stdout")
        else:
            child.add_argument("--insecure-tls", action="store_true", help="explicit opt-in for local self-signed TLS")
            child.add_argument("--dry-run", action="store_true", help="print commands without building or running")
    args = parser.parse_args(argv)
    presets = load_presets(args.presets_file)
    if args.command == "list":
        for name, preset in presets.items():
            print(f"{name}: {preset['description']}\n  {preset['test_binary']}::{preset['test']}\n  {json.dumps(preset['variant'], sort_keys=True)}")
        return 0
    args.preset = list(dict.fromkeys(args.preset))
    for name in args.preset:
        if name not in presets:
            parser.error(f"unknown preset: {name}; use list")
    args.evidence_dir = args.evidence_dir.resolve()
    if args.command == "ready":
        return readiness(args, presets)
    env = dict(os.environ, CONFORMANCE_SUITE_BASE=args.suite_base,
               CONFORMANCE_INSECURE_TLS=str(args.insecure_tls).lower(),
               CONFORMANCE_EVIDENCE_DIR=str(args.evidence_dir))
    for name in args.preset:
        preset = presets[name]
        command = cargo_command(preset)
        print(f"{name}: {shlex.join(command)}", flush=True)
        if args.dry_run:
            continue
        # Cargo exits successfully for a misspelled filter with zero tests.
        listing = subprocess.run(cargo_command(preset, listing=True), cwd=ROOT, env=env,
                                 check=True, capture_output=True, text=True)
        if f"{preset['test']}: test" not in listing.stdout.splitlines():
            raise ValueError(f"{name}: exact test was not found; refusing an empty run")
        subprocess.run(command, cwd=ROOT, env=env, check=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"certification: {error}", file=sys.stderr)
        sys.exit(1)
