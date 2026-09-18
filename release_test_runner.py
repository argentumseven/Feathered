"""Reconcile the complete pytest corpus with structured subprocess outcomes.

Batching limits cross-test state. It never turns an unexecuted test into a pass.
The parent requires normal process exit AND complete, matching phase evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
from typing import Any
import uuid

BATCH_SIZE = 20
WINDOWS_ISOLATED_PREFIXES = (
    "tests/test_application_startup.py::",
    "tests/test_build_spec.py::",
    "tests/test_build_worker_isolation.py::",
    "tests/test_end_to_end_build.py::",
    "tests/test_k8s_knowledge.py::",
    "tests/test_prepared_adapter_parity.py::",
    "tests/test_reported_defects.py::",
    "tests/test_review_dialog_lock.py::",
    "tests/test_signing_navigation.py::",
    "tests/test_ui_event_budget.py::",
    "tests/test_version_ui_fixes.py::",
    "tests/test_workload_dependency_and_vks_context.py::",
)
REPORT_PLUGIN = "release_pytest_exit"
DEFAULT_TIMEOUT = 300.0

# Only these Windows capability gaps may skip. Every one must execute in the
# required Debian full-corpus job; production publication needs both jobs.
# Match file AND exact reason so unrelated skips cannot inherit an exemption.
WINDOWS_SKIPS: dict[str, set[str]] = {
    "test_feather.py": {
        "GnuPG signing and verification tools are unavailable on this host"},
    "tests/test_linux_installation.py": {"Linux setup requires a Linux host"},
    "tests/test_end_to_end_build.py": {
        "dpkg-deb and dpkg-scanpackages are needed to build the repository fixture"},
    **{f"tests/{name}.py": {"requires dpkg fixture tools"} for name in (
        "test_headless_execution", "test_build_preparation", "test_cli_replay",
        "test_prepared_adapter_parity")},
    "tests/test_build_worker_isolation.py": {"needs dpkg tooling to build the repository fixture"},
    "tests/test_kubernetes_workflows.py": {"native dpkg fixture tools required; enforced in Debian CI"},
    "tests/test_installer_paths.py": {"bash is required"},
    "tests/test_integration_gate.py": {"bash is required to parse Linux workflow steps"},
    "tests/test_source_manifest.py": {"this platform does not permit symlink creation"},
    "tests/test_security_review_fixes.py": {
        "POSIX ownership and mode checks are not available",
        "POSIX ownership checks are not available",
    },
}


class GateFailure(RuntimeError):
    """Evidence is missing, inconsistent, or does not meet release policy."""


class GateTimeout(GateFailure):
    """A collection or batch process exceeded its deadline and was stopped."""


def _env() -> dict[str, str]:
    return dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")


def _pytest_command(*args: str) -> list[str]:
    command = [sys.executable, "-m", "pytest", "-p", REPORT_PLUGIN, *args]
    if os.name != "nt" and os.environ.get("FEATHERED_USE_XVFB") == "1":
        if not shutil.which("xvfb-run"):
            raise GateFailure("FEATHERED_USE_XVFB=1 but xvfb-run is unavailable")
        return ["xvfb-run", "-a", *command]
    return command


def _batch_plan(nodes: list[str], system: str) -> list[list[str]]:
    """Build release batches while isolating Windows Tk roots by process."""
    if system != "win32":
        return [nodes[start:start + BATCH_SIZE] for start in range(0, len(nodes), BATCH_SIZE)]

    batches: list[list[str]] = []
    pending: list[str] = []

    def flush() -> None:
        if pending:
            batches.append(pending.copy())
            pending.clear()

    for node in nodes:
        if node.startswith(WINDOWS_ISOLATED_PREFIXES):
            flush()
            batches.append([node])
            continue
        pending.append(node)
        if len(pending) == BATCH_SIZE:
            flush()
    flush()
    return batches


def _write(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _process(command: list[str], log: Path, timeout: float) -> int:
    # A file rather than PIPE keeps diagnostics available after a timeout/crash
    # and avoids buffering an unbounded traceback or long parameter ID in RAM.
    with log.open("w", encoding="utf-8") as stream:
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                   text=True, env=_env(), start_new_session=(os.name != "nt"))
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            # Kill the entire child tree, including an optional xvfb-run wrapper
            # and any subprocess a fixture started. Do not abandon a live batch.
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdout=stream, stderr=subprocess.STDOUT, timeout=15)
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.kill()
            process.wait(timeout=15)
            raise GateTimeout(f"Subprocess timeout after {timeout:g}s; diagnostics: {log}") from exc


def _record(path: Path, run_id: str, code: int, mode: str) -> dict[str, Any]:
    try:
        if path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("oversized outcome record")
        data = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(data, dict) or type(data.get("schema")) is not int
                or data["schema"] != 1 or data.get("run_id") != run_id):
            raise ValueError("wrong schema or stale invocation identity")
        if (data.get("complete") is not True or type(data.get("exit_code")) is not int
                or data["exit_code"] != code):
            raise ValueError("incomplete record or subprocess status mismatch")
        if data.get("mode") != mode:
            raise ValueError("wrong evidence mode")
        if not isinstance(data.get("pytest_version"), str):
            raise ValueError("missing pytest version")
        for key in ("nodes", "collection_issues", "deselected", "phases", "errors"):
            if not isinstance(data.get(key), list):
                raise ValueError(f"missing/invalid {key}")
        nodes = data["nodes"]
        if not all(isinstance(node, str) for node in nodes) or len(set(nodes)) != len(nodes):
            raise ValueError("invalid/duplicate test IDs")
        if type(data.get("testscollected")) is not int or data["testscollected"] != len(nodes):
            raise ValueError("collected count does not match IDs")
        return data
    except (OSError, ValueError, TypeError) as exc:
        raise GateFailure(f"Invalid subprocess evidence {path}: {exc} (status {code})") from exc


def _collection_contract(record: dict[str, Any]) -> None:
    if record["collection_issues"] or record["deselected"] or record["errors"]:
        raise GateFailure("Collection errors, skips, deselections or request mismatches; see structured report")


def reconcile(record: dict[str, Any], requested: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    """Check exact IDs and complete phase sequences, independently of pytest's code."""
    _collection_contract(record)
    if set(record["nodes"]) != set(requested) or len(record["nodes"]) != len(requested):
        raise GateFailure("Requested and collected batch IDs differ")
    grouped: dict[str, list[dict[str, Any]]] = {node: [] for node in requested}
    for phase in record["phases"]:
        if (not isinstance(phase, dict) or not isinstance(phase.get("nodeid"), str)
                or phase["nodeid"] not in grouped
                or not isinstance(phase.get("when"), str)
                or phase["when"] not in {"setup", "call", "teardown"}
                or not isinstance(phase.get("outcome"), str)
                or phase["outcome"] not in {"passed", "failed", "skipped"}):
            raise GateFailure("Malformed or unsolicited test phase")
        grouped[phase["nodeid"]].append(phase)
    outcomes: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for node, phases in grouped.items():
        order = [phase["when"] for phase in phases]
        if order not in (["setup", "call", "teardown"], ["setup", "teardown"]):
            raise GateFailure(f"Missing, duplicate or out-of-order phases for {node}")
        if (phases[0]["outcome"] == "passed") != (len(phases) == 3):
            raise GateFailure(f"Setup/call evidence contradicts itself for {node}")
        outcome = "passed"
        for phase in phases:
            status = phase["outcome"]
            if phase["when"] == "teardown" and status != "passed":
                outcome = "teardown-" + status
                break
            if status == "failed":
                outcome = ("xpassed" if "[XPASS(strict)]" in str(phase.get("detail", ""))
                           else "setup-failed" if phase["when"] == "setup" else "failed")
            elif phase.get("wasxfail") is not None:
                outcome = "xfailed" if status == "skipped" else "xpassed"
            elif status == "skipped":
                outcome = "skipped"
                reasons[node] = str(phase.get("reason", ""))
        outcomes[node] = outcome
    return outcomes, reasons


def permitted_skip(node: str, reason: str, system: str) -> bool:
    return system == "win32" and reason in WINDOWS_SKIPS.get(node.split("::", 1)[0], set())


def _revision() -> dict[str, object]:
    from source_manifest import iter_source_files
    root = Path.cwd()
    # Include uncommitted/new source in the identity. Logs live outside manifest
    # scope and cannot alter the source digest of the run recording them.
    source_digests = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                      for name in iter_source_files(root)}
    identity: dict[str, object] = {
        "source_tree_sha256": hashlib.sha256(json.dumps(source_digests, sort_keys=True).encode()).hexdigest(),
        "source_files": len(source_digests),
    }
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5)
        status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                                capture_output=True, text=True, timeout=5)
        return dict(identity, commit=sha.stdout.strip() if sha.returncode == 0 else None,
                    tracked_changes=bool(status.stdout.strip()) if status.returncode == 0 else None)
    except (OSError, subprocess.TimeoutExpired):
        return dict(identity, commit=None, tracked_changes=None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, default=Path("validation/release-gate"))
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="Maximum seconds per collection/batch process (default: 300)")
    args = parser.parse_args(argv)
    if not 0 < args.timeout < float("inf"):
        parser.error("--timeout must be positive and finite")
    directory = args.report_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex
    outcomes: dict[str, str] = {}
    skipped: dict[str, str] = {}
    summary: dict[str, Any] = {
        "schema": 1, "run_id": run_id, "status": "running", "failure": "",
        "started_at": datetime.now(timezone.utc).isoformat(), "python": sys.version,
        "platform": platform.platform(), "policy_platform": sys.platform,
        "revision": _revision(), "outcomes": outcomes, "allowed_skips": skipped,
        "counts": {}, "collected": 0, "batches": [], "processes": [], "pytest_version": None,
    }

    def invoke(command: list[str], log_path: Path) -> int:
        process_record: dict[str, Any] = {"log": log_path.name, "termination": "running", "returncode": None}
        summary["processes"].append(process_record)
        try:
            code = _process(command, log_path, args.timeout)
            process_record.update(termination="signal" if code < 0 else "exit", returncode=code)
            return code
        except GateTimeout:
            process_record["termination"] = "timeout"
            raise
        except OSError:
            process_record["termination"] = "launch-error"
            raise

    log = directory / "collection.log"
    try:
        record_path = directory / "collection.json"
        code = invoke(_pytest_command("--collect-only", "-q", "--feathered-report", str(record_path),
                                      "--feathered-run-id", run_id), log)
        collection = _record(record_path, run_id, code, "collection")
        summary["pytest_version"] = collection["pytest_version"]
        _collection_contract(collection)
        nodes = collection["nodes"]
        summary["collected"] = len(nodes)
        if code or not nodes or collection["phases"]:
            raise GateFailure(f"Collection failed or produced no tests (subprocess status {code})")
        print(f"Feathered release gate: {len(nodes)} collected; batches of up to {BATCH_SIZE}.", flush=True)
        for number, requested in enumerate(_batch_plan(nodes, sys.platform), start=1):
            stem = f"batch-{number:03}"
            record_path = directory / (stem + ".json")
            request_path = directory / (stem + "-request.json")
            paths_path = directory / (stem + "-paths.txt")
            _write(request_path, {"run_id": run_id, "nodes": requested})
            # Pytest's argument-file support carries only source paths. The
            # plugin filters exact IDs from JSON, including very long IDs.
            paths = list(dict.fromkeys(node.split("::", 1)[0] for node in requested))
            if any("\n" in path or "\r" in path for path in paths):
                raise GateFailure("Test source paths must not contain newlines")
            paths_path.write_text("\n".join(paths) + "\n", encoding="utf-8")
            log = directory / (stem + ".log")
            print(f"Batch {number}: {len(requested)} requested; log {log}", flush=True)
            code = invoke(_pytest_command("-q", "--feathered-report", str(record_path),
                "--feathered-run-id", run_id, "--feathered-request", str(request_path),
                "@" + str(paths_path)), log)
            record = _record(record_path, run_id, code, "batch")
            batch, reasons = reconcile(record, requested)
            outcomes.update(batch)
            summary["batches"].append({"report": record_path.name, "returncode": code})
            for node, outcome in batch.items():
                if outcome == "skipped" and permitted_skip(node, reasons[node], sys.platform):
                    skipped[node] = reasons[node]
            unexpected = {node: outcome for node, outcome in batch.items()
                          if outcome != "passed" and node not in skipped}
            if code or unexpected:
                raise GateFailure(f"Batch {number} failed: subprocess status {code}; unexpected outcomes {unexpected}")
            print(f"  {dict(Counter(batch.values()))}", flush=True)
        if set(outcomes) != set(nodes):
            raise GateFailure("Collected corpus and recorded outcomes differ")
        summary["status"] = "passed"
    except (GateFailure, OSError) as exc:
        summary.update(status="failed", failure=str(exc))
        print(f"Release gate FAILED: {exc}", file=sys.stderr, flush=True)
        if log.exists():
            print(log.read_text(encoding="utf-8", errors="replace")[-20000:], file=sys.stderr, flush=True)
    finally:
        summary["counts"] = dict(Counter(outcomes.values()))
        summary["finished_at"] = datetime.now(timezone.utc).isoformat()
        _write(directory / "summary.json", summary)
        lines = ["# Recorded release-test outcomes", "", f"Status: {summary['status']}", "",
                 f"Commit: {summary['revision']['commit']}",
                 f"Tracked source edits present: {summary['revision']['tracked_changes']}",
                 f"Source-tree SHA-256: {summary['revision']['source_tree_sha256']}",
                 f"Python: {platform.python_version()}; pytest: {summary['pytest_version']}",
                 f"Environment: {summary['platform']}",
                 f"Finished: {summary['finished_at']}", "",
                 f"Collected: {summary['collected']}", "", "| Outcome | Count |", "|---|---|"]
        lines.extend(f"| {outcome} | {count} |" for outcome, count in sorted(summary["counts"].items()))
        lines.extend(["", f"Permitted Windows capability skips: {len(skipped)} (never counted as passes).",
                      "", "Per-test phases, skip reasons and subprocess termination records are in summary.json and batch reports."])
        if summary["failure"]:
            lines.extend(["", "Failure: " + summary["failure"]])
        (directory / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if summary["status"] == "passed":
        print(f"Feathered release test gate PASSED: {summary['counts'].get('passed', 0)} passed, "
              f"{len(skipped)} platform skips; {summary['collected']} collected.", flush=True)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
