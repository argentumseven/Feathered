"""Exercise the release gate through real child pytest processes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _env():
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    for key in ("PYTEST_ADDOPTS", "FEATHERED_RELEASE_REPORT", "FEATHERED_RELEASE_REQUEST"):
        env.pop(key, None)
    return env


def _fixture(tmp_path, body):
    (tmp_path / "pytest.ini").write_text("[pytest]\ntestpaths = .\n", encoding="utf-8")
    (tmp_path / "test_fixture.py").write_text(body, encoding="utf-8")


def _gate(tmp_path, *args):
    return subprocess.run([sys.executable, str(ROOT / "release_test_runner.py"), *args],
                          cwd=tmp_path, env=_env(), text=True, capture_output=True, timeout=45)


def test_required_plugin_still_runs_with_release_plugin(tmp_path):
    _fixture(tmp_path, "import pytest\ndef test_case(): pytest.skip('missing required tool')\n")
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "release_pytest_exit",
                             "-p", "require_executed_tests"], cwd=tmp_path, env=_env(),
                            text=True, capture_output=True, timeout=20)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Required-test gate FAILED" in result.stdout


def test_release_plugin_preserves_assertion_diagnostics(tmp_path):
    _fixture(tmp_path, "def test_case(): assert False, 'visible failure explanation'\n")
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "release_pytest_exit"],
                            cwd=tmp_path, env=_env(), text=True, capture_output=True, timeout=20)
    assert result.returncode == 1
    assert "visible failure explanation" in result.stdout
    assert "FAILURES" in result.stdout


def test_runner_does_not_count_skips_as_passes(tmp_path):
    _fixture(tmp_path, "import pytest\ndef test_case(): pytest.skip('missing required tool')\n")
    result = _gate(tmp_path)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "PASSED" not in result.stdout


@pytest.mark.parametrize("body, outcome", [
    ("def test_case(): pass\n", "passed"),
    ("def test_case(): assert False, 'assertion fault'\n", "failed"),
    ("import pytest\n@pytest.fixture\ndef resource(): raise RuntimeError('setup fault')\n"
     "def test_case(resource): pass\n", "setup-failed"),
    ("import pytest\n@pytest.fixture\ndef resource():\n yield\n raise RuntimeError('teardown fault')\n"
     "def test_case(resource): pass\n", "teardown-failed"),
    ("import pytest\ndef test_case(): pytest.skip('unavailable')\n", "skipped"),
    ("import pytest\n@pytest.mark.xfail(reason='known fault')\ndef test_case(): assert False\n", "xfailed"),
    ("import pytest\n@pytest.mark.xfail(reason='known fault')\ndef test_case(): pass\n", "xpassed"),
    ("import pytest\n@pytest.mark.xfail(reason='known fault', strict=True)\ndef test_case(): pass\n", "xpassed"),
], ids=["pass", "assertion", "setup", "teardown", "skip", "xfail", "xpass", "strict-xpass"])
def test_gate_records_individual_phase_outcomes(tmp_path, body, outcome):
    _fixture(tmp_path, body)
    result = _gate(tmp_path)
    assert (result.returncode == 0) == (outcome == "passed"), result.stdout + result.stderr
    summary = json.loads((tmp_path / "validation/release-gate/summary.json").read_text())
    assert summary["outcomes"]["test_fixture.py::test_case"] == outcome
    batch = json.loads((tmp_path / "validation/release-gate/batch-001.json").read_text())
    assert batch["complete"] is True
    assert batch["phases"][0]["when"] == "setup"
    assert batch["phases"][-1]["when"] == "teardown"


def test_gate_rejects_collection_skip_and_records_reason(tmp_path):
    _fixture(tmp_path, "import pytest\npytest.skip('missing module', allow_module_level=True)\n")
    result = _gate(tmp_path)
    assert result.returncode != 0
    record = json.loads((tmp_path / "validation/release-gate/collection.json").read_text())
    assert record["collection_issues"][0]["outcome"] == "skipped"
    assert "missing module" in record["collection_issues"][0]["detail"]


def test_gate_rejects_deselection(tmp_path):
    _fixture(tmp_path, "def test_case(): pass\ndef test_other(): pass\n")
    env = _env(); env["PYTEST_ADDOPTS"] = "-k case"
    result = subprocess.run([sys.executable, str(ROOT / "release_test_runner.py")],
                            cwd=tmp_path, env=env, text=True, capture_output=True, timeout=20)
    assert result.returncode != 0
    record = json.loads((tmp_path / "validation/release-gate/collection.json").read_text())
    assert record["deselected"] == ["test_fixture.py::test_other"]


def test_gate_runs_long_node_id_without_command_line_expansion(tmp_path):
    tmp_path = tmp_path / "source and evidence with spaces"
    tmp_path.mkdir()
    # Pytest stores the current node ID in PYTEST_CURRENT_TEST. Windows limits
    # one environment-variable value to 32767 characters, independently of argv.
    id_length = 32600 if os.name == "nt" else 150000
    _fixture(tmp_path,
             f"import pytest\n@pytest.mark.parametrize('value', [1], ids=['x' * {id_length}])\n"
             "def test_case(value): assert value == 1\n")
    result = _gate(tmp_path)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr
    summary = json.loads((tmp_path / "validation/release-gate/summary.json").read_text())
    node = next(iter(summary["outcomes"]))
    assert len(node) > id_length
    if os.name == "nt":
        evidence = tmp_path / "validation/release-gate"
        direct = subprocess.list2cmdline([
            sys.executable, "-m", "pytest", "-p", "release_pytest_exit", "-q",
            "--feathered-report", str(evidence / "batch-001.json"),
            "--feathered-run-id", "0" * 36,
            "--feathered-request", str(evidence / "batch-001-request.json"),
            "@" + str(evidence / "batch-001-paths.txt"), node,
        ])
        assert len(direct) > 32767
    assert summary["counts"] == {"passed": 1}


@pytest.mark.parametrize("body, reason", [
    ("import os\ndef test_case(): os._exit(7)\n", "subprocess"),
    ("import os\ndef test_case(): os._exit(0)\n", "subprocess"),
    ("import time\ndef test_case(): time.sleep(20)\n", "timeout"),
], ids=["terminated", "early-zero-exit", "timeout"])
def test_gate_rejects_incomplete_subprocess(tmp_path, body, reason):
    _fixture(tmp_path, body)
    result = _gate(tmp_path, "--timeout", "2")
    assert result.returncode != 0
    summary = json.loads((tmp_path / "validation/release-gate/summary.json").read_text())
    assert reason in summary["failure"].lower()
    assert summary["status"] == "failed"


def test_normal_pytest_shutdown_runs_session_hooks_and_atexit(tmp_path):
    _fixture(tmp_path, "def test_case(): pass\n")
    (tmp_path / "conftest.py").write_text(
        "import atexit\nfrom pathlib import Path\nimport pytest\n"
        "atexit.register(lambda: Path('atexit-ran').write_text('yes'))\n"
        "@pytest.hookimpl(trylast=True)\ndef pytest_sessionfinish(session):\n"
        " Path('session-finished').write_text('yes')\n")
    result = _gate(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "atexit-ran").read_text() == "yes"
    assert (tmp_path / "session-finished").read_text() == "yes"


@pytest.mark.parametrize("body", ["raise RuntimeError('collection fault')\n", "# no tests\n"],
                         ids=["collection-error", "empty-corpus"])
def test_no_passing_gate_without_a_collected_corpus(tmp_path, body):
    _fixture(tmp_path, body)
    result = _gate(tmp_path)
    assert result.returncode != 0
    summary = json.loads((tmp_path / "validation/release-gate/summary.json").read_text())
    assert summary["status"] == "failed" and not summary["outcomes"]


def test_missing_final_report_fails_even_after_zero_exit(tmp_path):
    _fixture(tmp_path, "def test_case(): pass\n")
    (tmp_path / "conftest.py").write_text(
        "import atexit\nfrom pathlib import Path\n"
        "def pytest_configure(config):\n"
        " p=config.getoption('--feathered-report')\n"
        " if p and not config.option.collectonly:\n"
        "  atexit.register(lambda: Path(p).unlink(missing_ok=True))\n")
    result = _gate(tmp_path)
    assert result.returncode != 0
    summary = json.loads((tmp_path / "validation/release-gate/summary.json").read_text())
    assert "Invalid subprocess evidence" in summary["failure"]


def test_batches_account_for_every_id_without_counting_internal_selection_as_deselection(tmp_path):
    _fixture(tmp_path, "\n".join(f"def test_case_{i}(): pass" for i in range(23)))
    result = _gate(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    directory = tmp_path / "validation/release-gate"
    summary = json.loads((directory / "summary.json").read_text())
    assert summary["counts"] == {"passed": 23} and len(summary["batches"]) == 2
    for batch in summary["batches"]:
        record = json.loads((directory / batch["report"]).read_text())
        assert record["batch_excluded"] and not record["deselected"]


@pytest.mark.parametrize("change", [
    {"complete": False}, {"exit_code": 1}, {"run_id": "previous-run"},
    {"nodes": ["test::case", "test::case"]}, {"testscollected": 0},
    {"schema": True}, {"exit_code": False},
], ids=["incomplete", "status-mismatch", "stale", "duplicate-id", "count-mismatch", "bool-schema", "bool-status"])
def test_parent_rejects_contradictory_or_stale_evidence(tmp_path, change):
    from release_test_runner import _record, GateFailure
    record = dict(schema=1, run_id="current", complete=True, exit_code=0, mode="batch",
                  nodes=["test::case"], testscollected=1, collection_issues=[], deselected=[],
                  phases=[], errors=[], pytest_version="fixture")
    record.update(change)
    path = tmp_path / "report.json"; path.write_text(json.dumps(record))
    with pytest.raises(GateFailure):
        _record(path, "current", 0, "batch")


@pytest.mark.parametrize("orders", [[], ["setup", "call"], ["setup", "call", "call", "teardown"],
                                   ["call", "setup", "teardown"], ["setup", "teardown"]],
                         ids=["no-phases", "missing-teardown", "duplicate-call", "wrong-order", "missing-call"])
def test_parent_rejects_incomplete_or_duplicate_execution(orders):
    from release_test_runner import reconcile, GateFailure
    record = dict(nodes=["test::case"], collection_issues=[], deselected=[], errors=[],
                  phases=[dict(nodeid="test::case", when=phase, outcome="passed") for phase in orders])
    with pytest.raises(GateFailure):
        reconcile(record, ["test::case"])


def test_platform_skip_policy_is_scoped_and_has_required_linux_coverage():
    import yaml
    from release_test_runner import permitted_skip
    node = "tests/test_headless_execution.py::test_prepared_build_publishes_with_tk_blocked[workload]"
    assert permitted_skip(node, "requires dpkg fixture tools", "win32")
    assert not permitted_skip(node, "requires dpkg fixture tools", "linux")
    assert not permitted_skip(node, "no display", "win32")
    assert not permitted_skip("tests/test_other.py::test_case", "requires dpkg fixture tools", "win32")
    cache_node = "tests/test_security_review_fixes.py::test_artifact_cache_rejects_group_or_world_writable_root"
    cache_reason = "POSIX ownership and mode checks are not available"
    assert permitted_skip(cache_node, cache_reason, "win32")
    assert not permitted_skip(cache_node, cache_reason, "linux")
    assert not permitted_skip(cache_node, "POSIX checks are not available", "win32")
    parity = "tests/test_prepared_adapter_parity.py::test_gui_and_cli_preserve_payloads_sources_provenance_and_installer"
    assert permitted_skip(parity, "requires dpkg fixture tools", "win32")
    assert not permitted_skip(parity, "requires dpkg fixture tools", "linux")
    assert not permitted_skip(parity, "no display", "win32")
    crypto = "test_feather.py::test_openpgp_verification_round_trip"
    crypto_reason = "GnuPG signing and verification tools are unavailable on this host"
    assert permitted_skip(crypto, crypto_reason, "win32")
    assert not permitted_skip(crypto, crypto_reason, "linux")
    native = yaml.safe_load((ROOT / ".github/workflows/native-conformance.yml").read_text())
    steps = native["jobs"]["apt"]["steps"]
    install_commands = "\n".join(step.get("run", "") for step in steps)
    assert "gnupg" in install_commands and "gpgv" in install_commands
    assert any("xvfb-run -a python3 release_test_runner.py" in step.get("run", "") for step in steps)
    windows = yaml.safe_load((ROOT / ".github/workflows/windows-release.yml").read_text())
    assert "native-conformance" in windows["jobs"]["production-release"]["needs"]


def test_windows_release_plan_isolates_real_tk_root_modules():
    from release_test_runner import WINDOWS_ISOLATED_PREFIXES, _batch_plan

    assert set(WINDOWS_ISOLATED_PREFIXES) == {
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
    }
    isolated_nodes = [prefix + "test_case" for prefix in WINDOWS_ISOLATED_PREFIXES]
    nodes = [
        *[f"tests/test_before.py::test_{i}" for i in range(3)],
        *isolated_nodes,
        *[f"tests/test_after.py::test_{i}" for i in range(23)],
    ]
    batches = _batch_plan(nodes, "win32")
    flattened = [node for batch in batches for node in batch]
    assert flattened == nodes
    assert all(len(batch) <= 20 for batch in batches)
    isolated = [batch for batch in batches if batch[0] in isolated_nodes]
    assert isolated == [[node] for node in isolated_nodes]



def test_windows_tk_isolation_inventory_covers_real_application_modules():
    from release_test_runner import WINDOWS_ISOLATED_PREFIXES

    isolated = set(WINDOWS_ISOLATED_PREFIXES)
    discovered = set()
    app_constructor = "app." + "App("
    shared_fixture = "startup." + "application"
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        text = path.read_text(encoding="utf-8")
        if app_constructor in text or shared_fixture in text:
            discovered.add(f"tests/{path.name}::")
    assert discovered <= isolated


def test_non_windows_release_plan_keeps_normal_batching():
    from release_test_runner import _batch_plan

    nodes = [f"tests/test_file.py::test_{i}" for i in range(43)]
    assert [len(batch) for batch in _batch_plan(nodes, "linux")] == [20, 20, 3]
