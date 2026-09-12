"""Structured release evidence; the legacy plugin name remains compatible.

Never terminates pytest. Normal reporting, later hooks and process cleanup must
finish before the parent accepts the subprocess and its evidence together.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Generator

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("feathered release evidence")
    group.addoption("--feathered-report", help="Structured pytest outcome file")
    group.addoption("--feathered-request", help="JSON batch selection; IDs never enter argv")
    group.addoption("--feathered-run-id", default="", help="Evidence invocation identity")


def pytest_configure(config: pytest.Config) -> None:
    if config.getoption("--feathered-report"):
        config.pluginmanager.register(ReleaseReport(config), "feathered-release-report")


class ReleaseReport:
    def __init__(self, config: pytest.Config) -> None:
        self.path = Path(config.getoption("--feathered-report"))
        request_path = config.getoption("--feathered-request")
        self.requested: list[str] | None = None
        if request_path:
            try:
                request = json.loads(Path(request_path).read_text(encoding="utf-8"))
                nodes = request["nodes"]
                if (request["run_id"] != config.getoption("--feathered-run-id")
                        or not isinstance(nodes, list) or not nodes
                        or not all(isinstance(node, str) for node in nodes)
                        or len(set(nodes)) != len(nodes)):
                    raise ValueError("invalid batch request")
                self.requested = nodes
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise pytest.UsageError(f"Cannot read release batch request: {exc}") from exc
        self.data: dict[str, Any] = {
            "schema": 1, "run_id": config.getoption("--feathered-run-id"),
            "mode": "collection" if config.option.collectonly else "batch",
            "pytest_version": pytest.__version__, "nodes": [], "batch_excluded": [],
            "collection_issues": [], "deselected": [], "phases": [], "errors": [],
            "complete": False, "exit_code": None, "testscollected": 0,
        }
        self.write()

    def write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".writing")
        temporary.write_text(json.dumps(self.data, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)

    def pytest_collectreport(self, report: pytest.CollectReport) -> None:
        if not report.passed:
            self.data["collection_issues"].append({
                "nodeid": report.nodeid, "outcome": report.outcome, "detail": str(report.longrepr)})
            self.write()

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, items: list[pytest.Item]) -> None:
        if self.requested is None:
            return
        wanted = set(self.requested)
        # Internal batching is distinct from -k/-m/plugin deselection. The latter
        # is recorded separately and fails the parent gate, even during collection.
        self.data["batch_excluded"] = [item.nodeid for item in items if item.nodeid not in wanted]
        items[:] = [item for item in items if item.nodeid in wanted]
        found = [item.nodeid for item in items]
        if set(found) != wanted or len(found) != len(wanted):
            self.data["errors"].append("Batch collection does not match requested test IDs")

    def pytest_deselected(self, items: list[pytest.Item]) -> None:
        self.data["deselected"].extend(item.nodeid for item in items)

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        self.data["nodes"] = [item.nodeid for item in session.items]
        self.write()

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        detail = str(report.longrepr) if report.longrepr is not None else ""
        reason = ""
        if report.skipped and isinstance(report.longrepr, tuple):
            reason = str(report.longrepr[2]).removeprefix("Skipped: ")
        self.data["phases"].append({
            "nodeid": report.nodeid, "when": report.when, "outcome": report.outcome,
            "wasxfail": getattr(report, "wasxfail", None), "reason": reason, "detail": detail,
        })
        self.write()

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_sessionfinish(self, session: pytest.Session) -> Generator[None, None, None]:
        # An outer wrapper runs AFTER all ordinary finish hooks, including the
        # required-test gate. An exception prevents the completion marker.
        yield
        self.data.update(complete=True, exit_code=int(session.exitstatus),
                         testscollected=session.testscollected)
        self.write()
