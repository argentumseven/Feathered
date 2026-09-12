"""Pytest gate for jobs whose explicitly selected tests must all execute."""
from __future__ import annotations

import pytest


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    terminal = session.config.pluginmanager.get_plugin("terminalreporter")
    stats = terminal.stats if terminal is not None else {}
    skipped = len(stats.get("skipped", ()))
    deselected = len(stats.get("deselected", ()))
    if skipped or deselected or session.testscollected == 0:
        if terminal is not None:
            terminal.write_line(
                f"Required-test gate FAILED: {skipped} skipped, {deselected} deselected, "
                f"{session.testscollected} collected.")
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
