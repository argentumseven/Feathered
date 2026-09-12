"""Release-gate pytest plugin: exit immediately after pytest has its final status."""
from __future__ import annotations
import os
import sys
import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    code = int(exitstatus)
    print(
        f"\nRelease batch complete: {session.testscollected} collected, "
        f"{session.testsfailed} failed, pytest status {code}.",
        flush=True,
    )
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
