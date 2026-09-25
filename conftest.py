"""Shared test isolation for the Feathered suite.

`profiles.PROFILES` is a module-global registry of mutable `DistroProfile`
objects. Constructing `App` seeds every profile's `release_codenames` from
`release_seed.RELEASE_SEEDS`, and release discovery writes learned versions
into the same objects. Both mutations outlive the test that caused them,
because nothing in the process ever puts them back.

That made suite results depend on file order. `test_devuan_components_follow_
release_generation` passed when `test_feather.py` ran alone and failed when it
ran after any module that builds an `App`, because `_devuan_repos("6.0", ...)`
correctly starts returning codename-named suites ("excalibur") once the
codename for the 6 series is known. Seven separate modules triggered it.

Rather than have each test defend itself, snapshot the mutable release fields
before every test and restore them afterwards. Tests that deliberately seed or
discover releases keep working; they simply no longer leak into their
neighbours.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# The mutable, discovery-fed fields on a DistroProfile. Anything added here
# later that accumulates runtime state should join this list.
_VOLATILE_FIELDS = (
    "discovered_versions",
    "verified_versions",
    "release_codenames",
    "release_observed_at",
)


@pytest.fixture(autouse=True)
def _isolate_profile_release_state():
    try:
        from profiles import PROFILES
    except Exception:  # pragma: no cover - profiles must import for any test
        yield
        return

    snapshot = {
        key: {field: copy.deepcopy(getattr(profile, field))
              for field in _VOLATILE_FIELDS if hasattr(profile, field)}
        for key, profile in PROFILES.items()
    }
    try:
        yield
    finally:
        for key, fields in snapshot.items():
            profile = PROFILES.get(key)
            if profile is None:
                continue
            for field, value in fields.items():
                try:
                    current = getattr(profile, field, None)
                    # Restore *contents*, never rebind. `release_codenames` is
                    # the very same dict object as the module-level
                    # UBUNTU_CODENAMES / DEVUAN_CODENAMES that the repos
                    # factories read directly, so assigning a fresh copy would
                    # silently break that alias and leave the factories reading
                    # a dict nothing updates any more.
                    if isinstance(current, dict) and isinstance(value, dict):
                        current.clear()
                        current.update(copy.deepcopy(value))
                    elif isinstance(current, list) and isinstance(value, list):
                        current[:] = copy.deepcopy(value)
                    else:
                        setattr(profile, field, copy.deepcopy(value))
                except Exception:  # pragma: no cover - never fail a teardown
                    pass


# ---------------------------------------------------------------------------
# Tk availability on development hosts
# ---------------------------------------------------------------------------
# GUI modules import tkinter at module scope. On a Linux host without python3-tk
# that surfaced as ten opaque collection errors. Outside the release gate, report
# those modules as skipped with the remedy instead. The release gate (which runs
# pytest with --feathered-report) is deliberately untouched: there a missing Tk
# must remain a collection failure, never a quiet reduction in coverage.
try:
    import tkinter as _tkinter  # noqa: F401
    _TK_MISSING = False
except ImportError:
    _TK_MISSING = True

_TK_IMPORT_ERRORS = ("No module named 'tkinter'", "No module named '_tkinter'")


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector):
    outcome = yield
    report = outcome.get_result()
    if not (_TK_MISSING and report.failed):
        return
    try:
        release_gate = collector.config.getoption("--feathered-report", default=None)
    except ValueError:
        release_gate = None
    if release_gate:
        return
    if any(marker in str(report.longrepr) for marker in _TK_IMPORT_ERRORS):
        report.outcome = "skipped"
        report.longrepr = (str(collector.path), 0,
                           "Skipped: tkinter is not importable on this host "
                           "(install python3-tk); Tk-dependent tests were not run")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # Same rule for tests that import the GUI lazily inside the test body.
    outcome = yield
    report = outcome.get_result()
    if not (_TK_MISSING and report.failed and call.excinfo is not None):
        return
    if not call.excinfo.errisinstance(ImportError):
        return
    try:
        release_gate = item.config.getoption("--feathered-report", default=None)
    except ValueError:
        release_gate = None
    if release_gate:
        return
    if any(marker in str(call.excinfo.value) for marker in _TK_IMPORT_ERRORS):
        report.outcome = "skipped"
        report.longrepr = (str(item.path), 0,
                           "Skipped: tkinter is not importable on this host "
                           "(install python3-tk); Tk-dependent test was not run")
