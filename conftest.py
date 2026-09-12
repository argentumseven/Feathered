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
