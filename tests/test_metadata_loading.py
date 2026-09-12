"""Exercise the production adapter, real source rows and cancellation reporter."""
from __future__ import annotations

from threading import Event
from types import SimpleNamespace

import pytest

from core import Cancelled, RepoSpec, Reporter
from feathered_app.build_sources import BuildSourcesMixin


FALLBACK = "Public EL-compatible mirrors (recommended fallback)"


def source(name, **fields):
    repo = RepoSpec(name, "https://example.test/" + name)
    for key, value in fields.items():
        setattr(repo, key, value)
    return repo


def host_for(rows):
    calls, validations = [], []
    packages = {r.name: [object()] for r in rows}
    host = SimpleNamespace(
        repo_rows=rows, _arch_snapshot="x86_64", loaded_signature=None,
        loaded_packages=[], _build_repository_scope=lambda: list(rows),
        _mirror_mode=lambda: False, _active_source_method=lambda: "Custom repositories",
        _repo_tier=lambda row: row.source_tier,
        _validate_successful_source_scopes=lambda successful, attempted: validations.append((successful, attempted)),
    )
    host._signature = lambda: BuildSourcesMixin._signature(host)

    def backend(row, arches, reporter):
        calls.append((row.name, arches))
        result = packages[row.name]
        if isinstance(result, Exception):
            raise result
        return result

    host._load_repository_backend = backend
    return host, packages, calls, validations


def load(host, reporter=None, **kwargs):
    return BuildSourcesMixin._load_enabled_repos(host, reporter or Reporter(), **kwargs)


def forbidden(*args):
    raise AssertionError("Unneeded host capability was accessed")


def test_normal_load_retains_order_progress_cache_identity_and_laziness():
    first, second = source("first"), source("second")
    host, packages, calls, validations = host_for([first, second])
    logs, progress = [], []
    reporter = Reporter(log=logs.append, progress=lambda *args: progress.append(args))
    result = load(host, reporter)
    assert result == packages["first"] + packages["second"]
    assert all(a is b for a, b in zip(result, packages["first"] + packages["second"]))
    assert host.loaded_packages is result
    assert calls == [("first", {"x86_64", "noarch"}), ("second", {"x86_64", "noarch"})]
    assert validations == [([first, second], [first, second])]
    assert progress == [("Metadata 1/2: first", 0.05), ("Metadata 2/2: second", 0.26)]
    assert logs == ["Loaded 2 package records from 2 repositories"]
    host._load_repository_backend = host._validate_successful_source_scopes = forbidden
    host._active_source_method = host._mirror_mode = forbidden
    reporter.check_cancel = forbidden  # Existing cache hits perform no I/O checkpoint.
    assert load(host, reporter) is result
    assert logs[-1] == "Using cached repository metadata."


@pytest.mark.parametrize("field,value", [
    ("priority", 9), ("source_tier", "workload"), ("url", "https://example.test/new"),
    ("keyring", "keys.gpg"), ("allow_unverified_index", True),
    ("evidence_urls", ["https://example.test/evidence"]),
    ("redirect_allow_origins", ["https://example.test"]),
])
def test_source_edit_invalidates_metadata_cache(field, value):
    row = source("base")
    host, packages, calls, _ = host_for([row])
    load(host)
    setattr(row, field, value)
    replacement = object()
    packages[row.name] = [replacement]
    assert load(host) == [replacement]
    assert len(calls) == 2


def test_architecture_change_invalidates_cache():
    host, _, calls, _ = host_for([source("base")])
    load(host)
    host._arch_snapshot = "aarch64"
    load(host)
    assert calls[-1][1] == {"aarch64", "noarch"}
    assert len(calls) == 2


def test_successful_empty_metadata_is_retried():
    host, packages, calls, _ = host_for([source("base")])
    packages["base"] = []
    assert load(host) == []
    assert load(host) == []
    assert len(calls) == 2


@pytest.mark.parametrize("mirror,expected", [(False, ["enabled"]), (True, ["disabled", "enabled"])])
def test_scoped_load_uses_explicit_rows_and_never_touches_shared_cache(mirror, expected):
    disabled, enabled, blank = source("disabled", enabled=False), source("enabled"), source("blank", url=" ")
    rows = [disabled, enabled, blank]
    host, packages, calls, validations = host_for(rows)
    host._mirror_mode = lambda: mirror
    host._build_repository_scope = forbidden
    # Missing fields prove that even a cache lookup was not attempted.
    del host.loaded_signature, host.loaded_packages
    result = load(host, repositories=rows)
    assert [name for name, _ in calls] == expected
    assert result == [packages[name][0] for name in expected]
    assert [row.name for row in validations[0][1]] == expected
    assert not hasattr(host, "loaded_signature") and not hasattr(host, "loaded_packages")
    assert disabled.enabled is False


def test_scoped_load_cannot_replace_or_reuse_populated_global_cache():
    base, vendor = source("base"), source("vendor")
    host, packages, calls, _ = host_for([base, vendor])
    cached = load(host)
    signature = host.loaded_signature
    result = load(host, repositories=[vendor])
    assert result == packages["vendor"] and result is not cached
    assert host.loaded_signature == signature and host.loaded_packages is cached
    assert [name for name, _ in calls] == ["base", "vendor", "vendor"]


@pytest.mark.parametrize("rows", [[], [source("disabled", enabled=False)], [source("blank", url=" ")]])
def test_no_enabled_source_fails_before_backend(rows):
    host, _, calls, validations = host_for(rows)
    with pytest.raises(RuntimeError, match="No enabled repositories"):
        load(host)
    assert not calls and not validations
    assert host.loaded_signature is None


def test_failed_sources_warn_or_log_and_validate_only_successful_providers():
    optional, required, good = source("optional", optional=True), source("required"), source("good")
    host, packages, calls, validations = host_for([optional, required, good])
    packages["optional"] = RuntimeError("optional unavailable")
    packages["required"] = RuntimeError("required unavailable")
    logs = []
    reporter = Reporter(log=logs.append)
    assert load(host, reporter) == packages["good"]
    assert validations == [([good], [optional, required, good])]
    assert len(calls) == 3
    assert logs[0] == "Optional source failed; continuing with remaining providers: optional: optional unavailable"
    assert reporter.warnings == ["Enabled source could not be read and will not participate unless another source in its required scope is unavailable: required: required unavailable"]
    assert logs[-1] == "Loaded 1 package records from 1 repositories"


@pytest.mark.parametrize("optional", [False, True])
def test_backend_cancellation_propagates_without_caching_partial_packages(optional):
    first, cancelled, last = source("first"), source("cancelled", optional=optional), source("last")
    host, packages, calls, validations = host_for([first, cancelled, last])
    cancellation = Cancelled("cancelled in backend")
    packages["cancelled"] = cancellation
    reporter = Reporter()
    with pytest.raises(Cancelled) as caught:
        load(host, reporter)
    assert caught.value is cancellation
    assert [name for name, _ in calls] == ["first", "cancelled"]
    assert not validations and not reporter.warnings
    assert host.loaded_signature is None and host.loaded_packages == []


def test_cancellation_after_backend_failure_is_not_reported_as_source_failure():
    host, _, calls, validations = host_for([source("first"), source("last")])
    event = Event()
    reporter = Reporter(cancel_event=event)

    def backend(*args):
        event.set()
        raise RuntimeError("interrupted transport")

    host._load_repository_backend = backend
    with pytest.raises(Cancelled):
        load(host, reporter)
    assert not reporter.warnings and not validations
    assert host.loaded_signature is None


def test_preexisting_cancellation_stops_before_backend():
    host, _, calls, validations = host_for([source("base")])
    event = Event()
    event.set()
    with pytest.raises(Cancelled):
        load(host, Reporter(cancel_event=event))
    assert not calls and not validations


def test_failed_scope_validation_preserves_previous_cache():
    host, _, _, _ = host_for([source("base")])
    previous = load(host)
    signature = host.loaded_signature
    host.repo_rows[0].priority += 1

    def reject(*args):
        raise RuntimeError("required scope unavailable")

    host._validate_successful_source_scopes = reject
    with pytest.raises(RuntimeError, match="required scope unavailable"):
        load(host)
    assert host.loaded_signature == signature and host.loaded_packages is previous


@pytest.mark.parametrize("method", [FALLBACK, "Public EL-compatible + EPEL (broad fallback)"])
def test_fallback_requires_reachable_base_before_caching(method):
    row = source("vendor", source_tier="workload")
    host, _, _, _ = host_for([row])
    host._active_source_method = lambda: method
    with pytest.raises(RuntimeError, match="All EL-compatible fallback repositories failed"):
        load(host)
    assert host.loaded_signature is None
    row.source_tier = "base"
    logs = []
    load(host, Reporter(log=logs.append))
    assert logs[0] == "Fallback sources available: vendor"


def test_coverage_can_bypass_distribution_policy_without_accessing_it():
    row = source("vendor", source_tier="workload")
    host, packages, _, _ = host_for([row])
    host._active_source_method = host._repo_tier = forbidden
    assert load(host, repositories=[row], enforce_distribution_plan=False) == packages["vendor"]
