"""Headless package-coverage semantics and GUI worker boundary regressions."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
from queue import Queue
from threading import Event, Thread, current_thread, main_thread
from types import SimpleNamespace

import pytest

from feathered_app.package_coverage import (
    CoverageTarget, PackageCoverageService as Service,
)
from repository_config import RepoSpec


def repository(name="core", *, url=None, priority=50, role="dependency", tier="base",
               fmt="pacman"):
    repo = RepoSpec(name=name, url=url or f"https://example.test/{name}/",
                    priority=priority, role=role, repo_format=fmt)
    repo.source_tier = tier
    return repo


def package(name="nginx", *, repo=None, arch="x86_64", version="1:1.10.0-2",
            provides=(), depends=()):
    return SimpleNamespace(name=name, repo=repo or repository(), arch=arch,
                           version=version, evr_text=version, evr=(0, version, "0"),
                           nevra=f"{name}-{version}-{arch}",
                           files=[], provides=[SimpleNamespace(name=n) for n in provides],
                           depends=[SimpleNamespace(name=n) for n in depends])


ARCH = CoverageTarget("arch", "x86_64")


def test_coverage_is_headless_and_target_immutable():
    import feathered_app.package_coverage as module
    assert "tkinter" not in Path(module.__file__).read_text(encoding="utf-8")
    with pytest.raises(FrozenInstanceError):
        ARCH.arch = "aarch64"


def test_arch_epoch_pin_accepts_pacman_record():
    candidate = package("lz4", version="1:1.10.0-2")
    assert Service.matches(candidate, ("lz4", "1:1.10.0-2", None), ARCH)
    assert not Service.matches(candidate, ("lz4", "1:1.10.0-1", None), ARCH)
    assert Service.evaluate_roots([candidate], [("lz4", "1:1.10.0-2", None)], ARCH).rows[0][1] == "Available"


def test_arch_virtual_provides_and_any_arch_but_not_foreign_arch():
    provided = package("openbsd-netcat", arch="any", provides=("netcat",))
    assert Service.matches(provided, ("netcat", None, None), ARCH)
    assert not Service.matches(package(arch="aarch64"), ("nginx", None, None), ARCH)


def test_debian_direct_name_version_and_arch_are_exact_except_all():
    target = CoverageTarget("deb", "amd64")
    universal = package("nginx", arch="all", version="1:1.4-1", provides=("www-daemon",))
    assert Service.matches(universal, ("nginx", "1:1.4-1", None), target)
    assert not Service.matches(universal, ("www-daemon", None, None), target)
    assert not Service.matches(universal, ("nginx", "1:1.4-2", None), target)
    assert not Service.matches(package(arch="arm64"), ("nginx", None, None), target)


def test_rpm_virtual_file_and_noarch_can_satisfy_roots():
    rpm = package("provider", repo=repository(fmt="rpm"), arch="noarch")
    rpm.files = ["/usr/bin/nginx"]
    rpm.provides = [SimpleNamespace(name="webserver")]
    target = CoverageTarget("rpm", "x86_64")
    assert Service.matches(rpm, ("/usr/bin/nginx", None, None), target)
    assert Service.matches(rpm, ("webserver", None, None), target)


def test_scope_role_exact_arch_and_identity_are_enforced_independently():
    one = repository("duplicate", url="https://one.test/core/", role="docker", tier="workload")
    two = repository("duplicate", url="https://two.test/core/", role="docker", tier="workload")
    candidate = package(repo=one)
    assert one.source_identity != two.source_identity
    assert Service.matches(candidate, ("nginx", None, "docker", "duplicate", "x86_64", None, one.source_identity), ARCH)
    assert not Service.matches(candidate, ("nginx", None, "docker", "duplicate", "x86_64", None, two.source_identity), ARCH)
    assert not Service.matches(candidate, ("nginx", None, "docker", None, None, "distribution"), ARCH)
    assert not Service.matches(candidate, ("nginx", None, "different"), ARCH)
    assert not Service.matches(candidate, ("nginx", None, None, None, "aarch64"), ARCH)


def test_legacy_role_infers_nonbase_scope_when_source_tier_missing():
    repo = repository(role="vendor")
    del repo.source_tier
    candidate = package(repo=repo)
    scoped = CoverageTarget("arch", "x86_64", frozenset({"vendor"}))
    assert not Service.matches(candidate, ("nginx", None, None, None, None, "distribution"), scoped)
    assert Service.matches(candidate, ("nginx", None, "vendor"), scoped)


def test_priority_beats_newer_version_but_arch_beats_priority():
    slow = package(repo=repository("older", priority=5), version="1.0-1")
    newest = package(repo=repository("newest", priority=20), version="2.0-1")
    any_arch = package(repo=repository("any", priority=0), arch="any", version="3.0-1")
    assert Service.best_candidate([newest, slow], ARCH) is slow
    assert Service.best_candidate([any_arch, newest], ARCH) is newest
    tie = package(repo=repository("tie", priority=20), version="2.1-1")
    assert Service.best_candidate([newest, tie], ARCH) is tie
    assert Service.best_candidate([], ARCH) is None


def test_alias_substitution_and_optional_gap_are_explicit():
    mapped = package("openbsd-netcat")
    result = Service.evaluate_roots(
        [mapped], [("netcat", None, None), ("optional-plugin", None, None)], ARCH,
        optional={"optional-plugin"}, aliases={"netcat": "openbsd-netcat"})
    assert result.resolved_aliases == (("netcat", "openbsd-netcat"),)
    assert result.rows[0][:2] == ("netcat → openbsd-netcat", "Available (learned)")
    assert result.rows[1][1] == "Optional gap"
    assert result.rows[1][-2:] == ("warn", True)


def test_unresolved_required_materialized_root_stays_missing():
    policy = SimpleNamespace(package="missing", component="runtime", optional=False,
                             candidates=("missing", "fallback"))
    optional = SimpleNamespace(package="optional", component="other", optional=True,
                               candidates=("optional",))
    result = Service.evaluate_roots([], [("nginx", None, None)], ARCH,
                                    unresolved=(policy, optional))
    assert result.rows[0][1] == "Missing"
    assert result.rows[1] == ("runtime", "Missing", "",
                              "No approved candidate found: missing / fallback", "error", False)
    assert len(result.rows) == 2


def test_non_systemd_target_blocks_critical_root_even_when_present():
    candidate = package("systemd")
    target = CoverageTarget("arch", "x86_64", check_init_conflicts=True)
    row = Service.evaluate_roots([candidate], [("systemd", None, None)], target).rows[0]
    assert row[1] == "Blocked (init)" and "systemd" in row[3]
    assert row[4:] == ("error", False)


def test_mirror_coverage_uses_identity_not_duplicate_display_name():
    first = repository("same", url="https://one.test/core/")
    second = repository("same", url="https://two.test/core/")
    third = repository("empty", url="https://three.test/core/")
    packages = [package(repo=first), package("lz4", repo=first), package(repo=second)]
    result = Service.evaluate_mirrors(packages, [third, second, first])
    assert result.resolved_aliases == ()
    assert result.rows[0][1:4:2] == ("Empty", "No package records found")
    assert sorted((row[1], row[3]) for row in result.rows[1:]) == [
        ("Ready", "1 package record(s)"),
        ("Ready", "2 package record(s)"),
    ]


def test_gui_mirror_worker_uses_snapshot_and_emits_completion_without_alias_error():
    """Regression: mirror coverage previously referenced unassigned resolved_pairs."""
    from feathered_app.ui.panes import PaneMixin

    checked_on = []
    def main_only(value):
        def get():
            assert current_thread() is main_thread(), "coverage worker read a live GUI variable"
            checked_on.append(value)
            return value
        return SimpleNamespace(get=get)

    src = repository("core", fmt="pacman")
    events = Queue()
    threads = []
    host = SimpleNamespace()
    host.events = events
    host.repo_rows = [src]
    host.arch_var = main_only("x86_64")
    host._profile = lambda: SimpleNamespace(package_family="arch")
    host._known_workload_repository_roles = lambda: set()
    host._busy = lambda: False
    host._single_mode = lambda: False
    host._mirror_mode = lambda: True
    host._mirror_repo_selected = lambda repo: True
    host._selected_init_system = lambda: ""
    host._package_requests = lambda: ()
    host._source_plan = lambda: SimpleNamespace(distribution_required=False)
    host._validate_source_plan = lambda: None
    host._validate_sources = lambda *_: None
    host._package_coverage_repositories = lambda: [src]
    host._claim_operation = lambda *_a, **_k: True
    host._package_source_signature = lambda: ("snapshot",)
    host.package_source_status_var = SimpleNamespace(set=lambda _: None)
    host.package_source_status = SimpleNamespace(configure=lambda **_: None)
    host.cancel_event = Event()
    host._log = lambda *_: None
    host._progress = lambda *_: None
    host._load_enabled_repos = lambda *_a, **_k: [package(repo=src)]
    host._coverage_target = lambda **kw: PaneMixin._coverage_target(host, **kw)
    def start_worker(*, target):
        worker = Thread(target=target)
        threads.append(worker)
        worker.start()
    host._start_operation_worker = start_worker
    PaneMixin.check_package_source_coverage(host)
    for worker in threads:
        worker.join(timeout=5)
        assert not worker.is_alive()
    queued = []
    while not events.empty():
        queued.append(events.get_nowait())
    assert queued[0] == ("package_coverage", ("snapshot",),
                          [("core", "Ready", "core", "1 package record(s)", "ok", False)])
    assert queued[1] == ("done", True, "Package source coverage complete")
    assert checked_on == ["x86_64"]


def test_gui_root_worker_does_not_access_live_arch_widget_or_emit_alias_from_tk():
    """The GUI freezes target settings before the package-index worker runs."""
    from feathered_app.ui.panes import PaneMixin

    def get_arch():
        assert current_thread() is main_thread()
        return "x86_64"

    src = repository("extra")
    host = SimpleNamespace()
    host.events = Queue()
    host.repo_rows = [src]
    host.arch_var = SimpleNamespace(get=get_arch)
    host._profile = lambda: SimpleNamespace(package_family="arch")
    host._known_workload_repository_roles = lambda: set()
    host._busy = lambda: False
    host._single_mode = lambda: True
    host._mirror_mode = lambda: False
    host._selected_init_system = lambda: ""
    host._package_requests = lambda: (("netcat", None, None),)
    host._source_plan = lambda: SimpleNamespace(distribution_required=False)
    host._validate_source_plan = lambda: None
    host._validate_sources = lambda *_: None
    host._package_coverage_repositories = lambda: [src]
    host._claim_operation = lambda *_a, **_k: True
    host._package_source_signature = lambda: ("root",)
    host._optional_roots = lambda: set()
    host._aliases_for_target = lambda: {"netcat": "openbsd-netcat"}
    host.package_source_status_var = SimpleNamespace(set=lambda _: None)
    host.package_source_status = SimpleNamespace(configure=lambda **_: None)
    host.cancel_event = Event()
    host._log = lambda *_: None
    host._progress = lambda *_: None
    host._load_enabled_repos = lambda *_a, **_k: [package("openbsd-netcat", repo=src)]
    host._coverage_target = lambda **kw: PaneMixin._coverage_target(host, **kw)
    workers = []
    def start_worker(*, target):
        worker = Thread(target=target)
        workers.append(worker)
        worker.start()
    host._start_operation_worker = start_worker
    PaneMixin.check_package_source_coverage(host)
    for worker in workers:
        worker.join(timeout=5)
        assert not worker.is_alive()
    entries = []
    while not host.events.empty():
        entries.append(host.events.get_nowait())
    assert entries[0] == ("workload_aliases", [("netcat", "openbsd-netcat")])
    assert entries[1][0:2] == ("package_coverage", ("root",))
    assert entries[1][2][0][0:2] == ("netcat → openbsd-netcat", "Available (learned)")
    assert entries[2] == ("done", True, "Package source coverage complete")
