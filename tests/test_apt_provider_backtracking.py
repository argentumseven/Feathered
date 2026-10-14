"""APT backtracking must blame only the dependency chain that failed.

APT already tells builds of one package apart, so a broken newest build falls
back to an older one. What it lacked was causality: any unresolved requirement
was blamed on the most recent choice with alternatives, related or not. A
request with one genuinely missing package therefore walked every unrelated
dependency back to its oldest build, one full pass at a time. These tests pin
the repaired attribution and what must not change.
"""
import apt_core
from core import BuildOptions, Reporter
from test_feather import APT_REPO, deb_pkg


def _provides(pkg, *capabilities):
    pkg.provides = [apt_core._parse_atom(value) for value in capabilities]
    return pkg


def _resolve(packages, *, passes=None, log=None):
    options = BuildOptions() if passes is None else BuildOptions(max_resolution_passes=passes)
    reporter = Reporter() if log is None else Reporter(log=log.append)
    return apt_core.resolve([("app", None, None)], packages, "amd64", options, reporter)


def _versions(result):
    return {(pkg.name, pkg.version) for pkg in result.selected}


def _unresolved(result):
    return [requirement.raw or str(requirement) for requirement in result.unresolved]


def _passes(monkeypatch, packages, **kwargs):
    """Run a resolution and report how many dependency passes it took."""
    calls = []
    original = apt_core._resolve_pass

    def counted(*args, **kw):
        calls.append(1)
        return original(*args, **kw)

    monkeypatch.setattr(apt_core, "_resolve_pass", counted)
    result = _resolve(packages, **kwargs)
    return result, len(calls)


def test_unrelated_choices_are_not_walked_back_for_a_genuine_failure(monkeypatch):
    def packages(libfoo_versions):
        return [deb_pkg("app", "1.0", APT_REPO, depends="no-such-package, libfoo"),
                *[deb_pkg("libfoo", f"{v}.0", APT_REPO) for v in libfoo_versions]]
    log = []

    _, control_passes = _passes(monkeypatch, packages([3]))
    result, passes = _passes(monkeypatch, packages([3, 2, 1]), log=log)

    assert _unresolved(result) == ["no-such-package"]
    assert ("libfoo", "3.0") in _versions(result)
    assert not any("trying" in line for line in log)
    # Extra builds of an innocent package cost no extra passes.
    assert passes == control_passes


def test_broken_newest_build_still_falls_back_to_an_older_one():
    result = _resolve([
        deb_pkg("app", "1.0", APT_REPO, depends="helper"),
        deb_pkg("helper", "2.0", APT_REPO, depends="missing-library"),
        deb_pkg("helper", "1.0", APT_REPO),
    ])

    assert not result.unresolved
    assert _versions(result) == {("app", "1.0"), ("helper", "1.0")}


def test_broken_virtual_provider_build_still_falls_back_to_an_older_one():
    result = _resolve([
        deb_pkg("app", "1.0", APT_REPO, depends="feature"),
        _provides(deb_pkg("helper", "2.0", APT_REPO, depends="missing-library"), "feature"),
        _provides(deb_pkg("helper", "1.0", APT_REPO), "feature"),
    ])

    assert not result.unresolved
    assert _versions(result) == {("app", "1.0"), ("helper", "1.0")}


def test_conflicting_newest_build_still_falls_back_to_an_older_one():
    newest = _provides(deb_pkg("helper", "2.0", APT_REPO), "feature")
    newest.conflicts = apt_core.parse_dependency_field("database", "conflicts")
    result = _resolve([
        deb_pkg("app", "1.0", APT_REPO, depends="feature, database"),
        newest,
        _provides(deb_pkg("helper", "1.0", APT_REPO), "feature"),
        deb_pkg("database", "1.0", APT_REPO),
    ])

    assert not result.unresolved and not result.conflicts
    assert _versions(result) == {("app", "1.0"), ("helper", "1.0"), ("database", "1.0")}


def test_only_the_failing_branch_is_replaced_deep_in_the_closure():
    result = _resolve([
        deb_pkg("app", "1.0", APT_REPO, depends="middle, util"),
        deb_pkg("middle", "3.0", APT_REPO, depends="leaf"),
        deb_pkg("middle", "2.0", APT_REPO, depends="leaf"),
        deb_pkg("leaf", "2.0", APT_REPO, depends="missing-library"),
        deb_pkg("leaf", "1.0", APT_REPO),
        deb_pkg("util", "5.0", APT_REPO),
        deb_pkg("util", "4.0", APT_REPO),
    ])

    assert not result.unresolved
    assert _versions(result) == {
        ("app", "1.0"), ("middle", "3.0"), ("leaf", "1.0"), ("util", "5.0")}


def test_failure_is_reported_against_the_most_preferred_candidate():
    result = _resolve([
        deb_pkg("app", "1.0", APT_REPO, depends="helper"),
        deb_pkg("helper", "3.0", APT_REPO, depends="missing-newest"),
        deb_pkg("helper", "2.0", APT_REPO, depends="missing-middle"),
        deb_pkg("helper", "1.0", APT_REPO, depends="missing-oldest"),
    ])

    # Every build fails; the report describes the newest, not the last one tried.
    assert _versions(result) == {("app", "1.0"), ("helper", "3.0")}
    assert _unresolved(result) == ["missing-newest"]


def test_resolved_request_is_unchanged_when_the_newest_build_works():
    log = []

    result = _resolve([
        deb_pkg("app", "1.0", APT_REPO, depends="helper"),
        deb_pkg("helper", "2.0", APT_REPO),
        deb_pkg("helper", "1.0", APT_REPO),
    ], log=log)

    assert _versions(result) == {("app", "1.0"), ("helper", "2.0")}
    assert not any("trying" in line for line in log)


def test_search_is_bounded_by_the_pass_budget():
    packages = [deb_pkg("app", "1.0", APT_REPO, depends="helper")]
    packages += [deb_pkg("helper", f"{v}.0", APT_REPO, depends="missing-library" if v > 1 else "")
                 for v in range(1, 13)]

    short = _resolve(packages, passes=4)
    assert _versions(short) == {("app", "1.0"), ("helper", "12.0")}
    assert _unresolved(short) == ["missing-library"]

    enough = _resolve(packages, passes=16)
    assert not enough.unresolved
    assert _versions(enough) == {("app", "1.0"), ("helper", "1.0")}
