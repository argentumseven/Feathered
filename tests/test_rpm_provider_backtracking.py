"""RPM provider backtracking must distinguish exact candidates, not package names.

A newer build of a package can be uninstallable (missing dependency, conflict)
while an older build of the *same name* is fine. The retry bookkeeping used to
collapse candidates to package names, so there was nothing to retry. These tests
pin the repaired behaviour and, just as importantly, what must NOT change:
requests that resolve first time, roots, and failures unrelated to a choice.
"""
import core
from core import BuildOptions, Reporter, Requirement
from test_feather import rpm_pkg


def _provides(pkg, capability):
    pkg.provides.append(Requirement(capability, None, None, None, None, "provides"))
    return pkg


def _resolve(packages, root="app", *, passes=None, log=None):
    options = BuildOptions() if passes is None else BuildOptions(max_resolution_passes=passes)
    reporter = Reporter() if log is None else Reporter(log=log.append)
    return core.resolve([(root, None, None)], packages, "x86_64", options, reporter)


def _index_builds(log):
    return sum(1 for line in log if line == "Building provider index...")


def _name_versions(result):
    return {(pkg.name, pkg.version) for pkg in result.selected}


def test_virtual_provider_falls_back_to_older_build_of_same_package():
    packages = [
        rpm_pkg("app", "1.0", [Requirement("virtual-feature")]),
        _provides(rpm_pkg("helper", "2.0", [Requirement("missing-library")]), "virtual-feature"),
        _provides(rpm_pkg("helper", "1.0"), "virtual-feature"),
    ]

    result = _resolve(packages)

    assert not result.unresolved and not result.conflicts
    assert _name_versions(result) == {("app", "1.0"), ("helper", "1.0")}


def test_direct_dependency_falls_back_to_older_build():
    packages = [
        rpm_pkg("app", "1.0", [Requirement("helper")]),
        rpm_pkg("helper", "2.0", [Requirement("missing-library")]),
        rpm_pkg("helper", "1.0"),
    ]

    result = _resolve(packages)

    assert not result.unresolved
    assert _name_versions(result) == {("app", "1.0"), ("helper", "1.0")}


def test_conflicting_newest_build_falls_back_to_older_build():
    newest = _provides(rpm_pkg("helper", "2.0"), "virtual-feature")
    newest.conflicts = [Requirement("database")]
    packages = [
        rpm_pkg("app", "1.0", [Requirement("virtual-feature"), Requirement("database")]),
        newest,
        _provides(rpm_pkg("helper", "1.0"), "virtual-feature"),
        rpm_pkg("database", "1.0"),
    ]

    result = _resolve(packages)

    assert not result.unresolved and not result.conflicts
    assert _name_versions(result) == {("app", "1.0"), ("helper", "1.0"), ("database", "1.0")}


def test_fallback_is_found_deep_in_the_closure_and_leaves_other_choices_alone():
    packages = [
        rpm_pkg("app", "1.0", [Requirement("middle"), Requirement("util")]),
        rpm_pkg("middle", "3.0", [Requirement("leaf")]),
        rpm_pkg("middle", "2.0", [Requirement("leaf")]),
        rpm_pkg("leaf", "2.0", [Requirement("missing-library")]),
        rpm_pkg("leaf", "1.0"),
        rpm_pkg("util", "5.0"),
        rpm_pkg("util", "4.0"),
    ]

    result = _resolve(packages)

    assert not result.unresolved
    # Only the build that actually failed is replaced; the newest of everything
    # else is kept even though older builds exist.
    assert _name_versions(result) == {
        ("app", "1.0"), ("middle", "3.0"), ("leaf", "1.0"), ("util", "5.0")}


def test_fallback_is_explained_in_the_selection_reason():
    packages = [
        rpm_pkg("app", "1.0", [Requirement("helper")]),
        rpm_pkg("helper", "2.0", [Requirement("missing-library")]),
        rpm_pkg("helper", "1.0"),
    ]

    result = _resolve(packages)

    older = next(pkg for pkg in result.selected if pkg.name == "helper")
    reason = result.reasons[older.nevra]
    assert reason.startswith("required by app: helper")
    assert "selected instead of helper-2.0-1.el9.x86_64" in reason


def test_same_nevra_from_two_sources_is_two_candidates():
    broken_repo = core.RepoSpec("Broken", "https://fixture.invalid/broken/")
    sound_repo = core.RepoSpec("Sound", "https://fixture.invalid/sound/")
    packages = [
        rpm_pkg("app", "1.0", [Requirement("helper")]),
        rpm_pkg("helper", "2.0", [Requirement("missing-library")], repo=broken_repo),
        rpm_pkg("helper", "2.0", repo=sound_repo),
    ]

    result = _resolve(packages)

    assert not result.unresolved
    helper = next(pkg for pkg in result.selected if pkg.name == "helper")
    assert helper.repo.source_identity == sound_repo.source_identity


def test_requested_root_is_not_silently_downgraded():
    # Backtracking applies to dependencies. A root the operator asked for by
    # name stays at the best candidate and reports why it cannot be completed,
    # as DNF does by default.
    packages = [
        rpm_pkg("helper", "2.0", [Requirement("missing-library")]),
        rpm_pkg("helper", "1.0"),
    ]

    result = _resolve(packages, root="helper")

    assert _name_versions(result) == {("helper", "2.0")}
    assert [req.name for req in result.unresolved] == ["missing-library"]


def test_version_floor_still_limits_the_fallback():
    packages = [
        rpm_pkg("app", "1.0", [Requirement("helper", "GE", "0", "1.5", "1.el9")]),
        rpm_pkg("helper", "2.0", [Requirement("missing-library")]),
        rpm_pkg("helper", "1.0"),
    ]

    result = _resolve(packages)

    # helper-1.0 does not meet the stated floor, so it is never a candidate.
    assert _name_versions(result) == {("app", "1.0"), ("helper", "2.0")}
    assert [req.name for req in result.unresolved] == ["missing-library"]


def test_unrelated_choices_are_not_walked_back_for_a_genuine_failure():
    # `missing-library` exists nowhere, so no provider choice can fix it. The
    # other dependency has several older builds; none of them is to blame and
    # none may be retried, or a failed request would drift to ancient versions
    # of unrelated packages (and cost a full pass each time).
    def packages(libfoo_versions):
        return [rpm_pkg("app", "1.0", [Requirement("missing-library"), Requirement("libfoo")]),
                *[rpm_pkg("libfoo", f"{v}.0") for v in libfoo_versions]]
    control_log, log = [], []

    _resolve(packages([3]), log=control_log)
    result = _resolve(packages([3, 2, 1]), log=log)

    assert [req.name for req in result.unresolved] == ["missing-library"]
    assert ("libfoo", "3.0") in _name_versions(result)
    assert not any("trying" in line for line in log)
    # Extra versions of an innocent package cost no extra passes.
    assert _index_builds(log) == _index_builds(control_log)


def test_failure_is_reported_against_the_most_preferred_candidate():
    packages = [
        rpm_pkg("app", "1.0", [Requirement("helper")]),
        rpm_pkg("helper", "3.0", [Requirement("missing-newest")]),
        rpm_pkg("helper", "2.0", [Requirement("missing-middle")]),
        rpm_pkg("helper", "1.0", [Requirement("missing-oldest")]),
    ]

    result = _resolve(packages)

    # Every candidate fails; the report describes the newest, not the last tried.
    assert _name_versions(result) == {("app", "1.0"), ("helper", "3.0")}
    assert [req.name for req in result.unresolved] == ["missing-newest"]


def test_resolved_request_is_unchanged_when_the_newest_build_works():
    packages = [
        rpm_pkg("app", "1.0", [Requirement("helper")]),
        rpm_pkg("helper", "2.0"),
        rpm_pkg("helper", "1.0"),
    ]
    log = []

    result = _resolve(packages, log=log)

    assert _name_versions(result) == {("app", "1.0"), ("helper", "2.0")}
    newest = next(pkg for pkg in result.selected if pkg.name == "helper")
    assert "selected instead of" not in result.reasons[newest.nevra]
    assert not any("trying" in line for line in log)


def test_search_is_bounded_by_the_pass_budget():
    versions = range(1, 13)
    packages = [rpm_pkg("app", "1.0", [Requirement("helper")])]
    packages += [rpm_pkg("helper", f"{v}.0", [Requirement("missing-library")] if v > 1 else [])
                 for v in versions]

    # Eleven broken builds sit above the working one. A small budget stops
    # honestly and reports the preferred failure; a sufficient budget finds it.
    short = _resolve(packages, passes=4)
    assert _name_versions(short) == {("app", "1.0"), ("helper", "12.0")}
    assert [req.name for req in short.unresolved] == ["missing-library"]

    enough = _resolve(packages, passes=16)
    assert not enough.unresolved
    assert _name_versions(enough) == {("app", "1.0"), ("helper", "1.0")}
