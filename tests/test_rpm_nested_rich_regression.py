"""Regression for enterprise Linux nested rich requirements (issue #3).

Run from Feathered's repository root: pytest -q tests/test_rpm_nested_rich_regression.py
"""

import core
import rpm_resolution as rpm

RICH = (
    "((rpm-build >= 4.14.90 with "
    "(rpm-build < 4.19.90 or rpm-build >= 4.19.91-8)) if rpm-build)"
)


def _package(name, version="1", release="1", requires=()):
    return core.Package(
        name=name, arch="x86_64", epoch="0", version=version,
        release=release, location=name + ".rpm", checksum_type="sha256",
        checksum="0" * 64,
        repo=core.RepoSpec("test", "https://example.invalid/test", repo_format="rpm"),
        requires=list(requires),
    )


def _resolve(packages):
    return core.resolve(
        [("example", None, None)], packages, "x86_64",
        core.BuildOptions(max_resolution_passes=8), core.Reporter(),
    )


def test_nested_rich_parser_exposes_same_package_branches():
    parsed = rpm.parse_nested_rich_if_with_or(core.Requirement(RICH))
    assert parsed is not None
    left, branches, condition = parsed
    assert left.name == "rpm-build" and left.flags == ">="
    assert [b.flags for b in branches] == ["<", ">="]
    assert condition.name == "rpm-build"


def test_nested_rich_resolver_picks_valid_provider_below_excluded_gap():
    app = _package("example", requires=[core.Requirement(RICH)])
    invalid = _package("rpm-build", version="4.19.90")
    valid = _package("rpm-build", version="4.19.1.1")
    result = _resolve([app, invalid, valid])
    assert not result.unresolved, result.unresolved
    assert {(p.name, p.version) for p in result.selected} == {
        ("example", "1"), ("rpm-build", "4.19.1.1")}


def test_nested_rich_resolver_picks_valid_provider_above_excluded_gap():
    app = _package("example", requires=[core.Requirement(RICH)])
    invalid = _package("rpm-build", version="4.19.90")
    valid = _package("rpm-build", version="4.19.91", release="8")
    result = _resolve([app, invalid, valid])
    assert not result.unresolved, result.unresolved
    assert any(p.name == "rpm-build" and p.version == "4.19.91"
               for p in result.selected)


def test_nested_rich_without_matching_single_package_fails_closed():
    app = _package("example", requires=[core.Requirement(RICH)])
    invalid = _package("rpm-build", version="4.19.90")
    result = _resolve([app, invalid])
    assert result.unresolved
    assert any(r.name == RICH for r in result.unresolved)


def test_other_unsupported_nested_grammar_still_fails_closed():
    unknown = core.Requirement("((a and b) unless c)")
    assert rpm.parse_nested_rich_if_with_or(unknown) is None
