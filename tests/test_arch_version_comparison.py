import pytest

import arch_core
from core import BuildOptions, RepoSpec, Reporter


def _repo():
    return RepoSpec(
        "core", "https://example.invalid/core/os/x86_64/", "dependency", 40,
        repo_format="pacman", suite="core",
    )


def _pkg(name, version="1.0-1", *, depends=()):
    package = arch_core.ArchPackage(
        name=name,
        arch="x86_64",
        version=version,
        location=f"{name}-{version}-x86_64.pkg.tar.zst",
        checksum_type="sha256",
        checksum="a" * 64,
        repo=_repo(),
        digests={"sha256": "a" * 64},
        size=100,
    )
    package.depends = [arch_core.parse_relation(value, "depends") for value in depends]
    package.provides = [arch_core.ArchRelation(name, "=", version, "provides")]
    return package


def _sign(value):
    return (value > 0) - (value < 0)


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.0.0", "1.1.0", -1),
        ("1.2.0", "1.foo.0", 1),
        ("foo.0", "boo.0", 1),
        ("1.0", "1.0", 0),
        ("alpha0", "beta0", -1),
        ("alpha1", "alpha02", -1),
        ("1alpha0", "2alpha0", -1),
        ("alpha1", "alpha.0", -1),
        ("1...0", "1.2", 1),
        ("1", "1.0", -1),
        ("1", "1.foo", -1),
        ("1.0", "1.0foo.2", 1),
        ("1.foo", "1.foo2", -1),
        ("1...", "1.", 0),
        ("1.", "1.foo.2", 1),
        ("1.", "1.2", -1),
        ("1.", "1.2foo", -1),
        ("1.alpha.", "1.alpha0", -1),
    ],
)
def test_arch_vercmp_matches_alpm_pkgver_documented_cases(left, right, expected):
    assert _sign(arch_core.compare_versions(left, right)) == expected
    assert _sign(arch_core.compare_versions(right, left)) == -expected


def test_arch_vercmp_preserves_delimiter_count_for_equality():
    assert arch_core.compare_versions("1...0", "1.0") > 0
    assert arch_core.compare_versions("1...0-1", "1.0-1") > 0


def test_arch_exact_root_does_not_alias_distinct_delimiter_versions():
    packages = [_pkg("demo", "1...0-1")]

    result = arch_core.resolve(
        [("demo", "1.0-1", None)], packages, "x86_64", BuildOptions(), Reporter())

    assert result.unresolved
    assert not result.selected


def test_arch_versioned_dependency_accepts_alpm_newer_delimiter_version():
    packages = [
        _pkg("foo", depends=("bar>=1.2",)),
        _pkg("bar", "1...0-1"),
    ]

    result = arch_core.resolve(
        [("foo", None, None)], packages, "x86_64", BuildOptions(), Reporter())

    assert not result.unresolved
    assert {package.name for package in result.selected} == {"foo", "bar"}
