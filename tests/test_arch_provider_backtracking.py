import arch_core
from core import BuildOptions, RepoSpec, Reporter


def _repo(name="core", priority=40):
    return RepoSpec(
        name, f"https://example.invalid/{name}/os/x86_64/", "dependency", priority,
        repo_format="pacman", suite=name,
    )


def _pkg(name, version="1-1", *, repo=None, depends=(), provides=(), conflicts=()):
    repo = repo or _repo()
    pkg = arch_core.ArchPackage(
        name=name,
        arch="x86_64",
        version=version,
        location=f"{name}-{version}-x86_64.pkg.tar.zst",
        checksum_type="sha256",
        checksum="a" * 64,
        repo=repo,
        digests={"sha256": "a" * 64},
        size=100,
    )
    pkg.depends = [arch_core.parse_relation(value, "depends") for value in depends]
    pkg.provides = [arch_core.parse_relation(value, "provides") for value in provides]
    pkg.conflicts = [arch_core.parse_relation(value, "conflicts") for value in conflicts]
    if not any(value.name == name for value in pkg.provides):
        pkg.provides.append(arch_core.ArchRelation(name, "=", version, "provides"))
    return pkg


def _resolve(packages, root="app"):
    return arch_core.resolve(
        [(root, None, None)], packages, "x86_64", BuildOptions(), Reporter())


def test_arch_provider_backtracks_around_direct_conflict():
    packages = [
        _pkg("app", depends=("renderer", "database")),
        _pkg("provider-a", provides=("renderer",), conflicts=("database",)),
        _pkg("provider-b", provides=("renderer",)),
        _pkg("database"),
    ]

    result = _resolve(packages)

    assert not result.unresolved
    assert not result.conflicts
    assert {pkg.name for pkg in result.selected} == {"app", "provider-b", "database"}
    assert result.provider_choices
    assert result.provider_choices[0][0] == "renderer"
    assert "provider-b" in result.provider_choices[0][1]


def test_arch_provider_backtracks_when_conflict_is_transitive():
    packages = [
        _pkg("app", depends=("renderer", "database")),
        _pkg("provider-a", provides=("renderer",), depends=("helper",)),
        _pkg("provider-b", provides=("renderer",)),
        _pkg("helper", conflicts=("database",)),
        _pkg("database"),
    ]

    result = _resolve(packages)

    assert not result.unresolved
    assert not result.conflicts
    assert {pkg.name for pkg in result.selected} == {"app", "provider-b", "database"}


def test_arch_provider_backtracking_distinguishes_versions_of_same_package():
    packages = [
        _pkg("app", depends=("renderer", "database")),
        _pkg("renderer-bridge", "2-1", provides=("renderer",), conflicts=("database",)),
        _pkg("renderer-bridge", "1-1", provides=("renderer",)),
        _pkg("database"),
    ]

    result = _resolve(packages)

    assert not result.unresolved
    chosen = next(pkg for pkg in result.selected if pkg.name == "renderer-bridge")
    assert chosen.version == "1-1"
    assert result.provider_choices
    assert "renderer-bridge-1-1" in result.provider_choices[0][1]
    assert any("renderer-bridge-2-1" in value for value in result.provider_choices[0][2])


def test_arch_provider_search_handles_interacting_choices():
    packages = [
        _pkg("app", depends=("renderer", "storage")),
        _pkg("render-a", provides=("renderer",), conflicts=("store-a",)),
        _pkg("render-b", provides=("renderer",), conflicts=("store-b",)),
        _pkg("store-a", provides=("storage",)),
        _pkg("store-b", provides=("storage",)),
    ]

    result = _resolve(packages)

    assert not result.unresolved
    assert not result.conflicts
    names = {pkg.name for pkg in result.selected}
    assert names in (
        {"app", "render-a", "store-b"},
        {"app", "render-b", "store-a"},
    )


def test_arch_provider_search_fails_closed_when_every_provider_conflicts():
    packages = [
        _pkg("app", depends=("renderer", "database")),
        _pkg("provider-a", provides=("renderer",), conflicts=("database",)),
        _pkg("provider-b", provides=("renderer",), conflicts=("database",)),
        _pkg("database"),
    ]

    result = _resolve(packages)

    assert result.unresolved
    assert any(req.name == "renderer" for req in result.unresolved)
    note = result.unresolved_notes["renderer"]
    assert "cannot coexist with the selected transaction" in note


def test_arch_explicit_root_conflicts_keep_existing_review_semantics():
    packages = [
        _pkg("root-a", conflicts=("root-b",)),
        _pkg("root-b"),
    ]

    result = arch_core.resolve(
        [("root-a", None, None), ("root-b", None, None)],
        packages,
        "x86_64",
        BuildOptions(),
        Reporter(),
    )

    assert not result.unresolved
    assert result.conflicts
    assert {pkg.name for pkg in result.selected} == {"root-a", "root-b"}


def test_arch_provider_search_backtracks_across_multiple_decisions():
    packages = [
        _pkg("app", depends=("left", "right")),
        _pkg("left-a", provides=("left",), depends=("marker-a",)),
        _pkg("left-b", provides=("left",)),
        _pkg("marker-a"),
        _pkg("right-a", provides=("right",), depends=("helper-a",)),
        _pkg("right-b", provides=("right",), depends=("helper-b",)),
        _pkg("helper-a", conflicts=("marker-a",)),
        _pkg("helper-b", conflicts=("marker-a",)),
    ]

    result = _resolve(packages)

    assert not result.unresolved
    assert not result.conflicts
    names = {pkg.name for pkg in result.selected}
    assert "left-b" in names
    assert "left-a" not in names
    assert names & {"right-a", "right-b"}


def test_arch_provider_search_budget_fails_closed(monkeypatch):
    monkeypatch.setattr(arch_core, "MAX_ARCH_RESOLUTION_STATES", 1)
    packages = [
        _pkg("app", depends=("left", "right")),
        _pkg("left-a", provides=("left",)),
        _pkg("left-b", provides=("left",)),
        _pkg("right-a", provides=("right",)),
        _pkg("right-b", provides=("right",)),
    ]

    try:
        _resolve(packages)
    except RuntimeError as exc:
        assert "provider-search safety budget" in str(exc)
    else:
        raise AssertionError("provider search must not claim completeness after budget exhaustion")


def test_arch_provider_conflict_check_is_symmetric_for_virtual_providers():
    packages = [
        _pkg("app", depends=("renderer",), conflicts=("renderer",)),
        _pkg("provider-a", provides=("renderer",)),
        _pkg("provider-b", provides=("renderer",)),
    ]

    result = _resolve(packages)

    assert result.unresolved
    assert any(req.name == "renderer" for req in result.unresolved)
    assert not any(pkg.name.startswith("provider-") for pkg in result.selected)
