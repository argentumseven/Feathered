from __future__ import annotations

import io
import hashlib
import os
from pathlib import Path

import apt_core
import openpgp_verifier
import rpm_metadata
import rpm_resolution
import trusted_receiver
from core import BuildOptions, Package, RepoSpec, RepoTrust, Reporter, Requirement


def _rpm_pkg(repo: RepoSpec, name: str, *, provides=(), requires=(), conflicts=()) -> Package:
    package_provides = [Requirement(name, "EQ", "0", "1", "1", "provides")]
    package_provides.extend(Requirement(value, kind="provides") for value in provides)
    return Package(
        name=name,
        arch="x86_64",
        epoch="0",
        version="1",
        release="1",
        location=f"{name}.rpm",
        checksum_type="sha256",
        checksum="a" * 64,
        repo=repo,
        provides=package_provides,
        requires=[Requirement(value, kind="requires") for value in requires],
        conflicts=[Requirement(value, kind="conflicts") for value in conflicts],
    )


def _deb_pkg(repo: RepoSpec, name: str, *, provides=(), depends=(), conflicts=()) -> apt_core.DebPackage:
    package = apt_core.DebPackage(
        name=name,
        arch="amd64",
        version="1",
        location=f"{name}.deb",
        checksum_type="sha256",
        checksum="a" * 64,
        repo=repo,
    )
    package.provides = [
        atom for value in provides if (atom := apt_core._parse_atom(value)) is not None
    ]
    package.depends = [apt_core.parse_dependency_field(value, "depends")[0] for value in depends]
    package.conflicts = [apt_core.parse_dependency_field(value, "conflicts")[0] for value in conflicts]
    return package


def test_source_identity_excludes_url_credentials_and_secret_query_values() -> None:
    first = RepoSpec(
        "private",
        "https://alice:password-one@example.invalid/repo?token=token-one&channel=stable&license_key=abc",
        sensitive_query_keys=["license_key"],
    )
    second = RepoSpec(
        "private",
        "https://bob:password-two@example.invalid/repo?license_key=xyz&channel=stable&token=token-two",
        sensitive_query_keys=["license_key"],
    )
    changed_repository = RepoSpec(
        "private",
        "https://bob:password-two@example.invalid/repo?license_key=xyz&channel=edge&token=token-two",
        sensitive_query_keys=["license_key"],
    )

    assert first.source_identity == second.source_identity
    assert first.source_identity != changed_repository.source_identity
    assert "alice" not in first.identity_url
    assert "password-one" not in first.identity_url
    assert "token-one" not in first.identity_url
    assert "abc" not in first.identity_url
    assert "channel=stable" in first.identity_url


def test_gpg_backend_never_falls_back_to_ordinary_gpg(monkeypatch) -> None:
    monkeypatch.setattr(openpgp_verifier, "bundled_gpg_dir", lambda: None)
    monkeypatch.setattr(openpgp_verifier.sys, "frozen", False, raising=False)
    monkeypatch.setattr(
        openpgp_verifier.shutil,
        "which",
        lambda name: "/usr/bin/gpg" if name == "gpg" else None,
    )
    assert openpgp_verifier.gpg_backend() is None


def test_verify_openpgp_rejects_injected_gpg_backend(tmp_path: Path) -> None:
    keyring = tmp_path / "keyring.gpg"
    keyring.write_bytes(b"not-used")
    try:
        openpgp_verifier.verify_openpgp(
            b"payload",
            b"signature",
            str(keyring),
            "fixture",
            Reporter(),
            backend_fn=lambda: "/usr/bin/gpg",
        )
    except RuntimeError as exc:
        assert "requires gpgv" in str(exc)
    else:
        raise AssertionError("ordinary gpg was accepted as a verification backend")


def test_rpm_resolver_backtracks_on_conflicting_provider() -> None:
    repo = RepoSpec("rpm", "https://example.invalid/rpm/")
    packages = [
        _rpm_pkg(repo, "root-one", requires=("virtual-x",)),
        _rpm_pkg(repo, "c"),
        _rpm_pkg(repo, "provider-a", provides=("virtual-x",), conflicts=("c",)),
        _rpm_pkg(repo, "provider-b", provides=("virtual-x",)),
    ]

    result = rpm_resolution.resolve(
        [("root-one", None, None), ("c", None, None)],
        packages,
        "x86_64",
        BuildOptions(),
        Reporter(),
    )

    assert not result.unresolved
    assert not result.conflicts
    assert {package.name for package in result.selected} == {"root-one", "c", "provider-b"}


def test_rpm_explicit_root_conflict_is_not_hidden_by_backtracking() -> None:
    repo = RepoSpec("rpm", "https://example.invalid/rpm/")
    packages = [
        _rpm_pkg(repo, "root-a", conflicts=("root-b",)),
        _rpm_pkg(repo, "root-b"),
    ]
    result = rpm_resolution.resolve(
        [("root-a", None, None), ("root-b", None, None)],
        packages,
        "x86_64",
        BuildOptions(),
        Reporter(),
    )
    assert result.conflicts
    assert {package.name for package in result.selected} == {"root-a", "root-b"}


def test_rpm_resolver_backtracks_when_provider_dependency_conflicts() -> None:
    repo = RepoSpec("rpm", "https://example.invalid/rpm/")
    packages = [
        _rpm_pkg(repo, "root-one", requires=("virtual-x",)),
        _rpm_pkg(repo, "c"),
        _rpm_pkg(repo, "provider-a", provides=("virtual-x",), requires=("helper",)),
        _rpm_pkg(repo, "provider-b", provides=("virtual-x",)),
        _rpm_pkg(repo, "helper", conflicts=("c",)),
    ]
    result = rpm_resolution.resolve(
        [("root-one", None, None), ("c", None, None)],
        packages,
        "x86_64",
        BuildOptions(),
        Reporter(),
    )
    assert not result.conflicts
    assert {package.name for package in result.selected} == {"root-one", "c", "provider-b"}


def test_apt_resolver_backtracks_on_conflicting_provider() -> None:
    repo = RepoSpec(
        "apt",
        "https://example.invalid/apt/",
        repo_format="apt",
        suite="stable",
        components="main",
    )
    packages = [
        _deb_pkg(repo, "root-one", depends=("virtual-x",)),
        _deb_pkg(repo, "c"),
        _deb_pkg(repo, "provider-a", provides=("virtual-x",), conflicts=("c",)),
        _deb_pkg(repo, "provider-b", provides=("virtual-x",)),
    ]

    result = apt_core.resolve(
        [("root-one", None, None), ("c", None, None)],
        packages,
        "amd64",
        BuildOptions(),
        Reporter(),
    )

    assert not result.unresolved
    assert not result.conflicts
    assert {package.name for package in result.selected} == {"root-one", "c", "provider-b"}


def test_apt_resolver_backtracks_when_provider_dependency_conflicts() -> None:
    repo = RepoSpec(
        "apt",
        "https://example.invalid/apt/",
        repo_format="apt",
        suite="stable",
        components="main",
    )
    packages = [
        _deb_pkg(repo, "root-one", depends=("virtual-x",)),
        _deb_pkg(repo, "c"),
        _deb_pkg(repo, "provider-a", provides=("virtual-x",), depends=("helper",)),
        _deb_pkg(repo, "provider-b", provides=("virtual-x",)),
        _deb_pkg(repo, "helper", conflicts=("c",)),
    ]
    result = apt_core.resolve(
        [("root-one", None, None), ("c", None, None)],
        packages,
        "amd64",
        BuildOptions(),
        Reporter(),
    )
    assert not result.conflicts
    assert {package.name for package in result.selected} == {"root-one", "c", "provider-b"}


def test_rpm_primary_parser_does_not_retain_duplicate_raw_xml() -> None:
    repo = RepoSpec("rpm", "https://example.invalid/rpm/")
    xml = b'''<?xml version="1.0"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">
  <package type="rpm">
    <name>demo</name><arch>x86_64</arch>
    <version epoch="0" ver="1" rel="1"/>
    <checksum type="sha256" pkgid="YES">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</checksum>
    <size package="1"/><location href="demo.rpm"/>
    <format><rpm:provides><rpm:entry name="demo" flags="EQ" epoch="0" ver="1" rel="1"/></rpm:provides></format>
  </package>
</metadata>'''
    packages = rpm_metadata.parse_primary(
        io.BytesIO(xml),
        repo,
        {"x86_64"},
        Reporter(),
        normalized_hash_algorithm_fn=lambda value: value,
        select_digest_from_map_fn=lambda values, _preference: ("sha256", values["sha256"]),
        repo_trust_fn=lambda _repo: RepoTrust(repo="rpm"),
    )
    assert len(packages) == 1
    assert packages[0].raw_metadata == ""


def test_deb822_stream_parser_does_not_build_a_record_list() -> None:
    stream = io.StringIO("Package: one\nVersion: 1\n\nPackage: two\nVersion: 2\n\n")
    records = apt_core._iter_deb822(stream)
    assert not isinstance(records, list)
    assert [record["Package"] for record in records] == ["one", "two"]


def test_deb822_binary_line_reader_rejects_oversized_line_before_full_decode() -> None:
    stream = io.BytesIO(b"abcdef\n")
    try:
        list(apt_core._decoded_metadata_lines(stream, max_line_chars=1))
    except RuntimeError as exc:
        assert "line longer" in str(exc)
    else:
        raise AssertionError("oversized Deb822 line was accepted")


def test_apt_loader_bounds_aggregate_retained_stanza_text(monkeypatch) -> None:
    repo = RepoSpec(
        "apt",
        "https://example.invalid/apt/",
        repo_format="apt",
        suite="stable",
        components="main",
    )
    packages = (
        b"Package: demo\nVersion: 1\nArchitecture: amd64\nFilename: pool/demo.deb\n"
        b"SHA256: " + b"a" * 64 + b"\nDescription: deliberately-long-retained-field\n\n"
    )
    digest = hashlib.sha256(packages).hexdigest()
    monkeypatch.setattr(
        apt_core,
        "_fetch_release",
        lambda _repo, _reporter: (
            {"Components": "main", "Architectures": "amd64"},
            {"main/binary-amd64/Packages": ("sha256", digest, len(packages))},
        ),
    )
    monkeypatch.setattr(apt_core, "_fetch_index_bytes", lambda *args, **kwargs: packages)
    monkeypatch.setattr(apt_core, "MAX_RETAINED_METADATA_CHARS", 16)
    try:
        apt_core._load_repository_once(repo, {"amd64"}, Reporter())
    except RuntimeError as exc:
        assert "retained Packages stanza text" in str(exc)
    else:
        raise AssertionError("APT retained metadata aggregate limit was not enforced")


def test_receiver_bootstrap_uses_resolved_trusted_gpgv(monkeypatch, tmp_path: Path) -> None:
    directory = tmp_path / "bundle"
    directory.mkdir()
    for name in ("bundle-index.json", "verify-bundle.py"):
        (directory / name).write_bytes(b"x")
        (directory / f"{name}.asc").write_bytes(b"sig")
    keyring = tmp_path / "operator.gpg"
    keyring.write_bytes(b"key")
    calls = []
    monkeypatch.setattr(trusted_receiver, "_trusted_gpgv", lambda: "/trusted/usr/bin/gpgv")
    monkeypatch.setattr(
        trusted_receiver.subprocess,
        "run",
        lambda argv, **kwargs: calls.append((argv, kwargs)),
    )

    trusted_receiver._authenticate_bootstrap(directory, keyring)

    assert len(calls) == 2
    assert all(call[0][0] == "/trusted/usr/bin/gpgv" for call in calls)


def test_receiver_rejects_relative_gpgv_configuration(monkeypatch) -> None:
    monkeypatch.setenv("FEATHERED_GPGV", "gpgv")
    try:
        trusted_receiver._trusted_gpgv()
    except RuntimeError as exc:
        assert "absolute" in str(exc)
    else:
        raise AssertionError("receiver accepted PATH-relative gpgv configuration")
