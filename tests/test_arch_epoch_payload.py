"""ALPM epoch filenames must download and publish correctly from Windows.

The tests use a synthetic package stream. They check Feathered's acquisition,
record and pacman-database contracts; they are not a native pacman install test.
"""
from __future__ import annotations

import hashlib
import io
import json
import tarfile

import pytest

import arch_core
import core
from repository_paths import arch_package_basename, is_arch_epoch_filename, repo_relative_url


ORIGINAL = "lz4-1:1.10.0-2-x86_64.pkg.tar.zst"
LOCAL = "lz4-1_epoch_1.10.0-2-x86_64.pkg.tar.zst"
BASE = "https://fastly.mirror.pkgbuild.com/core/os/x86_64/"


def _package(repo, *, name="lz4", version="1:1.10.0-2", location=ORIGINAL, data=b"synthetic archive"):
    digest = hashlib.sha256(data).hexdigest()
    return arch_core.ArchPackage(
        name=name, arch="x86_64", version=version, location=location,
        checksum_type="sha256", checksum=digest, repo=repo,
        digests={"sha256": digest}, size=len(data),
    )


def test_arch_epoch_filename_uses_original_repository_url():
    assert is_arch_epoch_filename(ORIGINAL)
    assert arch_package_basename(ORIGINAL) == ORIGINAL
    assert repo_relative_url(BASE, ORIGINAL) == BASE + ORIGINAL
    assert repo_relative_url(BASE.rstrip("/"), ORIGINAL) == BASE + ORIGINAL
    assert arch_core._arch_bundle_payload_name(ORIGINAL) == LOCAL


def test_arch_epoch_filename_with_query_authenticated_repo():
    repo = core.RepoSpec("Signed mirror", BASE + "?token=repo-secret", repo_format="pacman")
    resolved = repo_relative_url(repo.normalized_url, ORIGINAL, repo)
    assert resolved.startswith(BASE + ORIGINAL)
    assert "token=repo-secret" in resolved


@pytest.mark.parametrize("location", [
    "https://evil.example/lz4.pkg.tar.zst", "//evil.example/lz4.pkg.tar.zst",
    "file:///etc/passwd", "javascript:alert(1)", "C:\\temp\\payload.pkg.tar.zst",
    "../lz4-1:1.10.0-2-x86_64.pkg.tar.zst",
    "%2e%2e%2flz4-1:1.10.0-2-x86_64.pkg.tar.zst",
    "evil:1.10.0-2-x86_64.pkg.tar.zst",
    "lz4-1:http://evil.example/lz4.pkg.tar.zst",
])
def test_epoch_exception_does_not_weaken_origin_confinement(location):
    with pytest.raises(RuntimeError):
        repo_relative_url(BASE, location)


def test_arch_epoch_filename_collision_with_existing_safe_name():
    repo = core.RepoSpec("Fixture", BASE, repo_format="pacman")
    one = _package(repo)
    two = _package(repo, version="1_epoch_1.10.0-2", location=LOCAL)
    with pytest.raises(RuntimeError, match="collision"):
        arch_core._safe_payload_names([one, two])


def test_ordinary_arch_names_remain_unchanged():
    repo = core.RepoSpec("Fixture", BASE, repo_format="pacman")
    pkg = _package(repo, name="nginx", version="1.30.1-1",
                   location="nginx-1.30.1-1-x86_64.pkg.tar.zst")
    assert arch_core._safe_payload_names([pkg])[id(pkg)] == pkg.location


def test_epoch_bundle_includes_download_local_db_and_provenance(tmp_path, monkeypatch):
    """Regression for nginx's lz4 dependency on a Windows build machine."""
    repo = core.RepoSpec(
        "Arch Linux core", BASE, repo_format="pacman", suite="core",
        allow_unverified_index=True,
    )
    content = b"synthetic lz4 archive bytes"
    pkg = _package(repo, data=content)
    result = arch_core.ArchResolutionResult(
        [pkg], [], [pkg], reasons={pkg.nevra: "dependency"},
    )
    urls = []

    class Response(io.BytesIO):
        def __init__(self, payload):
            super().__init__(payload)
            self.headers = {"Content-Length": str(len(payload))}

    def fake_fetch(url, timeout, repo=None):
        urls.append(url)
        assert url == BASE + ORIGINAL
        return Response(content)

    monkeypatch.setattr(core, "_urlopen", fake_fetch)
    output = tmp_path / "bundle"
    meta = {"distribution": "Arch Linux", "release": "rolling", "arch": "x86_64",
            "package_family": "arch", "workload": "nginx", "repositories": [
                {"name": repo.name, "url": repo.normalized_url}],
            "package_only_acquisition": True}
    arch_core.write_bundle(result, output, core.BuildOptions(emit_repository=True),
                           core.Reporter(), meta)

    assert urls == [BASE + ORIGINAL]
    pkg_dir = output / "packages"
    assert (pkg_dir / LOCAL).read_bytes() == content
    manifest = json.loads((pkg_dir / "manifest.json").read_text())
    row = manifest["packages"][0]
    assert row["version"] == "1:1.10.0-2"
    assert row["filename"] == LOCAL
    assert row["source"] == BASE + ORIGINAL
    assert row["sha256"] == hashlib.sha256(content).hexdigest()
    assert LOCAL in (pkg_dir / "SHA256SUMS.txt").read_text()
    assert LOCAL in (pkg_dir / "provenance.json").read_text()

    with tarfile.open(pkg_dir / "feathered.db", "r:gz") as tf:
        desc_name = next(member for member in tf.getmembers() if member.name.endswith("/desc"))
        desc = tf.extractfile(desc_name).read().decode()
    assert f"%FILENAME%\n{LOCAL}\n" in desc
    assert "%VERSION%\n1:1.10.0-2\n" in desc
    assert ORIGINAL not in desc
    assert (pkg_dir / "feathered.db.tar.gz").is_file()


def test_epoch_package_remains_readable_for_additive_repository_rebuild(tmp_path):
    """Renaming the payload must not change its epoch in .PKGINFO or rebuilt DB."""
    import repository_tools

    original = ORIGINAL.replace(".zst", ".gz")
    local = LOCAL.replace(".zst", ".gz")
    package_dir = tmp_path / "packages"
    package_dir.mkdir()
    data = io.BytesIO()
    pkginfo = (
        "pkgname = lz4\n"
        "pkgver = 1:1.10.0-2\n"
        "pkgdesc = Test LZ4\n"
        "arch = x86_64\n"
        "size = 123\n"
    ).encode()
    with tarfile.open(fileobj=data, mode="w:gz") as tf:
        member = tarfile.TarInfo(".PKGINFO")
        member.size = len(pkginfo)
        tf.addfile(member, io.BytesIO(pkginfo))
    (package_dir / local).write_bytes(data.getvalue())

    family, packages = repository_tools.load_local_repository_packages(package_dir, "arch")
    assert family == "arch" and len(packages) == 1
    loaded = packages[0]
    assert loaded.version == "1:1.10.0-2"
    assert loaded.location == local
    arch_core.emit_arch_repository(
        package_dir, packages, core.Reporter(), preserve_package_locations=True,
    )
    with tarfile.open(package_dir / "feathered.db", "r:gz") as tf:
        member = next(item for item in tf.getmembers() if item.name.endswith("/desc"))
        desc = tf.extractfile(member).read().decode()
    assert f"%FILENAME%\n{local}\n" in desc
    assert "%VERSION%\n1:1.10.0-2\n" in desc
    assert original not in desc


def test_maintenance_preserves_existing_linux_epoch_filenames(tmp_path):
    """Rebuilding an existing repo may not silently rename payloads on disk."""
    repo = core.RepoSpec("Fixture", tmp_path.as_uri() + "/", repo_format="pacman")
    pkg = _package(repo)
    arch_core.emit_arch_repository(
        tmp_path, [pkg], core.Reporter(), preserve_package_locations=True,
    )
    with tarfile.open(tmp_path / "feathered.db", "r:gz") as tf:
        member = next(item for item in tf.getmembers() if item.name.endswith("/desc"))
        desc = tf.extractfile(member).read().decode()
    assert f"%FILENAME%\n{ORIGINAL}\n" in desc
    assert "%VERSION%\n1:1.10.0-2\n" in desc
