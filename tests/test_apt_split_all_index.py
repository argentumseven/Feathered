"""Signed APT indexes can publish Architecture: all separately from the target arch."""
import hashlib
import lzma

import pytest

import apt_core
from core import Reporter, RepoSpec


def _stanza(name: str, arch: str, *, depends: str = "") -> bytes:
    fields = [
        f"Package: {name}", "Version: 1", f"Architecture: {arch}",
        f"Filename: pool/{name}_1_{arch}.deb", "Size: 4",
        f"SHA256: {hashlib.sha256(name.encode()).hexdigest()}",
    ]
    if depends:
        fields.append(f"Depends: {depends}")
    return ("\n".join(fields) + "\n\n").encode()


@pytest.fixture
def split_archive(monkeypatch):
    root = "https://example.invalid/merged/dists/excalibur/"
    arch_bytes = lzma.compress(_stanza("container-tool", "amd64", depends="debconf"))
    all_bytes = lzma.compress(_stanza("debconf", "all"))
    paths = {
        "main/binary-amd64/Packages.xz": arch_bytes,
        "main/binary-all/Packages.xz": all_bytes,
    }
    manifest = "".join(
        f" {hashlib.sha256(payload).hexdigest()} {len(payload)} {path}\n"
        for path, payload in paths.items()
    )
    release = ("Origin: Devuan\nSuite: excalibur\nCodename: excalibur\n"
               "Architectures: amd64 all\nComponents: main\nAcquire-By-Hash: yes\n"
               f"SHA256:\n{manifest}").encode()
    objects = {root + "InRelease": release}
    for path, payload in paths.items():
        pinned = (path.rsplit("/", 1)[0] + "/by-hash/SHA256/"
                  + hashlib.sha256(payload).hexdigest())
        objects[root + pinned] = payload
    calls = []

    def fake_fetch(url, *_args, **_kwargs):
        calls.append(url)
        value = objects.get(url)
        if value is None:
            raise FileNotFoundError(url)
        return value

    monkeypatch.setattr(apt_core, "fetch_bytes", fake_fetch)
    repo = RepoSpec("Devuan excalibur", "https://example.invalid/merged",
                    repo_format="apt", suite="excalibur", components="main",
                    verification_strategy="checksum-available")
    return repo, paths, objects, calls, root


def test_signed_split_binary_all_is_loaded_for_amd64(split_archive):
    repo, _paths, _objects, calls, _root = split_archive
    packages = apt_core._load_repository_once(repo, {"amd64"}, Reporter())
    assert {(p.name, p.arch) for p in packages} == {
        ("container-tool", "amd64"), ("debconf", "all")}
    assert all(p.verification and p.verification.index_digest_verified for p in packages)
    assert any("/binary-all/by-hash/SHA256/" in url for url in calls)
    outcome = apt_core.resolve([("container-tool", None, None)], packages, "amd64",
                               apt_core.BuildOptions(), Reporter())
    assert not outcome.unresolved


def test_split_indexes_deduplicate_identical_arch_all_packages(split_archive):
    repo, paths, objects, calls, root = split_archive
    original = paths["main/binary-amd64/Packages.xz"]
    duplicated = lzma.compress(_stanza("container-tool", "amd64", depends="debconf")
                                 + _stanza("debconf", "all"))
    old_digest = hashlib.sha256(original).hexdigest()
    new_digest = hashlib.sha256(duplicated).hexdigest()
    path = "main/binary-amd64/Packages.xz"
    objects[root + "InRelease"] = objects[root + "InRelease"].replace(
        f"{old_digest} {len(original)}".encode(),
        f"{new_digest} {len(duplicated)}".encode())
    objects[root + "main/binary-amd64/by-hash/SHA256/" + new_digest] = duplicated
    packages = apt_core._load_repository_once(repo, {"amd64"}, Reporter())
    assert [p.name for p in packages].count("debconf") == 1
    assert any("/binary-all/by-hash/SHA256/" in url for url in calls)


def test_conflicting_records_across_split_indexes_fail_closed(split_archive):
    repo, paths, objects, _calls, root = split_archive
    original = paths["main/binary-amd64/Packages.xz"]
    conflicted = lzma.compress(_stanza("container-tool", "amd64", depends="debconf")
                                + _stanza("debconf", "all").replace(b"Size: 4", b"Size: 5"))
    old_digest = hashlib.sha256(original).hexdigest()
    new_digest = hashlib.sha256(conflicted).hexdigest()
    objects[root + "InRelease"] = objects[root + "InRelease"].replace(
        f"{old_digest} {len(original)}".encode(),
        f"{new_digest} {len(conflicted)}".encode())
    objects[root + "main/binary-amd64/by-hash/SHA256/" + new_digest] = conflicted
    with pytest.raises(RuntimeError, match="conflicting metadata for duplicate APT package"):
        apt_core._load_repository_once(repo, {"amd64"}, Reporter())


def test_bad_signed_arch_all_index_is_rejected(split_archive):
    repo, paths, objects, _calls, root = split_archive
    index = paths["main/binary-all/Packages.xz"]
    pinned = root + "main/binary-all/by-hash/SHA256/" + hashlib.sha256(index).hexdigest()
    objects[pinned] = b"tampered"
    with pytest.raises(RuntimeError, match="metadata size mismatch"):
        apt_core._load_repository_once(repo, {"amd64"}, Reporter())
