"""Repository verification lifetime and transactional publication workflows."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

import apt_core
import arch_core
import artifact_verification
import bundle_sealing
import core
import publication_staging
import repository_tools
import rpm_bundle

FAMILIES = {
    "rpm": (core, "rpms", ".rpm", "x86_64"),
    "deb": (apt_core, "debs", ".deb", "amd64"),
    "arch": (arch_core, "packages", ".pkg.tar.gz", "x86_64"),
}


def package_fixture(tmp_path, family, name="demo", arch=None):
    backend, directory, suffix, default_arch = FAMILIES[family]
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    filename = name + suffix
    content = (name + " package payload\n").encode()
    (source / filename).write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    repo = core.RepoSpec(
        "Fixture", source.as_uri() + "/",
        repo_format={"rpm": "rpm", "deb": "apt", "arch": "pacman"}[family],
        suite="feathered", components="main",
    )
    if family == "rpm":
        package = core.Package(name, arch or default_arch, "0", "1", "1", filename,
                               "sha256", digest, repo, size=len(content))
        result = core.ResolutionResult([package], [], [package])
    elif family == "deb":
        package = apt_core.DebPackage(name, arch or default_arch, "1", filename,
                                     "sha256", digest, repo, size=len(content))
        result = apt_core.DebResolutionResult([package], [], [package])
    else:
        package = arch_core.ArchPackage(name, arch or default_arch, "1-1", filename,
                                       "sha256", digest, repo, size=len(content),
                                       digests={"sha256": digest})
        result = arch_core.ArchResolutionResult([package], [], [package])
    metadata = {"arch": default_arch, "package_family": family}
    return backend, directory, source, package, result, metadata


@contextmanager
def staging_session(destination):
    reporter = core.Reporter()
    with publication_staging.staging_scope(destination, reporter) as staging:
        yield staging, reporter


@pytest.mark.parametrize("family", ("rpm", "deb"))
@pytest.mark.parametrize("policy", ("no-keyring", "skip-provenance"))
def test_new_metadata_cannot_inherit_an_old_signature(tmp_path, monkeypatch, family, policy):
    backend, _, source, package, _, metadata = package_fixture(tmp_path, family)
    repo = package.repo
    repo.keyring = "fixture-keyring"
    calls = []
    monkeypatch.setattr(backend, "verify_openpgp", lambda *args: calls.append(args))

    def emit():
        if family == "deb":
            apt_core.emit_apt_repository(source, [package], core.Reporter(),
                                        preserve_package_locations=True)
            return source / "dists" / "feathered" / "Release.gpg"
        core.emit_rpm_repository(source, [package], core.Reporter(),
                                 preserve_package_locations=True)
        return source / "repodata" / "repomd.xml.asc"

    signature = emit()
    signature.write_bytes(b"fixture signature")
    old_packages = backend.load_repository(repo, {metadata["arch"]}, core.Reporter())
    assert repo.trust.archive_signature_verified
    assert artifact_verification.artifact_archive_signature_verified(old_packages[0])
    previous_calls = len(calls)

    if policy == "no-keyring":
        repo.keyring = ""
    else:
        repo.verification_strategy = "skip-provenance"
    signature.unlink()
    content = b"changed unsigned package\n"
    (source / package.location).write_bytes(content)
    package.checksum = hashlib.sha256(content).hexdigest()
    package.size = len(content)
    emit()
    new_packages = backend.load_repository(repo, {metadata["arch"]}, core.Reporter())

    assert len(calls) == previous_calls
    assert repo.trust.archive_signature_verified is False
    assert not artifact_verification.artifact_archive_signature_verified(new_packages[0])
    assert artifact_verification.artifact_archive_signature_verified(old_packages[0])
    if family == "deb":
        result = apt_core.DebResolutionResult(new_packages, [], new_packages)
        output = tmp_path / "bundle"
        apt_core.write_bundle(result, output, core.BuildOptions(emit_repository=True),
                              core.Reporter(), metadata)
        record = json.loads((output / "debs" / "provenance.json").read_text())["packages"][0]
        assert record["archive_signature_verified"] is False
        assert record["assurance"] != "archive-chain"
        assert "FEATHERED_ALLOW_UNSIGNED" in (output / "install-offline.sh").read_text()


@pytest.mark.parametrize("family", ("rpm", "deb"))
def test_failed_probe_drops_old_verification_facts(tmp_path, monkeypatch, family):
    backend, _, _, package, _, _ = package_fixture(tmp_path, family)
    repo = package.repo
    repo.trust = core.RepoTrust(repo=repo.name, archive_signature_verified=True,
                               metadata_digest_verified=True, notes=["previous load"])

    def unavailable(*args, **kwargs):
        raise OSError("metadata unavailable")

    monkeypatch.setattr(backend, "fetch_bytes", unavailable)
    assert backend.probe_repository(repo, core.Reporter())[0] is False
    assert repo.trust.archive_signature_verified is False
    assert repo.trust.metadata_digest_verified is False
    assert repo.trust.notes == []


def test_an_unsigned_package_does_not_gain_trust_from_a_later_probe(tmp_path, monkeypatch):
    _, _, source, package, _, _ = package_fixture(tmp_path, "deb")
    repo = package.repo
    apt_core.emit_apt_repository(source, [package], core.Reporter(),
                                preserve_package_locations=True)
    packages = apt_core.load_repository(repo, {"amd64"}, core.Reporter())
    repo.keyring = "fixture-keyring"
    (source / "dists" / "feathered" / "Release.gpg").write_bytes(b"fixture signature")
    monkeypatch.setattr(apt_core, "verify_openpgp", lambda *args: None)
    assert apt_core.probe_repository(repo, core.Reporter())[0]
    assert repo.trust.archive_signature_verified
    assert not artifact_verification.artifact_archive_signature_verified(packages[0])


@pytest.mark.parametrize("relative", ("debs/manifest.json", "install-offline.sh", "debs", "notes.txt"))
def test_existing_links_are_rejected_before_bundle_writes(tmp_path, relative):
    backend, _, _, _, result, metadata = package_fixture(tmp_path, "deb")
    output = tmp_path / "bundle"
    output.mkdir()
    link = output / relative
    link.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    if relative == "debs":
        outside.mkdir()
        sentinel = outside / "manifest.json"
    else:
        sentinel = outside
    sentinel.write_bytes(b"unchanged")
    try:
        link.symlink_to(outside, target_is_directory=relative == "debs")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlink creation is unavailable: {exc}")
    with pytest.raises(RuntimeError, match="symlink or reparse point"):
        backend.write_bundle(result, output, core.BuildOptions(emit_repository=False),
                             core.Reporter(), metadata)
    assert sentinel.read_bytes() == b"unchanged"
    assert link.is_symlink()
    assert not (tmp_path / ".bundle.feathered-building").exists()
    link.unlink()
    with staging_session(output):
        pass


def test_second_session_cannot_remove_the_first_sessions_files(tmp_path):
    output = tmp_path / "bundle"
    with staging_session(output) as (staging, reporter):
        marker = staging / "first-build.txt"
        marker.write_text("first")
        with pytest.raises(RuntimeError, match="Another build"):
            publication_staging.open_staging(output, reporter)
        assert marker.read_text() == "first"
        publication_staging.commit_staging(staging, output, reporter)
    assert (output / "first-build.txt").read_text() == "first"


def test_destination_lock_is_shared_with_other_processes(tmp_path):
    output = tmp_path / "bundle"
    probe = """
import sys
from pathlib import Path
from execution_reporter import Reporter
from publication_staging import open_staging, abandon_staging
try:
    staging = open_staging(Path(sys.argv[1]), Reporter())
except RuntimeError:
    print("blocked")
else:
    abandon_staging(staging, Reporter())
    print("opened")
"""
    with staging_session(output) as (staging, reporter):
        (staging / "first-build.txt").write_text("first")
        child = subprocess.run([sys.executable, "-c", probe, str(output)],
                               cwd=Path(__file__).resolve().parents[1],
                               capture_output=True, text=True, timeout=15)
        assert child.returncode == 0, child.stderr
        assert child.stdout.strip() == "blocked"
        assert (staging / "first-build.txt").read_text() == "first"
        publication_staging.commit_staging(staging, output, reporter)
    child = subprocess.run([sys.executable, "-c", probe, str(output)],
                           cwd=Path(__file__).resolve().parents[1],
                           capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == "opened"


def test_process_exit_releases_the_destination_lock(tmp_path):
    output = tmp_path / "bundle"
    output.mkdir()
    (output / "published.txt").write_text("published")
    program = """
import os, sys
from pathlib import Path
from execution_reporter import Reporter
from publication_staging import open_staging
staging = open_staging(Path(sys.argv[1]), Reporter())
(staging / "unfinished.txt").write_text("unfinished")
os._exit(0)
"""
    child = subprocess.run([sys.executable, "-c", program, str(output)],
                           cwd=Path(__file__).resolve().parents[1], timeout=15)
    assert child.returncode == 0
    with staging_session(output) as (staging, _):
        assert not (staging / "unfinished.txt").exists()
        assert (staging / "published.txt").read_text() == "published"


@pytest.mark.parametrize("family", FAMILIES)
def test_setup_failure_releases_the_destination_lock(tmp_path, family):
    backend, _, _, _, result, metadata = package_fixture(tmp_path, family)
    output = tmp_path / "bundle"
    conflict = output / "bundle-index.json"
    conflict.mkdir(parents=True)
    with pytest.raises(RuntimeError, match="directory"):
        backend.write_bundle(result, output, core.BuildOptions(emit_repository=False),
                             core.Reporter(), metadata)
    assert not (tmp_path / ".bundle.feathered-building").exists()
    conflict.rmdir()
    backend.write_bundle(result, output, core.BuildOptions(emit_repository=False),
                         core.Reporter(), metadata)


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("mode", ("package-only", "mirror", "no-repository", "no-roots"))
def test_output_mode_changes_remove_obsolete_transaction_files(tmp_path, family, mode):
    backend, directory, _, _, result, metadata = package_fixture(tmp_path, family, "old-app")
    output = tmp_path / "bundle"
    backend.write_bundle(result, output, core.BuildOptions(emit_repository=True),
                         core.Reporter(), metadata)
    assert (output / "install-offline.sh").is_file()
    _, _, _, _, result, metadata = package_fixture(tmp_path, family, "new-app")
    if mode == "package-only":
        metadata["package_only_acquisition"] = True
    elif mode == "mirror":
        metadata["repository_mirror"] = True
    elif mode == "no-roots":
        result.roots = []
    backend.write_bundle(result, output, core.BuildOptions(emit_repository=False, additive_publish=True),
                         core.Reporter(), metadata)
    records = output / directory
    for relative in ("install-offline.sh", "receiver-preflight.py", "USE-AS-REPOSITORY.txt"):
        assert not (output / relative).exists()
    assert not (records / "TRANSACTION-ARGS.txt").exists()
    if mode in ("package-only", "mirror"):
        assert not (records / "INSTALLATION-CONTRACT.json").exists()
        assert not (records / "REQUESTED-ROOTS.txt").exists()
    else:
        assert (records / "INSTALLATION-CONTRACT.json").is_file()
    if mode == "no-roots":
        assert not (records / "REQUESTED-ROOTS.txt").exists()
    marker = {"package-only": "PACKAGE-ONLY-WARNING.txt", "mirror": "MIRROR-BUNDLE.txt"}.get(mode)
    if marker:
        assert (records / marker).is_file()

    _, _, _, _, result, metadata = package_fixture(tmp_path, family, "current-app")
    backend.write_bundle(result, output, core.BuildOptions(emit_repository=True),
                         core.Reporter(), metadata)
    assert (output / "install-offline.sh").is_file()
    assert "current-app" in (records / "TRANSACTION-ARGS.txt").read_text()
    for name in ("PACKAGE-ONLY-WARNING.txt", "MIRROR-BUNDLE.txt"):
        assert not (records / name).exists()
    assert not (output / "INSTALL-OFFLINE-NOTE.txt").exists()


@pytest.mark.parametrize("arch", ("arm64", "ppc64el", "riscv64"))
@pytest.mark.parametrize("differential", (False, True))
def test_all_only_apt_bundle_keeps_its_target_architecture(tmp_path, arch, differential):
    backend, _, _, package, result, metadata = package_fixture(tmp_path, "deb", arch="all")
    metadata["arch"] = arch
    options = core.BuildOptions(emit_repository=True)
    if differential:
        baseline = tmp_path / "baseline.json"
        baseline.write_text(json.dumps({"packages": [
            {"package_id": package.nevra, "sha256": package.checksum},
        ]}))
        options.baseline_manifest = str(baseline)
    output = tmp_path / "bundle"
    backend.write_bundle(result, output, options, core.Reporter(), metadata)
    assert (output / "dists/feathered/main" / f"binary-{arch}/Packages").is_file()
    release = (output / "dists/feathered/Release").read_text()
    assert f"Architectures: {arch}\n" in release
    generated = core.RepoSpec("Generated", output.as_uri() + "/", repo_format="apt",
                              suite="feathered", components="main")
    loaded = apt_core.load_repository(generated, {arch}, core.Reporter())
    assert len(loaded) == (0 if differential else 1)


def test_all_packages_are_indexed_for_each_requested_architecture(tmp_path):
    _, _, source, package, _, _ = package_fixture(tmp_path, "deb", arch="all")
    apt_core.emit_apt_repository(source, [package], core.Reporter(),
                                target_arches={"arm64", "amd64"})
    for arch in ("arm64", "amd64"):
        assert "Package: demo" in (source / f"dists/feathered/main/binary-{arch}/Packages").read_text()


@pytest.mark.parametrize("family", FAMILIES)
def test_files_preserved_before_sealing_are_in_the_final_index(tmp_path, monkeypatch, family):
    backend, _, _, _, result, metadata = package_fixture(tmp_path, family)
    output = tmp_path / "bundle"
    backend.write_bundle(result, output, core.BuildOptions(emit_repository=False, sign_bundle_index=True),
                         core.Reporter(), metadata)
    original = publication_staging.prepare_publication

    def prepare(staging, destination, reporter, **kwargs):
        (destination / "late-note.txt").write_text("preserve")
        return original(staging, destination, reporter, **kwargs)

    monkeypatch.setattr(core, "prepare_publication", prepare)
    monkeypatch.setattr(rpm_bundle, "prepare_publication", prepare)
    backend.write_bundle(result, output, core.BuildOptions(emit_repository=False, sign_bundle_index=True),
                         core.Reporter(), metadata)
    assert (output / "late-note.txt").read_text() == "preserve"
    assert repository_tools.verify_bundle_files(output).ok
    checked = subprocess.run([sys.executable, str(output / "verify-bundle.py")],
                             capture_output=True, text=True, timeout=15)
    assert checked.returncode == 0, checked.stdout + checked.stderr


@pytest.mark.parametrize("family", FAMILIES)
def test_files_added_after_sealing_prevent_publication(tmp_path, monkeypatch, family):
    backend, directory, _, package, result, metadata = package_fixture(tmp_path, family)
    output = tmp_path / "bundle"
    backend.write_bundle(result, output, core.BuildOptions(emit_repository=False),
                         core.Reporter(), metadata)
    previous = (output / directory / "provenance.json").read_bytes()
    original = backend.write_bundle_index

    def seal(*args, **kwargs):
        index = original(*args, **kwargs)
        (output / "late-note.txt").write_text("preserve")
        return index

    monkeypatch.setattr(backend, "write_bundle_index", seal)
    with pytest.raises(RuntimeError, match="Output changed"):
        backend.write_bundle(result, output, core.BuildOptions(emit_repository=False, sign_bundle_index=True),
                             core.Reporter(), metadata)
    assert (output / directory / "provenance.json").read_bytes() == previous
    assert (output / directory / package.location).is_file()
    assert (output / "late-note.txt").read_text() == "preserve"
    assert not (output / "bundle-index.json").exists()
    assert not (tmp_path / ".bundle.feathered-building").exists()
    with staging_session(output):
        pass


def test_sealed_staging_is_not_extended_during_commit(tmp_path):
    output = tmp_path / "bundle"
    output.mkdir()
    with staging_session(output) as (staging, reporter):
        (staging / "payload.txt").write_text("payload")
        bundle_sealing.write_bundle_index(staging, reporter, {}, gpg_version_fn=lambda: "fixture")
        (output / "late-note.txt").write_text("preserve")
        with pytest.raises(RuntimeError, match="Output changed after sealing"):
            publication_staging.commit_staging(staging, output, reporter)
        assert not (output / "bundle-index.json").exists()
        assert repository_tools.verify_bundle_files(staging).ok


def _track_destination_locks(monkeypatch):
    descriptors = []
    acquire = publication_staging._acquire_destination_lock

    def tracked(destination):
        descriptor = acquire(destination)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(publication_staging, "_acquire_destination_lock", tracked)
    return descriptors


def _assert_descriptors_closed(descriptors):
    import os
    assert descriptors
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("name", (
    "test_staging_cannot_mutate_the_previous_bundle",
    "test_1082_staging_reuses_arch_payload_but_not_generated_companions",
    "test_117_commit_staging_preflights_conflicts_before_publication",
    "test_117_commit_staging_rolls_back_if_final_directory_swap_fails",
    "test_117_open_staging_recovers_interrupted_directory_swap",
))
def test_staging_workflows_close_the_lock_before_cleanup(tmp_path, monkeypatch, name):
    import inspect
    import test_feather
    descriptors = _track_destination_locks(monkeypatch)
    function = getattr(test_feather, name)
    fixtures = {"tmp_path": tmp_path, "monkeypatch": monkeypatch}
    function(**{key: fixtures[key] for key in inspect.signature(function).parameters})
    _assert_descriptors_closed(descriptors)


@pytest.mark.parametrize("failure", (OSError("build failed"), core.Cancelled("cancelled")))
def test_staging_scope_releases_the_lock_when_the_body_raises(tmp_path, monkeypatch, failure):
    output = tmp_path / "bundle"
    output.mkdir()
    (output / "published.txt").write_text("published")
    descriptors = _track_destination_locks(monkeypatch)
    with pytest.raises(type(failure)) as caught:
        with publication_staging.staging_scope(output, core.Reporter()) as staging:
            (staging / "unfinished.txt").write_text("unfinished")
            raise failure
    assert caught.value is failure
    _assert_descriptors_closed(descriptors)
    assert (output / "published.txt").read_text() == "published"
    assert not staging.exists()
    with staging_session(output):
        pass


def test_staging_scope_does_not_abandon_a_later_session(tmp_path, monkeypatch):
    import os
    output = tmp_path / "bundle"
    reporter = core.Reporter()
    descriptors = _track_destination_locks(monkeypatch)
    successor = None
    try:
        with publication_staging.staging_scope(output, reporter) as staging:
            (staging / "published.txt").write_text("published")
            publication_staging.commit_staging(staging, output, reporter)
            _assert_descriptors_closed(descriptors)
            successor = publication_staging.open_staging(output, reporter)
            (successor / "successor.txt").write_text("successor")
        assert (successor / "successor.txt").read_text() == "successor"
        assert (output / "published.txt").read_text() == "published"
        os.fstat(descriptors[-1])
    finally:
        if successor is not None:
            publication_staging.abandon_staging(successor, reporter)
    _assert_descriptors_closed(descriptors)
