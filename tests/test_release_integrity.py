from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import core


@pytest.fixture(autouse=True)
def _clean_verifier_cache():
    core._reset_verifier_integrity_cache()
    yield
    core._reset_verifier_integrity_cache()


def _policy(path: Path, files: dict[str, bytes]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    mapping = {}
    for name, data in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        mapping[name] = hashlib.sha256(data).hexdigest()
    policy = path.parent / "verifier-integrity.json"
    policy.write_text(json.dumps({"schema": 1, "files": mapping}), encoding="utf-8")
    return policy


def test_frozen_release_rejects_missing_bundled_verifier(monkeypatch, tmp_path):
    monkeypatch.setattr(core.sys, "frozen", True, raising=False)
    monkeypatch.setattr(core.sys, "executable", str(tmp_path / "Feathered.exe"))
    monkeypatch.setattr(core, "bundled_gpg_dir", lambda: None)
    with pytest.raises(RuntimeError, match="missing its bundled OpenPGP verifier"):
        core.gpg_backend()


def test_frozen_release_rejects_missing_embedded_policy(monkeypatch, tmp_path):
    gpg = tmp_path / "gnupg"
    gpg.mkdir()
    (gpg / "gpgv.exe").write_bytes(b"gpgv")
    monkeypatch.setattr(core.sys, "frozen", True, raising=False)
    monkeypatch.setattr(core, "bundled_gpg_dir", lambda: gpg)
    monkeypatch.setattr(core, "_verifier_policy_path", lambda: None)
    with pytest.raises(RuntimeError, match="integrity policy is missing"):
        core.gpg_backend()


def test_bundled_verifier_exact_hash_set_is_enforced(monkeypatch, tmp_path):
    gpg = tmp_path / "gnupg"
    policy = _policy(gpg, {"gpgv.exe": b"gpgv", "lib.dll": b"dll"})
    monkeypatch.setattr(core, "_verifier_policy_path", lambda: policy)
    core._verify_bundled_gpg_integrity(gpg)

    (gpg / "lib.dll").write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="integrity check failed"):
        core._verify_bundled_gpg_integrity(gpg)


def test_bundled_verifier_rejects_unexpected_file(monkeypatch, tmp_path):
    gpg = tmp_path / "gnupg"
    policy = _policy(gpg, {"gpgv.exe": b"gpgv"})
    monkeypatch.setattr(core, "_verifier_policy_path", lambda: policy)
    (gpg / "evil.dll").write_bytes(b"extra")
    with pytest.raises(RuntimeError, match="unexpected: evil.dll"):
        core._verify_bundled_gpg_integrity(gpg)


def test_build_requires_signing_iso_and_embedded_verifier_policy():
    text = (ROOT / "build_exe.bat").read_text(encoding="utf-8")
    lower = text.lower()
    assert "feathered_sign_cert_sha1 is required" in lower
    assert "feathered_smoke_iso" in lower
    assert "stage_gpgv.ps1" in lower
    assert "write_verifier_policy.py" in lower
    assert '--add-data "verifier-integrity.json;."' in lower
    assert "signtool.exe verify /pa dist\\feathered.exe" in lower
    assert "--require-hashes" in lower
    assert "--only-binary=:all:" in lower
    assert "requirements-build.lock" in lower
    assert "-m venv" in lower and ".release-venv" in lower
    assert "pyinstaller==%" not in lower and "pytest==%" not in lower
    assert "copy /y license dist\\license" in lower
    assert "copy /y notice.md dist\\notice.md" in lower
    assert "staging tcl/tk runtime into build virtual environment" in lower
    assert 'xcopy /e /i /y /q "%tcl_runtime_root%\\*" "%build_venv%\\tcl\\"' in lower
    assert 'set "tcl_library=%build_venv%\\tcl\\%tcl_dir_name%"' in lower
    assert 'set "tk_library=%build_venv%\\tcl\\%tk_dir_name%"' in lower
    assert "release-build tcl" in lower


def test_production_build_lock_authenticates_every_pinned_requirement():
    lock = (ROOT / "requirements-build.lock").read_text(encoding="utf-8")
    entries = []
    current = ""
    for raw in lock.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        current += (" " if current else "") + line.rstrip("\\").strip()
        if raw.rstrip().endswith("\\"):
            continue
        entries.append(current)
        current = ""
    assert not current
    assert entries
    for entry in entries:
        assert "==" in entry, entry
        assert "--hash=sha256:" in entry, entry
        digest = entry.split("--hash=sha256:", 1)[1].split()[0]
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), entry
    names = {entry.split("==", 1)[0].strip().lower() for entry in entries}
    assert {"zstandard", "pyinstaller", "pytest"} <= names


def test_windows_ci_contains_real_signed_production_release_gate():
    workflow = (ROOT / ".github" / "workflows" / "windows-release.yml").read_text(
        encoding="utf-8")
    lower = workflow.lower()
    assert "runs-on: windows-latest" in lower
    assert "requirements-build.lock" in lower and "--require-hashes" in lower
    assert "create_smoke_iso.ps1" in lower
    assert "windows_release_smoke.ps1" in lower
    assert "build_exe.bat" in lower
    assert "feathered_sign_pfx_b64" in lower
    assert "signtool.exe verify /pa dist\\feathered.exe" in lower
    assert "sha256sums.txt" in lower
    assert "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803" in lower
    assert "install authenticated python.org cpython with tcl/tk" in lower
    assert "install_windows_python.ps1" in lower
    assert "actions/setup-python@" not in lower
    assert "$tcltarget = join-path $venvroot 'tcl'" in lower
    assert 'get-childitem -literalpath $tclsource -force' in lower
    assert 'copy-item -destination $tcltarget -recurse -force' in lower
    assert 'release venv tcl/tk startup validation failed' in lower
    assert '"tcl_library=$env:tcl_library" | out-file -filepath $env:github_env' in lower
    assert '"tk_library=$env:tk_library" | out-file -filepath $env:github_env' in lower

    bootstrap = (ROOT / "install_windows_python.ps1").read_text(encoding="utf-8").lower()
    assert "feathered_expected_python3" in bootstrap
    assert "cygpath -u" in bootstrap
    assert "python3 --version" in bootstrap
    assert "python3 -c" not in bootstrap
    assert "system.text.utf8encoding($false)" in bootstrap
    assert "[system.io.file]::writealltext" in bootstrap
    assert "./.feathered_bash_probe.sh" in bootstrap
    assert "$gitcommand = get-command git.exe" in bootstrap
    assert "bin\\bash.exe" in bootstrap
    assert "'gnu bash'" in bootstrap
    assert "a real gnu bash installation was not found" in bootstrap
    assert "$bashprobe | & $bash -s --" not in bootstrap
    assert "& $bash -lc" not in bootstrap
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in lower
    assert "actions/checkout@v" not in lower
    assert "actions/upload-artifact@v" not in lower

    smoke_iso = (ROOT / "create_smoke_iso.ps1").read_text(encoding="utf-8").lower()
    assert ".filesystemstocreate = 1" in smoke_iso
    assert ".freemediablocks = 0" in smoke_iso
    assert "chooseimagedefaultsformediatype" not in smoke_iso

    # Signed publication must be mechanically coupled to the real package-
    # manager oracles for this caller SHA; documentation alone is not a gate.
    assert "native-conformance:" in lower
    assert "uses: ./.github/workflows/native-conformance.yml" in lower
    production = lower.split("production-release:", 1)[1]
    production_header = production.split("runs-on: windows-latest", 1)[0]
    assert "- windows-source-gate" in production_header
    assert "- native-conformance" in production_header
    assert "needs.windows-source-gate.result == 'success'" in production_header
    assert "needs.native-conformance.result == 'success'" in production_header

    native = (ROOT / ".github" / "workflows" / "native-conformance.yml").read_text(
        encoding="utf-8").lower()
    assert "workflow_call:" in native
    assert "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803" in native
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in native
    assert "actions/checkout@v" not in native
    assert "actions/upload-artifact@v" not in native
    # Live upstream availability is intentionally NOT a signed-release gate.
    # It is monitored by workload-drift.yml, where a transient upstream/network
    # failure can be reported without blocking a deterministic release.
    assert "workload-matrix:" not in native
    drift = (ROOT / ".github" / "workflows" / "workload-drift.yml").read_text(
        encoding="utf-8").lower()
    assert "python verify_workload_matrix.py" in drift
    assert "workload-matrix-report.json" in drift
    assert "uses: ./.github/workflows/workload-drift.yml" not in lower
    prefix = production.split("- name: import release signing identity", 1)[0]
    assert "feathered_sign_pfx_b64:" not in prefix
    import_step = production.split("- name: import release signing identity", 1)[1].split(
        "- name: create production smoke iso fixture", 1)[0]
    assert "feathered_sign_pfx_b64:" in import_step
    assert "feathered_sign_pfx_password:" in import_step
    assert "feathered_timestamp_url:" not in import_step
    build_step = production.split("- name: run fail-closed production build", 1)[1].split(
        "- name: independently verify signed artifact", 1)[0]
    assert "feathered_timestamp_url:" in build_step
    cleanup_pos = production.index("- name: remove signing material before third-party upload")
    upload_pos = production.index("- name: upload authenticated release evidence")
    assert cleanup_pos < upload_pos


def test_static_analysis_has_one_authoritative_push_pr_path():
    workflow = (ROOT / ".github" / "workflows" / "static-analysis.yml").read_text(
        encoding="utf-8"
    )
    assert "workflow_call:" in workflow
    assert "workflow_dispatch:" in workflow
    assert "\n  push:" not in workflow
    assert "\n  pull_request:" not in workflow

    windows = (ROOT / ".github" / "workflows" / "windows-release.yml").read_text(
        encoding="utf-8"
    )
    assert "push:" in windows
    assert "pull_request:" in windows
    assert "uses: ./.github/workflows/static-analysis.yml" in windows

    setup_python_v7 = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
    assert setup_python_v7 in workflow
    drift = (ROOT / ".github" / "workflows" / "workload-drift.yml").read_text(encoding="utf-8")
    assert setup_python_v7 in drift
    assert "a26af69be951a213d495a4c3e4e4022e16d87065" not in workflow
    assert "a26af69be951a213d495a4c3e4e4022e16d87065" not in drift


def test_project_is_mit_licensed_and_distribution_notice_is_present():
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    notice = (ROOT / "NOTICE.md").read_text(encoding="utf-8")
    assert license_text.startswith("MIT License\n")
    assert "Permission is hereby granted, free of charge" in license_text
    assert "third-party" in notice.lower()
    assert "not relicensed" in notice.lower()


def test_gpg_acquisition_is_pinned_to_expected_installer_hash():
    text = (ROOT / "stage_gpgv.ps1").read_text(encoding="utf-8")
    assert "https://www.gnupg.org/ftp/gcrypt/binary/$InstallerName" in text
    assert "2E5841E345D56F05199351BFCF585D28C6DC2326C8F76962F1E402F41F6D10E9" in text
    assert "$ExpectedInstallerHost = 'www.gnupg.org'" in text
    assert "FEATHERED_BUILD_TEMP" in text
    assert "FEATHERED_GNUPG_INSTALLER" in text


def test_verifier_cache_still_catches_a_later_tamper(monkeypatch, tmp_path):
    """A cache hit must not turn a swapped verifier into a pass."""
    gpg = tmp_path / "gnupg"
    policy = _policy(gpg, {"gpgv.exe": b"gpgv", "lib.dll": b"dll"})
    monkeypatch.setattr(core, "_verifier_policy_path", lambda: policy)
    core._verify_bundled_gpg_integrity(gpg)
    core._verify_bundled_gpg_integrity(gpg)  # served from the stat fingerprint

    # The executed binary is re-hashed on every call, even same-size and with
    # the original timestamps restored.
    original = (gpg / "gpgv.exe").stat()
    (gpg / "gpgv.exe").write_bytes(b"evil")
    os.utime(gpg / "gpgv.exe", ns=(original.st_atime_ns, original.st_mtime_ns))
    with pytest.raises(core.VerifierIntegrityError, match="integrity check failed"):
        core._verify_bundled_gpg_integrity(gpg)


def test_verifier_integrity_error_is_not_a_waivable_signature_failure():
    """core downgrades unsigned packages to warnings; it must not downgrade this."""
    assert issubclass(core.VerifierIntegrityError, RuntimeError)
    source = (ROOT / "core.py").read_text(encoding="utf-8")
    marker = "except VerifierIntegrityError:"
    assert marker in source, "the per-package vendor-signature handler must re-raise verifier tampering"


def test_source_checkout_keeps_path_fallback(monkeypatch, tmp_path):
    """An incomplete local gnupg/ dir is fatal only for a frozen release."""
    gpg = tmp_path / "gnupg"
    gpg.mkdir()
    (gpg / "notes.txt").write_text("no gpgv here", encoding="utf-8")
    monkeypatch.setattr(core, "bundled_gpg_dir", lambda: gpg)
    monkeypatch.setattr(core, "_verifier_policy_path", lambda: None)
    monkeypatch.setattr(core.sys, "frozen", False, raising=False)
    monkeypatch.setattr(core.shutil, "which", lambda name: "/usr/bin/gpgv" if name == "gpgv" else None)
    assert core.gpg_backend() == "gpgv"


def test_backend_modules_can_resolve_every_module_qualified_reference():
    """apt_core used core.merge_additive_manifest_rows without importing core.

    That is a guaranteed NameError on the APT additive-publish path, and the
    suite only ever asserted the option flag, never ran the branch. Check every
    backend for `<module>.attr` references whose module was never imported.
    """
    import ast

    backends = {"core", "apt_core", "arch_core", "provenance", "repository_tools"}
    offenders = []
    for name in sorted(backends):
        path = ROOT / f"{name}.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        bound = {name}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    bound.add(alias.asname or alias.name)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and node.value.id in backends and node.value.id not in bound):
                offenders.append(f"{path.name}:{node.lineno}: {node.value.id}.{node.attr}")
    assert not offenders, "module-qualified reference with no import: " + ", ".join(offenders)


def test_windows_release_smoke_executes_actual_mount_path():
    """The Windows gate must exercise Feathered's implementation, not only equivalent cmdlets."""
    ps1 = (ROOT / "windows_release_smoke.ps1").read_text(encoding="utf-8")
    probe = (ROOT / "windows_media_mount_smoke.py").read_text(encoding="utf-8")
    build = (ROOT / "build_exe.bat").read_text(encoding="utf-8")

    assert "windows_media_mount_smoke.py" in ps1
    assert "PythonExe" in ps1
    assert "Dismount-DiskImage" in ps1
    assert "probe._mount_disc_image(image)" in probe
    media = (ROOT / "feathered_app" / "application" / "media.py").read_text(encoding="utf-8")
    assert "Mount-DiskImage -ImagePath $p -PassThru" in media
    assert "Mount-DiskImage -LiteralPath" not in media
    assert "windows_release_smoke.ps1" in build
    assert '-PythonExe "%PY%"' in build


def _write_release_sum_fixture(dist: Path) -> None:
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "Feathered.exe").write_bytes(b"signed-exe-fixture")
    nested = dist / "gnupg" / "VERIFIER-VERSION.txt"
    nested.parent.mkdir()
    nested.write_text("gpgv fixture\n", encoding="utf-8")

    payloads = []
    for path in sorted((dist / name for name in ("Feathered.exe", "gnupg/VERIFIER-VERSION.txt")),
                       key=lambda p: p.relative_to(dist).as_posix().casefold()):
        payloads.append({
            "path": path.relative_to(dist).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    (dist / "RELEASE-MANIFEST.json").write_text(
        json.dumps({"schema": 1, "files": payloads}, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    rows = []
    for path in sorted((p for p in dist.rglob("*") if p.is_file()),
                       key=lambda p: p.relative_to(dist).as_posix().casefold()):
        rel = path.relative_to(dist).as_posix()
        if rel == "SHA256SUMS.txt":
            continue
        rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {rel}")
    (dist / "SHA256SUMS.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_release_checksum_verifier_accepts_exact_distribution_and_rejects_tamper(tmp_path):
    import verify_release_checksums

    dist = tmp_path / "dist"
    _write_release_sum_fixture(dist)
    assert verify_release_checksums.verify_distribution(dist) == 3

    (dist / "Feathered.exe").write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="SHA-256 verification failed"):
        verify_release_checksums.verify_distribution(dist)


def test_release_checksum_verifier_requires_exact_file_set(tmp_path):
    import verify_release_checksums

    dist = tmp_path / "dist"
    _write_release_sum_fixture(dist)
    (dist / "unexpected.txt").write_text("not listed\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="missing from SHA256SUMS"):
        verify_release_checksums.verify_distribution(dist)

    (dist / "unexpected.txt").unlink()
    sums = dist / "SHA256SUMS.txt"
    sums.write_text(sums.read_text(encoding="utf-8") + ("0" * 64) + "  missing.txt\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="references missing release files"):
        verify_release_checksums.verify_distribution(dist)


def test_release_checksum_verifier_rejects_unsafe_or_duplicate_paths(tmp_path):
    import verify_release_checksums

    dist = tmp_path / "dist"
    _write_release_sum_fixture(dist)
    sums = dist / "SHA256SUMS.txt"
    original = sums.read_text(encoding="utf-8")
    sums.write_text(original + ("0" * 64) + "  ../escape.txt\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Unsafe checksum path"):
        verify_release_checksums.verify_distribution(dist)

    first = original.splitlines()[0]
    sums.write_text(original + first + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Duplicate checksum entry"):
        verify_release_checksums.verify_distribution(dist)




def test_release_checksum_verifier_rejects_manifest_checksum_disagreement(tmp_path):
    import verify_release_checksums

    dist = tmp_path / "dist"
    _write_release_sum_fixture(dist)
    manifest_path = dist / "RELEASE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Update only the manifest's own checksum so SHA256SUMS.txt remains internally
    # valid; the semantic manifest-vs-payload disagreement must still be detected.
    sums_path = dist / "SHA256SUMS.txt"
    lines = []
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        if line.endswith("  RELEASE-MANIFEST.json"):
            lines.append(f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  RELEASE-MANIFEST.json")
        else:
            lines.append(line)
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="RELEASE-MANIFEST.json SHA-256 mismatch"):
        verify_release_checksums.verify_distribution(dist)


def test_production_build_executes_release_checksum_verifier_before_success():
    build = (ROOT / "build_exe.bat").read_text(encoding="utf-8").lower()
    manifest_pos = build.index("write_release_manifest.py")
    verify_pos = build.index("verify_release_checksums.py")
    cleanup_pos = build.index('rmdir /s /q "%build_venv%"', verify_pos)
    assert manifest_pos < verify_pos < cleanup_pos
    assert '"%py%" verify_release_checksums.py dist' in build


def test_windows_ci_rechecks_release_checksum_set_and_exe_independently():
    workflow = (ROOT / ".github" / "workflows" / "windows-release.yml").read_text(encoding="utf-8")
    lower = workflow.lower()
    assert "python verify_release_checksums.py dist" in lower
    assert "get-filehash -algorithm sha256 -literalpath dist\\feathered.exe" in lower
    assert "sha256sums.txt does not contain feathered.exe" in lower


def test_receiver_verifier_refuses_a_malformed_index_without_a_traceback(tmp_path):
    """A corrupt index must be distinguishable from an intact bundle.

    verify-bundle.py runs on the far side of an air gap. An uncaught exception
    there exits 1, which is the same status as "this bundle was tampered with",
    and prints a traceback instead of an instruction. Status 2 is reserved for
    "cannot verify" and the message must say so.
    """
    import subprocess

    bundle = tmp_path / "bundle"
    (bundle / "debs").mkdir(parents=True)
    (bundle / "debs" / "a.deb").write_bytes(b"PACKAGE")
    core.write_bundle_index(bundle, core.Reporter(), {})
    verifier = bundle / "verify-bundle.py"
    if not verifier.is_file():
        pytest.skip("verifier template unavailable in this checkout")
    index = bundle / core.INDEX_FILENAME

    def run():
        return subprocess.run([sys.executable, str(verifier)],
                              capture_output=True, text=True)

    assert run().returncode == 0

    for corrupt in ('{"files": [{"path": "debs/a.deb"',
                    '{"files": "not-a-list"}',
                    '{"files": []}',
                    '{"files": [{"path": "debs/a.deb"}]}',
                    '{"files": [{"path": "debs/a.deb", "sha256": "x"},'
                    ' {"path": "debs/a.deb", "sha256": "y"}]}'):
        index.write_text(corrupt, encoding="utf-8")
        result = run()
        assert result.returncode == 2, corrupt
        assert "Traceback" not in result.stderr, corrupt
        assert "do not install it" in result.stdout, corrupt


def test_source_tree_carries_no_superseded_working_copies():
    """1.2.4 shipped a stray editor backup directory beside the real source.

    It held older copies of provenance-handling modules and a duplicate
    test_feather.py, which broke pytest collection and gave an auditor two
    divergent copies of security-relevant code with no way to tell which was
    authoritative.
    """
    offenders = []
    for candidate in ROOT.rglob("*"):
        if not candidate.is_dir():
            continue
        name = candidate.name.lower()
        if "__pycache__" in candidate.parts or ".git" in candidate.parts:
            continue
        if name.startswith(("backup", "feathered-evidence-backup")) or ".backup" in name:
            offenders.append(candidate.relative_to(ROOT).as_posix())
    assert not offenders, f"superseded working copies in the source tree: {offenders}"

    duplicates: dict[str, list[str]] = {}
    for candidate in ROOT.rglob("test_*.py"):
        if "__pycache__" in candidate.parts:
            continue
        duplicates.setdefault(candidate.name, []).append(
            candidate.relative_to(ROOT).as_posix())
    collisions = {name: paths for name, paths in duplicates.items() if len(paths) > 1}
    # pytest imports test modules by basename, so a repeated basename aborts
    # collection and takes the whole release gate with it.
    assert not collisions, f"duplicate test module basenames: {collisions}"
