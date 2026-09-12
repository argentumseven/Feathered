"""The source manifest must describe the tree it ships with.

Feathered 1.2.4 shipped a SOURCE-SHA256.json that described the *previous*
revision of four files, and nothing detected it because no code read the file.
These tests exist so that failure mode cannot recur silently: the manifest is
now checked against the working tree, the verifier is checked against known
tampering, and the release workflow is checked for actually running it.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import source_manifest
import verify_source_checksums
import write_source_manifest


def _tree(root: Path) -> Path:
    """A minimal source tree with a correct manifest."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "pkg").mkdir()
    (root / "core.py").write_text("value = 1\n", encoding="utf-8")
    (root / "pkg" / "unit.py").write_text("value = 2\n", encoding="utf-8")
    manifest = write_source_manifest.build_manifest(root)
    (root / source_manifest.MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return root


def test_shipped_manifest_describes_the_shipped_tree():
    """The release gate's own precondition, asserted in the ordinary suite.

    Running write_source_manifest.py before the final edit is the mistake this
    catches, so failing here should be read as "regenerate the manifest", not
    as a defect in the code under test.
    """
    assert verify_source_checksums.verify_source(ROOT) == 0


def test_manifest_covers_every_tracked_source_file():
    manifest = json.loads((ROOT / source_manifest.MANIFEST_NAME).read_text(encoding="utf-8"))
    present = set(source_manifest.iter_source_files(ROOT))
    assert set(manifest) == present
    # The mistake that produced the stale 1.2.4 manifest left a whole directory
    # of superseded copies outside the manifest, so absence of coverage is the
    # specific thing worth asserting.
    assert not [path for path in present if path not in manifest]


def test_manifest_excludes_derived_and_cache_artifacts():
    manifest = json.loads((ROOT / source_manifest.MANIFEST_NAME).read_text(encoding="utf-8"))
    for path in manifest:
        assert "__pycache__" not in path, path
        assert not path.endswith((".pyc", ".pyo")), path
        # Captured gate output is excluded on purpose: a run that verifies the
        # manifest cannot also be recorded inside it.
        assert not path.startswith("validation/"), path
    assert source_manifest.MANIFEST_NAME not in manifest
    assert source_manifest.is_excluded("validation/pytest.txt")


def test_writer_is_idempotent_and_check_mode_detects_drift(tmp_path):
    root = _tree(tmp_path / "tree")
    assert verify_source_checksums.verify_source(root) == 0
    (root / "core.py").write_text("value = 99\n", encoding="utf-8")
    assert verify_source_checksums.verify_source(root) == 1
    manifest = write_source_manifest.build_manifest(root)
    (root / source_manifest.MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert verify_source_checksums.verify_source(root) == 0


def test_verifier_reports_missing_modified_and_unlisted(tmp_path, capsys):
    root = _tree(tmp_path / "tree")

    (root / "pkg" / "unit.py").unlink()
    assert verify_source_checksums.verify_source(root) == 1
    assert "MISSING: pkg/unit.py" in capsys.readouterr().out

    root = _tree(tmp_path / "modified")
    (root / "core.py").write_text("value = 2\n", encoding="utf-8")
    assert verify_source_checksums.verify_source(root) == 1
    assert "MODIFIED: core.py" in capsys.readouterr().out

    root = _tree(tmp_path / "unlisted")
    (root / "planted.py").write_text("import os\n", encoding="utf-8")
    assert verify_source_checksums.verify_source(root) == 1
    assert "UNLISTED: planted.py" in capsys.readouterr().out


def test_verifier_ignores_byte_compiled_caches(tmp_path):
    root = _tree(tmp_path / "tree")
    cache = root / "pkg" / "__pycache__"
    cache.mkdir()
    (cache / "unit.cpython-313.pyc").write_bytes(b"\x00compiled")
    assert verify_source_checksums.verify_source(root) == 0


def test_verifier_rejects_unsafe_duplicate_and_self_referential_entries(tmp_path):
    root = _tree(tmp_path / "tree")
    target = root / source_manifest.MANIFEST_NAME
    digest = "0" * 64

    for bad in ("../escape.py", "/etc/passwd", "C:/windows/x.py", "pkg\\unit.py", ""):
        target.write_text(json.dumps({bad: digest}), encoding="utf-8")
        with pytest.raises(RuntimeError, match="Unsafe manifest path"):
            verify_source_checksums.verify_source(root)

    target.write_text(json.dumps({source_manifest.MANIFEST_NAME: digest}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="self-referential"):
        verify_source_checksums.verify_source(root)

    target.write_text(json.dumps({"__pycache__/x.pyc": digest}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="out-of-scope"):
        verify_source_checksums.verify_source(root)

    target.write_text(json.dumps({"core.py": "short"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="Malformed SHA-256"):
        verify_source_checksums.verify_source(root)

    target.write_text("{not json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Unreadable source manifest"):
        verify_source_checksums.verify_source(root)

    target.write_text(json.dumps({}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="non-empty object"):
        verify_source_checksums.verify_source(root)


def test_verifier_refuses_a_symlinked_source_tree(tmp_path):
    root = _tree(tmp_path / "tree")
    outside = tmp_path / "outside.py"
    outside.write_text("value = 3\n", encoding="utf-8")
    try:
        (root / "linked.py").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("this platform does not permit symlink creation")
    with pytest.raises(RuntimeError, match="contains a symlink"):
        verify_source_checksums.verify_source(root)


def test_windows_source_gate_verifies_the_source_manifest():
    workflow = (ROOT / ".github" / "workflows" / "windows-release.yml").read_text(
        encoding="utf-8").lower()
    assert "verify_source_checksums.py" in workflow
    # The check has to run inside the source gate, ahead of the signed job that
    # depends on it; a verification that only runs after publication is theatre.
    gate = workflow.split("windows-source-gate:", 1)[1].split("native-conformance:", 1)[0]
    assert "verify_source_checksums.py" in gate
    # And it must run before the corpus, so a stale manifest fails in seconds
    # rather than after the full batched suite.
    assert gate.index("verify_source_checksums.py") < gate.index("release_test_runner.py")
