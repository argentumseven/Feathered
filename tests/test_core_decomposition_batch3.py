from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import core
import bundle_sealing
import bundle_support
import metadata_digests
import openpgp_verifier
import package_acquisition
import package_contracts
import package_transfer
import repository_loader


ROOT = Path(__file__).resolve().parents[1]


def test_new_boundaries_import_without_legacy_core() -> None:
    modules = (
        "bundle_sealing",
        "bundle_support",
        "metadata_digests",
        "openpgp_verifier",
        "package_acquisition",
        "package_contracts",
        "package_transfer",
        "repository_loader",
    )
    for module in modules:
        code = (
            "import sys; "
            f"import {module}; "
            "assert 'core' not in sys.modules"
        )
        subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)


def test_core_is_now_a_compatibility_facade_not_the_implementation_home() -> None:
    source = (ROOT / "core.py").read_text(encoding="utf-8")
    assert len(source.splitlines()) < 900
    assert "def load_repository_once(" not in source
    assert "def verify_bundled_gpg_integrity(" not in source
    assert "def copy_or_download(" not in source
    assert "def write_bundle_index(" in source


def test_compatibility_names_point_at_extracted_boundaries() -> None:
    assert core.STRONG_HASHES is metadata_digests.STRONG_HASHES
    assert core.VerifierIntegrityError is openpgp_verifier.VerifierIntegrityError
    assert core.trust_summary is bundle_support.trust_summary
    assert core._sign_detached is bundle_sealing.sign_detached
    assert repository_loader.repo_trust(core.RepoSpec("x", "file:///tmp"))
    assert package_acquisition.AcquisitionServices
    assert package_contracts.PackageArtifact in core.DownloadPackage.__mro__
    assert package_transfer.package_download_limit
