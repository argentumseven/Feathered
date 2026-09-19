"""Compatibility and dependency-direction contracts for the core decomposition."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import core
import core_models
import artifact_verification
import rpm_bundle
import rpm_repository_writer
import rpm_resolution
import rpm_target_inventory
import credential_redaction
import execution_reporter
import publication_staging
import repository_config
import repository_paths
import rpm_metadata


def test_domain_models_are_canonical_compatibility_exports():
    for name in (
        "ArtifactVerification", "BuildOptions", "Package", "ProviderMatch",
        "RepoDataRef", "RepoTrust", "Requirement", "ResolutionResult",
        "TargetInventory",
    ):
        assert getattr(core, name) is getattr(core_models, name)


def test_repository_and_reporting_boundaries_are_canonical_exports():
    assert core.RepoSpec is repository_config.RepoSpec
    assert core.Reporter is execution_reporter.Reporter
    assert core.Cancelled is execution_reporter.Cancelled
    assert core.open_staging is publication_staging.open_staging
    assert core.commit_staging is publication_staging.commit_staging
    assert core.repo_relative_url is repository_paths.repo_relative_url
    assert core.redact_url is credential_redaction.redact_url




def test_new_rpm_boundaries_are_canonical_exports():
    assert core.build_provider_index is rpm_resolution.build_provider_index
    assert core.apply_mirror_evidence is artifact_verification.apply_mirror_evidence
    assert core.emit_rpm_repository is rpm_repository_writer.emit_rpm_repository
    assert core.parse_target_inventory is rpm_target_inventory.parse_target_inventory
    assert core._write_provenance is rpm_bundle._write_provenance

def test_leaf_boundaries_do_not_runtime_import_core():
    root = Path(core.__file__).resolve().parent
    modules = [
        "core_models", "credential_redaction", "execution_reporter",
        "package_transfer", "publication_staging", "repository_config",
        "repository_paths", "rpm_metadata", "rpm_resolution",
        "artifact_verification", "rpm_repository_writer", "rpm_target_inventory",
        "rpm_bundle", "runtime_limits",
    ]
    code = (
        "import importlib,sys; "
        f"mods={modules!r}; "
        "[importlib.import_module(m) for m in mods]; "
        "assert 'core' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", code], cwd=root, check=True)


def test_reporter_redacts_after_repo_configuration_registers_secret():
    secret = "super-secret-token"
    repository_config.RepoSpec(
        "private", f"https://repo.invalid/path?token={secret}"
    )
    events = []
    execution_reporter.Reporter(log=events.append).log(
        f"failed while contacting token={secret}"
    )
    assert secret not in events[-1]
    assert "REDACTED" in events[-1]


def test_core_metadata_wrappers_keep_runtime_injection_seams(monkeypatch):
    seen = {}

    def fake_get(repo, reporter, retries=3, **services):
        seen.update(services)
        return {}

    monkeypatch.setattr(rpm_metadata, "get_repo_data", fake_get)
    repo = core.RepoSpec("demo", "https://repo.invalid/")
    core.get_repo_data(repo, core.Reporter())
    assert seen["fetch_bytes_fn"] is core.fetch_bytes
    assert seen["verify_openpgp_fn"] is core.verify_openpgp
    assert seen["repo_relative_url_fn"] is core.repo_relative_url
