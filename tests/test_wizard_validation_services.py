"""Pure validation contracts and compatibility behavior for the v17 GUI adapters."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidence_model import REL_EXACT_ARTIFACT, REL_REBUILD_PEER
from feathered_app.package_name_validation import PackageNameValidationService
from feathered_app.provenance_validation import (
    EvidenceSourceCheck, ProvenanceValidationService,
)


@pytest.mark.parametrize("module", ["provenance_validation.py", "package_name_validation.py"])
def test_validation_modules_have_no_gui_or_application_imports(module):
    path = Path(__file__).resolve().parents[1] / "feathered_app" / module
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.append(node.module or "")
    assert not any(name.startswith(("tkinter", "feathered_app.application", "app",
                                     "feathered_app.context")) for name in names)


def test_checksum_gate_precedes_inspection_gate():
    gate = ProvenanceValidationService()
    with pytest.raises(RuntimeError, match="checksum policy"):
        gate.validate_prerequisites(checksum_selected=False, pending_inspection=["Alpha"])
    with pytest.raises(RuntimeError, match="Inspect checksum support first.*Alpha"):
        gate.validate_prerequisites(checksum_selected=True, pending_inspection=["Alpha"])
    gate.validate_prerequisites(checksum_selected=True, pending_inspection=[])


def test_inspection_error_is_bounded_to_four_names():
    with pytest.raises(RuntimeError) as exc:
        ProvenanceValidationService.validate_prerequisites(
            checksum_selected=True, pending_inspection=[f"source-{i}" for i in range(6)])
    assert "source-3" in str(exc.value) and "source-4" not in str(exc.value)


@pytest.mark.parametrize("strategy", ["evidence-fallback", "full-corroboration"])
def test_missing_evidence_blocks_both_strategies(strategy):
    with pytest.raises(RuntimeError, match="No evidence source is selected.*missing"):
        ProvenanceValidationService.validate_evidence(
            strategy=strategy, strategy_label="verification",
            sources=[EvidenceSourceCheck("missing", False)])


@pytest.mark.parametrize("status", ["", "testing", "untested"])
def test_untested_evidence_never_counts_as_passed(status):
    with pytest.raises(RuntimeError, match="explicit spot test"):
        ProvenanceValidationService.validate_evidence(
            strategy="full-corroboration", strategy_label="maximum",
            sources=[EvidenceSourceCheck("source", True, preflight_status=status)])


@pytest.mark.parametrize("status", ["repository", "artifact-only", "peer"])
def test_successful_spot_tests_pass_in_maximum_mode(status):
    ProvenanceValidationService.validate_evidence(
        strategy="full-corroboration", strategy_label="maximum",
        sources=[EvidenceSourceCheck("source", True, preflight_status=status,
                                     preflight_relationship=REL_REBUILD_PEER)])


def test_enhanced_rejects_selected_semantic_peer_before_test():
    with pytest.raises(RuntimeError, match="Maximum-only"):
        ProvenanceValidationService.validate_evidence(
            strategy="evidence-fallback", strategy_label="enhanced",
            sources=[EvidenceSourceCheck("peer", True, selected_relationship=REL_REBUILD_PEER)])


def test_enhanced_rejects_peer_from_test_even_when_selected_hint_is_exact():
    with pytest.raises(RuntimeError, match="Maximum-only"):
        ProvenanceValidationService.validate_evidence(
            strategy="evidence-fallback", strategy_label="enhanced",
            sources=[EvidenceSourceCheck("peer", True, selected_relationship=REL_EXACT_ARTIFACT,
                                         preflight_status="peer",
                                         preflight_relationship=REL_REBUILD_PEER)])


def test_enhanced_accepts_exact_artifact_test():
    ProvenanceValidationService.validate_evidence(
        strategy="evidence-fallback", strategy_label="enhanced",
        sources=[EvidenceSourceCheck("mirror", True,
                                     selected_relationship=REL_EXACT_ARTIFACT,
                                     preflight_status="artifact-only")])


def test_unknown_success_sounding_status_fails_closed():
    with pytest.raises(RuntimeError, match="Evidence testing failed.*unrecognized"):
        ProvenanceValidationService.validate_evidence(
            strategy="evidence-fallback", strategy_label="enhanced",
            sources=[EvidenceSourceCheck("unrecognized", True,
                                         preflight_status="success")])


def test_error_precedence_is_invalid_before_missing_untested_and_failed():
    sources = [
        EvidenceSourceCheck("failed", True, preflight_status="failed", preflight_detail="bad digest"),
        EvidenceSourceCheck("untested", True), EvidenceSourceCheck("missing", False),
        EvidenceSourceCheck("invalid", True, selected_relationship=REL_REBUILD_PEER),
    ]
    with pytest.raises(RuntimeError, match="Maximum-only.*invalid"):
        ProvenanceValidationService.validate_evidence(
            strategy="evidence-fallback", strategy_label="enhanced", sources=sources)


def test_non_evidence_strategies_are_noop():
    for strategy in ("checksum-required", "checksum-available", "skip-provenance"):
        ProvenanceValidationService.validate_evidence(
            strategy=strategy, strategy_label="basic", sources=[EvidenceSourceCheck("x", False)])


def package(name, provides=()):
    return SimpleNamespace(name=name, provides=[SimpleNamespace(name=p) for p in provides])


def test_package_names_empty_and_no_index_are_distinct():
    service = PackageNameValidationService()
    assert service.check(" , \n", []).status == "empty"
    assert service.check("curl", None).status == "index-required"
    result = service.check("nginx, curl", [])
    assert result.status == "index-required" and "2 name(s)" in result.message


def test_package_names_match_real_and_virtual_provides():
    result = PackageNameValidationService.check(
        "nginx http-server", [package("nginx", ("http-server",))])
    assert result.status == "valid" and "All 2" in result.message


def test_package_names_report_typo_suggestions_and_limit_display():
    result = PackageNameValidationService.check(
        "ngnix missing1 missing2 missing3 missing4", [package("nginx")])
    assert result.status == "missing"
    assert result.missing == ("ngnix", "missing1", "missing2", "missing3", "missing4")
    assert "did you mean nginx" in result.message
    assert "and 1 more" in result.message and "missing4" not in result.message


def test_package_names_do_not_mask_duplicate_missing_roots():
    result = PackageNameValidationService.check("unknown unknown", [package("nginx")])
    assert result.missing == ("unknown", "unknown")


def test_gui_custom_package_adapter_preserves_search_prompt_and_quiet_mode():
    from feathered_app.application.sources import SourcesMixin

    class Status:
        def configure(self, **kwargs):
            self.fields = kwargs

    class Host:
        custom_status = Status()
        custom_var = SimpleNamespace(get=lambda: "nginx")
        single_catalog_packages = []
        searches = []

        def open_package_search(self, mode):
            self.searches.append(mode)

    host = Host()
    SourcesMixin._validate_custom_names(host, quiet=True)
    assert host.searches == []
    assert "Search repositories" in host.custom_status.fields["text"]
    SourcesMixin._validate_custom_names(host, quiet=False)
    assert host.searches == ["names"]
    host.single_catalog_packages = [package("nginx")]
    SourcesMixin._validate_custom_names(host)
    assert host.custom_status.fields["text"].startswith("All 1")


def test_app_exposes_per_instance_validator_owners():
    import app

    # Distinct service identities also make overrides local to one host.
    assert app.App._validate_provenance_step is not None
    assert "_provenance_validation_service" in app.App.__init__.__code__.co_consts or (
        "ProvenanceValidationService" in app.App.__init__.__code__.co_names)


def test_identical_repository_names_do_not_share_spot_test_results():
    """The GUI adapter must key by repository identity, never display label."""
    import app
    from repository_config import RepoSpec

    class Var:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

    first = RepoSpec("mirror", "https://first.invalid/path", enabled=True,
                     evidence_urls=["https://evidence.invalid/first"])
    second = RepoSpec("mirror", "https://second.invalid/path", enabled=True,
                      evidence_urls=["https://evidence.invalid/second"])
    host = object.__new__(app.App)
    host.repo_rows = [first, second]
    host.prov_strategy_var = Var("Corroborate every package (maximum)")
    host.prov_digest_var = Var("SHA-256 or stronger")
    first_key = app.App._evidence_preflight_key(host, first, first.evidence_urls[0])
    host._evidence_preflight_cache = {
        first_key: {"status": "artifact-only", "detail": "verified"},
    }
    with pytest.raises(RuntimeError, match="explicit spot test"):
        app.App._validate_provenance_step(host)
    second_key = app.App._evidence_preflight_key(host, second, second.evidence_urls[0])
    assert second_key != first_key
    host._evidence_preflight_cache[second_key] = {"status": "artifact-only"}
    app.App._validate_provenance_step(host)
    second.evidence_urls = ["https://different.invalid/second"]
    with pytest.raises(RuntimeError, match="explicit spot test"):
        app.App._validate_provenance_step(host)
