"""Headless policy services and compatibility adapters for the mixin shell."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidence_model import (AUTH_INDEPENDENT, REL_EXACT_ARTIFACT, EvidenceCandidate)
from feathered_app.application.provenance import ProvenanceMixin
from feathered_app.application.repositories import RepositoriesMixin
from feathered_app.provenance_policy import ProvenancePolicyService
from feathered_app.repository_policy import (
    EvidenceSelection, RepositoryOverride, RepositoryPolicyService, STRATEGY_FIELDS,
)
from repository_config import RepoSpec


@pytest.fixture
def repo():
    return RepoSpec("primary", "https://primary.example.invalid/ubuntu")


def override(**kwargs):
    defaults = dict(digest_preference="sha384", verification_strategy="evidence-fallback",
                    keyring=" /keys/trusted.gpg ", allow_unverified_index=False,
                    sensitive_query_keys="subscription_key, license_token",
                    inheritable_query_credential_keys="license_token")
    defaults.update(kwargs)
    return RepositoryOverride(**defaults)


def pkg(repo, **digests):
    return SimpleNamespace(repo=repo, digests=digests, checksum_type="", checksum="")


def test_services_do_not_import_tk_or_app():
    root = Path(__file__).resolve().parents[1] / "feathered_app"
    for module in ("repository_policy.py", "provenance_policy.py"):
        imports = []
        for node in ast.walk(ast.parse((root / module).read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        assert not any(name.startswith(("tkinter", "app", "feathered_app.context",
                                        "feathered_app.application")) for name in imports)


def test_override_updates_legacy_strategy_fields_and_normalizes_credentials(repo):
    service = RepositoryPolicyService()
    assert service.apply_override(repo, override())
    assert (repo.digest_requirement, repo.evidence_policy) == ("preferred", "fallback")
    assert repo.keyring == "/keys/trusted.gpg"
    assert repo.sensitive_query_keys == ["license_token", "subscription_key"]
    assert repo.inheritable_query_credential_keys == ["license_token"]
    assert not service.apply_override(repo, override())


@pytest.mark.parametrize("strategy,fields", STRATEGY_FIELDS.items())
def test_every_verification_strategy_synchronizes_compatibility_fields(repo, strategy, fields):
    assert RepositoryPolicyService().apply_override(repo, override(
        verification_strategy=strategy))
    assert (repo.digest_requirement, repo.evidence_policy) == fields


def test_unknown_policy_inputs_do_not_partially_mutate(repo):
    service = RepositoryPolicyService()
    before = dict(repo.__dict__)
    with pytest.raises(ValueError, match="strategy"):
        service.apply_override(repo, override(verification_strategy="unsafe-new-mode"))
    with pytest.raises(ValueError, match="digest"):
        service.apply_override(repo, override(digest_preference="md5"))
    with pytest.raises(ValueError, match="disagree"):
        service.apply_override(repo, override(evidence=EvidenceSelection(
            "https://a.invalid", EvidenceCandidate("https://b.invalid"))))
    assert repo.__dict__ == before


def test_curated_evidence_preserves_explicit_relationship_hints(repo):
    candidate = EvidenceCandidate("https://independent.invalid/archive/", "independent",
                                  REL_EXACT_ARTIFACT, AUTH_INDEPENDENT)
    service = RepositoryPolicyService()
    assert service.apply_override(repo, override(evidence=EvidenceSelection(
        candidate.url, candidate)))
    assert repo.evidence_urls == [candidate.url]
    assert repo.evidence_relationship_hints == {candidate.url: REL_EXACT_ARTIFACT}
    assert repo.evidence_authority_hints == {candidate.url: AUTH_INDEPENDENT}
    assert not service.apply_override(repo, override(evidence=EvidenceSelection(
        candidate.url, candidate)))


def test_same_origin_or_empty_evidence_cannot_retain_false_relationship_hints(repo):
    service = RepositoryPolicyService()
    a = EvidenceCandidate("https://independent.invalid/archive", "independent")
    service.apply_override(repo, override(evidence=EvidenceSelection(a.url, a)))
    same = EvidenceCandidate("https://primary.example.invalid/ubuntu", "same")
    assert service.apply_override(repo, override(evidence=EvidenceSelection(same.url, same)))
    assert repo.evidence_urls == []
    assert repo.evidence_authority_hints == {}
    assert repo.evidence_relationship_hints == {}
    service.apply_override(repo, override(evidence=EvidenceSelection(a.url, a)))
    assert service.apply_override(repo, override(evidence=EvidenceSelection()))
    assert not repo.evidence_urls


def test_malformed_manual_endpoint_clears_evidence_without_crashing(repo):
    service = RepositoryPolicyService()
    assert service.apply_override(repo, override(
        evidence=EvidenceSelection("https://[unclosed")))
    assert repo.evidence_urls == []
    assert repo.verification_strategy == "evidence-fallback"


def test_unchanged_evidence_selection_is_preserved_when_policy_only_edited(repo):
    repo.evidence_urls = ["https://independent.invalid/archive"]
    repo.evidence_relationship_hints = {repo.evidence_urls[0]: REL_EXACT_ARTIFACT}
    before = repo.evidence_relationship_hints.copy()
    RepositoryPolicyService().apply_override(repo, override(evidence=None))
    assert repo.evidence_urls == ["https://independent.invalid/archive"]
    assert repo.evidence_relationship_hints == before


def test_credential_key_lists_reject_signed_url_field_inheritance(repo):
    RepositoryPolicyService().apply_override(repo, override(
        sensitive_query_keys="signature, license_token, license_token",
        inheritable_query_credential_keys="X-Amz-Signature license_token",
    ))
    assert repo.inheritable_query_credential_keys == ["license_token"]
    assert "license_token" in repo.sensitive_query_keys


def test_common_policy_only_modifies_participating_repositories(repo):
    second = RepoSpec("second", "https://second.invalid/repo")
    untouched = RepoSpec("untouched", "https://third.invalid/repo")
    policy = RepositoryPolicyService()
    assert policy.apply_common_policy([repo, second], strategy="full-corroboration",
                                      digest_preference="sha512") == 2
    assert all(r.verification_strategy == "full-corroboration" for r in (repo, second))
    assert repo.digest_preference == "sha512"
    assert untouched.verification_strategy == ""
    assert policy.apply_common_policy([repo, second], strategy="full-corroboration",
                                      digest_preference="sha512") == 0


def test_common_policy_mixed_retains_each_strategy_and_skip_retains_digest(repo):
    other = RepoSpec("other", "https://other.invalid")
    repo.verification_strategy = "evidence-fallback"
    other.verification_strategy = "checksum-required"
    other.digest_preference = "sha512"
    policy = RepositoryPolicyService()
    assert policy.apply_common_policy([repo, other], digest_preference="sha384") == 2
    assert repo.evidence_policy == "fallback" and other.evidence_policy == "off"
    assert policy.apply_common_policy([repo, other], strategy="skip-provenance",
                                      digest_preference="sha256") == 2
    assert repo.digest_preference == other.digest_preference == "sha384"


def test_mixed_policy_retains_legacy_evidence_contract(repo):
    repo.verification_strategy = ""
    repo.digest_requirement = "preferred"
    repo.evidence_policy = "best-effort"
    assert RepositoryPolicyService().apply_common_policy(
        [repo], digest_preference="sha384") == 1
    assert repo.digest_preference == "sha384"
    assert repo.evidence_policy == "best-effort"
    assert repo.verification_strategy == ""


def test_inspection_uses_detailed_per_package_coverage_not_union(repo):
    service = ProvenancePolicyService()
    key = service.cache_key(repo)
    detected = {key: ["sha256", "sha512"]}
    packages = [pkg(repo, sha512="a" * 128), pkg(repo, sha256="b" * 64)]
    assert service.detected_algorithms(repo, detected, packages) == ["sha512", "sha256"]
    assert not service.meets_digest_minimum(
        repo, "sha512", coverage={}, detected=detected, packages=packages)
    # Even a union containing SHA512 does not establish whole-source coverage.
    assert service.minimum_met_by_algorithms(detected[key], "sha512")
    assert service.meets_digest_minimum(
        repo, "sha256", coverage={}, detected=detected, packages=packages)
    detailed = {key: {"total": 2, "sha256": 2, "sha512": 1}}
    assert not service.meets_digest_minimum(
        repo, "sha512", coverage=detailed, detected=detected, packages=packages)


def test_zero_package_index_does_not_count_as_digest_coverage(repo):
    service = ProvenancePolicyService()
    key = service.cache_key(repo)
    assert service.inspection_known(repo, {key: []}, [])
    assert not service.meets_digest_minimum(repo, "auto", coverage={key: {"total": 0}},
                                            detected={key: []}, packages=[])


def test_explicit_coverage_takes_precedence_over_loaded_package_sample(repo):
    service = ProvenancePolicyService()
    key = service.cache_key(repo)
    sample = [pkg(repo, sha512="a" * 128)]
    assert not service.meets_digest_minimum(
        repo, "sha512", coverage={key: {"total": 200, "sha512": 199}},
        detected={}, packages=sample)


def test_loaded_packages_for_other_repository_do_not_contaminate_inspection(repo):
    other = RepoSpec("other", "https://other.invalid")
    service = ProvenancePolicyService()
    assert not service.inspection_known(repo, {}, [pkg(other, sha256="a" * 64)])
    assert service.inspection_known(repo, {}, [pkg(repo, sha256="a" * 64)])


def test_enhanced_distinguishes_unknown_missing_and_complete(repo):
    good = RepoSpec("good", "https://good.invalid", digest_preference="sha256")
    unknown = RepoSpec("unknown", "https://unknown.invalid")
    service = ProvenancePolicyService()
    known = {repo.name, good.name}
    enough = {good.name}
    result = service.evidence_requirements(
        [repo, good, unknown], "evidence-fallback",
        inspection_known=lambda r: r.name in known,
        meets_digest_minimum=lambda r, pref: r.name in enough,
    )
    assert result.required == (repo,)
    assert result.pending_inspection == (unknown,)
    maximum = service.evidence_requirements(
        [repo, good, unknown], "full-corroboration",
        inspection_known=lambda r: (_ for _ in ()).throw(AssertionError("not consulted")),
        meets_digest_minimum=lambda r, pref: (_ for _ in ()).throw(AssertionError("not consulted")),
    )
    assert maximum.required == (repo, good, unknown) and not maximum.pending_inspection
    for strategy in ("checksum-required", "checksum-available", "skip-provenance"):
        assert not service.evidence_requirements([repo], strategy,
            inspection_known=lambda r: True,
            meets_digest_minimum=lambda r, pref: False).required


def test_mixin_adapters_use_injected_services_without_tk(repo):
    class Host(RepositoriesMixin, ProvenanceMixin):
        def _enabled_provenance_repos(self):
            return self.repo_rows

    host = Host()
    host.repo_rows = [repo]
    host._provenance_detected_cache = {("primary", repo.normalized_url): ["sha256"]}
    assert host._detected_digest_algorithms(repo) == ["sha256"]
    assert host._digest_inspection_known(repo)
    assert host._repo_meets_digest_minimum(repo, "sha256")
    assert host._get_repository_policy_service().apply_override(repo, override())
    assert repo.verification_strategy == "evidence-fallback"
    assert host._evidence_required_repos("evidence-fallback") == [repo]
    assert host._evidence_pending_inspection_repos("evidence-fallback") == []
    assert isinstance(host._get_provenance_policy_service(), ProvenancePolicyService)
