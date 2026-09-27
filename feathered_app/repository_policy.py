"""Headless mutations of repository verification configuration.

UI modules translate widget labels into these typed inputs. The service owns the
policy invariants, evidence endpoint decisions, and compatibility fields; it
never refers to the application shell or widget state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from artifact_verification import mirrors_are_distinct, repository_verification_strategy
from evidence_model import EvidenceCandidate
from repository_config import RepoSpec
from repository_transport import normalize_query_key_names


STRATEGY_FIELDS = {
    "checksum-required": ("required", "off"),
    "checksum-available": ("preferred", "off"),
    "evidence-fallback": ("preferred", "fallback"),
    "full-corroboration": ("required", "required"),
    "skip-provenance": ("preferred", "off"),
}
DIGEST_PREFERENCES = frozenset(("auto", "sha256", "sha384", "sha512"))


@dataclass(frozen=True)
class EvidenceSelection:
    """An explicit operator decision: blank URL clears the evidence selection.

    ``candidate`` carries the source's configured *claim* about the relationship;
    manually entered URLs must not silently acquire that claim. The actual
    artifact comparison still takes place during preflight/build.
    """

    url: str = ""
    candidate: EvidenceCandidate | None = None


@dataclass(frozen=True)
class RepositoryOverride:
    digest_preference: str
    verification_strategy: str
    keyring: str
    allow_unverified_index: bool
    sensitive_query_keys: str
    inheritable_query_credential_keys: str
    evidence: EvidenceSelection | None = None  # None = keep current selection


class RepositoryPolicyService:
    """Apply per-source and shared verification policy without GUI dependencies."""

    @staticmethod
    def _policy_fields(repo: RepoSpec) -> tuple:
        return (
            repo.digest_preference, repo.digest_requirement, repo.evidence_policy,
            repo.verification_strategy, tuple(repo.evidence_urls),
            tuple(sorted(repo.evidence_relationship_hints.items())),
            tuple(sorted(repo.evidence_authority_hints.items())),
            repo.keyring, repo.allow_unverified_index,
            tuple(repo.sensitive_query_keys), tuple(repo.inheritable_query_credential_keys),
        )

    @staticmethod
    def _query_keys(raw: str) -> list[str]:
        return sorted(normalize_query_key_names(raw.replace(",", " ").split()))

    def apply_override(self, repo: RepoSpec, values: RepositoryOverride) -> bool:
        """Apply a trust edit; return True iff the effective configuration changed.

        Validate before mutating: unknown strategies, digest labels or malformed
        candidate selections must not partially update an existing repository.
        """
        strategy = values.verification_strategy
        if strategy not in STRATEGY_FIELDS:
            raise ValueError(f"Unsupported verification strategy: {strategy!r}")
        if values.digest_preference not in DIGEST_PREFERENCES:
            raise ValueError(f"Unsupported digest preference: {values.digest_preference!r}")
        selected = values.evidence
        if selected and selected.candidate and selected.candidate.url != selected.url:
            raise ValueError("Evidence candidate and selected endpoint disagree")
        # Parse/compare the endpoint before touching any mutable trust fields;
        # malformed manual URLs must not produce a partially applied edit.
        selected_url = None
        if selected is not None:
            selected_url = selected.url.strip()
            if selected_url:
                try:
                    distinct, _ = mirrors_are_distinct(repo.normalized_url, selected_url)
                except ValueError:
                    distinct = False
                if not distinct:
                    selected_url = ""

        old = self._policy_fields(repo)
        requirement, evidence_policy = STRATEGY_FIELDS[strategy]
        sensitive = self._query_keys(values.sensitive_query_keys)
        inheritable = self._query_keys(values.inheritable_query_credential_keys)
        repo.digest_preference = values.digest_preference
        repo.verification_strategy = strategy
        repo.digest_requirement = requirement
        repo.evidence_policy = evidence_policy
        repo.keyring = values.keyring.strip()
        repo.allow_unverified_index = values.allow_unverified_index
        # RepoSpec's setter independently rejects non-inheritable credentials.
        repo.sensitive_query_keys = sensitive
        repo.inheritable_query_credential_keys = inheritable

        if selected is not None:
            url = selected_url
            repo.evidence_urls = [url] if url else []
            repo.evidence_relationship_hints = {}
            repo.evidence_authority_hints = {}
            if url and selected.candidate is not None:
                repo.evidence_relationship_hints[url] = selected.candidate.relationship
                repo.evidence_authority_hints[url] = selected.candidate.authority
        return self._policy_fields(repo) != old

    def apply_common_policy(self, repositories: Iterable[RepoSpec], *,
                            strategy: str | None = None,
                            digest_preference: str | None = None) -> int:
        """Update the participating sources while retaining mixed per-source values.

        A skipped upstream strategy leaves each inactive digest minimum intact.
        Legacy requirement/evidence fields are updated even when the explicit
        strategy was already set. Return the number of changed repositories.
        """
        if strategy is not None and strategy not in STRATEGY_FIELDS:
            raise ValueError(f"Unsupported verification strategy: {strategy!r}")
        if digest_preference is not None and digest_preference not in DIGEST_PREFERENCES:
            raise ValueError(f"Unsupported digest preference: {digest_preference!r}")
        if strategy == "skip-provenance":
            digest_preference = None
        rows = tuple(repositories)
        changes = 0
        for repo in rows:
            effective = strategy or repository_verification_strategy(repo)
            old = self._policy_fields(repo)
            if digest_preference is not None:
                repo.digest_preference = digest_preference
            # Legacy fallback/corroboration modes cannot be represented by a
            # modern strategy without changing their historical requirements.
            # A mixed-strategy checksum edit must leave them untouched.
            if effective in STRATEGY_FIELDS:
                requirement, policy = STRATEGY_FIELDS[effective]
                repo.verification_strategy = effective
                repo.digest_requirement = requirement
                repo.evidence_policy = policy
            changes += self._policy_fields(repo) != old
        return changes
