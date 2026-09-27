"""GUI-independent validation of the wizard's repository evidence contract.

The presentation layer supplies a snapshot of the *current* repository/evidence
selection and its explicitly keyed spot-test results.  Validation never performs
network I/O, consults App, or upgrades an untested/failed source to usable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from evidence_model import REL_REBUILD_PEER


@dataclass(frozen=True)
class EvidenceSourceCheck:
    """One currently required repository and its selected evidence test."""

    repository_name: str
    has_source: bool
    selected_relationship: str = ""
    preflight_status: str = ""
    preflight_relationship: str = ""
    preflight_detail: str = ""


class ProvenanceValidationService:
    """Deterministic navigation gate, independent of widgets and cache identity."""

    PASSING_STATUSES = frozenset({"repository", "artifact-only", "peer"})

    @staticmethod
    def validate_prerequisites(*, checksum_selected: bool,
                               pending_inspection: Sequence[str]) -> None:
        if not checksum_selected:
            raise RuntimeError(
                "Enhanced or Maximum verification requires a checksum policy. Choose the Minimum "
                "checksum strength before configuring independent evidence.")
        if pending_inspection:
            raise RuntimeError(
                "Enhanced verification must inspect checksum support before Feathered can determine "
                "which repositories require fallback evidence. Use Inspect checksum support first. "
                "Not yet inspected: " + ", ".join(pending_inspection[:4]))

    @classmethod
    def validate_evidence(cls, *, strategy: str, sources: Sequence[EvidenceSourceCheck],
                          strategy_label: str) -> None:
        """Preserve the GUI's historical error priority: invalid/missing/untested/failed."""
        if strategy not in {"evidence-fallback", "full-corroboration"}:
            return
        missing: list[str] = []
        untested: list[str] = []
        failed: list[tuple[str, str]] = []
        invalid: list[str] = []
        for source in sources:
            if not source.has_source:
                missing.append(source.repository_name)
                continue
            if strategy == "evidence-fallback" and source.selected_relationship == REL_REBUILD_PEER:
                invalid.append(source.repository_name)
                continue
            if not source.preflight_status or source.preflight_status in {"testing", "untested"}:
                untested.append(source.repository_name)
                continue
            if source.preflight_status not in cls.PASSING_STATUSES:
                failed.append((source.repository_name,
                               source.preflight_detail or "Evidence source is unusable"))
                continue
            if strategy == "evidence-fallback" and source.preflight_relationship == REL_REBUILD_PEER:
                invalid.append(source.repository_name)

        if invalid:
            raise RuntimeError(
                "Enhanced verification can fill checksum gaps only with an exact mirror or exact-artifact source whose bytes match the acquisition artifact. "
                "Semantic rebuild peers are Maximum-only. Replace the evidence source for: " + ", ".join(invalid[:4]))
        if missing:
            scope = ("every participating package source" if strategy == "full-corroboration"
                     else "every source that may need checksum fallback")
            raise RuntimeError(
                f"{strategy_label} requires evidence for {scope}. "
                "No evidence source is selected for: " + ", ".join(missing[:4]))
        if untested:
            raise RuntimeError(
                "Every required evidence pairing must pass an explicit spot test before continuing. Use Test evidence sources. "
                "Not yet tested: " + ", ".join(untested[:4]))
        if failed:
            first_name, first_detail = failed[0]
            raise RuntimeError(f"Evidence testing failed for {first_name}: {first_detail}")
