from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from source_readiness import SourceReadiness


WORKLOAD_PACKAGE_ONLY_MODE = "Workload packages only"


class AcquisitionIntent(str, Enum):
    """What the operator is asking Feathered to acquire."""

    WORKLOAD = "workload"
    PACKAGES = "packages"
    REPOSITORY_MIRROR = "repository-mirror"


class AcquisitionCapability(str, Enum):
    """The strongest honest operation Feathered can perform for the intent."""

    FULL_TRANSACTION = "full-transaction"
    PACKAGE_ONLY = "package-only"
    REPOSITORY_MIRROR = "repository-mirror"
    BLOCKED = "blocked"


class MirrorLayout(str, Enum):
    """How a multi-repository mirror is published.

    ``SEPARATE`` is the default and the conservative choice: one output
    directory and one metadata set per selected repository, no cross-repository
    de-duplication, so each output stays a faithful snapshot of one upstream.

    ``UNIFIED`` republishes the selected repositories as a single repository
    with one metadata set, collapsing package identities that Feathered can
    prove are the same artifact.  It is a merge, not a snapshot, and the
    resulting directory is nobody's upstream.  See mirror_unification.py.
    """

    SEPARATE = "separate"
    UNIFIED = "unified"


MIRROR_LAYOUT_LABELS = {
    MirrorLayout.SEPARATE: "Separate folders, one per repository (faithful snapshots)",
    MirrorLayout.UNIFIED: "One unified repository, duplicates removed (merged union)",
}


def mirror_layout_from_label(value: str) -> MirrorLayout:
    """Map the Output Directories control back to the domain enum."""
    text = str(value or "").strip().lower()
    if text.startswith("one unified") or text == MirrorLayout.UNIFIED.value:
        return MirrorLayout.UNIFIED
    return MirrorLayout.SEPARATE


class AnalysisType(str, Enum):
    DEPENDENCY_CLOSURE = "dependency-closure"
    ROOT_ONLY = "root-only"
    MIRROR_INVENTORY = "mirror-inventory"
    NONE = "none"


class PublicationType(str, Enum):
    TRANSACTION_BUNDLE = "transaction-bundle"
    PACKAGE_ONLY = "package-only"
    REPOSITORY_MIRROR = "repository-mirror"
    BLOCKED = "blocked"


class VerificationScope(str, Enum):
    RESOLVED_TRANSACTION = "resolved-transaction"
    REQUESTED_ROOTS = "requested-roots"
    MIRROR_CONTENTS = "mirror-contents"
    NONE = "none"


@dataclass(frozen=True)
class AcquisitionState:
    """Derived state shared by navigation, analysis, verification and build UI.

    The state is deliberately a result rather than mutable configuration.  The
    operator chooses an intent and repositories; Feathered derives what can be
    honestly analyzed/published from those inputs.  Impossible combinations
    therefore do not need to be represented by independent booleans.
    """

    intent: AcquisitionIntent
    capability: AcquisitionCapability
    analysis: AnalysisType
    publication: PublicationType
    verification_scope: VerificationScope
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.capability is AcquisitionCapability.BLOCKED

    @property
    def allows_dependency_analysis(self) -> bool:
        return self.analysis is AnalysisType.DEPENDENCY_CLOSURE

    @property
    def is_package_only(self) -> bool:
        return self.capability is AcquisitionCapability.PACKAGE_ONLY

    @property
    def is_mirror(self) -> bool:
        return self.capability is AcquisitionCapability.REPOSITORY_MIRROR


def intent_from_selection_mode(value: str) -> AcquisitionIntent:
    value = str(value or "").strip().lower()
    if value == "choose packages":
        return AcquisitionIntent.PACKAGES
    if value == "entire repository (mirror)":
        return AcquisitionIntent.REPOSITORY_MIRROR
    return AcquisitionIntent.WORKLOAD


def _state(intent: AcquisitionIntent, capability: AcquisitionCapability, reason: str = "") -> AcquisitionState:
    if capability is AcquisitionCapability.FULL_TRANSACTION:
        return AcquisitionState(
            intent, capability, AnalysisType.DEPENDENCY_CLOSURE,
            PublicationType.TRANSACTION_BUNDLE,
            VerificationScope.RESOLVED_TRANSACTION, reason)
    if capability is AcquisitionCapability.PACKAGE_ONLY:
        return AcquisitionState(
            intent, capability, AnalysisType.ROOT_ONLY,
            PublicationType.PACKAGE_ONLY,
            VerificationScope.REQUESTED_ROOTS, reason)
    if capability is AcquisitionCapability.REPOSITORY_MIRROR:
        return AcquisitionState(
            intent, capability, AnalysisType.MIRROR_INVENTORY,
            PublicationType.REPOSITORY_MIRROR,
            VerificationScope.MIRROR_CONTENTS, reason)
    return AcquisitionState(
        intent, AcquisitionCapability.BLOCKED, AnalysisType.NONE,
        PublicationType.BLOCKED, VerificationScope.NONE, reason)


def derive_acquisition_state(
    intent: AcquisitionIntent,
    *,
    workload_readiness: Optional[SourceReadiness] = None,
    exact_root_count: int = 0,
    exact_root_sources_ready: bool = False,
    mirror_repository_count: int = 0,
    workload_root_count: Optional[int] = None,
    workload_package_only_requested: bool = False,
) -> AcquisitionState:
    """Derive the only valid downstream state for an acquisition intent."""

    if intent is AcquisitionIntent.REPOSITORY_MIRROR:
        if mirror_repository_count <= 0:
            return _state(intent, AcquisitionCapability.BLOCKED,
                          "Select at least one enabled repository to mirror.")
        return _state(intent, AcquisitionCapability.REPOSITORY_MIRROR)

    if intent is AcquisitionIntent.PACKAGES:
        if exact_root_count <= 0:
            return _state(intent, AcquisitionCapability.BLOCKED,
                          "Choose at least one package after configuring repositories.")
        if not exact_root_sources_ready:
            return _state(intent, AcquisitionCapability.BLOCKED,
                          "A repository containing one or more selected package roots is no longer enabled.")
        # Exact-package mode is a transaction request.  It never silently
        # degrades to package-only acquisition; the resolver must prove the
        # dependency closure from the configured universe.
        return _state(intent, AcquisitionCapability.FULL_TRANSACTION)

    if workload_readiness is None:
        return _state(intent, AcquisitionCapability.BLOCKED,
                      "Workload repository readiness has not been evaluated.")
    if workload_root_count is not None and workload_root_count <= 0:
        return _state(intent, AcquisitionCapability.BLOCKED,
                      "Choose at least one workload package on Repositories before analyzing or building.")
    if workload_readiness.missing_scopes:
        missing = ", ".join(workload_readiness.missing_scopes)
        return _state(intent, AcquisitionCapability.BLOCKED,
                      f"Required workload source scope is unavailable: {missing}.")
    if workload_package_only_requested:
        return _state(
            intent, AcquisitionCapability.PACKAGE_ONLY,
            "Package-only acquisition was selected. Enabled dependency providers will not be used.")
    if workload_readiness.package_only:
        return _state(
            intent, AcquisitionCapability.PACKAGE_ONLY,
            "Workload roots are available, but no other enabled repository remains to provide dependencies. Enable a target-compatible OS or supplemental repository to analyze the dependency closure.")
    return _state(intent, AcquisitionCapability.FULL_TRANSACTION)
