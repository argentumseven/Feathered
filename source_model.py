from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class RootSourcePolicy:
    """Source intent for one requested workload root.

    ``distribution`` means any enabled top-level repository belonging to the
    selected OS distribution. ``workload`` means any enabled repository with
    the declared role. ``enabled`` is reserved for free-form/custom package
    selections where the operator intentionally allows the whole enabled set.
    """
    package: str
    source_kind: str
    role: Optional[str] = None
    # Semantic component identity and ordered, explicitly-approved package
    # names. A singleton preserves the legacy fixed-package behavior.
    component: str = ""
    candidates: Tuple[str, ...] = field(default_factory=tuple)
    optional: bool = False


@dataclass(frozen=True)
class SourcePlan:
    """Single package-source contract shared by UI, validation and resolver."""
    roots: List[RootSourcePolicy] = field(default_factory=list)

    @property
    def required_roles(self) -> List[str]:
        return list(dict.fromkeys(
            root.role for root in self.roots
            if root.source_kind == "workload" and root.role))

    @property
    def distribution_required(self) -> bool:
        return any(root.source_kind == "distribution" for root in self.roots)

    @property
    def source_model(self) -> str:
        kinds = {root.source_kind for root in self.roots}
        if not kinds:
            return "empty"
        if kinds == {"distribution"}:
            return "distribution-native"
        if kinds == {"workload"}:
            return "workload-specific"
        if "distribution" in kinds and "workload" in kinds:
            return "mixed distribution + workload-specific"
        if kinds == {"enabled"}:
            return "all enabled repositories"
        return "mixed source policy"


