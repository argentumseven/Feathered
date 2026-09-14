"""Typed, owned inputs for one prepared execution; no toolkit dependencies."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Collection, Generic, Sequence, TypeAlias, TypeVar

from acquisition_model import AcquisitionState
from core import BuildOptions, RepoSpec, TargetInventory
from apt_core import AptTargetInventory
from arch_core import ArchTargetInventory
from root_requests import RootInput, RootRequest

InventoryT = TypeVar('InventoryT')


@dataclass(frozen=True)
class BuildPlan(Generic[InventoryT]):
    """Own the mutable execution graph while fixing the operator's root intent.

    Constructor order and legacy request tuples remain supported. Copy the graph
    together so intentional aliases inside a run survive, but callers and other
    runs cannot change it. Verification and publication may annotate the owned
    options and repositories; they are deliberately not recursively frozen.
    """
    state: AcquisitionState
    opts: BuildOptions[InventoryT]
    requests: Sequence[RootInput]
    requested_source_plan: list[dict[str, str]]
    build_repositories: Sequence[RepoSpec]
    package_only: bool
    picked_at_start: Collection[str] | None
    do_download: bool = True
    locked_output_folder_name: str | None = None
    locked_mirror_publications: Sequence[tuple[str, str, BuildOptions[InventoryT]]] | None = None

    def __post_init__(self) -> None:
        opts, source_plan, repositories, publications = copy.deepcopy((
            self.opts, self.requested_source_plan, self.build_repositories,
            self.locked_mirror_publications))
        # Roots are immutable values, with all seven exact-identity fields kept.
        roots = tuple(RootRequest.from_value(row) for row in self.requests)
        object.__setattr__(self, 'opts', opts)
        object.__setattr__(self, 'requests', roots)
        object.__setattr__(self, 'requested_source_plan', source_plan)
        object.__setattr__(self, 'build_repositories', tuple(repositories))
        object.__setattr__(self, 'picked_at_start',
                           None if self.picked_at_start is None else frozenset(self.picked_at_start))
        object.__setattr__(self, 'locked_mirror_publications',
                           None if publications is None else tuple(publications))


# Keep the three concrete option/inventory pairings in public signatures.
# BuildPlan[InventoryA | InventoryB] would allow swapping families inside a run.
PreparedPlan: TypeAlias = (BuildPlan[TargetInventory] | BuildPlan[AptTargetInventory]
                           | BuildPlan[ArchTargetInventory])
