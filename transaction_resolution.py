"""Checked fixed-point transaction orchestration with explicit family capabilities.

Family adapters retain inventory filtering, reverse-dependency interpretation and
result storage. This loop owns convergence, repair scheduling and cancellation
ordering. It returns the original concrete result object, without copying it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, Protocol, Sequence, TypeVar

from root_requests import RootRequest


class TransactionSource(Protocol):
    @property
    def source_identity(self) -> str: ...


class TransactionPackage(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def nevra(self) -> str: ...
    @property
    def repo(self) -> TransactionSource: ...


PackageT = TypeVar("PackageT", bound=TransactionPackage)
RequirementT = TypeVar("RequirementT")
OptionsT = TypeVar("OptionsT")
ResultT = TypeVar("ResultT")


@dataclass(frozen=True)
class TransactionContext(Generic[PackageT, RequirementT, OptionsT, ResultT]):
    """Capabilities needed by the loop, retaining all family-specific types.

    Callbacks are lazy: inventory preparation happens after the cancellation
    checkpoint, reverse validation happens only at stability with dependencies
    enabled, and finalization happens only on a completed transaction.
    """

    resolve_once: Callable[[list[RootRequest], Sequence[PackageT], OptionsT], ResultT]
    prepare_options: Callable[[list[PackageT]], OptionsT]
    selected: Callable[[ResultT], Sequence[PackageT]]
    retained_failures: Callable[[ResultT], Sequence[tuple[PackageT, RequirementT, str]]]
    record_unresolved: Callable[[ResultT, RequirementT, str, str], None]
    finalize: Callable[[ResultT, list[RootRequest]], None]
    check_cancel: Callable[[], None]
    max_resolution_passes: Callable[[], int]
    include_dependencies: Callable[[], bool]


def resolve_fixed_point(context: TransactionContext[PackageT, RequirementT, OptionsT, ResultT],
                        requests: list[RootRequest], packages: Sequence[PackageT]) -> ResultT:
    """Resolve an owned, normalized request list within the existing pass budget.

    Repairs extend ``requests`` in place. The public adapter supplies a fresh
    normalized list, so an operator's original request sequence is not mutated.
    """
    prior: list[PackageT] = []
    repair_names: set[str] = set()
    seen: set[tuple[tuple[str, str], ...]] = set()
    for _ in range(max(4, int(context.max_resolution_passes()) + 2)):
        context.check_cancel()
        options = context.prepare_options(prior)
        result = context.resolve_once(requests, packages, options)
        state = tuple(sorted((p.nevra, p.repo.source_identity) for p in context.selected(result)))
        if state == tuple(sorted((p.nevra, p.repo.source_identity) for p in prior)):
            problems = context.retained_failures(result) if context.include_dependencies() else []
            repairs: list[RootRequest] = []
            for owner, requirement, label in problems:
                if (owner.name not in repair_names and owner.name not in {r.name for r in requests}
                        and any(p.name == owner.name and p.nevra != owner.nevra for p in packages)):
                    repairs.append(RootRequest(owner.name))
                    repair_names.add(owner.name)
                elif not repairs:
                    context.record_unresolved(
                        result, requirement, label,
                        f"Retained target package {owner.nevra} would lose this requirement")
            if repairs:
                requests += repairs
                prior = []
                seen.clear()
                continue
            context.finalize(result, requests)
            return result
        if state in seen:
            raise RuntimeError("Target transaction did not converge; package replacements or conditional dependencies form an unresolved cycle.")
        seen.add(state)
        prior = list(context.selected(result))
    raise RuntimeError("Final target-state validation exceeded the resolution budget; no complete transaction was established.")
