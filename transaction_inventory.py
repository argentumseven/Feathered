"""Family-specific installed-state policies, independent of the UI and loop.

Returned inventories own their mutable capability collections. Reverse checks
consume the captured relationships and the selected final payload together.
"""
from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from apt_core import AptTargetInventory, DebPackage, DebRequirement
    from arch_core import ArchPackage, ArchRelation, ArchTargetInventory
    from core import BuildOptions, Package, Requirement, TargetInventory
    from root_requests import RootRequest


def retained_rpm_inventory(original: TargetInventory | None,
                           selected: Sequence[Package]) -> TargetInventory | None:
    if original is None:
        return None
    inv = copy.deepcopy(original)
    if not selected:
        return inv
    import core
    names = {p.name for p in selected}
    kept: dict[str, list[Requirement]] = {}
    for owner, capabilities in inv.package_capabilities.items():
        if owner.rsplit("-", 2)[0] in names:
            continue
        if any(core.evr_satisfies(cap, obsolete)
               for p in selected for obsolete in p.obsoletes for cap in capabilities
               if core.capability_names_equal(cap.name, obsolete.name)):
            continue
        kept[owner] = capabilities
    inv.package_capabilities = kept
    inv.nevras = set(kept)
    inv.capabilities.clear()
    for caps in kept.values():
        for cap in caps:
            for key in core._index_keys(cap.name):
                inv.capabilities[key].append(cap)
    return inv


def retained_deb_inventory(original: AptTargetInventory | None,
                           selected: Sequence[DebPackage]) -> AptTargetInventory | None:
    if original is None:
        return None
    inv = copy.deepcopy(original)
    names = {p.name for p in selected}
    inv.packages = {k: v for k, v in inv.packages.items() if k[0] not in names}
    inv.provides = {key: [row for row in rows if row[0].split("=", 1)[0] not in names]
                    for key, rows in inv.provides.items()}
    return inv


def retained_arch_inventory(original: ArchTargetInventory | None,
                            selected: Sequence[ArchPackage]) -> ArchTargetInventory | None:
    if original is None:
        return None
    import arch_core
    inv = copy.deepcopy(original)
    removed = {p.name for p in selected}
    for name, version in inv.packages.items():
        if any(r.name == name and arch_core._satisfies_version(version, r.operator, r.version)
               for p in selected for r in p.replaces):
            removed.add(name)
    inv.packages = {k: v for k, v in inv.packages.items() if k not in removed}
    return inv


def rpm_retained_failures(selected: Sequence[Package], inventory: TargetInventory | None
                          ) -> list[tuple[Package, Requirement, str]]:
    if inventory is None or not inventory.relationships_complete:
        return []
    import core
    active = retained_rpm_inventory(inventory, selected)
    assert active is not None
    retained = [p for p in inventory.retained_packages if p.nevra in active.nevras]
    final = list(selected) + retained
    selected_names = {p.name for p in selected}
    problems: list[tuple[Package, Requirement, str]] = []

    def satisfied(req: Requirement) -> bool:
        if req.name.startswith('rpmlib('):
            return True
        conditional = core.parse_simple_rich_if(req)
        if conditional:
            consequence, condition = conditional
            return not satisfied(condition) or satisfied(consequence)
        either = core.parse_simple_rich_or(req)
        if either:
            return any(satisfied(r) for r in either)
        same = core.parse_simple_rich_with(req)
        if same:
            return any(all(core.package_satisfies(p, r) for r in same) for p in final)
        return any(core.package_satisfies(p, req) for p in final)

    for package in retained:
        if package.name in selected_names:
            continue
        for requirement in package.requires:
            if not satisfied(requirement):
                problems.append((package, requirement, core.format_requirement(requirement)))
    return problems


def deb_retained_failures(selected: Sequence[DebPackage], inventory: AptTargetInventory | None
                          ) -> list[tuple[DebPackage, DebRequirement, str]]:
    if inventory is None or not inventory.relationships_complete:
        return []
    import apt_core
    active = retained_deb_inventory(inventory, selected)
    assert active is not None
    retained = [p for p in inventory.retained_packages if (p.name, p.arch) in active.packages]
    final = list(selected) + retained
    selected_names = {p.name for p in selected}
    problems: list[tuple[DebPackage, DebRequirement, str]] = []
    for package in retained:
        if package.name in selected_names:
            continue
        for requirement in package.depends + package.pre_depends:
            if not any(apt_core._pkg_satisfies_atom(p, atom)
                       for atom in requirement.alternatives for p in final):
                problems.append((package, requirement, apt_core.format_requirement(requirement)))
    return problems


def arch_retained_failures(selected: Sequence[ArchPackage], inventory: ArchTargetInventory | None
                           ) -> list[tuple[ArchPackage, ArchRelation, str]]:
    if inventory is None or not inventory.relationships_complete:
        return []
    import arch_core
    active = retained_arch_inventory(inventory, selected)
    assert active is not None
    retained = [p for p in inventory.retained_packages if p.name in active.packages]
    final = list(selected) + retained
    selected_names = {p.name for p in selected}
    problems: list[tuple[ArchPackage, ArchRelation, str]] = []
    for package in retained:
        if package.name in selected_names:
            continue
        for requirement in package.depends:
            if not any(arch_core._relation_matches_package(p, requirement) for p in final):
                problems.append((package, requirement, arch_core.format_requirement(requirement)))
    return problems


def arch_upgrade_requests(requests: list[RootRequest], packages: Sequence[ArchPackage],
                          architecture: str, options: BuildOptions[ArchTargetInventory]
                          ) -> tuple[list[RootRequest], bool]:
    """Extend roots to the loaded snapshot, rejecting incomplete target upgrades."""
    import arch_core
    from root_requests import RootRequest
    inv = options.target_inventory
    if inv is None or not options.include_dependencies:
        return requests, False
    if not inv.relationships_complete:
        raise RuntimeError('Arch target-aware installation requires a fresh inventory with relationships. Copy target_inventory.sh and target_inventory_details.py together to the target and collect again.')
    requested = {r.name: r for r in requests}
    additions: list[RootRequest] = []
    for installed in inv.retained_packages:
        current = arch_core._find_root((installed.name, None, None), packages, architecture)
        if current is None:
            if installed.managed:
                raise RuntimeError(f'{installed.name}: installed repository-managed package has no candidate in this repository snapshot. Include its repository or use a complete matching snapshot.')
            continue
        if arch_core.compare_versions(current.version, installed.version) < 0:
            raise RuntimeError(f'{installed.name}: repository snapshot is older than the captured target; use a consistent newer snapshot.')
        request = requested.get(installed.name)
        if request is not None:
            wanted = arch_core._find_root(request.as_tuple(), packages, architecture)
            if wanted is None or wanted.nevra != current.nevra or wanted.repo.source_identity != current.repo.source_identity:
                raise RuntimeError(f'{installed.name}: exact root conflicts with the full repository upgrade plan. Select a matching snapshot.')
        else:
            additions.append(RootRequest(current.name, current.version, current.repo.role,
                                         current.repo.name, current.arch, None, current.repo.source_identity))
    return requests + additions, True
