"""Check selected packages against the installed packages that will remain."""
from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from apt_core import AptTargetInventory, DebPackage
    from arch_core import ArchPackage, ArchTargetInventory
    from core_models import Package, TargetInventory


def deb_installed_conflicts(selected: Sequence[DebPackage], inventory: AptTargetInventory | None,
                            architecture: str) -> list[tuple[DebPackage, str]]:
    if inventory is None:
        return []
    import apt_core as apt
    from transaction_inventory import retained_deb_inventory
    active = retained_deb_inventory(inventory, selected)
    assert active is not None
    problems = []
    for package in selected:
        for requirement in package.conflicts + package.breaks:
            for atom in requirement.alternatives:
                owner = apt._inventory_atom_satisfied(active, atom, architecture)
                if owner:
                    problems.append((package, f'{package.nevra} declares {requirement.kind}: '
                                     f'{apt.format_requirement(requirement)}; installed {owner}'))
        for retained in active.retained_packages:
            if (retained.name, retained.arch) not in active.packages:
                continue
            for requirement in retained.conflicts + retained.breaks:
                if any(apt._pkg_satisfies_atom(package, atom) for atom in requirement.alternatives):
                    problems.append((package, f'Installed {retained.nevra} declares {requirement.kind}: '
                                     f'{apt.format_requirement(requirement)}; selected {package.nevra}'))
    return problems


def rpm_installed_conflicts(selected: Sequence[Package], inventory: TargetInventory | None
                            ) -> list[tuple[Package, str]]:
    if inventory is None:
        return []
    import core
    from transaction_inventory import retained_rpm_inventory
    active = retained_rpm_inventory(inventory, selected)
    assert active is not None
    problems = []
    for retained in active.retained_packages:
        if retained.nevra not in active.nevras:
            continue
        for requirement in retained.conflicts:
            for package in selected:
                if core.package_satisfies(package, requirement):
                    problems.append((package, f'Installed {retained.nevra} conflicts with '
                                     f'{package.nevra} via {core.format_requirement(requirement)}'))
    return problems


def arch_installed_conflicts(selected: Sequence[ArchPackage], inventory: ArchTargetInventory | None
                             ) -> list[tuple[ArchPackage, str]]:
    if inventory is None:
        return []
    import arch_core as arch
    from transaction_inventory import retained_arch_inventory
    active = retained_arch_inventory(inventory, selected)
    assert active is not None
    problems = []
    for package in selected:
        for requirement in package.conflicts:
            if arch._inventory_satisfies(active, requirement):
                problems.append((package, f'{package.nevra} conflicts with an installed target capability: '
                                 f'{arch.format_requirement(requirement)}'))
        for retained in active.retained_packages:
            if retained.name not in active.packages:
                continue
            for requirement in package.conflicts:
                if arch._relation_matches_package(retained, requirement):
                    problems.append((package, f'{package.nevra} conflicts with installed {retained.nevra} '
                                     f'via {arch.format_requirement(requirement)}'))
            for requirement in retained.conflicts:
                if arch._relation_matches_package(package, requirement):
                    problems.append((package, f'Installed {retained.nevra} conflicts with '
                                     f'{package.nevra} via {arch.format_requirement(requirement)}'))
    return problems
