"""Typed, late-bound backend operations with the legacy selection precedence."""
from __future__ import annotations
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Generic, TypeVar
import core
import apt_core
import arch_core
from root_requests import RootInput

P = TypeVar('P')
R = TypeVar('R')
I = TypeVar('I')


@dataclass(frozen=True)
class Backend(Generic[P, R, I]):
    resolve: Callable[[Sequence[RootInput], Sequence[P], str, core.BuildOptions[I], core.Reporter], R]
    write: Callable[[R, Path, core.BuildOptions[I], core.Reporter, dict[str, object]], Path]
    load: Callable[[core.RepoSpec, set[str], core.Reporter], list[P]]
    inventory: Callable[[Path], I]


# Lambdas look up module attributes at invocation time. Capturing the functions
# themselves would silently bypass the public backend monkeypatch/override seams.
RPM = Backend[core.Package, core.ResolutionResult, core.TargetInventory](
    lambda roots, packages, arch, options, reporter: core.resolve(roots, packages, arch, options, reporter),
    lambda result, path, options, reporter, metadata: core.write_bundle(result, path, options, reporter, metadata),
    lambda repo, arches, reporter: core.load_repository(repo, arches, reporter),
    lambda path: core.parse_target_inventory(path),
)
DEB = Backend[apt_core.DebPackage, apt_core.DebResolutionResult, apt_core.AptTargetInventory](
    lambda roots, packages, arch, options, reporter: apt_core.resolve(roots, packages, arch, options, reporter),
    lambda result, path, options, reporter, metadata: apt_core.write_bundle(result, path, options, reporter, metadata),
    lambda repo, arches, reporter: apt_core.load_repository(repo, arches, reporter),
    lambda path: apt_core.parse_target_inventory(path),
)
ARCH = Backend[arch_core.ArchPackage, arch_core.ArchResolutionResult, arch_core.ArchTargetInventory](
    lambda roots, packages, arch, options, reporter: arch_core.resolve(roots, packages, arch, options, reporter),
    lambda result, path, options, reporter, metadata: arch_core.write_bundle(result, path, options, reporter, metadata),
    lambda repo, arches, reporter: arch_core.load_repository(repo, arches, reporter),
    lambda path: arch_core.parse_target_inventory(path),
)
SelectedBackend = (Backend[core.Package, core.ResolutionResult, core.TargetInventory]
                   | Backend[apt_core.DebPackage, apt_core.DebResolutionResult, apt_core.AptTargetInventory]
                   | Backend[arch_core.ArchPackage, arch_core.ArchResolutionResult, arch_core.ArchTargetInventory])
BACKENDS: MappingProxyType[str, SelectedBackend] = MappingProxyType({'rpm': RPM, 'deb': DEB, 'arch': ARCH})


def select_backend(is_arch: Callable[[], bool], is_deb: Callable[[], bool],
                   repository_format: str = '') -> SelectedBackend:
    # Preserve short-circuit order, including APT-format sources on Arch hosts.
    if repository_format == 'pacman' or is_arch():
        return BACKENDS['arch']
    if repository_format == 'apt' or is_deb():
        return BACKENDS['deb']
    return BACKENDS['rpm']
