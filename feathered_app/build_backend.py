"""Package-backend dispatch for the selected distribution.

Given the package family implied by the target profile, this module selects the
RPM, Debian, or Arch implementation used for repository loading, dependency
analysis, and publication.

Imports no Tk, enforced by tests/test_build_request_module.py. It imports the
three package backends directly rather than through feathered_app.context, which
pulls in the widget toolkit for the benefit of the wizard modules.

Depends on BuildIntentMixin for the family predicates, which is the reason these
moved after it rather than before.
"""
from __future__ import annotations

from pathlib import Path
from typing import Collection, Protocol

import apt_core
import arch_core
import core


class BackendHost(Protocol):
    """Family selection and catalog knowledge consumed by backend dispatch."""

    def _is_arch(self) -> bool: ...
    def _is_deb(self) -> bool: ...
    def _known_workload_repository_roles(self) -> Collection[str]: ...


class BuildBackendMixin:
    """Family dispatch for repository loading, resolution and publication."""

    def _resolve_backend(self: BackendHost, requests, packages, arch: str, opts,
                         reporter: core.Reporter) -> core.ResolutionResult | apt_core.DebResolutionResult | arch_core.ArchResolutionResult:
        if self._is_arch():
            return arch_core.resolve(requests, packages, arch, opts, reporter)
        return apt_core.resolve(requests, packages, arch, opts, reporter) if self._is_deb() else core.resolve(requests, packages, arch, opts, reporter)

    def _write_bundle_backend(self: BackendHost, result, dest: Path, opts, reporter: core.Reporter, meta):
        from kubernetes_workflow import WorkloadContext, VKS_KEY, report, check_acknowledgement, enforce_baseline
        context = getattr(opts, "workload_context", None)
        if isinstance(context, WorkloadContext):
            meta = dict(meta, platform_note=context.platform_note)
            if context.active:
                data = report(context, result.selected)
                check_acknowledgement(data)
                if context.workload == VKS_KEY and context.pin_baseline and not meta.get('repository_mirror'):
                    enforce_baseline(result, opts.target_inventory)
                if context.workload == VKS_KEY and not meta.get('repository_mirror'):
                    from dataclasses import asdict
                    data['image_draft_context'] = asdict(context)
                meta['kubernetes'] = data
        if self._is_arch():
            return arch_core.write_bundle(result, dest, opts, reporter, meta)
        return apt_core.write_bundle(result, dest, opts, reporter, meta) if self._is_deb() else core.write_bundle(result, dest, opts, reporter, meta)

    def _load_repository_backend(self: BackendHost, repo: core.RepoSpec, arches: set[str],
                                 reporter: core.Reporter) -> list[core.Package] | list[apt_core.DebPackage] | list[arch_core.ArchPackage]:
        if repo.repo_format == "pacman" or self._is_arch():
            return arch_core.load_repository(repo, arches, reporter)
        if repo.repo_format == "apt" or self._is_deb():
            return apt_core.load_repository(repo, arches, reporter)
        return core.load_repository(repo, arches, reporter)

    def _repo_tier(self: BackendHost, repo: object) -> str:
        tier = getattr(repo, "source_tier", "")
        if tier in {"base", "workload", "additional"}:
            return tier
        # Workload/vendor roles are not distribution base sources.  Old
        # RepoSpec objects may predate source_tier, so recover the distinction
        # from the current workload-role catalog rather than special-casing
        # Docker forever.
        if getattr(repo, "role", "") in self._known_workload_repository_roles():
            return "workload"
        note = (getattr(repo, "note", "") or "").lower()
        if note.startswith("user-added"):
            return "additional"
        return "base"

    def _parse_target_inventory_backend(self: BackendHost, path: Path) -> core.TargetInventory | apt_core.AptTargetInventory | arch_core.ArchTargetInventory:
        if self._is_arch():
            return arch_core.parse_target_inventory(path)
        return apt_core.parse_target_inventory(path) if self._is_deb() else core.parse_target_inventory(path)
