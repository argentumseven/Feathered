"""Repository metadata loading and root requests shared by GUI and CLI.

Frozen accessors serve execution. Preparation rules live in build_preparation;
the public spec entry point is build_api. Metadata cache signatures remain
independent of publication names and locks. This module imports no Tk.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from acquisition_model import (AcquisitionCapability, AcquisitionIntent,
                               intent_from_selection_mode)
from core import (BuildOptions, Cancelled, Reporter, redact_url,
                  repository_verification_strategy)
from feathered_app.build_request import BuildRequestMixin, _SnapshotMode
from feathered_app.build_runner import _indexed_evidence_records
from source_readiness import missing_reachable_scopes
from workload_materialization import MaterializedWorkload

from feathered_app.build_intent import BuildIntentMixin
from feathered_app.metadata_loading import (MetadataLoadContext, load_metadata,
                                            lookup_metadata_cache, store_metadata_cache)


class _SnapshotSelection:
    """The Content label from the frozen request, in ``.get()`` shape."""

    __slots__ = ("_host",)

    def __init__(self, host):
        self._host = host

    def get(self):
        read = getattr(self._host, "_selected_mode_label", None)
        return read() if callable(read) else ""


class BuildSourcesMixin:
    """Repository loading and request construction. No widget access."""

    def _signature(self):
        """Everything about the sources that changes what metadata is loaded.

        Cached indexes are reused when this is unchanged, so anything omitted
        here would serve stale packages after the operator edited it.
        """
        return (tuple((r.name, r.url, r.role, r.priority, r.enabled, r.client_cert,
                       r.client_key, r.ca_cert, tuple(getattr(r, "redirect_allow_origins", []) or []),
                       r.optional, r.repo_format, r.suite,
                       r.components, getattr(r, "vendor_id", ""), r.keyring, r.allow_unverified_index,
                       tuple(r.evidence_urls),
                       tuple(sorted(getattr(r, "evidence_relationship_hints", {}).items())),
                       tuple(sorted(getattr(r, "evidence_authority_hints", {}).items())),
                       r.evidence_policy,
                       r.digest_preference, r.digest_requirement, r.verification_strategy)
                      for r in self.repo_rows),
                BuildRequestMixin._selected_arch(self))

    def _load_enabled_repos(self, reporter: Reporter, repositories=None,
                            enforce_distribution_plan: bool = True):
        """Load package metadata from the requested enabled repository set.

        Normal analysis loads the complete enabled set and may reuse the global
        metadata cache. Selection coverage is deliberately narrower: it loads
        only repositories that are eligible to satisfy the requested roots.
        This prevents an unconfigured or unreachable base-source plan from
        blocking proof that a workload-only upstream actually carries its root
        packages.
        """
        context = MetadataLoadContext(
            build_scope=lambda: self._build_repository_scope(),
            signature=lambda: self._signature(),
            signature_tier=lambda repo: getattr(repo, "source_tier", "base"),
            selected_arch=lambda: BuildRequestMixin._selected_arch(self),
            mirror_mode=lambda: self._mirror_mode(),
            load_repository=lambda repo, arches, rep: self._load_repository_backend(repo, arches, rep),
            validate_successful=lambda successful, enabled: self._validate_successful_source_scopes(successful, enabled),
            active_source_method=lambda: self._active_source_method(),
            source_tier=lambda repo: self._repo_tier(repo),
            lookup_cache=lambda signature: lookup_metadata_cache(self, signature),
            store_cache=lambda signature, packages: store_metadata_cache(self, signature, packages),
            cancelled_error=Cancelled,
        )
        return load_metadata(context, reporter, repositories, enforce_distribution_plan)

    def _package_requests(self, materialized: Optional[MaterializedWorkload] = None):
        if self._mirror_mode():
            return []
        if self._single_mode():
            requests = [(p.name, p.evr_text, p.repo.role, p.repo.name, p.arch, None, p.repo.source_identity)
                        for p in self.selected_packages]
            # The "Custom packages" preset routes through this same exact-package
            # workflow (one workflow, not a fork). Names typed on Content remain
            # a convenience seed and are merged as unpinned roots so nothing
            # typed is silently dropped once the chooser exists on Repositories.
            var = _SnapshotMode(self)
            in_workload_mode = var is not None and intent_from_selection_mode(var.get()) is AcquisitionIntent.WORKLOAD
            if in_workload_mode and self._workload().custom:
                chosen = {str(r[0]) for r in requests}
                # Frozen request: this runs on the build worker, and custom_var
                # is a Tk variable. Missed by the isolation tripwire because no
                # fixture used the "Custom packages" preset.
                typed = [x for x in re.split(
                    r"[\s,]+", BuildRequestMixin._selected_content(
                        self, "custom_packages", "custom_var")) if x]
                requests.extend((name, None, None) for name in typed if name not in chosen)
                if not requests:
                    raise RuntimeError(
                        "Choose at least one exact package on Repositories (or type names on Content)")
                return self._augment_requests_for_init(requests)
            if not requests:
                raise RuntimeError("Choose at least one exact package on Repositories")
            return self._augment_requests_for_init(requests)
        workload = self._workload()

        version = BuildRequestMixin._selected_content(self, "package_version", "package_version_var")
        pinned = set(workload.versioned_packages)
        family = self._profile().package_family
        if family == "arch" and workload.has_version_axis:
            # Built-in version axes were originally named for RPM/DEB package
            # identities. On Arch, the first native mapped root is the semantic
            # version anchor (for example docker rather than docker-ce).
            native = workload.packages_for("arch")
            pinned = {native[0]} if native else set()
        elif not pinned and workload.has_version_axis and workload.version_package:
            pinned = {workload.version_package}

        roots = []
        if materialized is not None:
            for root in materialized.roots:
                roots.append((root.package, root.primary_package, root.source_kind, root.role))
            # Preserve unresolved optional components so the resolver can report
            # them as optional gaps rather than silently erasing catalog intent.
            for policy in materialized.unresolved:
                if policy.optional:
                    roots.append((policy.package, policy.package, policy.source_kind, policy.role))
        else:
            for policy in self._source_plan().roots:
                roots.append((policy.package, policy.package, policy.source_kind, policy.role))

        requests = []
        for name, primary, source_kind, role in roots:
            pin = (version if version not in ("Latest", "Follows repositories")
                   and (primary in pinned or workload.version_package == primary) else None)
            if source_kind == "workload" and role:
                requests.append((name, pin, role))
            elif source_kind == "distribution":
                requests.append((name, pin, None, None, None, "distribution"))
            else:
                requests.append((name, pin, None))
        return self._augment_requests_for_init(requests)

    def _validate_successful_source_scopes(self, successful, attempted):
        """Require source scopes, not every individual enabled repository.

        A failed supplemental source reduces available providers and is reported,
        but it should not abort before the resolver can prove whether the
        remaining metadata is sufficient. Requested root scopes are stricter:
        at least one reachable repository must remain for each required workload
        role and for distribution-native roots.
        """
        successful = list(successful)
        attempted = list(attempted)
        if not successful:
            raise RuntimeError("None of the selected package sources could be read")
        if self._mirror_mode():
            missing = [r.name for r in attempted
                       if self._mirror_repo_selected(r) and r not in successful]
            if missing:
                raise RuntimeError("Selected mirror source(s) could not be read: " + ", ".join(missing))
            return
        if self._single_mode():
            required = {p.repo.source_identity: p.repo.name for p in getattr(self, "selected_packages", [])}
            reached = {r.source_identity for r in successful}
            missing = sorted(name for identity, name in required.items() if identity not in reached)
            if missing:
                raise RuntimeError("Repository/repositories for selected exact package roots could not be read: " + ", ".join(missing))
            return
        missing = missing_reachable_scopes(
            self._source_plan(), successful, tier_getter=self._repo_tier)
        if "distribution" in missing:
            raise RuntimeError("No distribution repository required by the selected roots could be read")
        role_gaps = [scope.split(":", 1)[1] for scope in missing if scope.startswith("role:")]
        if len(role_gaps) == 1:
            raise RuntimeError(
                f"No reachable workload repository remains for required role '{role_gaps[0]}'")
        if role_gaps:
            raise RuntimeError(
                "No reachable workload repository remains for required roles: "
                + ", ".join(repr(role) for role in role_gaps))

    def _mirror_repository_record(self, mirror_repo, evidence_relationship,
                                  evidence_authority_relationship) -> dict:
        """Provenance record for one mirrored repository.

        Shared by both mirror layouts so a separate fork and a unified merge
        describe their sources identically; a unified bundle lists one of these
        per merged repository rather than a different, thinner shape.
        """
        return {
            "name": mirror_repo.name,
            "url": redact_url(mirror_repo.url),
            "role": mirror_repo.role,
            "priority": mirror_repo.priority,
            "build_purposes": self._repository_build_purposes(mirror_repo),
            "format": mirror_repo.repo_format,
            "suite": mirror_repo.suite,
            "components": mirror_repo.components,
            "credential_redirect_allow_origins": [
                redact_url(u) for u in getattr(mirror_repo, "redirect_allow_origins", [])],
            "keyring_configured": bool(mirror_repo.keyring),
            "signature_verified": bool(
                getattr(mirror_repo, "trust", None)
                and mirror_repo.trust.archive_signature_verified),
            "allow_unverified_index": mirror_repo.allow_unverified_index,
            "evidence_policy": mirror_repo.evidence_policy,
            "evidence_urls": [redact_url(u) for u in mirror_repo.evidence_urls],
            "evidence_relationships": _indexed_evidence_records(
                mirror_repo, evidence_relationship, "relationship"),
            "evidence_authorities": _indexed_evidence_records(
                mirror_repo, evidence_authority_relationship, "authority"),
            "digest_preference": mirror_repo.digest_preference,
            "digest_requirement": mirror_repo.digest_requirement,
            "verification_strategy": repository_verification_strategy(mirror_repo),
        }

    def _mirror_bundle_metadata(self, state, release, reporter, repo_records) -> dict:
        """Metadata common to every repository-mirror publication."""
        return {
            "distribution": self._profile().label,
            "release": release,
            "codename": self._profile().codename(release),
            "arch": self._selected_arch(),
            "package_family": self._profile().package_family,
            "dependency_mode": "Repository mirror (dependency closure not applicable)",
            "package_version": "Repository metadata inventory",
            "workload_key": "repository-mirror",
            "requested_packages": [],
            "init_system": self._selected_init_system(),
            "requested_source_plan": [],
            "acquisition_intent": state.intent.value,
            "acquisition_capability": state.capability.value,
            "analysis_type": state.analysis.value,
            "publication_type": state.publication.value,
            "verification_scope": state.verification_scope.value,
            "repository_mirror": True,
            "package_only_acquisition": False,
            "dependency_completeness": "not-applicable",
            "package_only_warning": "",
            "os_dependency_source": self._active_source_method(),
            "signature_verification": "openpgp" if any(
                row.get("keyring_configured") for row in repo_records) else "none",
            "trust_warnings": list(reporter.warnings),
            "repositories": list(repo_records),
        }

    def _repository_build_purposes(self, repo):
        """Describe why an enabled repository participates in this build.

        Provenance follows the source policy emitted by Packages. Every enabled
        base-tier repository is part of the distribution source of record. Any
        enabled repository satisfying an explicit workload/vendor root role is a
        workload/root source; the resolver later records which concrete source
        actually supplied each package.
        """
        purposes = []
        if self._repo_tier(repo) == "base":
            purposes.append("distribution")
        selection = _SnapshotSelection(self)
        if selection is not None:
            if selection.get() == "Workload preset" and repo.role in set(self._workload_required_repository_roles()):
                purposes.append("workload/root")
            elif selection.get() == "Choose packages" and any(
                    p.repo.source_identity == repo.source_identity for p in self.selected_packages):
                purposes.append("workload/root")
        if not purposes:
            purposes.append("dependency/supplement")
        return purposes

