"""Translate the operator selection into roots and source requirements.

A workload or package selection becomes a source plan and a concrete request
set, including target init-system packages and required repository roles.

Imports no Tk, enforced by tests/test_build_request_module.py. Depends on
BuildIntentMixin for the profile and workload derivations, which is why it moved
after them.
"""
from __future__ import annotations

import re
from typing import Optional

from feathered_app.build_request import BuildRequestMixin
from source_model import RootSourcePolicy, SourcePlan
from workload_materialization import MaterializedWorkload, materialize_source_plan


class BuildPlanMixin:
    """Source plan and request construction. No widget access."""

    def _source_plan(self):
        """Authoritative package-source contract for the current Packages state.

        Repository population, validation, coverage and root request generation
        all consume this object (directly or through compatibility wrappers), so
        they cannot independently reinterpret what the selected workload means.
        """
        if self._mirror_mode() or self._single_mode():
            return SourcePlan([])
        workload = self._workload()
        if getattr(workload, "contextual_packages", False):
            return SourcePlan([
                RootSourcePolicy(
                    package.name, "enabled", component=package.name,
                    candidates=(package.name,))
                for package in (self.__dict__.get("selected_packages") or ())
            ])
        if workload.custom:
            custom = BuildRequestMixin._selected_content(self, "custom_packages", "custom_var")
            roots = [x for x in re.split(r"[\s,]+", custom) if x]
            return SourcePlan([RootSourcePolicy(name, "enabled") for name in roots])
        try:
            package_family = getattr(self._profile(), "package_family", "rpm")
        except Exception:
            # Keep plan derivation usable in backend/unit-test contexts where
            # Tk target widgets have not been constructed.
            package_family = "rpm"
        return workload.source_plan(package_family)

    def _materialize_selected_workload(self, packages) -> Optional[MaterializedWorkload]:
        """Bind semantic workload components to approved package identities in live metadata."""
        if self._mirror_mode() or self._single_mode():
            return None
        workload = self._workload()
        if workload.custom or getattr(workload, "contextual_packages", False):
            return None
        family = getattr(self._profile(), "package_family", "rpm")
        return materialize_source_plan(
            workload_key=workload.key,
            catalog_revision=getattr(workload, "catalog_revision", 1),
            catalog_sha256=workload.catalog_fingerprint(family),
            package_family=family,
            plan=self._source_plan(),
            packages=packages,
            # Runs on the worker via _build_request; must not read a widget.
            preferred_arch=BuildRequestMixin._selected_arch(self),
            tier_getter=self._repo_tier,
            catalog_signature_verified=getattr(workload, "catalog_signature_verified", False),
        )

    def _augment_requests_for_init(self, requests):
        """Append init-specific packages for targets where init is a real axis.

        Artix (companion-packages): each service-bearing preset root gains its
        <service>-<init> companion for the chosen init, as a required root.
        Devuan (bundled-scripts): service packages already include their
        scripts; choosing a non-default init adds that init's own package as a
        root so the bundle can install the init itself."""
        try:
            profile = self._profile()
        except Exception:
            return requests
        init = self._selected_init_system() if hasattr(self, "_selected_init_system") else ""
        if not init:
            return requests
        style = getattr(profile, "init_style", "")
        names = {str(r[0]) for r in requests}
        if style == "companion-packages":
            from workloads import ARTIX_SERVICE_COMPANIONS
            try:
                workload = self._workload()
            except Exception:
                workload = None
            services = list(ARTIX_SERVICE_COMPANIONS.get(getattr(workload, "key", ""), []))
            # Exact/custom selections also get companions for known services.
            services += [n for n in names if n in {s for v in ARTIX_SERVICE_COMPANIONS.values() for s in v}]
            for service in dict.fromkeys(services):
                companion = f"{service}-{init}"
                if service in names and companion not in names:
                    requests.append((companion, None, None))
                    names.add(companion)
        elif style == "bundled-scripts" and init != (profile.init_systems[0] if profile.init_systems else ""):
            if init not in names:
                requests.append((init, None, None))
                names.add(init)
        return requests

    def _selected_init_system(self) -> str:
        profile = self._profile()
        inits = list(getattr(profile, "init_systems", []) or [])
        if not inits:
            return ""
        # Frozen request first. This is a worker-thread read, and it escaped
        # the isolation tripwire only because every fixture used a profile with
        # no selectable init systems, so the branch never ran.
        chosen = BuildRequestMixin._build_snapshot_value(self, "target", "init_system")
        if chosen is None:
            chosen = BuildRequestMixin._live_value(self, "init_system_var")
        return chosen if chosen in inits else inits[0]

    def _known_workload_repository_roles(self):
        roles = set()
        for workload in self.__dict__.get("workloads", {}).values():
            try:
                roles.update(workload.required_repository_roles())
            except Exception:
                if getattr(workload, "requires_docker_repo", False):
                    roles.add("docker")
        return roles

    def _workload_required_repository_roles(self):
        if self._mirror_mode() or self._single_mode():
            return []
        return list(self._source_plan().required_roles)
