"""Shared source, inventory, trust and publication preparation rules.

The GUI supplies live accessors and dialogs; a spec host supplies frozen values
and explicit policies. This module imports neither App nor the UI context.
"""

from __future__ import annotations
from feathered_app.dependency_ports import ports_for

import copy
from datetime import datetime
from pathlib import Path

from acquisition_model import (AcquisitionCapability, AcquisitionIntent, WORKLOAD_PACKAGE_ONLY_MODE,
                               derive_acquisition_state)
from core import BuildOptions, Cancelled, infer_vendor_id
from feathered_app.build_output import FOLDER_SCHEMES
from feathered_app.build_request import BuildRequestMixin
from feathered_app.build_runner import BuildPlan
from feathered_app.prepared_plan import PreparedPlan
from source_readiness import evaluate_source_readiness
from feathered_app.source_scope import (
    BuildScopeContext, ParticipationContext,
    RepositoryTarget, TargetScope, init_blocked_required_roles,
    participates, select_build_scope, target_compatible,
)
import workload_resolution


class PreparationRejected(RuntimeError):
    """The request cannot be prepared with its supplied inputs."""


class DecisionDeclined(Cancelled):
    """A required operator decision was declined."""


class BuildPreparationMixin:
    """Rules shared by GUI preparation and a spec-driven host."""

    def _repository_target_compatible(self, repo) -> bool:
        """Whether a repository belongs to the currently selected Linux target.

        Profile-derived repositories are rebuilt/retargeted by the profile
        machinery. Operator-added repositories are instead remembered with the
        target tuple under which they were created so they can survive a
        temporary target switch without silently participating in the wrong
        distribution/release/architecture.
        """
        try:
            profile = self._profile()
            target = TargetScope(profile.package_family, profile.key,
                                 BuildRequestMixin._selected_release(self), self._selected_arch())
        except Exception:
            # Preserve partial-host compatibility; build preparation separately
            # validates that a complete target has been selected.
            return True
        return target_compatible(target, RepositoryTarget(
            getattr(repo, "repo_format", ""), getattr(repo, "target_profile_key", ""),
            getattr(repo, "target_release", ""), getattr(repo, "target_arch", "")))


    def _repository_participates_in_current_intent(self, repo) -> bool:
        """Whether *repo* belongs to the current transaction workflow.

        ``enabled`` is operator/configuration state.  It is not, by itself, a
        statement that an auto-materialized workload side-channel belongs to a
        different Content intent.  Keeping this distinction here prevents a
        Docker source from leaking into Specific packages provenance merely
        because Docker was selected earlier in the session.
        """
        context = ParticipationContext(
            enabled=lambda row: bool(getattr(row, "enabled", False)),
            url=lambda row: str(getattr(row, "url", "") or ""),
            profile_managed=lambda row: bool(getattr(row, "workload_profile_managed", False)),
            identity=lambda row: getattr(row, "source_identity", None),
            role=lambda row: row.role,
            compatible=lambda row: self._repository_target_compatible(row),
            mirror_mode=lambda: self._mirror_mode(),
            mirror_selected=lambda row: self._mirror_repo_selected(row),
            tier=lambda row: self._repo_tier(row),
            exact_mode=lambda: self._single_mode(),
            exact_source_ids=lambda: {
                getattr(getattr(pkg, "repo", None), "source_identity", None)
                for pkg in getattr(self, "selected_packages", [])},
            required_roles=lambda: set(self._workload_required_repository_roles()),
        )
        return participates(repo, context)


    def _participating_transaction_repositories(self):
        if self._mirror_mode():
            return [r for r in self.repo_rows if self._repository_participates_in_current_intent(r)]
        return [r for r in self.repo_rows if self._repository_participates_in_current_intent(r)]


    def _package_coverage_repositories(self):
        """Enabled repositories relevant to the selected *root* packages only.

        Coverage is not dependency analysis. A dedicated workload root should
        therefore be checked against its workload role without first requiring
        or probing the target distribution's base repository plan. Distribution
        roots still require the enabled base set, and free-form selections may
        use the whole enabled repository set.
        """
        if self._mirror_mode():
            return [r for r in self.repo_rows if r.url.strip() and self._mirror_repo_selected(r)]
        enabled = [repo for repo in self._participating_transaction_repositories()
                   if not self._init_repository_conflict(repo)]
        try:
            contextual_packages = bool(
                not self._mirror_mode()
                and getattr(self._workload(), "contextual_packages", False))
        except (AttributeError, TypeError, StopIteration, KeyError):
            contextual_packages = False
        if self._single_mode() or contextual_packages:
            source_ids = {p.repo.source_identity for p in getattr(self, "selected_packages", [])}
            return [r for r in enabled if r.source_identity in source_ids]
        readiness = evaluate_source_readiness(
            self._source_plan(), enabled, tier_getter=self._repo_tier)
        return list(readiness.root_repositories)


    def _validate_source_plan(self):
        if self._mirror_mode():
            # Mirroring copies repositories; there is no workload, so workload
            # requirements (Docker's repository, for instance) do not apply.
            # Consulting the workload dropdown here produced "this workload
            # requires Docker's package repository" for a mirror run.
            selected = [r for r in self.repo_rows if r.url.strip()
                        and self._mirror_repo_selected(r)]
            if not selected:
                raise RuntimeError(
                    "No repositories are ticked, so there is nothing to mirror. Tick the "
                    "repositories you want on the Repositories step - 'All' selects "
                    "every enabled repository.")
            mismatch = self._mirror_format_conflict(selected)
            if mismatch:
                raise RuntimeError(mismatch)
            return
        target_issue = self._workload_target_conflict()
        if target_issue:
            raise RuntimeError(target_issue)
        eligible = [repo for repo in self._participating_transaction_repositories()
                    if not self._init_repository_conflict(repo)]
        workload = self._workload()
        contextual_packages = bool(getattr(workload, "contextual_packages", False))
        if self._single_mode() or contextual_packages:
            if not self.selected_packages:
                message = (
                    "Choose at least one VKS node OS package addition on Repositories"
                    if contextual_packages else
                    "Choose at least one exact package + version first")
                raise RuntimeError(message)
            enabled_ids = {r.source_identity for r in eligible}
            missing_sources = sorted({p.repo.name for p in self.selected_packages
                                      if p.repo.source_identity not in enabled_ids})
            if missing_sources:
                raise RuntimeError(
                    "Repository/repositories containing selected exact packages are no longer eligible "
                    "for this target or init system: " + ", ".join(missing_sources)
                    + ". Choose the affected package(s) again or enable a compatible exact source.")
        else:
            if self._workload_uses_distribution_sources() and not any(
                    self._repo_tier(r) == "base" for r in eligible):
                raise RuntimeError(
                    f"{workload.label} includes distribution-native root packages, but no distribution "
                    "repository is eligible for this target or init system. Enable compatible "
                    "distribution sources on Repositories.")
            for role in self._workload_required_repository_roles():
                if not any(r.role == role for r in eligible):
                    blocked = self._init_blocked_workload_source_message()
                    if blocked:
                        raise RuntimeError(blocked)
                    raise RuntimeError(
                        f"{workload.label} requires a target-compatible workload repository for role '{role}'. "
                        "Add or enable a compatible source on Repositories.")
            # Presence in the configured list is not readiness. An enabled
            # Docker source, for example, can still be excluded by the target
            # init lock; reject that contradiction before loading OS indexes.
            blocked = self._init_blocked_workload_source_message()
            if blocked:
                raise RuntimeError(blocked)
        # Do not require a repository whose *label* is role="dependency" here.
        # The resolver can satisfy transitive dependencies from any enabled
        # repository; only requested workload roots are role-constrained.  A
        # curated/internal workload repository may therefore be self-contained.
        # Requiring a separate dependency-tagged source would reject a source
        # set the resolver can actually solve.
        if self._needs_dependency_repos() and not self._package_only_acquisition_mode() and \
                self._profile().key == "rhel" and \
                self._active_source_method() == "Red Hat CDN entitlement (official)" and \
                not self._entitlement_ready():
            raise RuntimeError("Red Hat CDN access requires the Red Hat vendor entitlement certificate, private key, and repository CA. Configure the Red Hat row under Provenance and Keying first.")


    def _build_repository_scope(self, package_only: bool = False):
        """Repositories that may actually participate in the current operation.

        Normal dependency analysis intentionally keeps the complete enabled set
        because any enabled repository may satisfy a transitive dependency.
        Package-only acquisition is different: it promises only the selected
        roots, so unrelated base/additional repositories must not become hidden
        prerequisites. Mirror mode similarly uses only repositories selected for
        mirroring.
        """
        context = BuildScopeContext(
            participating=lambda: self._participating_transaction_repositories(),
            root_coverage=lambda: self._package_coverage_repositories(),
            capability=lambda: self._acquisition_state().capability,
            repositories=lambda: self.repo_rows,
            mirror_selected=lambda repo: self._mirror_repo_selected(repo),
            url=lambda repo: repo.url,
            name=lambda repo: getattr(repo, "name", "?"),
            init_conflict=lambda repo: self._init_repository_conflict(repo),
            log=lambda message: self._log_init_exclusion_once(message),
        )
        return select_build_scope(context, package_only=package_only)

    def _log_init_exclusion_once(self, message: str) -> None:
        """Do not flood the activity log on every GUI readiness refresh."""
        seen = self.__dict__.setdefault("_reported_init_exclusions", set())
        if message not in seen:
            seen.add(message)
            self._log(message)

    def _init_blocked_workload_source_message(self, participating=None) -> str:
        """Explain an impossible workload/source combination without network I/O."""
        if self._mirror_mode() or self._single_mode():
            return ""
        plan = self._source_plan()
        if not plan.required_roles:
            return ""
        rows = (self._participating_transaction_repositories()
                if participating is None else participating)
        blocked = init_blocked_required_roles(
            plan.required_roles, rows, self._init_repository_conflict)
        if not blocked:
            return ""
        problems = []
        for role, excluded in blocked.items():
            names = ", ".join(str(getattr(repo, "name", "repository")) for repo, _ in excluded)
            reasons = "; ".join(dict.fromkeys(reason for _, reason in excluded))
            problems.append(f"role '{role}' ({names}): {reasons}")
        message = (
            f"{self._workload().label} cannot be built for the selected init system: "
            "all enabled, target-compatible sources for required workload " + "; ".join(problems)
            + ". Select an init-compatible source or choose a different workload/target."
        )
        if self._profile().key == "devuan" and "docker" in blocked:
            message += (
                " On Devuan, an alternative is Choose packages, then select "
                "docker.io from Devuan's own repositories; verify availability "
                "and init-service support for the selected release."
            )
        return message


    def _workload_target_conflict(self) -> str:
        """Enforce the workload catalog in GUI, CLI and saved-spec replay alike."""
        if self._mirror_mode() or self._single_mode():
            return ""
        # Legacy tests construct an App using __new__, without Tk or target
        # controls. Those partial hosts can validate repository-role topology
        # but have no selected target against which to validate the catalog.
        # A prepared CLI host has _build_snapshot; a live GUI has distro_var.
        if not (self.__dict__.get("_build_snapshot") is not None
                or "distro_var" in self.__dict__
                or "_profile" in self.__dict__):
            return ""
        workload = self._workload()
        supports = getattr(workload, "supports_target", None)
        if not callable(supports):
            return ""  # Legacy partial-host compatibility.
        profile = self._profile()
        if not getattr(profile, "key", ""):
            return ""  # An uninitialized target cannot have a catalog conflict.
        release = BuildRequestMixin._selected_release(self)
        if not supports(profile.key, release):
            return (f"{workload.label} is not offered for {profile.label} {release or '(unspecified release)'}. "
                    "Choose a supported workload or target before reading repository metadata.")
        family = getattr(profile, "package_family", "")
        if (family and not getattr(workload, "custom", False)
                and not workload.packages_for(family)):
            return (f"{workload.label} has no package mapping for {profile.package_family} targets. "
                    "Choose a supported workload or supply an explicit package catalog.")
        return ""


    def _configured_source_conflict(self, plan, eligible) -> str:
        """Explain when a configured source is unusable rather than absent."""
        enabled = [repo for repo in self.repo_rows
                   if repo.enabled and str(repo.url or "").strip()]
        scopes = []
        if plan.distribution_required:
            scopes.append(("distribution roots", lambda repo: self._repo_tier(repo) == "base"))
        scopes.extend((f"role '{role}'", lambda repo, role=role: repo.role == role)
                      for role in plan.required_roles)
        for label, matches in scopes:
            relevant = [repo for repo in enabled if matches(repo)]
            if not relevant or any(repo in eligible for repo in relevant):
                continue
            # Only explain explicit target incompatibility here. Init-blocked
            # roles have their own more detailed diagnostic and alternatives.
            if all(not self._repository_target_compatible(repo) for repo in relevant):
                return (f"Configured repositories for {label} belong to a different target "
                        "distribution, release, architecture or package format. Select a compatible source.")
        return ""


    def _mirror_format_conflict(self, selected=None) -> str:
        """Publication uses the target's backend even when indexes load per source.

        A foreign distribution is mirrorable when it uses the same package
        format. Mixing APT, RPM and pacman would otherwise load successfully
        but pass the wrong package objects to the publication backend.
        """
        profile = self._profile()
        expected = {"deb": "apt", "rpm": "rpm", "arch": "pacman"}[profile.package_family]
        if selected is None:
            selected = [repo for repo in self.repo_rows
                        if str(repo.url or "").strip() and self._mirror_repo_selected(repo)]
        foreign = [repo for repo in selected if (repo.repo_format or expected) != expected]
        if foreign:
            names = ", ".join(dict.fromkeys(repo.name for repo in foreign))
            return (f"Selected mirror source(s) have a different package format from the "
                    f"{expected} target: {names}. Mirror these repositories in a matching "
                    "target profile, or unselect them before building.")
        return ""


    def _build_options(self, package_only: bool = False):
        if not package_only:
            state = self._acquisition_state()
            package_only = state.capability is AcquisitionCapability.PACKAGE_ONLY
        try:
            trust_scope = self._build_repository_scope(package_only=package_only)
        except Exception:
            trust_scope = None
        try:
            trust = self._trust_options(trust_scope)
        except TypeError:  # Lightweight compatibility/test doubles may expose the older no-arg helper.
            trust = self._trust_options()
        if package_only:
            # A workload-only upstream cannot prove a complete transaction, so
            # dependencies are never followed. Repository metadata over the
            # collected roots is the operator's explicit choice (default off on
            # entering package-only): a local repository of a few artifacts is
            # a legitimate object, and the PACKAGE-ONLY warning still records
            # that it is not install-complete.
            trust["emit_repository"] = bool(trust.get("emit_repository"))
            return BuildOptions(
                include_dependencies=False, include_recommends=False,
                include_rootless=False, target_inventory=None,
                max_resolution_passes=self.resolution_pass_budget or 8,
                **trust,
            )
        if state.capability is AcquisitionCapability.REPOSITORY_MIRROR:
            # A repository mirror is a complete repository object, not a flat
            # package collection or a differential addendum. Every publication
            # fork therefore emits its own repository metadata and ignores any
            # stale differential baseline retained from another workflow.
            trust["emit_repository"] = True
            trust["baseline_manifest"] = ""
            return BuildOptions(
                include_dependencies=False, include_recommends=False,
                include_rootless=False, target_inventory=None,
                max_resolution_passes=self.resolution_pass_budget or 8,
                **trust,
            )
        if self._single_mode():
            # Exact-package mode is intentionally strict: only strong RPM
            # Requires or APT Depends/Pre-Depends are followed. Weak recommendations are excluded.
            return BuildOptions(include_dependencies=True, include_recommends=False,
                                include_rootless=False,
                                max_resolution_passes=self.resolution_pass_budget or 8,
                                **trust)
        mode = BuildRequestMixin._selected_content(self, "dependency_mode", "mode_var")
        inv = None
        if mode == "Target-aware complete":
            inventory_path = BuildRequestMixin._selected_inventory(self)
            if inventory_path:
                inv = self._parse_target_inventory_backend(Path(inventory_path))
        return BuildOptions(
            include_dependencies=True,
            include_recommends=mode == "Complete + weak dependencies",
            include_rootless=False,
            target_inventory=inv,
            max_resolution_passes=self.resolution_pass_budget or 8,
            **trust,
        )


    def _local_media_pending(self) -> bool:
        """True when a local-media source is selected but nothing was loaded."""
        method = self._active_source_method()
        if method != "Installation media / local mirror (ISO, DVD, folder, SMB)":
            return False
        return not any(r.enabled and r.url.startswith("file:") for r in self.repo_rows)


    def _validate_signing(self) -> None:
        """An explicit security request must not degrade to a warning."""
        if (self._selected_output_option("sign_bundle_index", "sign_index_var", flag=True)
                and not self._selected_output_option("signing_key", "signing_key_var").strip()):
            raise RuntimeError(
                "Bundle sealing is enabled but no signing key is set. Add a GPG key id on the "
                "Provenance & Keying step, or turn off sealing under Output Directories.")


    def _validate_output_naming(self) -> None:
        """Custom naming needs either literal text or a date/time prefix."""
        if BuildRequestMixin._selected_output_option(self, "folder_scheme", "folder_scheme_var") != FOLDER_SCHEMES[3]:
            return
        if not BuildRequestMixin._selected_output_option(self, "folder_label", "folder_label_var").strip() and BuildRequestMixin._selected_output_option(self, "folder_stamp", "folder_stamp_var") not in {"date", "time"}:
            raise RuntimeError(
                "The output folder scheme is set to 'Custom label', but both the label and Prefix are empty. "
                "Enter a label, choose Date or Date + time, or choose a different naming scheme.")


    def _validate_sources(self, want_dependencies: bool) -> None:
        """Validate that there is a usable source set before metadata loading.

        Repository roles constrain requested roots, not dependency providers.
        Transitive dependencies are intentionally resolved across all enabled
        repositories, so a self-contained internal/workload repository must be
        allowed to prove that it satisfies the closure.  Missing dependencies
        are reported by the resolver instead of being guessed from a UI role.
        """
        # A pending base-media plan matters only when the selected workload has
        # distribution-native roots. Dedicated workload/internal repositories
        # are allowed to prove their own roots (and, during normal analysis,
        # potentially a self-contained closure) without an irrelevant base-plan
        # configuration becoming a global gate.
        if self._local_media_pending() and self._workload_uses_distribution_sources():
            raise RuntimeError(
                "Local media is selected as the base source, but no media folder has been loaded. "
                "Use 'Choose folder…' on Repositories and select the mounted ISO or mirror "
                "root - the folder containing repodata/ (RPM), dists/ (APT), or a pacman repository .db (Arch).")
        enabled = self._participating_transaction_repositories()
        if not enabled:
            raise RuntimeError("No usable package sources are enabled. Configure and enable at least one "
                               "repository before checking coverage or analyzing the build.")


    def _trust_options(self, repositories=None) -> dict:
        """Collect trust settings for repositories that can participate in this build."""
        source_rows = list(repositories) if repositories is not None else [
            r for r in self.repo_rows if r.enabled and r.url.strip()]
        enabled_vendor_ids = {
            getattr(r, "vendor_id", "") or infer_vendor_id(r.name, r.url)
            for r in source_rows if r.repo_format == "rpm"
        }
        vendor_keyrings = {
            vendor_id: str(self.vendor_signature_profiles.get(vendor_id, {}).get("keyring", "")).strip()
            for vendor_id in enabled_vendor_ids
            if str(self.vendor_signature_profiles.get(vendor_id, {}).get("keyring", "")).strip()
        }
        required_vendors = {
            vendor_id for vendor_id in enabled_vendor_ids
            if self.vendor_signature_profiles.get(vendor_id, {}).get("policy") == "require"
        }
        return {
            # Legacy global fields are intentionally blank/false. Vendor package
            # signature trust is scoped explicitly below.
            "vendor_keyring": "",
            "require_vendor_signatures": False,
            "vendor_keyrings": vendor_keyrings,
            "require_vendor_signatures_by_vendor": required_vendors,
            "signing_key": self._selected_output_option("signing_key", "signing_key_var").strip(),
            "baseline_manifest": self._selected_output_option(
                "baseline_path", "baseline_var").strip(),
            "optional_roots": self._optional_roots(),
            "sign_bundle_index": self._selected_output_option(
                "sign_bundle_index", "sign_index_var", flag=True),
            "emit_repository": self._selected_output_option(
                "emit_repository", "emit_repo_var", flag=True),
            # verification strategy is per
            # repository. Keep the legacy BuildOptions digest flag false; the
            # explicit 1.0.36 strategy enforces strict/fallback behavior itself.
            "require_package_digests": False,
        }


    def _optional_roots(self) -> set:
        """Names whose absence should be reported, not fatal.

        Exact-package mode has no optional members: the operator asked for those
        specific packages by name, so a missing one is an error.
        """
        if self._single_mode() or self._mirror_mode():
            return set()
        workload = self._workload()
        if workload.custom:
            return set()
        family = self._profile().package_family
        optional = set(workload.optional_for(family))
        optional.update(root.package for root in workload.source_plan(family).roots if root.optional)
        return optional


    def _entitlement_credentials(self):
        """Return a configured Red Hat entitlement tuple, if one is available.

        The GUI keeps vendor-scoped aliases, while saved/prepared repository
        rows may already carry the same client-auth material. Both forms are
        accepted so capability and build validation cannot disagree merely
        because credentials entered through one path were not mirrored into the
        other representation yet.
        """
        direct = tuple(str(self.__dict__.get(k) or "")
                       for k in ('rhsm_cert', 'rhsm_key', 'rhsm_ca'))
        if all(direct):
            return direct
        cdn = [r for r in getattr(self, 'repo_rows', ())
               if getattr(r, 'enabled', False)
               and str(getattr(r, 'url', '') or '').startswith('https://cdn.redhat.com/')]
        if not cdn:
            return ('', '', '')
        candidates = [
            (str(getattr(repo, 'client_cert', '') or ''),
             str(getattr(repo, 'client_key', '') or ''),
             str(getattr(repo, 'ca_cert', '') or ''))
            for repo in cdn
        ]
        if not all(all(candidate) for candidate in candidates):
            return ('', '', '')
        return candidates[0]

    def _entitlement_ready(self):
        # Readiness means every enabled Red Hat CDN endpoint has client-auth
        # material available. It does not claim that the CDN has accepted that
        # material; the repository probe/load path establishes that separately.
        direct = tuple(str(self.__dict__.get(k) or "")
                       for k in ('rhsm_cert', 'rhsm_key', 'rhsm_ca'))
        if all(direct):
            return True
        cdn = [r for r in getattr(self, 'repo_rows', ())
               if getattr(r, 'enabled', False)
               and str(getattr(r, 'url', '') or '').startswith('https://cdn.redhat.com/')]
        return bool(cdn) and all(
            getattr(r, 'client_cert', '') and getattr(r, 'client_key', '') and getattr(r, 'ca_cert', '')
            for r in cdn)

    def _needs_dependency_repos(self):
        return not self._mirror_mode()

    def _workload_uses_distribution_sources(self):
        return self._source_plan().distribution_required

    def _init_repository_conflict(self, repo):
        # The same partial-host contract as _repository_target_compatible:
        # no target/init policy exists until either a frozen request or the
        # initialized GUI target controls are present.
        if not (self.__dict__.get("_build_snapshot") is not None
                or "distro_var" in self.__dict__
                or "_profile" in self.__dict__):
            return ""
        profile = self._profile()
        if not getattr(profile, "key", ""):
            return ""
        return workload_resolution.repository_init_conflict(
            repo.name, repo.url, profile.key, self._selected_init_system())

    def _acquisition_state(self):
        intent = self._acquisition_intent()
        if intent is AcquisitionIntent.REPOSITORY_MIRROR:
            selected = self._selected_mirror_repositories()
            return derive_acquisition_state(
                intent, mirror_repository_count=len(selected),
                blocked_mirror_reason=self._mirror_format_conflict(selected))
        rows = self._participating_transaction_repositories()
        # Readiness must describe the same init-safe universe that execution
        # will load, not merely the enabled checkboxes in the repository table.
        safe_rows = [row for row in rows if not self._init_repository_conflict(row)]
        if intent is AcquisitionIntent.PACKAGES:
            enabled = {r.source_identity for r in safe_rows}
            unavailable = [p.repo for p in self.selected_packages
                           if p.repo.source_identity not in enabled]
            exact_issue = ""
            for source in unavailable:
                configured = [r for r in self.repo_rows
                              if r.source_identity == source.source_identity
                              and r.enabled and str(r.url or "").strip()]
                if not configured:
                    continue
                if all(not self._repository_target_compatible(r) for r in configured):
                    exact_issue = ("A selected exact package comes from a repository configured for a "
                                   "different target distribution, release, architecture or package format.")
                    break
                conflicts = [self._init_repository_conflict(r) for r in configured]
                if conflicts and all(conflicts):
                    exact_issue = ("A selected exact package comes from a repository incompatible "
                                   "with the selected init system: " + conflicts[0])
                    break
            return derive_acquisition_state(intent, exact_root_count=len(self.selected_packages),
                exact_root_sources_ready=bool(self.selected_packages) and
                all(p.repo.source_identity in enabled for p in self.selected_packages),
                blocked_exact_reason=exact_issue)
        plan = self._source_plan()
        safe_readiness = evaluate_source_readiness(
            plan, safe_rows, tier_getter=self._repo_tier)
        preflight_issue = (self._workload_target_conflict()
                           or self._init_blocked_workload_source_message(rows)
                           or self._configured_source_conflict(plan, safe_rows))
        package_only_requested = (
            BuildRequestMixin._selected_content(self, "dependency_mode", "mode_var")
            == WORKLOAD_PACKAGE_ONLY_MODE)
        return derive_acquisition_state(
            intent,
            workload_readiness=safe_readiness,
            workload_root_count=len(plan.roots),
            workload_package_only_requested=package_only_requested,
            blocked_workload_reason=preflight_issue)

    def _package_only_acquisition_mode(self):
        return self._acquisition_state().capability is AcquisitionCapability.PACKAGE_ONLY


def prepare_job(host, *, do_download=True, state=None, picked_at_start=None,
                confirm_package_only=None) -> PreparedPlan:
    """Validate one operation and lock its publication choices before execution.

    Callers own source configuration and selected-package resolution. A GUI
    adapter can supply its already derived state and current reviewed selection.
    Publication interaction is a host callback; no GUI is imported here.
    """
    if state is None:
        state = host._acquisition_state()
    if state.blocked:
        raise PreparationRejected(state.reason or 'The acquisition request is blocked.')
    package_only = state.capability is AcquisitionCapability.PACKAGE_ONLY
    if package_only:
        message = host._package_only_warning_text()
        if not do_download:
            raise PreparationRejected(message)
        confirm = confirm_package_only or host._ask_on_ui_thread
        if not confirm('Feathered', message + '\n\nDownload only the requested root package artifacts?'):
            raise DecisionDeclined('Package-only acquisition was declined.')
    host._validate_source_plan()
    requests = host._package_requests()
    requested_source_plan = host._request_source_plan_metadata(requests)
    repositories = copy.deepcopy(host._build_repository_scope(package_only=package_only))
    opts = host._build_options(package_only=package_only)
    from dataclasses import replace
    from kubernetes_workflow import VKS_KEY, rolling_source
    context = BuildRequestMixin._selected_workload_context(host)
    context.validate()
    if context.workload == VKS_KEY and not host._mirror_mode():
        path = BuildRequestMixin._selected_inventory(host)
        if path:
            opts.target_inventory = host._parse_target_inventory_backend(Path(path))
        baseline_available = bool(
            opts.target_inventory is not None
            and getattr(opts.target_inventory, "retained_packages", None))
        if context.pin_baseline and not baseline_available:
            context = replace(context, pin_baseline=False)
            log = getattr(host, "_log", None)
            if callable(log):
                log("Pin to inventory baseline was ignored because no usable installed inventory is loaded.")
        if context.pin_baseline:
            repositories = [r for r in repositories if not rolling_source(r)]
        if not package_only:
            opts.include_dependencies = True
        opts.emit_repository = True
    opts.workload_context = context
    host._validate_signing()
    host._validate_output_naming()
    host._validate_sources(opts.include_dependencies)
    # Freeze the clock before any confirmation; GUI snapshot capture preserves it.
    host.__dict__['_build_naming_time'] = ports_for(host).datetime.now()
    locked_name = None
    forks = []
    if do_download:
        if host._mirror_mode() and not host._unified_mirror_mode():
            proposed = host._mirror_output_folder_names()
            names = [name for _, name in proposed]
            if len(names) != len(set(names)):
                raise PreparationRejected('Selected repositories resolve to the same output folder name.')
            for repo, name in proposed:
                repo_opts = copy.deepcopy(opts)
                confirmed = host._confirm_output_folder_name(name, repo_opts)
                if confirmed is None:
                    raise DecisionDeclined('Output publication was declined.')
                forks.append((repo.source_identity, confirmed, repo_opts))
        else:
            folder_name = host._folder_name()
            if folder_name in {"", ".", ".."}:
                raise PreparationRejected('The output folder label must identify a child directory.')
            locked_name = host._confirm_output_folder_name(folder_name, opts)
            if locked_name is None:
                raise DecisionDeclined('Output publication was declined.')
    return BuildPlan(state, opts, requests, requested_source_plan, repositories,
                     package_only, picked_at_start, do_download, locked_name, forks)
