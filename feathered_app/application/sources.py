"""Workload/source planning, repository templates, target selection, package browsing, and source configuration.

"""

from feathered_app.application.build import BuildMixin
from feathered_app.build_backend import BuildBackendMixin
from feathered_app.build_intent import BuildIntentMixin
from feathered_app.build_mirror import BuildMirrorMixin
from feathered_app.build_plan import BuildPlanMixin
from feathered_app.context import (
    APP_TITLE,
    AcquisitionCapability,
    AcquisitionIntent,
    AcquisitionState,
    AnalysisType,
    BG_APP,
    Cancelled,
    FG_MUTED,
    MIRROR_LAYOUT_LABELS,
    MaterializedWorkload,
    MergePolicy,
    MirrorLayout,
    OK_FG,
    Optional,
    Path,
    PublicationType,
    RepoSpec,
    Reporter,
    ResolutionResult,
    RootSourcePolicy,
    SourcePlan,
    VerificationScope,
    WARN_FG,
    apt_core,
    arch_core,
    compare_evr,
    conflict_report,
    derive_acquisition_state,
    evaluate_source_readiness,
    filedialog,
    gpg_backend,
    infer_vendor_id,
    intent_from_selection_mode,
    json,
    materialize_source_plan,
    merge_policy_from_label,
    mirror_layout_from_label,
    profile_by_label,
    re,
    redact_text,
    rpm_compare_evr,
    rpm_format_requirement,
    rpm_load_repository,
    rpm_package_versions,
    rpm_parse_target_inventory,
    rpm_probe_repository,
    rpm_resolve,
    rpm_write_bundle,
    rpm_write_bundle_archive,
    simpledialog,
    threading,
    tk,
    traceback,
    ttk,
    unify_mirror_packages,
    vendor_display_name,
    version_key,
    workload_by_label,
    workload_resolution,
    zstd_backend,
)
from feathered_app.ui.theme import human_size, messagebox


class SourcesMixin(BuildIntentMixin, BuildBackendMixin, BuildPlanMixin, BuildMirrorMixin):
    """Workload/source planning, repository templates, target selection, package browsing, and source configuration."""

    def _combo_field(self, parent, label, var, values, col, callback=None, width=22, editable=False):
        ttk.Label(parent, text=label).grid(row=0, column=col, sticky="w", padx=(0 if col == 0 else 12, 0))
        combo = ttk.Combobox(parent, textvariable=var, values=values, width=width,
                             state="normal" if editable else "readonly")
        combo.grid(row=1, column=col, sticky="ew", padx=(0 if col == 0 else 12, 0), pady=(3, 0))
        if callback:
            combo.bind("<<ComboboxSelected>>", lambda _e: callback())
            if editable:
                combo.bind("<FocusOut>", lambda _e: callback())
        return combo






    def _workload_root_source_plan(self):
        """Return (package, source_kind, role) rows for the current workload."""
        return [(root.package, root.source_kind, root.role) for root in self._source_plan().roots]

    def _workload_uses_distribution_sources(self) -> bool:
        return self._source_plan().distribution_required




    def _set_repo_tier(self, repo, tier: str):
        """Tag a repository as source-plan/base or supplemental UI state.

        1.0.46 keeps this as an App-side
        presentation attribute rather than changing the backend repository
        contract. The tier controls which editor owns the row; it never changes
        dependency semantics, trust, or the repository URL itself.
        """
        repo.source_tier = tier if tier in {"base", "workload", "additional"} else "additional"
        return repo


    def _base_repo_indices(self):
        return [i for i, repo in enumerate(self.repo_rows) if self._repo_tier(repo) == "base"]

    def _workload_repo_indices(self):
        return [i for i, repo in enumerate(self.repo_rows) if self._repo_tier(repo) == "workload"]

    def _additional_repo_indices(self):
        return [i for i, repo in enumerate(self.repo_rows) if self._repo_tier(repo) == "additional"]

    def _repo_from_template(self, x, tier=None):
        repo = RepoSpec(
            x.name, x.url, x.role, x.priority, x.enabled, x.note, x.target_release,
            redirect_allow_origins=list(getattr(x, "redirect_allow_origins", []) or []),
            optional=getattr(x, "optional", False),
            repo_format=getattr(x, "repo_format", self._profile().package_family),
            flat_repo=getattr(x, "flat_repo", False),
            suite=getattr(x, "suite", ""), components=getattr(x, "components", ""),
            expected_release_version=getattr(x, "expected_release_version", ""),
            keyring=getattr(x, "keyring", ""),
            allow_unverified_index=getattr(x, "allow_unverified_index", False),
            # profile suggestions are shown to the user
            # but do not become active evidence until a source bond is enabled.
            evidence_suggestions=list(getattr(x, "evidence_suggestions", []) or []),
        )
        if tier is None:
            tier = "workload" if getattr(x, "role", "") in self._known_workload_repository_roles() else "base"
        return self._set_repo_tier(repo, tier)

    def _refresh_base_repo_tree(self):
        tree = getattr(self, "base_repo_tree", None)
        if not tree or not tree.winfo_exists():
            return
        tree.delete(*tree.get_children())
        for i in self._base_repo_indices():
            repo = self.repo_rows[i]
            tags = () if repo.enabled else ("disabled",)
            tree.insert("", "end", iid=str(i), tags=tags, values=(
                "Yes" if repo.enabled else "No", repo.name, repo.priority,
                repo.url or "<not configured>"))

    def _selected_base_repo_index(self):
        tree = getattr(self, "base_repo_tree", None)
        if not tree:
            return None
        sel = tree.selection()
        if not sel:
            return None
        try:
            return int(sel[0])
        except (TypeError, ValueError):
            return None

    def _toggle_base_repo(self, _event=None):
        i = self._selected_base_repo_index()
        if i is None or not (0 <= i < len(self.repo_rows)):
            return
        repo = self.repo_rows[i]
        if 'pin_to_inventory_baseline_var' in self.__dict__:
            from kubernetes_workflow import VKS_KEY, rolling_source
            if self._workload().key == VKS_KEY and self.pin_to_inventory_baseline_var.get() and rolling_source(repo):
                self._log('Pin to inventory baseline keeps this rolling source disabled. Change the baseline option on Content to include it.')
                return
        repo.enabled = not repo.enabled
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._refresh_repo_tree_if_open(); self._update_source_status()

    def _edit_repo_at(self, i, parent=None):
        if i is None or not (0 <= i < len(self.repo_rows)):
            return
        repo = self.repo_rows[i]
        parent = parent or self
        url = simpledialog.askstring(
            "Edit repository", "Repository root:", initialvalue=repo.url, parent=parent)
        if url is None:
            return
        repo.url = url.strip(); repo.enabled = bool(repo.url)
        repo.vendor_id = infer_vendor_id(repo.name, repo.url)
        if repo.repo_format == "apt" or self._is_deb():
            suite = simpledialog.askstring(
                "APT suite", "Suite/codename:", initialvalue=repo.suite, parent=parent)
            if suite is not None:
                repo.suite = suite.strip()
            comps = simpledialog.askstring(
                "APT components", "Space-separated components:",
                initialvalue=repo.components or "main", parent=parent)
            if comps is not None:
                repo.components = comps.strip()
            repo.repo_format = "apt"
        elif repo.repo_format == "pacman" or self._is_arch():
            suite = simpledialog.askstring(
                "Pacman repository name", "Repository database name (for example core, extra, multilib):",
                initialvalue=repo.suite or repo.name, parent=parent)
            if suite is not None and suite.strip():
                repo.suite = suite.strip()
            repo.repo_format = "pacman"
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._refresh_repo_tree_if_open(); self._update_source_status()

    def _edit_base_repo(self):
        self._edit_repo_at(self._selected_base_repo_index(), self)

    def _remove_base_repo(self):
        i = self._selected_base_repo_index()
        if i is None or not (0 <= i < len(self.repo_rows)):
            return
        del self.repo_rows[i]
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._refresh_repo_tree_if_open(); self._update_source_status()

    def _restore_base_source_defaults(self):
        """Repopulate only the source-plan tier and preserve supplements."""
        self._apply_source_method()
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._refresh_repo_tree_if_open(); self._update_source_status()
        self._log(f"Restored base source defaults for '{self.source_method_var.get()}'.")


    def _probe_repository_backend(self, repo, reporter):
        if repo.repo_format == "pacman" or self._is_arch():
            return arch_core.probe_repository(repo, reporter)
        if repo.repo_format == "apt" or self._is_deb():
            return apt_core.probe_repository(repo, reporter)
        return rpm_probe_repository(repo, reporter)


    def _package_versions_backend(self, packages, name, role, arch):
        if self._is_arch():
            return arch_core.package_versions(packages, name, role, arch)
        return apt_core.package_versions(packages, name, role, arch) if self._is_deb() else rpm_package_versions(packages, name, role, arch)


    def _compare_package_versions(self, a, b):
        if self._is_arch():
            return arch_core.compare_versions(a.version, b.version)
        return apt_core.compare_deb_versions(a.version, b.version) if self._is_deb() else rpm_compare_evr(a.evr, b.evr)

    def _parse_target_inventory_backend(self, path):
        if self._is_arch():
            return arch_core.parse_target_inventory(path)
        return apt_core.parse_target_inventory(path) if self._is_deb() else rpm_parse_target_inventory(path)



    def _preflight(self):
        for note in self.workload_notes:
            if note.startswith("Ignored"):
                self._log("WARNING: " + note)
                messagebox.showwarning(APP_TITLE, note)
            else:
                self._log(note)
        # gpg_backend() raises when a frozen release has a missing or tampered
        # bundled verifier. Preflight runs from a Tk `after` callback in a
        # --noconsole build, where an escaping exception would be written to a
        # stderr nobody can see and would skip the rest of this method. Report
        # the failure to the operator instead.
        try:
            verifier = gpg_backend()
        except RuntimeError as exc:
            verifier = None
            self._log(f"SECURITY: {exc}")
            messagebox.showerror(APP_TITLE, str(exc))
        else:
            if verifier is None:
                self._log("OpenPGP verifier (gpgv/gpg) not found. Repository signature verification is "
                          "unavailable until GnuPG is installed; metadata will be reported as unsigned.")
            else:
                self._log(f"OpenPGP verifier: {verifier}")
        backend = zstd_backend()
        if backend:
            self._log(f"Zstandard backend: {backend}")
        else:
            self._log("Zstandard support is unavailable; RPM repositories using .zst metadata will require the zstandard module.")





    def _activate_repository_universe_for_intent(self):
        """Swap the active repository collection to match Content intent.

        Transaction/workload/package repositories and mirror repositories are
        intentionally different universes.  Keeping each list intact while the
        other workflow is active prevents source-plan changes in one branch from
        silently rewriting the other branch.
        """
        want = "mirror" if self._acquisition_intent() is AcquisitionIntent.REPOSITORY_MIRROR else "transaction"
        if not self.activate_repository_universe(want):
            return
        # Nothing is copied between universes: each keeps its own list and
        # repo_rows simply resolves to the active one from here on. Only the
        # analysis derived from the previous universe has to be discarded.
        self.loaded_signature = None
        self.loaded_packages = []
        self.last_result = None
        self.package_source_coverage_signature = None


    def _repositories_for_source_readiness(self, plan=None):
        """Return repositories that are actually usable for capability derivation.

        An enabled URL is configuration, not proof that the source can be used.
        The important case is an unsubscribed RHEL target: the CDN rows are
        concrete URLs, but without the entitlement certificate/private key/CA
        they cannot supply dependencies.  Counting them as a live base universe
        incorrectly upgrades a workload-only Docker request from package-only to
        full transaction analysis and then throws an entitlement/fallback error.

        For a workload whose *roots* are all supplied by dedicated upstreams,
        hide only those unusable CDN base rows from readiness.  Mixed or
        distribution-native plans still retain them so the normal entitlement
        recovery gate remains mandatory.
        """
        rows = list(self.repository_rows() or [])
        if plan is None:
            plan = self._source_plan()
        try:
            rhel = self._profile().key == "rhel"
        except Exception:
            rhel = False
        method_var = self.__dict__.get("source_method_var")
        try:
            method = method_var.get() if method_var is not None else ""
        except Exception:
            method = ""
        entitlement_ready = bool(
            self.__dict__.get("rhsm_cert") and
            self.__dict__.get("rhsm_key") and
            self.__dict__.get("rhsm_ca"))
        workload_only_roots = bool(plan.roots) and not plan.distribution_required
        if not (rhel and workload_only_roots and
                method == "Red Hat CDN entitlement (official)" and
                not entitlement_ready):
            return rows
        return [repo for repo in rows if self._repo_tier(repo) != "base"]

    def _ui_acquisition_state(self):
        """State helper tolerant of lightweight non-App GUI test doubles."""
        state_fn = getattr(self, "_acquisition_state", None)
        if callable(state_fn):
            return state_fn()
        if getattr(self, "_mirror_mode", lambda: False)():
            return AcquisitionState(
                AcquisitionIntent.REPOSITORY_MIRROR, AcquisitionCapability.REPOSITORY_MIRROR,
                AnalysisType.MIRROR_INVENTORY, PublicationType.REPOSITORY_MIRROR,
                VerificationScope.MIRROR_CONTENTS)
        if getattr(self, "_package_only_acquisition_mode", lambda: False)():
            return AcquisitionState(
                AcquisitionIntent.WORKLOAD, AcquisitionCapability.PACKAGE_ONLY,
                AnalysisType.ROOT_ONLY, PublicationType.PACKAGE_ONLY,
                VerificationScope.REQUESTED_ROOTS)
        intent = (AcquisitionIntent.PACKAGES
                  if getattr(self, "_single_mode", lambda: False)()
                  else AcquisitionIntent.WORKLOAD)
        return AcquisitionState(
            intent, AcquisitionCapability.FULL_TRANSACTION, AnalysisType.DEPENDENCY_CLOSURE,
            PublicationType.TRANSACTION_BUNDLE, VerificationScope.RESOLVED_TRANSACTION)










    def single_selected_package(self):
        """First chosen package. Retained for call sites that want one."""
        return self.selected_packages[0] if self.selected_packages else None

    def _toggle_mirror_repo(self, event):
        iid = self.mirror_tree.identify_row(event.y)
        if not iid:
            return
        source_id = self.__dict__.get("_mirror_iid_to_source_identity", {}).get(iid, iid)
        selected = source_id not in self.mirror_repos
        if selected:
            self.mirror_repos.add(source_id)
        else:
            self.mirror_repos.discard(source_id)
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._paint_mirror_rows()

    def _bulk_mirror(self, action: str):
        iids = list(self.mirror_tree.get_children())
        mapping = self.__dict__.get("_mirror_iid_to_source_identity", {})
        source_ids = {mapping.get(iid, iid) for iid in iids}
        if action == "all":
            selected = source_ids
        elif action == "none":
            selected = set()
        else:
            selected = {source_id for source_id in source_ids if source_id not in self.mirror_repos}
        self.mirror_repos = selected
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._paint_mirror_rows()

    def _paint_mirror_rows(self):
        off, on = self._checkbox_images()
        mapping = self.__dict__.get("_mirror_iid_to_source_identity", {})
        for iid in self.mirror_tree.get_children():
            source_id = mapping.get(iid, iid)
            self.mirror_tree.item(iid, image=on if source_id in self.mirror_repos else off)
        visible_ids = {mapping.get(iid, iid) for iid in self.mirror_tree.get_children()}
        count = len(self.mirror_repos & visible_ids)
        total = len(visible_ids)
        if getattr(self, "mirror_status", None):
            base = self.mirror_status.cget("text").split("  |  ")[0]
            self.mirror_status.configure(
                text=f"{base}  |  {count} of {total} selected for mirroring"
                if count else f"{base}  |  none selected; nothing will be mirrored")
        self._refresh_package_source_plan()
        self._refresh_workload_repository_views()
        self._refresh_package_source_coverage()
        # Output Directories is built up-front with the rest of the wizard.
        # Mirror checkbox changes therefore have to invalidate its cached
        # naming preview explicitly; otherwise it can keep showing the last
        # workload example (for example ``docker``) even though the active
        # acquisition is now a multi-repository mirror.
        self._update_folder_preview()

    def _sync_mirror_selection_card_visibility(self):
        """Compatibility wrapper for the unified Repositories layout."""
        self._sync_repository_mode_layout()

    def _refresh_mirror_repos(self):
        """Refresh the one authoritative repository list used by mirror mode.

        Every configured repository with a concrete location is visible, even if
        it is normally disabled by a distribution template. Selection in this
        table is authoritative for mirror participation without mutating the
        repository's normal transaction-mode enabled state. Newly populated rows
        inherit the template's enabled default; explicit mirror choices survive
        ordinary UI refreshes.
        """
        if not getattr(self, "mirror_tree", None):
            return
        old_seen = set(getattr(self, "_mirror_seen", set()))
        existing_selection = set(getattr(self, "mirror_repos", set()))
        self.mirror_tree.delete(*self.mirror_tree.get_children())
        self._mirror_iid_to_source_identity = {}
        self._mirror_iid_to_repo_index = {}
        listed = 0
        unconfigured = 0
        current = set()
        for repo_index, repo in enumerate(self.repo_rows):
            tier = self._repo_tier(repo)
            # A repository auto-materialized for a workload selected before the
            # operator switched to mirror intent is stale workflow state, not a
            # mirror candidate. Explicit/manual workload repositories remain
            # eligible because the operator actually configured them.
            if tier == "workload" and getattr(repo, "workload_profile_managed", False):
                continue
            if not repo.url.strip():
                unconfigured += 1
                continue
            source_id = repo.source_identity
            current.add(source_id)
            origin = {
                "base": "Distribution",
                "workload": "Workload",
                "additional": "Added",
            }.get(tier, tier.title() if tier else "Configured")
            iid = f"mirror-row-{listed}"
            self._mirror_iid_to_source_identity[iid] = source_id
            self._mirror_iid_to_repo_index[iid] = repo_index
            self.mirror_tree.insert(
                "", "end", iid=iid,
                values=(repo.name, origin, repo.role, repo.priority, repo.url))
            listed += 1

        # Keep explicit choices for repositories that still exist. New rows use
        # their configured enabled default instead of being blindly selected.
        self.mirror_repos = existing_selection & current
        for repo in self.repo_rows:
            source_id = repo.source_identity
            if source_id in current and source_id not in old_seen and repo.enabled:
                self.mirror_repos.add(source_id)
        self._mirror_seen = current

        if listed:
            detail = (f"{listed} configured repository/repositories for "
                      f"{self.distro_var.get()} {self.release_var.get()}")
            if unconfigured:
                detail += (f"; {unconfigured} configured row(s) have no location yet and are "
                           "not selectable until configured")
            colour = FG_MUTED
        elif unconfigured:
            detail = ("Repositories exist but have no usable location yet. Configure the selected "
                      "source plan or add a repository in this card.")
            colour = WARN_FG
        else:
            detail = ("No repositories are configured. Choose a starting source plan above or add "
                      "a URL/local repository here.")
            colour = WARN_FG
        if getattr(self, "mirror_status", None):
            self.mirror_status.configure(text=detail, foreground=colour)
        self._paint_mirror_rows()

    def _selection_mode_changed(self):
        # Content intent owns the repository workflow. Swap to that intent's
        # isolated repository universe before any downstream synchronization.
        self._activate_repository_universe_for_intent()
        if not self._mirror_mode():
            self._ensure_transaction_base_sources()
        self._render_repository_workflow(force=True)
        if self._mirror_mode():
            self.workload_panel.pack_forget(); self.single_intent_panel.pack_forget()
            self.mirror_panel.pack(fill="x")
            self._sync_mirror_selection_card_visibility()
            self._sync_exact_package_selection_card_visibility()
            self.workload_note.configure(text=(
                "Mirror mode copies whole repositories rather than resolving a closure. "
                "Choose the mode here, then select the actual repositories on the next step "
                "after the target source plan has populated them."))
            repo_count = len(self._selected_mirror_repositories())
            noun = "repository" if repo_count == 1 else "repositories"
            self.analyze_btn.configure(text=f"Inventory {repo_count} {noun}")
            self.build_btn.configure(text=f"Mirror {repo_count} {noun}")
            self._sync_workload_repo_state()
            self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
            self._update_source_status(); self._refresh_repo_tree_if_open()
            self._refresh_package_source_plan()
            # The mirror branch returns early, so keep the Output Directories
            # plan synchronized here instead of relying on the common tail used
            # by workload/exact-package modes.
            self._update_folder_preview()
            self._sync_wizard_nav()
            return
        self.mirror_panel.pack_forget()
        if self.selection_mode_var.get() == "Choose packages":
            self.workload_panel.pack_forget()
            self.single_intent_panel.pack(fill="x")
            self.workload_note.configure(text=(
                "Exact package selection happens on Repositories after the source universe is configured. "
                "This keeps package discovery downstream of repository metadata and removes the need to "
                "return to this step after adding or changing sources."))
            self.analyze_btn.configure(text="Analyze")
            self.build_btn.configure(text="Build offline bundle")
        else:
            self.single_intent_panel.pack_forget()
            self.workload_panel.pack(fill="x")
            self.workload_note.configure(text=self._workload().description)
            self.analyze_btn.configure(text="Analyze")
            self.build_btn.configure(text="Build offline bundle")
            # Entering workload mode establishes the source plan immediately,
            # not only after navigating to Repositories.
            self._activate_workload_repository_selection()
        if self._single_mode() or self._mirror_mode():
            self._sync_workload_repo_state()
        self._sync_mirror_selection_card_visibility()
        self._sync_exact_package_selection_card_visibility()
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._update_source_status(); self._refresh_repo_tree_if_open()
        self._update_folder_preview()
        self._refresh_package_source_plan()
        self._sync_wizard_nav()

    def clear_single_selection(self, silent=False):
        self.selected_packages = []
        if hasattr(self, "single_selected_var"):
            self.single_selected_var.set("No package selected")
        self.single_catalog_packages = []
        self.single_catalog_signature = None
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        if hasattr(self, "repo_rows") and hasattr(self, "selection_mode_var"):
            self._sync_workload_repo_state()
            self._update_source_status()
            self._refresh_repo_tree_if_open()
        self._refresh_review_contract()
        self._sync_review_action_states()
        self._refresh_package_source_plan()
        if not silent:
            self.summary_var.set("Choose an exact package/version before analyzing or building.")

    def _default_workload_label(self) -> str:
        """Custom targets have no distribution packages, so a preset makes no
        sense as the default; start them on the custom package list."""
        labels = self._workload_labels_for_profile()
        if self._profile().key.startswith("custom-"):
            for label in labels:
                if workload_by_label(self.workloads, label).custom:
                    return label
        return labels[0] if labels else ""

    def _workload_labels_for_profile(self):
        distro = self._profile().key
        family = getattr(self._profile(), "package_family", "rpm")
        labels = []
        for item in self.workloads.values():
            if not item.supports_target(distro, BuildMixin._live_value(self, "release_var")):
                continue
            # An explicit supported_distros list is authoritative in both
            # directions: it can grant a distro and it can exclude one whose
            # repositories genuinely lack the software (e.g. Cockpit requires
            # systemd and does not exist on Artix or Devuan). Without a list,
            # availability is having a non-empty package mapping for the
            # target's family.
            if item.custom:
                labels.append(item.label)
                continue
            if item.supported_distros is not None:
                if distro in item.supported_distros:
                    labels.append(item.label)
            elif item.packages_for(family):
                labels.append(item.label)
        return labels

    def _set_release_choices(self, versions, keep_current: bool = True) -> None:
        """Repopulate the release dropdown safely.

        Previously this assigned the list and then indexed [0] unconditionally,
        so an empty result raised IndexError inside the event pump and left the
        dropdown blank -- the "it says it found releases but the list is wrong"
        symptom. Now an empty result leaves the existing choices alone, and the
        current selection survives a refresh whenever it is still offered.
        """
        profile = self._profile()
        values = [str(v) for v in (versions or []) if str(v).strip()]
        if not values:
            values = profile.known_versions()
        if not values:
            self._log("No releases could be determined for this target; type one directly.")
            return
        current = self.release_var.get().strip()
        self.release_combo["values"] = values
        if keep_current and current in values:
            return
        self.release_var.set(values[0])
        self._release_changed()

    def _sync_init_system_control(self, profile) -> None:
        """Show the init selector only where the target has a real choice.

        Artix splits service scripts into per-init companion packages, so the
        selection changes the resolved package set; Devuan records the choice
        and can add the init's own packages, but service packages keep their
        bundled scripts."""
        combo = self.__dict__.get("init_system_combo")
        if combo is None:
            return
        inits = list(getattr(profile, "init_systems", []) or [])
        if inits:
            combo["values"] = inits
            if self.init_system_var.get() not in inits:
                self.init_system_var.set(inits[0])
            combo.configure(state="readonly")
        else:
            self.init_system_var.set("")
            combo["values"] = [""]
            combo.configure(state="disabled")


    def _profile_changed(self):
        p = self._profile()
        selections = self.__dict__.setdefault("_release_selections", {})
        previous_profile = self.__dict__.get("_release_selection_profile")
        if previous_profile:
            selections[previous_profile] = self.release_var.get().strip()
        self._release_selection_profile = p.key
        # known_versions() exposes the latest discovered/cached state so switching
        # targets does not discard validated release knowledge.
        known = p.known_versions()
        self.release_combo["values"] = known
        # Startup supplies cached observations or a bundled release snapshot.
        # Unknown/custom profiles without either must never inherit a release
        # from another distribution.
        remembered = selections.get(p.key)
        if remembered in known:
            self.release_var.set(remembered)
        elif self.release_var.get() not in known:
            self.release_var.set(known[0] if known else "")
        self.arch_combo["values"] = p.arches
        if self.arch_var.get() not in p.arches:
            self.arch_var.set("x86_64" if "x86_64" in p.arches else p.arches[0])
        self._sync_init_system_control(p)
        self.target_note.configure(text=p.note)
        workload_labels = self._workload_labels_for_profile()
        self.workload_combo["values"] = workload_labels
        if self.workload_var.get() not in workload_labels:
            self.workload_var.set(self._default_workload_label() or workload_labels[0])
        elif self._profile().key.startswith("custom-"):
            # A custom target has no distribution packages behind a preset.
            self.workload_var.set(self._default_workload_label() or self.workload_var.get())
        choices = self._source_choices()
        source_combo = getattr(self, "source_method_combo", None)
        if source_combo is not None:
            try:
                if source_combo.winfo_exists():
                    source_combo["values"] = choices
            except tk.TclError:
                pass
        mirror_combo = getattr(self, "mirror_source_method_combo", None)
        if mirror_combo is not None:
            try:
                if mirror_combo.winfo_exists():
                    mirror_combo["values"] = choices
            except tk.TclError:
                pass
        if self.mirror_source_method_var is not None and self.mirror_source_method_var.get() not in choices:
            self.mirror_source_method_var.set(self._default_mirror_source_method())
        # Distribution identity owns the foundational transaction source plan.
        # A source method inherited from the previously selected distribution
        # is more dangerous than useful (for example, an unconfigured local
        # media plan carrying from RHEL into Rocky).  Re-derive the default on
        # every distribution change; release/architecture changes retain that
        # same plan and simply repopulate it for the new target tuple.
        self.source_method_var.set(self._default_transaction_source_method())
        self._release_changed()
        self._workload_changed()
        self._update_folder_preview()
        after = getattr(self, "after", None)
        if callable(after):
            after(0, self._auto_refresh_releases)

    def _remember_release(self, value: str) -> None:
        """Persist a release the operator named themselves.

        Discovery already caches what the archive advertises, but a brand-new
        release is precisely the one you have to type in - and that was being
        forgotten on exit, so it had to be retyped every session.
        """
        value = (value or "").strip()
        if not value:
            return
        profile = self._profile()
        if value in profile.known_versions():
            return
        profile.discovered_versions = sorted(
            {*profile.discovered_versions, value},
            key=lambda v: version_key(v if any(c.isdigit() for c in v) else "0"),
            reverse=True)
        self._cache_release_state(
            profile.key, profile.discovered_versions, profile.verified_versions,
            profile.release_source or "operator-entered release", False)
        self._log(f"Remembered release '{value}' for {profile.label}.")
        known = profile.known_versions()
        if getattr(self, "release_combo", None):
            self.release_combo["values"] = known

    def _update_release_hint(self):
        """Explain how releases are named for this target, and that typing works."""
        if not getattr(self, "release_hint", None):
            return
        profile = self._profile()
        value = self.release_var.get().strip()
        if profile.package_family == "arch":
            self.release_hint.configure(
                text="Arch Linux is rolling release. Feathered targets the current repository state under the stable 'rolling' label rather than inventing a numbered release.")
            return
        if profile.package_family != "deb":
            self.release_hint.configure(
                text="Release metadata refreshes automatically. If a new release is not listed yet, "
                     "type it directly; 'Refresh releases' forces an immediate repository check.")
            return
        codename = profile.codename(value)
        if profile.release_style == "codename":
            known = value in profile.release_codenames.values()
            detail = ("" if known else
                      "  This name is not in the currently discovered release state; it will be used "
                      "verbatim as the archive suite so a newly published release can still be tested.")
            self.release_hint.configure(
                text=f"Debian identifies releases by codename, so the archive suite is "
                     f"'{codename}'. Feathered refreshes release metadata automatically; type any "
                     f"new codename and use 'Refresh releases' to force an immediate check.{detail}")
        else:
            self.release_hint.configure(
                text=f"Archive suite for {value or 'this release'} is '{codename}'. You can also "
                     "type a codename directly instead of a version number.")

    def _refresh_profile_managed_workload_repositories(self):
        """Retarget recommended workload sources after distro/release changes."""
        try:
            templates = self._profile().repos_factory(
                self.release_var.get().strip(), self.arch_var.get())
        except Exception:
            templates = []
        by_role = {}
        for template in templates:
            by_role.setdefault(template.role, []).append(template)
        for repo in self.repo_rows:
            if self._repo_tier(repo) != "workload" or not getattr(repo, "workload_profile_managed", False):
                continue
            choices = by_role.get(repo.role, [])
            if not choices:
                repo.enabled = False
                continue
            template = sorted(choices, key=lambda x: (not x.enabled, x.priority, x.name))[0]
            repo.name = template.name
            repo.url = template.url
            repo.priority = template.priority
            repo.target_release = template.target_release
            repo.repo_format = getattr(template, "repo_format", repo.repo_format)
            repo.suite = getattr(template, "suite", repo.suite)
            repo.components = getattr(template, "components", repo.components)
            repo.expected_release_version = getattr(template, "expected_release_version", "")
            repo.evidence_suggestions = list(getattr(template, "evidence_suggestions", []) or [])

    def _release_changed(self):
        if 'workload_combo' in self.__dict__:
            labels = self._workload_labels_for_profile()
            self.workload_combo['values'] = labels
            if self.workload_var.get() not in labels:
                self.workload_var.set(self._default_workload_label() if self._default_workload_label() in labels else labels[0])
        # Inspection caches use repository names/URLs, which can remain the
        # same across suites and architectures. They describe the old target.
        self._provenance_detected_cache = {}
        self._provenance_digest_coverage_cache = {}
        self._provenance_inspection_errors = {}
        self._update_release_hint()
        self._update_folder_preview()
        release = self.release_var.get().strip()
        p = self._profile()

        # Target changes invalidate both repository workflows. Rebuild the
        # transaction universe against the new target even if mirror intent is
        # currently active, then recreate the mirror universe from its own
        # mirror preset.
        mirror_active = self._repository_universe_mode == "mirror"
        self.activate_repository_universe("transaction")

        self.repo_rows = [r for r in self.repo_rows if self._repo_tier(r) != "base"]
        if release:
            self._refresh_profile_managed_workload_repositories()
        else:
            self.repo_rows = [r for r in self.repo_rows
                             if not getattr(r, "workload_profile_managed", False)]
        self.selected_packages = []
        self._refresh_selected_packages()
        self.single_catalog_packages = []; self.single_catalog_signature = None
        self._apply_source_method()
        self._sync_workload_repo_state()

        # A mirror created for the old target is never silently reused for the
        # new release/distribution. Preserve only the selected mirror preset.
        self.mirror_repo_rows = []
        self.mirror_repos.clear()
        self._mirror_seen.clear()
        choices = self._source_choices()
        if self.mirror_source_method_var is not None:
            current = self.mirror_source_method_var.get()
            if current not in choices:
                self.mirror_source_method_var.set(self._default_mirror_source_method())

        if mirror_active:
            # Re-activating the mirror universe is the whole restoration: its
            # list was never moved, only left inactive while the transaction
            # universe was rebuilt against the new target.
            self.activate_repository_universe("mirror")
            self._ensure_mirror_repository_seeded()

        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        major = re.match(r"\d+", release)
        if not release:
            self.target_note.configure(text=p.note + " Choose a target release to populate repositories.")
        elif p.key == "rhel" and major:
            self.target_note.configure(text=f"Target: RHEL {release}. OS-native workloads use matching RHEL {release} content. Docker Engine, when selected, maps its upstream packages to Docker's RHEL {major.group(0)} repository.")
        elif p.package_family == "deb":
            self.target_note.configure(text=f"Target: {p.label} {release} ({p.codename(release)}), {self.arch_var.get()}. APT dependencies use the selected suite/update/security repositories; Docker uses Docker's {p.key} APT repository when selected.")
        elif p.package_family == "arch":
            self.target_note.configure(text=f"Target: Arch Linux rolling, {self.arch_var.get()}. Pacman dependencies use core/extra plus any explicitly enabled Arch repositories; 'any' packages are accepted for x86_64.")
        else:
            self.target_note.configure(text=p.note)
        self._render_repository_workflow(force=True)
        self._update_source_status()
        self._refresh_repo_tree_if_open()

    def _default_transaction_source_method(self) -> str:
        """Target-derived default for the transaction repository universe.

        Workload and exact-package acquisition both need a usable distribution
        universe before dependency analysis can be meaningful.  Local media is
        an explicit operator choice, never a sensible global default.
        """
        profile = self._profile()
        if profile.key in {"custom-rpm", "custom-apt"}:
            return "Custom repositories"
        if profile.key == "rhel":
            # Preserve RHEL provenance by default: populate the official CDN
            # rows immediately and let validation request entitlement material
            # before they are contacted.  Public rebuild fallbacks remain an
            # explicit source-plan choice.
            return "Red Hat CDN entitlement (official)"
        if profile.package_family == "deb":
            return "Distribution APT repositories"
        if profile.package_family == "arch":
            return "Distribution pacman repositories"
        return "Distribution repositories"

    def _source_choices(self):
        if self._profile().key == "custom-rpm":
            return ["Custom repositories", "Installation media / local mirror (ISO, DVD, folder, SMB)"]
        if self._profile().key == "custom-apt":
            return ["Custom repositories", "Installation media / local mirror (ISO, DVD, folder, SMB)"]
        if self._profile().key == "rhel":
            return [
                "Installation media / local mirror (ISO, DVD, folder, SMB)",
                "Red Hat CDN entitlement (official)",
                "Public EL-compatible mirrors (recommended fallback)",
                "Public EL-compatible + EPEL (broad fallback)",
                "Custom repositories",
            ]
        if self._is_deb():
            return ["Distribution APT repositories",
                "Installation media / local mirror (ISO, DVD, folder, SMB)",
                "Custom repositories"]
        if self._is_arch():
            return ["Distribution pacman repositories",
                "Installation media / local mirror (ISO, DVD, folder, SMB)",
                "Custom repositories"]
        return ["Distribution repositories",
                "Installation media / local mirror (ISO, DVD, folder, SMB)",
                "Custom repositories"]

    def _source_method_changed(self):
        # Rebuilds the repository list, so remembered keyrings must be reapplied.
        self._apply_source_method()
        self.selected_packages = []
        self._refresh_selected_packages()
        self.single_catalog_packages = []; self.single_catalog_signature = None
        self._sync_workload_repo_state()
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._update_source_status(); self._refresh_repo_tree_if_open()
        self._update_folder_preview()

    def _rhel_cdn_repo(self, name, component, priority):
        release = self.release_var.get().strip()
        major_m = re.match(r"(\d+)", release)
        major = major_m.group(1) if major_m else release
        arch = self.arch_var.get()
        url = f"https://cdn.redhat.com/content/dist/rhel{major}/{release}/{arch}/{component}/os/"
        return RepoSpec(name, url, "dependency", priority, True,
                        "Official Red Hat CDN using RHSM entitlement client-certificate authentication.", release,
                        self.rhsm_cert, self.rhsm_key, self.rhsm_ca)

    def _compatible_repos(self, distro):
        release = self.release_var.get().strip(); arch = self.arch_var.get()
        if distro == "alma":
            base = f"https://repo.almalinux.org/almalinux/{release}"
            label = "AlmaLinux"
        else:
            base = f"https://download.rockylinux.org/pub/rocky/{release}"
            label = "Rocky Linux"
        return [
            RepoSpec(f"{label} {release} BaseOS (RHEL-compatible fallback)", f"{base}/BaseOS/{arch}/os/", "dependency", 70, True,
                     "Runtime-compatible fallback; not Red Hat content.", release),
            RepoSpec(f"{label} {release} AppStream (RHEL-compatible fallback)", f"{base}/AppStream/{arch}/os/", "dependency", 75, True,
                     "Runtime-compatible fallback; not Red Hat content.", release),
            RepoSpec(f"{label} {release} CRB (fallback)", f"{base}/CRB/{arch}/os/", "dependency", 85, True,
                     "CodeReady Builder equivalent; useful for dependencies outside BaseOS/AppStream.", release, optional=True),
            RepoSpec(f"{label} {release} Extras (fallback)", f"{base}/extras/{arch}/os/", "dependency", 90, True,
                     "Distribution extras repository. Does not replace BaseOS/AppStream.", release, optional=True),
        ]

    def _epel_repo(self):
        major_m = re.match(r"(\d+)", self.release_var.get().strip())
        major = major_m.group(1) if major_m else self.release_var.get().strip()
        arch = self.arch_var.get()
        return RepoSpec(
            f"EPEL {major} Everything (supplemental)",
            f"https://dl.fedoraproject.org/pub/epel/{major}/Everything/{arch}/",
            "dependency", 160, True,
            "Supplemental Extra Packages for Enterprise Linux. EPEL is EL-targeted, not a Fedora OS repository.",
            self.release_var.get().strip(), optional=True,
        )

    def _apply_source_method(self):
        # Transaction source-plan changes are never allowed to rewrite the
        # isolated repository-mirror universe. Some target/release helpers call
        # this even while mirror intent is active, so the rebuild runs explicitly
        # against the transaction universe and the caller's mode is restored.
        with self.transaction_universe():
            self._apply_source_method_inner()
            self._refresh_base_repo_tree()
            # Rebuilding discards RepoSpec objects, so restore remembered keyrings.
            self._apply_keystore()
        self._sync_transaction_source_controls()
        self._sync_mirror_source_controls()
        self._sync_mirror_repos()
        if getattr(self, "keyring_tree", None):
            self._refresh_keyring_tree()
        self._refresh_vendor_signature_tree()
        self._refresh_entitlement_state()

    def _transaction_source_control_spec(self, method=None):
        """Return the presentation contract for the current transaction plan.

        Step 3 is rebuilt dynamically from Content intent, so source-plan
        widgets cannot rely on side effects from the callback that originally
        populated ``repo_rows``.  This pure-ish helper lets every newly created
        view reconstruct its label/button/note from the current target + plan.
        """
        method = method or (self.source_method_var.get() if getattr(self, "source_method_var", None) else "")
        p = self._profile()
        if method == "Installation media / local mirror (ISO, DVD, folder, SMB)":
            return (
                "Choose folder…", "normal",
                "Use matching installation media or a local repository mirror for the selected "
                "distribution, release and architecture. No distribution rows appear until media "
                "has been selected and discovered.")
        if method == "Custom repositories":
            return (
                "Add base repositories…", "normal",
                "Custom base mode starts empty. Add only the foundational repositories or internal "
                "mirrors you intend Feathered to use for this target; Additional repositories remain "
                "a separate supplement below.")
        if p.key == "rhel":
            if method == "Red Hat CDN entitlement (official)":
                return (
                    "Entitlement files…", "normal",
                    "Uses the official RHEL CDN BaseOS and AppStream repositories for this target. "
                    "CodeReady Builder is available as a lower-priority optional dependency source; "
                    "configure RHSM entitlement material before testing the plan.")
            if method == "Public EL-compatible mirrors (recommended fallback)":
                return (
                    "No setup needed", "disabled",
                    "Uses exact-minor AlmaLinux/Rocky BaseOS, AppStream, CRB and Extras as public "
                    "RHEL-compatible fallbacks. Alma is preferred and Rocky provides an alternate provider set.")
            if method == "Public EL-compatible + EPEL (broad fallback)":
                return (
                    "No setup needed", "disabled",
                    "Uses exact-minor AlmaLinux/Rocky BaseOS, AppStream, CRB and Extras, then EPEL "
                    "as a low-priority EL-targeted supplemental source.")
        if p.package_family == "deb" and method == "Distribution APT repositories":
            return (
                "No setup needed", "disabled",
                f"Uses the selected distribution's APT archive for suite {p.codename(self.release_var.get().strip())!r}: "
                "the normal release, updates and security repositories are populated automatically; "
                "optional backports remain disabled unless selected.")
        if method == "Distribution pacman repositories":
            return (
                "No setup needed", "disabled",
                "Uses Arch Linux's rolling core and extra repositories for x86_64. The optional multilib "
                "repository remains disabled unless you explicitly enable it below.")
        if method == "Distribution repositories":
            return (
                "No setup needed", "disabled",
                "Uses the selected distribution's own repositories for this release and architecture. "
                "The rows below are derived from the Linux Distribution step and may be tailored before analysis.")
        return ("Configure…", "normal", "Review the repositories populated by this source plan below.")

    def _sync_transaction_source_controls(self):
        """Synchronize a freshly rendered transaction source-plan UI.

        This is the single UI synchronization point for source-plan choices.
        It intentionally does *not* repopulate repositories, because rebuilding a
        view must never erase operator edits to the current base rows.
        """
        if getattr(self, "source_method_var", None) is None:
            self.source_method_var = tk.StringVar(value=self._default_transaction_source_method())
        choices = list(self._source_choices())
        current = self.source_method_var.get()
        if current not in choices:
            current = self._default_transaction_source_method()
            self.source_method_var.set(current)
        combo = getattr(self, "source_method_combo", None)
        if combo is not None:
            try:
                if combo.winfo_exists():
                    combo["values"] = choices
            except (tk.TclError, AttributeError):
                pass
        button_text, button_state, note = self._transaction_source_control_spec(current)
        self._set_transaction_source_ui(button_text=button_text, note=note, state=button_state)

    def _set_transaction_source_ui(self, button_text=None, note=None, state=None):
        button = getattr(self, "source_config_btn", None)
        if button is not None:
            try:
                exists = getattr(button, "winfo_exists", lambda: True)()
                if exists:
                    options = {}
                    if button_text is not None:
                        options["text"] = button_text
                    if state is not None:
                        options["state"] = state
                    if options:
                        button.configure(**options)
            except (tk.TclError, AttributeError):
                pass
        label = getattr(self, "source_note", None)
        if label is not None and note is not None:
            try:
                exists = getattr(label, "winfo_exists", lambda: True)()
                if exists:
                    label.configure(text=note)
            except (tk.TclError, AttributeError):
                pass

    def _apply_source_method_inner(self):
        method = self.source_method_var.get()
        # 1.0.46 source-plan changes
        # repopulate only the base tier. Supplemental repositories remain
        # exactly as the operator configured them.
        self.repo_rows = [r for r in self.repo_rows if self._repo_tier(r) != "base"]
        p = self._profile()
        if not self.release_var.get().strip():
            self._set_transaction_source_ui(note="Choose a target release to populate distribution repositories.")
            return
        if p.key != "rhel":
            if method in {"Distribution repositories", "Distribution APT repositories", "Distribution pacman repositories"}:
                templates = p.repos_factory(self.release_var.get().strip(), self.arch_var.get())
                workload_roles = set(self._known_workload_repository_roles())
                self.repo_rows.extend(
                    self._repo_from_template(x, "base") for x in templates
                    if x.role not in workload_roles)
            if method == "Custom repositories":
                # Custom is an operator-owned base source plan, not a request to
                # mix hidden distribution defaults into the same list. Start
                # empty so every foundational repository visible below is one
                # the operator explicitly added.
                pass
            local_method = method == "Installation media / local mirror (ISO, DVD, folder, SMB)"
            self._set_transaction_source_ui(
                button_text="Choose folder…" if local_method
                else "Add base repositories…" if method == "Custom repositories"
                else "No setup needed")
            if method == "Custom repositories":
                self._set_transaction_source_ui(
                    note="Custom base mode starts with an empty distribution-source list. Add the exact "
                         "repository or internal mirror you want Feathered to treat as foundational; Additional "
                         "repositories remain a separate supplement below.")
            elif p.package_family == "deb":
                self._set_transaction_source_ui(note=f"APT sources use suite {p.codename(self.release_var.get().strip())!r}. Distribution mode includes the normal release, updates and security repositories; optional backports stay disabled.")
            elif p.package_family == "arch":
                self._set_transaction_source_ui(note="Pacman sources use Arch's rolling core and extra repositories for x86_64; multilib remains optional unless explicitly enabled.")
            else:
                self._set_transaction_source_ui(note="Use the selected distribution's own repositories whenever possible.")
            return
        if method == "Red Hat CDN entitlement (official)":
            crb = self._rhel_cdn_repo(f"RHEL {self.release_var.get()} CodeReady Builder (CDN)", "codeready-builder", 55)
            crb.optional = True
            self.repo_rows.extend([
                self._set_repo_tier(self._rhel_cdn_repo(f"RHEL {self.release_var.get()} BaseOS (CDN)", "baseos", 40), "base"),
                self._set_repo_tier(self._rhel_cdn_repo(f"RHEL {self.release_var.get()} AppStream (CDN)", "appstream", 45), "base"),
                self._set_repo_tier(crb, "base"),
            ])
            self._set_transaction_source_ui(
                button_text="Entitlement files…",
                note="Uses RHSM entitlement certificate + private key (mTLS). BaseOS and AppStream are primary; CodeReady Builder is also available as a lower-priority optional dependency source.")
        elif method in {"Public EL-compatible mirrors (recommended fallback)", "Public EL-compatible + EPEL (broad fallback)"}:
            alma = [self._set_repo_tier(r, "base") for r in self._compatible_repos("alma")]
            rocky = [self._set_repo_tier(r, "base") for r in self._compatible_repos("rocky")]
            # Alma is preferred; Rocky acts as a mirror/provider fallback. Every
            # public compatible repo is optional individually so one mirror
            # outage does not abort the whole resolution.
            for r in alma:
                r.optional = True
            for r in rocky:
                r.priority += 30
                r.optional = True
            self.repo_rows.extend(alma)
            self.repo_rows.extend(rocky)
            if method == "Public EL-compatible + EPEL (broad fallback)":
                self.repo_rows.append(self._set_repo_tier(self._epel_repo(), "base"))
            self._set_transaction_source_ui(button_text="No setup needed")
            if "EPEL" in method:
                self._set_transaction_source_ui(note="Uses exact-minor AlmaLinux/Rocky BaseOS, AppStream, CRB and Extras, then EPEL as a low-priority EL9 supplemental source. Fedora OS repositories are never used.")
            else:
                self._set_transaction_source_ui(note="Uses exact-minor AlmaLinux/Rocky BaseOS, AppStream, CRB and Extras. Alma is preferred and Rocky is used as a provider/mirror fallback. Fedora OS repositories are deliberately excluded.")
        elif method == "Custom repositories":
            # Do not silently mix Alma/Rocky fallback content into an operator
            # supplied RHEL source plan. The base list is intentionally empty
            # until the operator adds the exact internal/Satellite/mirror roots
            # they want to trust as foundational.
            self._set_transaction_source_ui(
                button_text="Add base repositories…",
                note="Custom base mode starts empty. Add the RHEL-compatible internal, Satellite, Pulp "
                     "or mirror repositories you intend to use. Public EL-compatible fallbacks remain a "
                     "separate source-plan choice rather than appearing implicitly here.")
        else:
            self._set_transaction_source_ui(
                button_text="Choose folder…",
                note=f"Preferred for deterministic RHEL {self.release_var.get()} bundles: matching RHEL BaseOS + AppStream DVD/ISO or local mirror.")

    def _finish_source_rebuild(self):
        """Called after any repository-list rebuild."""
        self._apply_keystore()
        self._refresh_keyring_tree()
        self._refresh_vendor_signature_tree()
        self._refresh_entitlement_state()

    def configure_source(self):
        method = self.source_method_var.get()
        if method == "Installation media / local mirror (ISO, DVD, folder, SMB)":
            self.select_media(); return
        if method == "Red Hat CDN entitlement (official)":
            self.configure_rhsm(); return
        if method == "Custom repositories":
            self.open_repositories("base"); return
        # Public fallback/distribution sources require no credentials.
        self.probe_all()

    def _entitlement_store_path(self) -> Path:
        return self._user_state_dir() / "vendor-entitlements.json"

    def _sync_redhat_entitlement_aliases(self) -> None:
        """Keep legacy Red Hat fields backed by the vendor-scoped profile."""
        profile = self.entitlement_profiles.get("redhat", {}) if hasattr(self, "entitlement_profiles") else {}
        self.rhsm_cert = str(profile.get("cert", ""))
        self.rhsm_key = str(profile.get("key", ""))
        self.rhsm_ca = str(profile.get("ca", ""))
        self.rhsm_last_folder = str(profile.get("last_folder", ""))

    def _load_entitlement_paths(self) -> None:
        """Restore vendor-scoped credential file references.

        entitlement material is not a
        global application credential.  Each vendor gets its own reference set;
        Feathered persists only those paths in the OS user configuration area.
        The private-key bytes are never copied into Feathered state or bundles.
        """
        path = self._entitlement_store_path()
        legacy = self._legacy_program_state_path("entitlements.json")
        source = path if path.is_file() else legacy if legacy.is_file() else None
        if source is None:
            self._sync_redhat_entitlement_aliases()
            return
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
        except Exception as exc:
            self._log(f"Entitlement reference store could not be read ({exc}); ignoring it.")
            self._sync_redhat_entitlement_aliases()
            return
        if isinstance(data, dict) and isinstance(data.get("vendors"), dict):
            profiles = data.get("vendors", {})
        else:
            # 1.0.44 and older stored one Red Hat tuple globally. Migrate it to
            # the vendor-scoped shape without copying any credential material.
            profiles = {"redhat": {k: str(data.get(k, "")) for k in ("cert", "key", "ca", "last_folder")}} if isinstance(data, dict) else {}
        cleaned = {}
        for vendor_id, profile in profiles.items():
            if not isinstance(profile, dict):
                continue
            refs = {k: str(profile.get(k, "")) for k in ("cert", "key", "ca", "last_folder")}
            missing = [refs[k] for k in ("cert", "key", "ca") if refs[k] and not Path(refs[k]).is_file()]
            if missing:
                self._log(
                    f"Remembered {vendor_display_name(vendor_id)} entitlement files are no longer present "
                    f"({len(missing)} missing); reconfigure that vendor profile when needed.")
                # Keep the last folder for convenience, but do not activate a
                # partially missing credential set.
                cleaned[vendor_id] = {"cert": "", "key": "", "ca": "",
                                      "last_folder": refs.get("last_folder", "")}
            else:
                cleaned[vendor_id] = refs
        self.entitlement_profiles = cleaned
        self._sync_redhat_entitlement_aliases()
        if source == legacy:
            try:
                self._save_entitlement_paths()
                legacy.unlink(missing_ok=True)
                self._log("Migrated entitlement file references to vendor-scoped per-user configuration.")
            except OSError as exc:
                self._log(f"Could not migrate the legacy entitlement reference store: {exc}")
        if self.rhsm_cert and self.rhsm_key and self.rhsm_ca:
            self._log("Restored Red Hat entitlement file references from the previous session.")

    def _save_entitlement_paths(self) -> None:
        try:
            self._secure_write_json(self._entitlement_store_path(),
                                    {"vendors": self.entitlement_profiles})
        except OSError as exc:
            self._log(f"Entitlement references could not be saved: {exc}")

    def _apply_entitlement_profile_to_vendor_repos(self, vendor_id: str) -> None:
        profile = self.entitlement_profiles.get(vendor_id, {})
        cert, key, ca = (str(profile.get(k, "")) for k in ("cert", "key", "ca"))
        for repo in self.repo_rows:
            repo_vendor = getattr(repo, "vendor_id", "") or infer_vendor_id(repo.name, repo.url)
            if repo_vendor != vendor_id:
                continue
            # Only repositories already identified as client-auth endpoints get
            # credentials.  Never spray an entitlement certificate onto every
            # public repository belonging to the same vendor.
            client_auth_endpoint = bool(repo.client_cert or repo.client_key or repo.ca_cert) or \
                (vendor_id == "redhat" and repo.url.startswith("https://cdn.redhat.com"))
            if client_auth_endpoint:
                repo.client_cert, repo.client_key, repo.ca_cert = cert, key, ca

    def forget_entitlement(self, vendor_id: str = "redhat") -> None:
        self.entitlement_profiles.pop(vendor_id, None)
        self._sync_redhat_entitlement_aliases()
        self._apply_entitlement_profile_to_vendor_repos(vendor_id)
        self._save_entitlement_paths()
        if vendor_id == "redhat":
            self._apply_source_method(); self._update_source_status()
        self._log(f"Forgot {vendor_display_name(vendor_id)} entitlement file references.")

    def configure_rhsm(self):
        self._configure_vendor_entitlement("redhat")

    def _configure_vendor_entitlement(self, vendor_id: str) -> None:
        """Configure an mTLS certificate/key/CA reference set for one vendor."""
        existing = self.entitlement_profiles.get(vendor_id, {})
        last_folder = str(existing.get("last_folder", ""))
        start = last_folder if last_folder and Path(last_folder).is_dir() else None
        label = vendor_display_name(vendor_id)
        cert = filedialog.askopenfilename(
            title=f"{label} entitlement certificate", initialdir=start,
            filetypes=[("PEM certificates", "*.pem *.crt"), ("All files", "*.*")])
        if not cert:
            return
        start = str(Path(cert).parent)
        key = filedialog.askopenfilename(
            title=f"{label} entitlement private key", initialdir=start,
            filetypes=[("PEM private keys", "*.pem *.key"), ("All files", "*.*")])
        if not key:
            return
        ca = filedialog.askopenfilename(
            title=f"{label} repository CA", initialdir=start,
            filetypes=[("PEM certificates", "*.pem *.crt"), ("All files", "*.*")])
        if not ca:
            return
        self.entitlement_profiles[vendor_id] = {
            "cert": cert, "key": key, "ca": ca, "last_folder": str(Path(cert).parent)}
        self._sync_redhat_entitlement_aliases()
        self._apply_entitlement_profile_to_vendor_repos(vendor_id)
        self._save_entitlement_paths()
        if vendor_id == "redhat":
            self._apply_source_method()
            self.loaded_signature = None; self.loaded_packages = []
            self._update_source_status(); self._refresh_repo_tree_if_open()
        self._refresh_entitlement_state()
        self._log(
            f"Configured {label} entitlement authentication. Feathered remembers only file references; "
            "the certificate/private-key bytes remain in the selected files and are never bundled.")
        if vendor_id == "redhat":
            self.probe_all()

    def _workload_repo_needed(self) -> bool:
        """Whether the current package request declares workload repositories."""
        if self._single_mode():
            return any(self._repo_tier(p.repo) == "workload" for p in self.selected_packages)
        return bool(self._workload_required_repository_roles())

    def _sync_workload_repo_state(self):
        """Keep workload-owned sources aligned without overriding manual sources.

        Profile-managed workload repositories follow the workload selected on
        Packages. Manually added sources are never silently disabled merely
        because the operator switches presets.
        """
        required = set(self._workload_required_repository_roles())
        if not self._single_mode():
            for repo in self.repo_rows:
                # Only sources Feathered materialized from a workload profile are
                # lifecycle-managed here. Operator-added vendor repositories
                # remain exactly as configured when the workload changes.
                if (self._repo_tier(repo) == "workload" and
                        getattr(repo, "workload_profile_managed", False) and
                        repo.role not in required and repo.enabled):
                    repo.enabled = False
                    self._log(f"Disabled no-longer-required workload repository: {repo.name}")
        else:
            source_ids = {p.repo.source_identity for p in self.selected_packages}
            for repo in self.repo_rows:
                if (self._repo_tier(repo) == "workload" and
                        getattr(repo, "workload_profile_managed", False)):
                    # Profile-managed side channels are discovery candidates in
                    # Specific packages mode, not inherited participants.  Only
                    # selecting an exact root from that concrete repository activates it.
                    repo.enabled = repo.source_identity in source_ids
                elif repo.source_identity in source_ids:
                    repo.enabled = True
        self._refresh_workload_repository_views()
        self._refresh_keyring_tree()

    def _workload_repository_for_role(self, role):
        """Return the concrete enabled repository chosen for one workload role."""
        if not role:
            return None
        candidates = [r for r in self.repo_rows
                      if r.enabled and r.url.strip() and r.role == role]
        return sorted(candidates, key=lambda r: (r.priority, r.name, r.url))[0] if candidates else None

    def _activate_workload_repository_selection(self):
        """Materialize the repository implied by the current workload selection.

        Packages is the authority for source requirements.  Explicit
        workload/vendor roles are therefore materialized at selection time so
        the following Repositories stage opens pre-populated.  The operation is
        idempotent and may also be called immediately before validation as a
        defensive synchronization point.
        """
        if self._single_mode() or self._mirror_mode():
            return
        from kubernetes_workflow import KUBERNETES_KEYS, synchronize_repository
        if self._workload().key in KUBERNETES_KEYS:
            minor = self.k8s_minor_var.get().strip()
            if not minor:
                return
            from k8s_version import parse
            try:
                parse(minor)
            except ValueError:
                # An editable minor may be incomplete while the operator
                # changes presets. Validation belongs to the input/build;
                # it must not abort a UI transition halfway through.
                return
            synchronize_repository(self.repo_rows, self._profile().package_family, minor, self._repo_from_template)
        roles = list(self._workload_required_repository_roles())
        changed = []
        for role in roles:
            if self._workload_repository_for_role(role) is not None:
                continue
            configured = [r for r in self.repo_rows if r.role == role and r.url.strip()]
            if configured:
                best = sorted(configured, key=lambda r: (r.priority, r.name, r.url))[0]
                if not best.enabled:
                    best.enabled = True
                    changed.append(f"enabled {best.name}")
                continue
            templates = self._workload_repo_templates([role])
            if not templates:
                continue
            template = sorted(templates, key=lambda r: (not r.enabled, r.priority, r.name))[0]
            repo = self._repo_from_template(template, "workload")
            repo.enabled = True
            repo.workload_profile_managed = True
            self.repo_rows.append(repo)
            changed.append(f"selected {repo.name}")
        if changed:
            self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
            self.package_source_coverage_signature = None
            self._log("Workload source determined by Packages: " + ", ".join(changed))
            self._refresh_repo_tree_if_open(); self._update_source_status()
        self._sync_workload_repo_state()
        self._refresh_workload_repository_views()

    def _workload_repo_templates(self, roles=None):
        """Profile templates satisfying workload repository roles."""
        wanted = set(roles if roles is not None else self._workload_required_repository_roles())
        if not wanted or not self.release_var.get().strip():
            return []
        profile = self._profile()
        try:
            templates = profile.repos_factory(self.release_var.get().strip(), self.arch_var.get())
        except Exception:
            return []
        if 'kubernetes' in wanted and 'k8s_minor_var' in self.__dict__ and self.k8s_minor_var.get().strip():
            from kubernetes_workflow import repository_template
            try:
                templates.append(repository_template(profile.package_family, self.k8s_minor_var.get()))
            except ValueError:
                pass  # Do not invent a repository for an incomplete minor.
        return [t for t in templates if t.role in wanted]

    def _workload_repo_state_rows(self):
        """Return presentation rows for source requirements from Packages."""
        rows = []
        if self._mirror_mode():
            for repo in self.repo_rows:
                if repo.url.strip() and self._mirror_repo_selected(repo):
                    rows.append((f"mirror:{repo.name}", "Ready", repo.name, repo.url, "ready"))
            return rows
        if self._single_mode():
            for pkg in self.selected_packages:
                enabled = any(r.enabled and r.name == pkg.repo.name and r.url.strip() for r in self.repo_rows)
                rows.append((f"exact:{pkg.repo.name}", "Ready" if enabled else "Disabled",
                             pkg.repo.name, pkg.repo.url or "<not configured>",
                             "ready" if enabled else "disabled"))
            return rows
        plan = self._workload_root_source_plan()

        # Put explicit side-channel sources first: they are the workload-owned
        # additions the operator most needs to see/override on this page.
        for role in self._workload_required_repository_roles():
            configured = [r for r in self.repo_rows if r.role == role]
            enabled = [r for r in configured if r.enabled and r.url.strip()]
            templates = self._workload_repo_templates([role])
            key = f"role:{role}"
            if enabled:
                best = sorted(enabled, key=lambda r: (r.priority, r.name))[0]
                rows.append((key, "Ready", best.name, best.url, "ready"))
            elif configured:
                best = sorted(configured, key=lambda r: (r.priority, r.name))[0]
                rows.append((key, "Disabled", best.name, best.url or "<not configured>", "disabled"))
            elif templates:
                best = sorted(templates, key=lambda r: (not r.enabled, r.priority, r.name))[0]
                rows.append((key, "Available to add", best.name, best.url or "<manual setup>", "available"))
            else:
                rows.append((key, "Source needed", "No profile source defined", "Configure manually", "missing"))

        if any(kind == "distribution" for _name, kind, _role in plan):
            enabled_base = [r for r in self.repo_rows
                            if self._repo_tier(r) == "base" and r.enabled and r.url.strip()]
            if enabled_base:
                names = ", ".join(r.name for r in sorted(enabled_base, key=lambda r: (r.priority, r.name))[:4])
                more = len(enabled_base) - 4
                if more > 0:
                    names += f" + {more} more"
                rows.append(("distribution", "Ready", names,
                             "All enabled distribution repositories are eligible", "ready"))
            else:
                rows.append(("distribution", "Source needed", "No distribution repository enabled",
                             "Enable at least one base distribution source", "missing"))
        if any(kind == "enabled" for _name, kind, _role in plan):
            enabled = [r for r in self.repo_rows if r.enabled and r.url.strip()]
            rows.append(("enabled", "Ready" if enabled else "Source needed",
                         f"{len(enabled)} enabled repository/repositories" if enabled else "None",
                         "Operator-defined roots may use any enabled repository",
                         "ready" if enabled else "missing"))
        return rows

    def _refresh_workload_repository_views(self):
        """Refresh the Repositories-stage requirements derived from Content intent."""
        req_tree = getattr(self, "package_workload_repo_tree", None)
        rows = self._workload_repo_state_rows()
        status_var = getattr(self, "workload_repo_status_var", None)
        if status_var is not None:
            if not rows:
                status_var.set("No concrete roots are selected yet. Choose exact packages below, or return to Content to change the acquisition intent.")
            else:
                missing = sum(r[1] != "Ready" for r in rows)
                if missing:
                    status_var.set(f"{missing} source requirement(s) need attention before coverage analysis.")
                else:
                    status_var.set("All source requirements derived from the current acquisition intent are satisfied.")
        if req_tree is not None and req_tree.winfo_exists():
            req_tree.delete(*req_tree.get_children())
            for key, state, name, url, tag in rows:
                label = ("Distribution repository set" if key == "distribution" else
                         "Any enabled repository" if key == "enabled" else
                         key.split(":", 1)[1] if key.startswith("role:") else
                         "Exact package source" if key.startswith("exact:") else
                         "Mirror source" if key.startswith("mirror:") else key)
                req_tree.insert("", "end", iid=key, tags=(f"workload-{tag}",),
                                values=(label, state, name, url))
        actionable = any(r[0].startswith("role:") and r[1] in {"Available to add", "Disabled"} for r in rows)
        btn = getattr(self, "add_workload_repos_btn", None)
        if btn is not None:
            btn.configure(state="normal" if actionable and not self._busy() else "disabled")
        selected_role = self._selected_workload_requirement_role(allow_none=True)
        for name in ("edit_workload_repo_btn", "manual_workload_repo_btn"):
            btn = getattr(self, name, None)
            if btn is not None:
                btn.configure(state="normal" if selected_role else "disabled")

    def _add_or_enable_recommended_workload_repositories(self):
        """Materialise the current workload's recommended repository templates."""
        roles = self._workload_required_repository_roles()
        if not roles:
            return
        changed = []
        for role in roles:
            existing = [r for r in self.repo_rows if r.role == role]
            if existing:
                # Preserve operator-edited URLs; only re-enable the best existing
                # source instead of replacing it with profile defaults.
                best = sorted(existing, key=lambda r: (r.priority, r.name))[0]
                if not best.enabled:
                    best.enabled = True
                    changed.append(f"enabled {best.name}")
                continue
            templates = self._workload_repo_templates([role])
            if not templates:
                continue
            template = sorted(templates, key=lambda r: (not r.enabled, r.priority, r.name))[0]
            repo = self._repo_from_template(template, "workload")
            repo.enabled = True
            repo.workload_profile_managed = True
            self.repo_rows.append(repo)
            changed.append(f"added {repo.name}")
        if changed:
            self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
            self.package_source_coverage_signature = None
            self._log("Workload repository update: " + ", ".join(changed))
        self._refresh_repo_tree_if_open(); self._update_source_status(); self._refresh_workload_repository_views()

    def _selected_workload_requirement_role(self, allow_none: bool = False):
        tree = getattr(self, "package_workload_repo_tree", None)
        if tree is not None:
            sel = tree.selection()
            if sel:
                key = str(sel[0])
                if key.startswith("role:"):
                    return key.split(":", 1)[1]
                return None if allow_none else (self._workload_required_repository_roles()[0]
                                                if self._workload_required_repository_roles() else None)
        roles = self._workload_required_repository_roles()
        return roles[0] if roles else None

    def _add_manual_workload_repository(self):
        role = self._selected_workload_requirement_role()
        if not role:
            return
        self.add_url_repo("workload", role=role)
        self._refresh_workload_repository_views()

    def _edit_selected_workload_requirement_repository(self):
        role = self._selected_workload_requirement_role()
        if not role:
            return
        repo = self._workload_repository_for_role(role)
        if repo is None:
            configured = [r for r in self.repo_rows if r.role == role]
            repo = sorted(configured, key=lambda r: (r.priority, r.name))[0] if configured else None
        if repo is None:
            self._add_manual_workload_repository()
            return
        try:
            index = self.repo_rows.index(repo)
        except ValueError:
            return
        self._edit_repo_at(index, self)
        self._refresh_workload_repository_views()

    def _show_workload_repositories_stage(self):
        self.show_pane("repositories")
        card = getattr(self, "workload_repositories_card", None)
        if card is not None:
            self.after(10, lambda: self._scroll_to_widget(card))

    def _sync_package_version_control(self):
        """Restore workload-dependent version controls after global operation locks.

        ``_lock_operation_controls`` temporarily disables process starters and
        later restores their previous widget state.  The previous state is not
        necessarily semantically valid if the workload changed while an
        operation was active, so derive the version controls from the current
        workload again after unlock.
        """
        has_version = self._workload().has_version_axis
        self.package_version_combo.configure(state="readonly" if has_version else "disabled")
        self.version_scan_btn.configure(state="normal" if has_version else "disabled")
        self._sync_kubernetes_controls(discover=False)
        return has_version

    def _workload_changed(self):
        workload = self._workload()
        context = (self._profile().key, self.release_var.get(), self.arch_var.get(), workload.key)
        previous = self.__dict__.get('_content_version_context')
        states = self.__dict__.setdefault('_content_version_states', {})
        if previous != context:
            if previous is not None:
                states[previous] = (self.package_version_var.get(), tuple(self.package_version_combo['values']), self.k8s_minor_var.get())
            self._content_version_context = context
            version, values, minor = states.get(context, ('Latest', ('Latest',), self.k8s_minor_var.get()))
            self._restoring_workload_controls = True
            try:
                self.package_version_var.set(version if workload.has_version_axis else 'Follows repositories')
                self.package_version_combo['values'] = values if workload.has_version_axis else ()
                self.k8s_minor_var.set(minor)
            finally:
                self._restoring_workload_controls = False
        if workload.key == "vks-node-additions" and self.__dict__.get("_last_workload_key") != workload.key:
            self.custom_var.set("")
        self._last_workload_key = workload.key
        custom = workload.custom
        # Custom packages IS exact-package acquisition: the identities are
        # chosen in the one shared chooser on Repositories. The old freehand
        # entry + Search/Check/Clear row on this page was the second, diverging
        # workflow; it is gone. A short note points at the real chooser.
        self.custom_entry.configure(state="disabled")
        self.custom_label.grid_remove(); self.custom_entry.grid_remove()
        self.custom_tools.grid_remove()
        if custom:
            self.custom_status.grid()
        else:
            self.custom_status.grid_remove()
        # Only workloads with a real version axis get a version selector.
        # Falling back to "the first package" made grab-bag toolsets look
        # versionable, offering to pin tcpdump as though it dated the whole set.
        has_version = workload.has_version_axis
        self.package_version_combo.configure(state="readonly" if has_version else "disabled")
        self.version_scan_btn.configure(state="normal" if has_version else "disabled")
        self.workload_note.configure(text=workload.description)
        self._sync_kubernetes_controls(discover=False)
        # Custom presets use the shared package chooser, but remain presets on
        # Content. Rebuild the downstream view before touching its controls.
        self._render_repository_workflow()
        if custom and workload.key != "vks-node-additions" and not self.custom_var.get():
            self.custom_var.set("docker" if self._profile().key == "photon" else "")
        if custom:
            self._update_custom_guidance()
        # 1.0.52: selecting the workload is the moment its explicit
        # side-channel source requirements become known. Materialize them now,
        # while still on Packages, so the next Repositories page is already
        # populated and coverage checks never observe a half-applied plan.
        if not self._single_mode() and not self._mirror_mode():
            self._activate_workload_repository_selection()
        else:
            self._sync_workload_repo_state()
        self._refresh_package_source_plan()
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._update_source_status(); self._refresh_repo_tree_if_open()
        self._sync_kubernetes_controls()
        self._update_folder_preview()

    def _browser_repositories(self):
        # Search enabled OS/custom sources plus any profile-known workload
        # source even when it is currently disabled. This lets Exact packages
        # discover vendor roots without contaminating ordinary dependency
        # resolution, and keeps the behavior generic instead of Docker-only.
        repos = []
        seen = set()
        workload_roles = set(self._known_workload_repository_roles())
        for repo in self.repo_rows:
            if not repo.url.strip():
                continue
            if not self._repository_target_compatible(repo):
                continue
            if not repo.enabled and repo.role not in workload_roles:
                continue
            key = (repo.name, repo.url)
            if key in seen:
                continue
            seen.add(key); repos.append(repo)
        return repos

    def _browser_signature(self):
        repos = self._browser_repositories()
        return (
            tuple((r.name, r.url, r.role, r.priority, r.client_cert, r.client_key, r.ca_cert,
                   tuple(getattr(r, "redirect_allow_origins", []) or []),
                   r.optional, r.repo_format, r.suite, r.components, tuple(r.evidence_urls),
                   tuple(sorted(getattr(r, "evidence_relationship_hints", {}).items())),
                   tuple(sorted(getattr(r, "evidence_authority_hints", {}).items())),
                   r.evidence_policy, r.digest_preference, r.digest_requirement, r.verification_strategy) for r in repos),
            self.arch_var.get(), self.release_var.get().strip(),
        )

    def _update_custom_guidance(self) -> None:
        """State the order of operations for a custom target.

        Choosing "Custom RPM/APT repositories" used to land the operator on an
        empty freehand box with no indication that repositories had to be added
        first, or that the same search used by Exact packages was available here.
        """
        if not getattr(self, "custom_status", None):
            return
        configured = [r for r in self.repo_rows if r.enabled and r.url.strip()]
        if not configured:
            self.custom_status.configure(
                text="Continue to Repositories: configure your sources there, then pick exact "
                     "packages in the chooser below them. This is the same chooser 'Choose "
                     "packages' mode uses.", foreground=FG_MUTED)
        else:
            self.custom_status.configure(
                text=f"{len(configured)} repository/repositories configured. Pick your exact "
                     "packages in the chooser on Repositories.", foreground=FG_MUTED)

    def _validate_custom_names(self, quiet: bool = False) -> None:
        """Check typed package names against the configured repositories.

        Freehand entry with nothing behind it meant a typo surfaced as an
        unresolved requirement after a full index load. This answers the same
        question up front, and suggests near matches for anything unknown.
        """
        names = [x for x in re.split(r"[\s,]+", self.custom_var.get()) if x]
        if not names:
            self.custom_status.configure(text="No package names entered.", foreground=FG_MUTED)
            return
        catalog = self.single_catalog_packages
        if not catalog:
            self.custom_status.configure(
                text=f"{len(names)} name(s) entered. Use 'Search repositories…' to load the "
                     "package index and confirm they exist.", foreground=FG_MUTED)
            if not quiet:
                self.open_package_search("names")
            return
        known = {p.name for p in catalog}
        provided = {prov.name for p in catalog for prov in getattr(p, "provides", [])}
        missing = [n for n in names if n not in known and n not in provided]
        if not missing:
            self.custom_status.configure(
                text=f"All {len(names)} package name(s) exist in the configured repositories.",
                foreground=OK_FG)
            return
        import difflib
        hints = []
        for name in missing[:4]:
            close = difflib.get_close_matches(name, sorted(known), n=2, cutoff=0.7)
            hints.append(f"{name}" + (f" (did you mean {', '.join(close)}?)" if close else ""))
        more = f" and {len(missing) - 4} more" if len(missing) > 4 else ""
        self.custom_status.configure(
            text=f"{len(missing)} name(s) not found: " + "; ".join(hints) + more +
                 ". They will be reported as unresolved unless another repository provides them.",
            foreground=WARN_FG)

    def open_package_search(self, mode: str = "exact"):
        """Route a search request to the inline chooser.

        Exact package identities are chosen on Repositories after source
        configuration. "names" mode still exists for free-form custom workload
        names and opens the search dialog without pinning a version.
        """
        self.browser_mode = mode
        if mode == "names":
            self.open_single_package_browser()
            return
        self.selection_mode_var.set("Choose packages")
        self._selection_mode_changed()
        self.show_pane("repositories")

    def open_single_package_browser(self):
        if self.single_browser_window and self.single_browser_window.winfo_exists():
            self.single_browser_window.lift(); return
        win = tk.Toplevel(self); self.single_browser_window = win
        win.configure(background=BG_APP)
        win.title("Search repositories - add package"
                  if getattr(self, "browser_mode", "exact") == "exact"
                  else "Search repositories - add package name")
        win.geometry("1100x620"); win.minsize(760, 450); win.transient(self)
        frame = ttk.Frame(win, padding=12); frame.pack(fill="both", expand=True)

        top = ttk.Frame(frame); top.pack(fill="x")
        ttk.Label(top, text="Package search").pack(side="left")
        first = self.single_selected_package
        self.single_browser_query_var = tk.StringVar(value=first.name if first else "")
        query = ttk.Entry(top, textvariable=self.single_browser_query_var, width=42)
        query.pack(side="left", fill="x", expand=True, padx=(8, 8))
        query.bind("<Return>", lambda _e: self.search_single_packages())
        self.single_browser_search_btn = ttk.Button(
            top, text="Search repositories", command=self.search_single_packages)
        self.single_browser_search_btn.pack(side="left")
        self._register_operation_control(self.single_browser_search_btn)

        self.single_browser_status_var = tk.StringVar(value="Type at least 2 characters, then search. Exact names are listed first.")
        ttk.Label(frame, textvariable=self.single_browser_status_var, style="Hint.TLabel", wraplength=1000).pack(fill="x", pady=(6, 8))

        tf = ttk.Frame(frame); tf.pack(fill="both", expand=True)
        cols = ("name", "version", "arch", "repo", "size")
        tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        self.single_browser_tree = tree
        tree.heading("name", text="Package")
        tree.heading("version", text="Exact version / release")
        tree.heading("arch", text="Arch")
        tree.heading("repo", text="Repository")
        tree.heading("size", text="Package size")
        tree.column("name", width=235, minwidth=140)
        tree.column("version", width=285, minwidth=180)
        tree.column("arch", width=85, minwidth=70)
        tree.column("repo", width=390, minwidth=200)
        tree.column("size", width=95, minwidth=80, anchor="e")
        tv = ttk.Scrollbar(tf, orient="vertical", command=tree.yview)
        th = ttk.Scrollbar(tf, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=tv.set, xscrollcommand=th.set)
        tf.rowconfigure(0, weight=1); tf.columnconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew"); tv.grid(row=0, column=1, sticky="ns"); th.grid(row=1, column=0, sticky="ew")
        tree.bind("<Double-1>", lambda _e: self.use_selected_single_package())

        bottom = ttk.Frame(frame); bottom.pack(fill="x", pady=(10, 0))
        ttk.Label(bottom, text="Selecting an OS package keeps Docker's repo out of its dependency closure; selecting a Docker package enables Docker's repository.", style="Hint.TLabel").pack(side="left", fill="x", expand=True)
        ttk.Button(bottom, text="Use selected package", style="Primary.TButton", command=self.use_selected_single_package).pack(side="right")

        query.focus_set()
        if self.single_browser_query_var.get().strip():
            self.search_single_packages()

    def search_single_packages(self):
        if self._busy():
            return
        popup = bool(self.single_browser_window and self.single_browser_window.winfo_exists())
        if not popup and not self._single_mode():
            return
        query = (self.single_browser_query_var.get() if self.single_browser_query_var else "").strip()
        if len(query) < 2:
            self.single_browser_status_var.set("Enter at least 2 characters to search package names.")
            return
        if self._profile().key == "rhel" and self.source_method_var.get() == "Red Hat CDN entitlement (official)" and not (self.rhsm_cert and self.rhsm_key and self.rhsm_ca):
            messagebox.showerror(APP_TITLE, "Configure the RHSM entitlement certificate/key/CA before searching Red Hat CDN metadata.")
            return
        sig = self._browser_signature()
        if sig == self.single_catalog_signature and self.single_catalog_packages:
            self._populate_single_package_results(query)
            return
        repos = self._browser_repositories()
        if not repos:
            messagebox.showerror(APP_TITLE, "No package repositories are configured.")
            return
        self.single_browser_status_var.set(f"Loading package metadata from {len(repos)} repository source(s)…")
        arches = {self.arch_var.get(), 'noarch'}
        arch_family, deb_family = self._is_arch(), self._is_deb()
        loaders = [(repo, arch_core.load_repository if repo.repo_format == 'pacman' or arch_family else
                    apt_core.load_repository if repo.repo_format == 'apt' or deb_family else rpm_load_repository)
                   for repo in repos]
        self._begin_worker("Loading package catalog…")
        def work():
            try:
                rep = Reporter(self._log, self._progress, self.cancel_event)
                packages = []
                failures = []
                for i, (repo, loader) in enumerate(loaders, 1):
                    rep.progress(f"Catalog {i}/{len(repos)}: {repo.name}", i / max(1, len(repos)) * 0.85)
                    try:
                        packages.extend(loader(repo, arches, rep))
                    except Cancelled:
                        raise
                    except Exception as exc:
                        failures.append(f"{repo.name}: {exc}")
                        rep.log(f"Package browser skipped unavailable source {repo.name}: {exc}")
                if not packages:
                    raise RuntimeError("No package metadata could be loaded from the configured sources" + (": " + "; ".join(failures) if failures else ""))
                self.events.put(("single_catalog", packages, sig, query, failures))
                self.events.put(("done", True, f"Package catalog loaded: {len(packages):,} package records"))
            except Cancelled as exc:
                self.events.put(("done", "cancelled", redact_text(str(exc) or "Operation cancelled")))
            except Exception as exc:
                self._log(traceback.format_exc()); self.events.put(("done", False, redact_text(str(exc))))
        self.worker = threading.Thread(target=work, daemon=True); self.worker.start()

    def _receive_single_catalog(self, packages, signature, query, failures):
        if signature != self._browser_signature():
            return
        self.single_catalog_packages = packages
        self.single_catalog_signature = signature
        self._populate_single_package_results(query, failures)

    def _populate_single_package_results(self, query, failures=None):
        tree = self.single_browser_tree
        if not tree or not tree.winfo_exists():
            return
        q = query.lower().strip()
        matches = [p for p in self.single_catalog_packages if q in p.name.lower()]

        from functools import cmp_to_key
        def cmp_pkg(a, b):
            ae = 0 if a.name.lower() == q else 1
            be = 0 if b.name.lower() == q else 1
            if ae != be: return -1 if ae < be else 1
            if a.name.lower() != b.name.lower(): return -1 if a.name.lower() < b.name.lower() else 1
            ev = self._compare_package_versions(a, b)
            if ev: return -ev
            if a.arch != b.arch:
                if a.arch == self.arch_var.get(): return -1
                if b.arch == self.arch_var.get(): return 1
            if a.repo.priority != b.repo.priority: return -1 if a.repo.priority < b.repo.priority else 1
            return -1 if a.repo.name < b.repo.name else (1 if a.repo.name > b.repo.name else 0)
        matches.sort(key=cmp_to_key(cmp_pkg))

        # Layered sources mean the same name-version-arch often appears in
        # several repositories (a base repo, its updates suite, a mirror, a
        # custom overlay). Listing every copy makes the browser unusable, so
        # collapse them and keep the one the resolver would actually pick --
        # the sort above already puts the best-priority repository first. The
        # duplicate count is shown so nothing is hidden silently.
        deduped = []
        seen_identity = {}
        duplicates = 0
        for pkg in matches:
            identity = (pkg.name, pkg.evr_text, pkg.arch)
            if identity in seen_identity:
                duplicates += 1
                seen_identity[identity].append(pkg.repo.name)
                continue
            seen_identity[identity] = [pkg.repo.name]
            deduped.append(pkg)

        tree.delete(*tree.get_children()); self.single_browser_rows = {}
        limit = 1000
        for i, pkg in enumerate(deduped[:limit]):
            iid = f"pkg-{i}"
            self.single_browser_rows[iid] = pkg
            others = len(seen_identity[(pkg.name, pkg.evr_text, pkg.arch)]) - 1
            source = pkg.repo.name + (f"  (+{others} more)" if others else "")
            tree.insert("", "end", iid=iid,
                        values=(pkg.name, pkg.evr_text, pkg.arch, source, human_size(pkg.size)))
        extra = f" Showing first {limit:,}." if len(deduped) > limit else ""
        dupe_note = (f" {duplicates:,} duplicate copy/copies across repositories collapsed; "
                     "the highest-priority source is shown." if duplicates else "")
        failure_note = (f" {len(failures)} source(s) unavailable; healthy sources were still searched."
                        if failures else "")
        self.single_browser_status_var.set(
            f"Found {len(deduped):,} distinct package(s).{extra}{dupe_note}{failure_note}")
        if deduped:
            first = tree.get_children()[0]
            tree.selection_set(first); tree.focus(first); tree.see(first)

    def _live_single_browser_tree(self):
        """Return the chooser tree that is actually on screen right now.

        Removing a selected package re-renders the Repositories workflow,
        which clears the cached widget references. Without re-resolving, the
        Add button kept reading a destroyed tree and reported "Select a
        package/version row first" for every subsequent click."""
        tree = self.__dict__.get("single_browser_tree")
        try:
            if tree is not None and tree.winfo_exists():
                return tree
        except (tk.TclError, AttributeError):
            pass
        self.single_browser_tree = None
        render = getattr(self, "_render_repository_workflow", None)
        if callable(render):
            try:
                render(force=True)
            except Exception:
                pass
        tree = self.__dict__.get("single_browser_tree")
        try:
            return tree if tree is not None and tree.winfo_exists() else None
        except (tk.TclError, AttributeError):
            return None

    def use_selected_single_package(self):
        tree = self._live_single_browser_tree()
        # Fall back to the focused row: a row can be focused (and visibly
        # highlighted) without being in selection() after a redraw.
        chosen = ""
        if tree is not None:
            selection = tree.selection()
            chosen = selection[0] if selection else (tree.focus() or "")
        if tree is None or not chosen:
            messagebox.showinfo(APP_TITLE, "Select a package/version row first.")
            return
        pkg = self.single_browser_rows.get(chosen)
        if pkg is None:
            return
        if getattr(self, "browser_mode", "exact") == "names":
            # Append the bare name to the custom list, de-duplicated.
            existing = [x for x in re.split(r"[\s,]+", self.custom_var.get()) if x]
            if pkg.name not in existing:
                existing.append(pkg.name)
                self.custom_var.set(" ".join(existing))
                self._log(f"Added '{pkg.name}' from {pkg.repo.name}")
            self._validate_custom_names(quiet=True)
            return
        # Add rather than replace, so several exact packages can be bundled.
        if any(existing.nevra == pkg.nevra and existing.repo.source_identity == pkg.repo.source_identity
               for existing in self.selected_packages):
            self._log(f"{pkg.nevra} is already selected")
            return
        self.selected_packages.append(pkg)
        self._refresh_selected_packages()
        self._sync_workload_repo_state()
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self.summary_var.set(f"Selected {pkg.nevra}. Analyze to compute its strict strong-dependency closure.")
        self._update_source_status(); self._refresh_repo_tree_if_open()
        if self.single_browser_window and self.single_browser_window.winfo_exists():
            self.single_browser_window.destroy()
        self.single_browser_window = None; self.single_browser_tree = None

    def _init_repository_conflict(self, repo) -> str:
        """Reason this repository must not participate under the chosen init."""
        try:
            profile = self._profile()
            init = self._selected_init_system()
        except Exception:
            return ""
        if not init:
            return ""
        return workload_resolution.repository_init_conflict(
            getattr(repo, "name", ""), getattr(repo, "url", ""), profile.key, init)

    def _needs_dependency_repos(self):
        # Every installable workload can pull operating-system dependencies,
        # including vendor-sourced workloads such as Docker.  Workload
        # repositories supplement the distribution base; they do not replace it.
        return not self._mirror_mode()

    def _mode_changed(self):
        """React to a dependency-policy change.

        The inventory control lives on the Target stage and is always visible,
        so this only has to point the operator at it when target-aware mode is
        chosen without an inventory loaded.
        """
        target_aware = BuildMixin._selected_content(
            self, "dependency_mode", "mode_var") == "Target-aware complete"
        if target_aware and not self.inventory_var.get().strip():
            self.workload_note.configure(
                text="Target-aware mode needs the target's installed-package inventory. "
                     "Load it on Linux Distribution (step 1) before analyzing.")
        self._update_source_status()

    def _acquisition_state(self):
        """Derive the one valid downstream operation from current wizard state."""
        intent = self._acquisition_intent()
        if intent is AcquisitionIntent.REPOSITORY_MIRROR:
            selected_ids = self.__dict__.get("mirror_repos", set())
            selected = [r for r in self.repository_rows()
                        if str(getattr(r, "url", "") or "").strip()
                        and getattr(r, "source_identity", getattr(r, "name", "")) in selected_ids]
            return derive_acquisition_state(
                intent, mirror_repository_count=len(selected))
        if intent is AcquisitionIntent.PACKAGES:
            roots = list(self.__dict__.get("selected_packages", []) or [])
            rows = self.repository_rows(default=None)
            if rows is None:
                # Lightweight review-contract tests do not construct repository
                # state; the selected package object itself is enough there.
                ready = bool(roots)
            else:
                enabled_ids = {getattr(r, "source_identity", getattr(r, "name", "")) for r in rows
                               if getattr(r, "enabled", False) and str(getattr(r, "url", "") or "").strip()}
                ready = bool(roots) and all(
                    getattr(pkg.repo, "source_identity", getattr(pkg.repo, "name", None)) in enabled_ids
                    for pkg in roots)
            return derive_acquisition_state(
                intent, exact_root_count=len(roots), exact_root_sources_ready=ready)
        # Compatibility: tests that inject the old package-only predicate are
        # describing a derived state directly rather than a full App model.
        package_only_override = self.__dict__.get("_package_only_acquisition_mode")
        if callable(package_only_override) and package_only_override is not BuildIntentMixin._package_only_acquisition_mode:
            try:
                if package_only_override():
                    return AcquisitionState(
                        AcquisitionIntent.WORKLOAD, AcquisitionCapability.PACKAGE_ONLY,
                        AnalysisType.ROOT_ONLY, PublicationType.PACKAGE_ONLY,
                        VerificationScope.REQUESTED_ROOTS)
            except TypeError:
                pass
        plan = self._source_plan()
        readiness_repositories = self._repositories_for_source_readiness(plan)
        readiness = evaluate_source_readiness(
            plan, readiness_repositories, tier_getter=self._repo_tier)
        return derive_acquisition_state(intent, workload_readiness=readiness)

    def _package_only_acquisition_mode(self) -> bool:
        """Whether the derived acquisition capability is root-artifact-only."""
        return self._acquisition_state().capability is AcquisitionCapability.PACKAGE_ONLY
