from feathered_app.build_request import BuildRequestMixin
"""Result selection, unresolved requirements, and review-state coordination.

"""

from feathered_app.build_intent import BuildIntentMixin
from feathered_app.context import (
    ACCENT,
    ACCENT_DIM,
    ACCENT_TEXT,
    AcquisitionCapability,
    AcquisitionIntent,
    AnalysisType,
    BG_APP,
    BG_INPUT,
    ERR_FG,
    FG_DIM,
    FG_TEXT,
    LINE,
    WARN_FG,
    infer_vendor_id,
    redact_url,
    repository_verification_strategy,
    tk,
    ttk,
)
from feathered_app.ui.theme import human_size


def _pinned(host, field: str, variable: str) -> str:
    """A Content value from the frozen request, falling back to the control.

    _parameter_signature runs on the build worker, so these must not be widget
    reads while a build is in flight.
    """
    read = getattr(host, "_build_snapshot_value", None)
    value = read("content", field) if callable(read) else None
    if value is not None:
        return str(value)
    var = host.__dict__.get(variable)
    return var.get() if var is not None else ""


class SelectionMixin(BuildIntentMixin):
    """Result selection, unresolved requirements, and review-state coordination."""


    def _checkbox_images(self):
        """Two small drawn checkboxes: unchecked outline and accent-filled tick."""
        if getattr(self, "_check_imgs", None):
            return self._check_imgs
        size = 15
        off = tk.PhotoImage(width=size, height=size)
        on = tk.PhotoImage(width=size, height=size)
        border, fill_bg = FG_DIM, BG_INPUT
        for img, checked in ((off, False), (on, True)):
            body = ACCENT if checked else fill_bg
            img.put(fill_bg, to=(0, 0, size, size))
            img.put(body, to=(2, 2, size - 2, size - 2))
            for i in range(2, size - 2):
                edge = ACCENT if checked else border
                img.put(edge, to=(i, 2, i + 1, 3))
                img.put(edge, to=(i, size - 3, i + 1, size - 2))
                img.put(edge, to=(2, i, 3, i + 1))
                img.put(edge, to=(size - 3, i, size - 2, i + 1))
            if checked:
                for x, y in ((4, 8), (5, 9), (6, 10), (7, 9), (8, 8), (9, 7), (10, 6)):
                    img.put(ACCENT_TEXT, to=(x, y, x + 2, y + 2))
        self._check_imgs = (off, on)
        return self._check_imgs

    def _set_row_checked(self, iid: str, checked: bool) -> None:
        off, on = self._checkbox_images()
        self.result_tree.item(iid, image=on if checked else off,
                              tags=("ok",) if checked else ("pending",))

    def _unresolved_key(self, req) -> str:
        return self._format_requirement_backend(req)

    def _blocking_unresolved(self, result=None):
        result = result or self.last_result
        if result is None:
            return []
        return [req for req in result.unresolved
                if self._unresolved_key(req) not in self.ignored_unresolved]

    def _update_unresolved_actions(self):
        if not getattr(self, "unresolved_bar", None):
            return
        selected = set(self.result_tree.selection()) if getattr(self, "result_tree", None) else set()
        actionable = any(iid in getattr(self, "unresolved_rows", {}) and
                         self.unresolved_rows[iid] not in self.ignored_unresolved
                         for iid in selected)
        self.ignore_unresolved_btn.configure(state="normal" if actionable else "disabled")
        self.restore_unresolved_btn.configure(state="normal" if self.ignored_unresolved else "disabled")

    def _ignore_selected_unresolved(self):
        """Waive only the highlighted unresolved requirements for this build.

        waivers remain visible in the result
        and are written to ignored-unresolved.txt; they never disappear from
        resolver/provenance output.
        """
        selected = list(self.result_tree.selection())
        keys = [self.unresolved_rows[iid] for iid in selected
                if iid in getattr(self, "unresolved_rows", {})]
        if not keys:
            self.summary_var.set("Select one or more unresolved rows first.")
            return
        self.ignored_unresolved.update(keys)
        if self.last_result is not None:
            self.last_result.ignored_unresolved = sorted(self.ignored_unresolved)
            self._show_result(self.last_result)

    def _restore_ignored_unresolved(self):
        self.ignored_unresolved.clear()
        if self.last_result is not None:
            self.last_result.ignored_unresolved = []
            self._show_result(self.last_result)

    def _retry_unresolved(self):
        """Retry analysis with a larger solver pass budget.

        This is intentionally not a blind full restart button: the package
        indexes remain cacheable, while the dependency solver gets additional
        passes for provider/backtracking cases that previously hit its budget.
        """
        if self._busy():
            return
        current = self.resolution_pass_budget or 8
        self.resolution_pass_budget = min(max(current * 2, 16), 128)
        self._log(f"Retrying unresolved requirements with a {self.resolution_pass_budget}-pass solver budget")
        self.start_build(False)

    def _bulk_pick(self, action: str) -> None:
        """Standard bulk selection actions across the complete result set."""
        if not self._pick_mode() or self.last_result is None:
            return
        all_identities = {p.nevra for p in self.last_result.selected}
        roots = {p.nevra for p in getattr(self.last_result, "roots", [])}
        highlighted_iids = set(self.result_tree.selection())
        highlighted = {identity for identity, iid in self.result_rows.items()
                       if iid in highlighted_iids}
        if action == "highlighted" and not highlighted:
            self.summary_var.set("Highlight one or more rows first, then press Highlighted. "
                                 "Use All or None to change everything.")
            return
        if action == "all":
            self.picked = set(all_identities)
        elif action == "none":
            self.picked = set()
        elif action == "invert":
            self.picked = all_identities - set(self.picked)
        elif action == "roots":
            self.picked = all_identities & roots
        else:
            self.picked = set(highlighted)

        # Only the current page has Treeview rows, but the selection contract is
        # global. Refresh the visible checkboxes from that global set.
        for identity, iid in self.result_rows.items():
            if self.result_tree.exists(iid):
                self._set_row_checked(iid, identity in self.picked)
        self.picked_closure = set(all_identities)
        self._update_pick_summary()

    def _toggle_selected_rows(self) -> None:
        """Space toggles every highlighted row, for keyboard use."""
        if not self._pick_mode():
            return
        for iid in self.result_tree.selection():
            identity = next((k for k, v in self.result_rows.items() if v == iid), None)
            if identity is None:
                continue
            checked = identity not in self.picked
            self.picked.add(identity) if checked else self.picked.discard(identity)
            self._set_row_checked(iid, checked)
        self._update_pick_summary()

    def _toggle_pick(self, event):
        """Toggle inclusion of the clicked row."""
        if not self._pick_mode() or self.worker is not None:
            return
        iid = self.result_tree.identify_row(event.y)
        if not iid:
            return
        identity = next((k for k, v in self.result_rows.items() if v == iid), None)
        if identity is None:
            return
        checked = identity not in self.picked
        self.picked.add(identity) if checked else self.picked.discard(identity)
        self._set_row_checked(iid, checked)
        self._update_pick_summary()

    def _update_pick_summary(self):
        if not self._pick_mode() or self.last_result is None:
            return
        total = len(self.last_result.selected)
        chosen = len(self.picked)
        size = sum(p.size for p in self.last_result.selected if p.nevra in self.picked)
        note = (f"{chosen} of {total} packages selected, {human_size(size)}. "
                "Click a row to include or exclude it.")
        if chosen < total:
            note += ("  Excluding dependencies can produce a bundle the target cannot install; "
                     "the closure was computed assuming all of them.")
        self.summary_var.set(note)
        self._refresh_download_size_preview(self.last_result)
        self._sync_review_action_states()

    def _sort_results(self, column: str):
        """Sort the complete package result, then render the first page.

        Pagination must not turn heading sort into a page-local operation: that
        would make rows jump between inconsistent partial orderings. Issue rows
        stay pinned by the page renderer.
        """
        previous, descending = getattr(self, "_result_sort", (None, False))
        descending = not descending if previous == column else False
        self._result_sort = (column, descending)
        arrow = " ▾" if descending else " ▴"
        for name, label in (("package", "Package / issue"), ("status", "Status"),
                            ("source", "Source"), ("reason", "Why")):
            self.result_tree.heading(name, text=label + (arrow if name == column else ""))
        if self.last_result is not None and hasattr(self, "_render_result_page"):
            self.result_page = 0
            self._render_result_page(self.last_result)


    def _parameter_signature(self) -> tuple:
        """Everything that would change what a build produces."""
        selection: tuple = ()
        if self._mirror_mode():
            selection = ("mirror",)
        elif self._single_mode():
            selection = tuple(sorted(f"{p.nevra}@{p.repo.source_identity}" for p in self.selected_packages))
        else:
            workload = self._workload()
            plan_identity = tuple(
                (root.component, root.package, tuple(root.candidates or (root.package,)),
                 root.source_kind, root.role, root.optional)
                for root in self._source_plan().roots)
            contextual_roots = (
                tuple(sorted(f"{p.nevra}@{p.repo.source_identity}" for p in self.selected_packages))
                if getattr(workload, "contextual_packages", False) else ())
            selection = (workload.key, _pinned(self, "package_version", "package_version_var"),
                         self.custom_var.get().strip(),
                         getattr(workload, "catalog_revision", 1),
                         getattr(workload, "catalog_sha256", "builtin"),
                         plan_identity, contextual_roots)
        return (
            self.distro_var.get(), self.release_var.get().strip(), self.arch_var.get(),
            self._active_source_method(), _pinned(self, "dependency_mode", "mode_var"),
            self.inventory_var.get(),
            _pinned(self, "selection_mode", "selection_mode_var"), selection,
            tuple(sorted(getattr(self, "mirror_repos", set()))),
            # Derived from the same source-of-truth as the metadata cache, so
            # an edit that changes what loads also invalidates the analysis.
            self._signature(),
        )

    def _invalidate_analysis_if_changed(self) -> None:
        """Discard a result that no longer matches the current parameters.

        Leaving a stale analysis on the Review page let the operator change the
        target and then build from a closure computed for something else.
        """
        if self.last_result is None or self.worker is not None:
            return
        if self._parameter_signature() == getattr(self, "analysis_signature", None):
            return
        self.last_result = None
        self.analysis_signature = None
        self.last_warnings = []
        self._refresh_trust_review_bar()
        self.result_rows = {}
        self._result_item_states = {}
        self.result_page = 0
        if getattr(self, "result_page_bar", None):
            self.result_page_bar.grid_remove()
        if getattr(self, "result_tree", None):
            self.result_tree.delete(*self.result_tree.get_children())
        if getattr(self, "summary_var", None):
            self.summary_var.set("Parameters changed since the last analysis. "
                                 "Analyze again before building.")
        if getattr(self, "build_btn", None):
            self.build_btn.configure(style="TButton")
        # when an analysis becomes stale,
        # immediately fall back to the explicit requested-package contract
        # instead of leaving Review empty.
        self._refresh_review_contract()
        self._sync_review_action_states()
        self._log("Discarded the previous analysis: parameters changed.")

    def _refresh_review_summary(self):
        self._invalidate_analysis_if_changed()
        """Restate every decision so the last stage is a real confirmation."""
        if not getattr(self, "review_labels", None):
            return
        state = self._ui_acquisition_state()
        package_only = state.capability is AcquisitionCapability.PACKAGE_ONLY
        enabled = self._build_repository_scope(package_only=package_only)
        base = [r for r in enabled if r.url.strip() and self._repo_tier(r) == "base"]
        signed = sum(1 for r in enabled if r.keyring)
        if state.intent is AcquisitionIntent.REPOSITORY_MIRROR:
            chosen = [r for r in enabled if self._mirror_repo_selected(r)]
            selection = f"Mirror {len(chosen)} repository/repositories"
        elif state.intent is AcquisitionIntent.PACKAGES:
            selection = (f"{len(self.selected_packages)} exact package(s)"
                         if self.selected_packages else "no packages chosen")
        else:
            selection = f"{self.workload_var.get()} · {self.package_version_var.get()}"
        verification = f"{signed}/{len(enabled)} sources with archive keys"
        strategies = {repository_verification_strategy(r) for r in enabled}
        if len(strategies) == 1:
            verification += f" | {self._strategy_policy_to_ui(next(iter(strategies)))}"
        else:
            verification += " | mixed verification strategies"
        bonds = sum(1 for r in enabled
                    if self._strategy_uses_evidence(repository_verification_strategy(r)) and r.evidence_urls)
        if bonds:
            verification += f" | {bonds} evidence source(s) configured"
        vendor_ids = {getattr(r, "vendor_id", "") or infer_vendor_id(r.name, r.url)
                      for r in enabled if r.repo_format == "rpm"}
        configured_vendor_keys = [v for v in vendor_ids
                                  if str(self.vendor_signature_profiles.get(v, {}).get("keyring", "")).strip()]
        required_vendor_keys = [v for v in vendor_ids
                                if self.vendor_signature_profiles.get(v, {}).get("policy") == "require"]
        if configured_vendor_keys:
            verification += f" | {len(configured_vendor_keys)} vendor keyring profile(s)"
        if required_vendor_keys:
            verification += f" | signatures required for {len(required_vendor_keys)} vendor(s)"
        if self.signing_key_var.get().strip():
            verification += " · bundle signed"
        if state.capability is AcquisitionCapability.PACKAGE_ONLY:
            transfer = "Package-only artifacts; dependency completeness not derived"
            sources_text = (f"{len(enabled)} root source(s) participating · "
                            + (state.reason or "dependency closure not requested"))
            selection_text = f"{selection} · package-only acquisition"
        elif state.capability is AcquisitionCapability.REPOSITORY_MIRROR:
            transfer = "Repository mirror; package-root dependency closure does not apply"
            sources_text = f"{len(enabled)} repository/repositories selected for mirroring"
            selection_text = selection
        elif state.capability is AcquisitionCapability.BLOCKED:
            transfer = "Blocked until the acquisition/source requirements are satisfied"
            sources_text = state.reason or "Source requirements incomplete"
            selection_text = selection
        else:
            transfer = ("Differential against a baseline" if self.baseline_var.get().strip()
                        else "Full transaction bundle")
            sources_text = (f"{len(enabled)} enabled, {len(base)} distribution/base source(s)"
                            + ("  |  add a base source" if not base and self._workload_uses_distribution_sources() else ""))
            selection_text = f"{selection} · {self.mode_var.get()}"
        if state.capability is AcquisitionCapability.REPOSITORY_MIRROR:
            mirror_folders = list(getattr(self, "_mirror_output_folder_names", lambda: [])())
            bundle_path_text = ("\n".join(str(self._resolved_output_path(name))
                                           for _repo, name in mirror_folders)
                                if mirror_folders else "-")
        else:
            bundle_path_text = str(self._resolved_output_path()) if self._folder_name() else "-"
        values = {
            "Linux Distribution": f"{self.distro_var.get()} {self.release_var.get()} ({self.arch_var.get()})",
            "Sources": sources_text,
            "Selection": selection_text,
            "Verification": verification,
            "Bundle path": bundle_path_text,
            "Output": transfer,
        }
        note = BuildRequestMixin._selected_workload_context(self).platform_note
        if note:
            values['Linux Distribution'] += '\nPlatform note: ' + note
        self._render_kubernetes_advice()
        for key, text in values.items():
            self.review_labels[key].configure(text=text or "-")
        # Colour the two fields that can silently invalidate a build.
        self.review_labels["Sources"].configure(
            foreground=(WARN_FG if package_only else
                        (FG_TEXT if base or not self._workload_uses_distribution_sources() else ERR_FG)))
        self.review_labels["Output"].configure(
            foreground=WARN_FG if package_only or self.baseline_var.get().strip() else FG_TEXT)

    def _show_review_source_urls(self):
        """Show the exact network/local endpoints analysis is configured to use.

        Review previously summarized only
        source counts/names.  This read-only view makes the actual acquisition
        and evidence endpoints inspectable before any metadata or payload
        request is started.  URLs are shown exactly as configured and are not
        copied into the activity log.
        """
        package_only = bool(getattr(self, "_package_only_acquisition_mode", lambda: False)())
        enabled = self._build_repository_scope(package_only=package_only)
        win = tk.Toplevel(self)
        win.title("Source URLs for this build")
        win.geometry("900x620")
        win.minsize(680, 420)
        win.transient(self)
        win.configure(background=BG_APP)
        frame = ttk.Frame(win, padding=16)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Configured source endpoints", style="PaneTitle.TLabel").pack(anchor="w")
        ttk.Label(
            frame, style="Hint.TLabel", wraplength=840,
            text=("These are the exact source URLs Feathered is configured to contact during analysis. "
                  "Independent evidence endpoints are used only for verification; exact evidence artifacts may be fetched transiently for checksum comparison and are never added to the bundle. "
                  "This local view may contain credentials embedded in a URL, so it is intentionally not written to the log."),
        ).pack(anchor="w", pady=(4, 12))
        holder = ttk.Frame(frame)
        holder.pack(fill="both", expand=True)
        text = tk.Text(
            holder, background=BG_INPUT, foreground=FG_TEXT, insertbackground=FG_TEXT,
            selectbackground=ACCENT_DIM, selectforeground=FG_TEXT, relief="flat",
            wrap="word", font=("Cascadia Mono", 9), padx=10, pady=10)
        bar = ttk.Scrollbar(holder, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=bar.set)
        text.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        if not enabled:
            text.insert("end", "No enabled repository URLs are configured.\n")
        else:
            for index, repo in enumerate(enabled, 1):
                text.insert("end", f"{index}. {repo.name}\n")
                text.insert("end", f"   Role: {repo.role}\n")
                text.insert("end", f"   Package / metadata source: {repo.url}\n")
                strategy = repository_verification_strategy(repo)
                evidence = list(getattr(repo, "evidence_urls", []) or [])
                if self._strategy_uses_evidence(strategy):
                    if evidence:
                        for eidx, url in enumerate(evidence, 1):
                            text.insert("end", f"   Evidence source {eidx}: {url}\n")
                    else:
                        text.insert("end", "   Evidence source: none configured\n")
                text.insert("end", "\n")
        text.configure(state="disabled")
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="Close", command=win.destroy).pack(side="right")

    def _start_review_work_glow(self):
        """Pulse Review's result border during Build analysis/preflight."""
        frame = getattr(self, "result_glow_frame", None)
        if frame is None or not frame.winfo_exists():
            return
        self._stop_review_work_glow(reset=False)
        self._review_glow_phase = 0
        palette = (ACCENT_DIM, "#3A8065", ACCENT, "#3A8065")

        def pulse():
            try:
                if not frame.winfo_exists():
                    return
                colour = palette[self._review_glow_phase % len(palette)]
                frame.configure(highlightbackground=colour, highlightcolor=colour)
                self._review_glow_phase += 1
                self._review_glow_job = self.after(180, pulse)
            except tk.TclError:
                self._review_glow_job = None

        pulse()

    def _stop_review_work_glow(self, reset=True):
        job = getattr(self, "_review_glow_job", None)
        if job is not None:
            try:
                self.after_cancel(job)
            except tk.TclError:
                pass
            self._review_glow_job = None
        if reset:
            frame = getattr(self, "result_glow_frame", None)
            if frame is not None:
                try:
                    frame.configure(highlightbackground=LINE, highlightcolor=LINE)
                except tk.TclError:
                    pass

    def _review_contract_rows(self):
        """Return the operator's requested build roots before analysis.

        The rows are deliberately independent of repository loading. Analysis
        enriches this contract with dependencies; it does not create the
        contract itself. Mirror mode uses the selected repositories as its
        equivalent build roots.
        """
        state = self._ui_acquisition_state()
        if state.intent is AcquisitionIntent.REPOSITORY_MIRROR:
            rows = []
            for repo in self.repo_rows:
                if repo.url.strip() and self._mirror_repo_selected(repo):
                    rows.append((repo.name, "selected", redact_url(repo.url) if repo.url else "location not configured",
                                 "repository selected for mirroring"))
            return rows
        if state.intent is AcquisitionIntent.PACKAGES:
            return [(pkg.nevra, "requested", pkg.repo.name, "explicit package selection")
                    for pkg in self.selected_packages]
        try:
            requests = self._package_requests()
        except Exception:
            return []
        workload = self._workload()
        rows = []
        for request in requests:
            name = str(request[0])
            version = request[1] if len(request) > 1 else None
            package = f"{name} {version}" if version else name
            reason = (
                "VKS node OS package addition"
                if getattr(workload, "contextual_packages", False) else
                "custom package request" if workload.custom else
                f"requested by {workload.label}")
            rows.append((package, "requested", "enabled repositories", reason))
        return rows

    def _has_review_contract(self) -> bool:
        """True when Review contains at least one explicit build root."""
        return bool(self._review_contract_rows())

    def _refresh_review_contract(self):
        """Render requested roots while there is no dependency-analysis result."""
        if self.last_result is not None or not getattr(self, "result_tree", None):
            return
        self.result_tree.delete(*self.result_tree.get_children())
        self.result_rows = {}
        self.unresolved_rows = {}
        self._result_item_states = {}
        self.result_page = 0
        if getattr(self, "result_page_bar", None):
            self.result_page_bar.grid_remove()
        self.result_tree.column("#0", width=0, minwidth=0, stretch=False)
        if getattr(self, "pick_bar", None):
            self.pick_bar.pack_forget()
        if getattr(self, "unresolved_bar", None):
            self.unresolved_bar.pack_forget()
        rows = self._review_contract_rows()
        for package, status, source, reason in rows:
            self.result_tree.insert("", "end", tags=("pending",),
                                    values=(package, status, source, reason))
        count = len(rows)
        if not count:
            self.summary_var.set(
                "Nothing is selected for this build. Return to Content/Repositories and complete the acquisition request before analyzing or building.")
        elif self._ui_acquisition_state().capability is AcquisitionCapability.REPOSITORY_MIRROR:
            self.summary_var.set(
                f"{count} repository source(s) selected. Inventory them first to see each "
                "repository's package-record count and size, or build now to inventory and "
                "publish every repository as its own mirror folder.")
        elif self._ui_acquisition_state().capability is AcquisitionCapability.PACKAGE_ONLY:
            noun = "package" if count == 1 else "packages"
            reason = self._ui_acquisition_state().reason or "Dependency analysis is disabled for this request."
            self.summary_var.set(
                f"{count} requested {noun} are ready for package-only acquisition. {reason} "
                "Downloading will collect only the requested root artifacts; this is not a complete "
                "offline installation bundle.")
        else:
            noun = "package" if count == 1 else "packages"
            self.summary_var.set(
                f"{count} requested {noun} ready. Analyze to preview the dependency addendum, "
                "or build now to analyze and collect in one run.")
        self._refresh_download_size_preview(None)

    def _sync_review_action_states(self):
        """Make Analyze/Build reflect the actual Review build contract.

        Pre-analysis, a non-empty contract may be analyzed or built directly.
        Post-analysis, unresolved blockers or an empty package pick disable
        Build until the operator fixes/waives them.
        """
        if not getattr(self, "analyze_btn", None) or not getattr(self, "build_btn", None):
            return
        if getattr(self, "worker", None) is not None or getattr(self, "active_operation", None) is not None:
            self.analyze_btn.configure(state="disabled")
            self.build_btn.configure(state="disabled")
            return
        has_contract = self._has_review_contract()
        state = self._ui_acquisition_state()
        package_only = state.capability is AcquisitionCapability.PACKAGE_ONLY
        if state.capability is AcquisitionCapability.REPOSITORY_MIRROR:
            repo_count = len(getattr(self, "_selected_mirror_repositories", lambda: [])())
            noun = "repository" if repo_count == 1 else "repositories"
            self.analyze_btn.configure(text=f"Inventory {repo_count} {noun}")
            self.build_btn.configure(text=f"Mirror {repo_count} {noun}")
        elif package_only:
            self.analyze_btn.configure(text="Dependency analysis unavailable")
            self.build_btn.configure(text="Download requested packages")
        elif state.capability is AcquisitionCapability.BLOCKED:
            self.analyze_btn.configure(text="Analysis unavailable")
            self.build_btn.configure(text="Build unavailable")
        else:
            self.analyze_btn.configure(text="Analyze dependency closure")
            self.build_btn.configure(text="Build offline bundle")
        analyze_ok = has_contract and state.analysis in {AnalysisType.DEPENDENCY_CLOSURE, AnalysisType.MIRROR_INVENTORY}
        self.analyze_btn.configure(state="normal" if analyze_ok else "disabled")
        build_ok = has_contract and not state.blocked
        if self.last_result is not None and state.capability is AcquisitionCapability.FULL_TRANSACTION:
            build_ok = build_ok and not self._blocking_unresolved(self.last_result)
            if self._pick_mode():
                build_ok = build_ok and bool(self.picked)
        if "k8s_review_var" in self.__dict__:
            build_ok = build_ok and self._kubernetes_build_allowed()
        self.build_btn.configure(state="normal" if build_ok else "disabled")
        self.build_btn.configure(
            style="Primary.TButton" if build_ok and (package_only or self.last_result is not None) else "TButton")
