"""Pane construction and view composition.

"""

from feathered_app.context import (
    ACCENT,
    APP_TITLE,
    MERGE_POLICY_LABELS,
    MIRROR_LAYOUT_LABELS,
    AcquisitionCapability,
    MergePolicy,
    MirrorLayout,
    AcquisitionIntent,
    BG_APP,
    BG_INPUT,
    BG_PANEL,
    Cancelled,
    ERR_FG,
    FG_MUTED,
    FG_TEXT,
    FOLDER_SCHEMES,
    LINE,
    MODES,
    OK_FG,
    PROFILES,
    Path,
    Reporter,
    WARN_FG,
    arch_core,
    mirror_catalog,
    redact_text,
    threading,
    tk,
    traceback,
    ttk,
    workload_resolution,
)
from feathered_app.ui.theme import human_size, messagebox


def _widget_is_live(widget) -> bool:
    """True when a widget still exists in the Tk interpreter.

    ``winfo_exists`` itself raises once the interpreter is gone (teardown, a
    closed window), so the check has to tolerate that rather than assume a
    widget object implies a usable widget.
    """
    try:
        return bool(widget.winfo_exists())
    except Exception:
        return False


from feathered_app.ui.kubernetes import KubernetesWorkloadMixin


class PaneMixin(KubernetesWorkloadMixin):
    """Pane construction and view composition."""

    def _build_target_pane(self, pane):
        # this first stage is the Linux
        # identity itself; repository and package choices now live on separate
        # subsequent stages.
        self._pane_heading(pane, "Linux Distribution",
                           "Choose the exact Linux release and architecture of the disconnected "
                           "system. Feathered uses this identity to populate compatible repositories "
                           "and resolve package metadata for the correct target.")
        card = self._card(pane, "Distribution")
        row = ttk.Frame(card, style="Panel.TFrame"); row.pack(fill="x")
        self.distro_var = tk.StringVar(value=PROFILES["rhel"].label)
        self.release_var = tk.StringVar(value="")
        self.arch_var = tk.StringVar(value="x86_64")
        self._combo_field(row, "Distribution", self.distro_var,
                          [p.label for p in PROFILES.values()], 0, self._profile_changed, 32)
        self.release_combo = self._combo_field(row, "Release", self.release_var, [], 1,
                                               self._release_changed, 14, editable=True)
        self.arch_combo = self._combo_field(row, "Architecture", self.arch_var, ["x86_64"], 2,
                                            self._release_changed, 14)
        self.init_system_var = tk.StringVar(value="")
        self.init_system_combo = self._combo_field(row, "Init system", self.init_system_var,
                                                   [""], 3, self._release_changed, 12)
        self.release_refresh_btn = ttk.Button(row, text="Refresh releases", command=self.detect_versions)
        self.release_refresh_btn.grid(row=1, column=4, padx=(12, 0), sticky="ew")
        self._register_operation_control(self.release_refresh_btn)
        self.target_note = ttk.Label(card, style="PanelHint.TLabel", wraplength=700)
        self.target_note.pack(fill="x", pady=(12, 0))
        self.release_hint = ttk.Label(card, style="PanelHint.TLabel", wraplength=700, text="")
        self.release_hint.pack(fill="x", pady=(6, 0))

        self.platform_note_var = tk.StringVar(value='')
        note = self._card(pane, 'Platform note (optional)', pady=(12, 0))
        ttk.Entry(note, textvariable=self.platform_note_var).pack(fill='x')
        self._panel_hint(note, 'Describe the target environment if helpful. This note is included with the bundle.')
        inv = self._card(pane, "Installed inventory (optional)", pady=(18, 0))
        self._panel_hint(inv, "Run target_inventory.sh on the disconnected system and load the file "
                              "it writes. Feathered then skips dependencies the target already "
                              "satisfies. Only packages that are genuinely installed and configured "
                              "count, so the bundle never assumes something is present when it is not.",
                         pady=(0, 10))
        invrow = ttk.Frame(inv, style="Panel.TFrame"); invrow.pack(fill="x")
        self.inventory_var = tk.StringVar(value="")
        self.inventory_entry = tk.Entry(invrow, textvariable=self.inventory_var,
            state="readonly", readonlybackground=BG_INPUT, foreground=FG_TEXT,
            relief="flat", borderwidth=0, highlightthickness=1,
            highlightbackground=LINE, highlightcolor=ACCENT)
        self.inventory_entry.pack(side="left", fill="x", expand=True, ipady=5)
        self.inventory_btn = ttk.Button(invrow, text="Load…", command=self.choose_inventory)
        self.inventory_btn.pack(side="left", padx=(8, 0))
        ttk.Button(invrow, text="Clear", command=lambda: self.inventory_var.set("")).pack(
            side="left", padx=(8, 0))

    def _build_sources_pane(self, pane, heading=True, include_status=True, include_workload=True):
        if heading:
            self._pane_heading(
                pane, "Package sources",
                "Choose the distribution sources that provide the operating-system base, then layer any additional repositories on top.")

        # Workload-specific source requirements are populated before this page opens.
        if include_workload:
            # Distribution/base sources render first; the workload-derived
            # side-channel card is built after them (see below). Same visual
            # order as exact-package mode: universe first, selection-specific
            # cards after.
            pass
        else:
            # Exact-package acquisition has no workload-derived source role.
            # Do not render a dormant workload card that suggests another place
            # to define repositories.
            self.workload_repositories_card = None
            self.package_workload_repositories_card = None
            self.package_workload_repo_tree = None
            self.workload_repo_status_var = None

        # Keep workload-specific requirements visually separate from the base source plan.
        card = self._card(pane, "Base distribution sources", pady=(18, 0))
        self.base_sources_card = card
        sr = ttk.Frame(card, style="Panel.TFrame"); sr.pack(fill="x")
        ttk.Label(sr, text="Source plan", style="Panel.TLabel").pack(side="left")
        if getattr(self, "source_method_var", None) is None:
            # Source-plan defaults are a property of the selected target, not a
            # global GUI default.  Starting every target on "local media" left
            # the derived Base distribution sources empty until the operator
            # supplied media, even when the distribution profile already knows
            # its normal repositories.
            self.source_method_var = tk.StringVar(
                value=self._default_transaction_source_method())
        self.source_method_combo = ttk.Combobox(
            sr, textvariable=self.source_method_var, values=self._source_choices(),
            state="readonly", width=44)
        self.source_method_combo.pack(side="left", padx=(10, 8), fill="x", expand=True)
        self.source_method_combo.bind("<<ComboboxSelected>>", lambda _e: (
            self._clear_validation_attention(), self._source_method_changed()))
        self.source_config_btn = ttk.Button(sr, text="Choose folder…", command=lambda: (
            self._clear_validation_attention(), self.configure_source()))
        self.source_config_btn.pack(side="left")
        self.source_note = ttk.Label(card, text="", style="PanelHint.TLabel", wraplength=700)
        self.source_note.pack(fill="x", pady=(12, 0))
        # Dynamic repository workflows recreate these widgets after the target
        # profile callbacks may already have run.  Synchronize the freshly
        # created controls from domain state immediately instead of depending
        # on callback ordering.
        self._sync_transaction_source_controls()

        # The source plan seeds the base repository list but does not lock it.
        self._panel_hint(
            card,
            "The source plan populates this base list. Tailor the repositories below as needed; "
            "choosing another plan or restoring defaults repopulates only this list and leaves "
            "Additional repositories alone.\n"
            "Priority breaks ties when more than one enabled repository offers the same package: "
            "the lowest number wins. Architecture match is considered first, then priority, then "
            "the newest version within that repository.",
            pady=(10, 7))
        base_tree_frame = ttk.Frame(card, style="Panel.TFrame")
        base_tree_frame.pack(fill="x")
        base_cols = ("enabled", "name", "priority", "url")
        self.base_repo_tree = ttk.Treeview(
            base_tree_frame, columns=base_cols, show="headings", height=5, selectmode="browse")
        for col, text_, width, stretch in (
                ("enabled", "Use", 58, False),
                ("name", "Repository", 250, True),
                ("priority", "Priority \u2193 wins", 92, False),
                ("url", "Location", 430, True)):
            self.base_repo_tree.heading(col, text=text_)
            self.base_repo_tree.column(col, width=width, minwidth=50, stretch=stretch)
        self.base_repo_tree.tag_configure("disabled", foreground=FG_MUTED)
        base_scroll = ttk.Scrollbar(
            base_tree_frame, orient="vertical", command=self.base_repo_tree.yview)
        self.base_repo_tree.configure(yscrollcommand=base_scroll.set)
        self.base_repo_tree.pack(side="left", fill="x", expand=True)
        base_scroll.pack(side="right", fill="y")
        self.base_repo_tree.bind("<Double-1>", self._toggle_base_repo)
        base_buttons = ttk.Frame(card, style="Panel.TFrame")
        base_buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(base_buttons, text="Enable / disable", command=self._toggle_base_repo).pack(side="left")
        ttk.Button(base_buttons, text="Edit…", command=self._edit_base_repo).pack(side="left", padx=(6, 0))
        ttk.Button(base_buttons, text="Add URL…", command=lambda: self.add_url_repo("base")).pack(side="left", padx=(6, 0))
        ttk.Button(base_buttons, text="Add local…", command=lambda: self.add_local_repo("base")).pack(side="left", padx=(6, 0))
        ttk.Button(base_buttons, text="Remove", command=self._remove_base_repo).pack(side="left", padx=(6, 0))
        ttk.Button(base_buttons, text="Restore plan defaults", command=self._restore_base_source_defaults).pack(side="right")

        extra = self._card(pane, "Additional repositories", pady=(18, 0))
        self.additional_repositories_card = extra
        self._panel_hint(extra, "Internal mirrors, Satellite/Pulp roots and vendor repositories supplement the distribution base. They are kept separate here so it is clear which sources are foundational and which are add-ons.",
                         pady=(0, 10))
        erow = ttk.Frame(extra, style="Panel.TFrame"); erow.pack(fill="x")
        self.manage_repositories_btn = ttk.Button(
            erow, text="Manage additional repositories…", command=lambda: (
                self._clear_validation_attention(), self.open_repositories("additional")))
        self.manage_repositories_btn.pack(side="left")

        if include_workload:
            self._build_workload_repositories_card(pane)
        if include_status:
            self._build_source_status_card(pane)

    def _build_workload_repositories_card(self, pane):
        """Render repository requirements derived from the Content stage.

        Packages has already chosen the workload and pre-populated every
        profile-known side-channel repository required by explicit root roles.
        This card therefore starts with the workload-specific sources instead
        of presenting an error that the application already knows how to fix.
        Distribution-native roots still use the entire base repository set.
        """
        card = self._card(pane, "Required by selected packages", pady=(18, 0))
        self.workload_repositories_card = card
        self.package_workload_repositories_card = card
        self._panel_hint(
            card,
            "These requirements come from the acquisition intent on the previous step. "
            "Workload/vendor side-channel sources are pre-populated when the workload is selected. "
            "Distribution-native roots are searched across the enabled distribution repository "
            "set; use this page to review or override either source class before coverage analysis.",
            pady=(0, 8))
        self.workload_repo_status_var = tk.StringVar(value="")
        self.package_workload_repo_status_var = self.workload_repo_status_var
        ttk.Label(card, textvariable=self.workload_repo_status_var, style="PanelHint.TLabel",
                  wraplength=700).pack(anchor="w", pady=(0, 8))
        frame = ttk.Frame(card, style="Panel.TFrame"); frame.pack(fill="x")
        cols = ("role", "status", "repo", "url")
        self.package_workload_repo_tree = ttk.Treeview(
            frame, columns=cols, show="headings", height=5, selectmode="browse")
        for col, label, width, stretch in (
                ("role", "Source requirement", 170, False), ("status", "Status", 120, False),
                ("repo", "Repository / set", 250, True), ("url", "Location / policy", 390, True)):
            self.package_workload_repo_tree.heading(col, text=label)
            self.package_workload_repo_tree.column(col, width=width, minwidth=60, stretch=stretch)
        self.package_workload_repo_tree.tag_configure("workload-ready", foreground=OK_FG)
        self.package_workload_repo_tree.tag_configure("workload-disabled", foreground=WARN_FG)
        self.package_workload_repo_tree.tag_configure("workload-available", foreground=ACCENT)
        self.package_workload_repo_tree.tag_configure("workload-missing", foreground=ERR_FG)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.package_workload_repo_tree.yview)
        self.package_workload_repo_tree.configure(yscrollcommand=scroll.set)
        self.package_workload_repo_tree.pack(side="left", fill="x", expand=True)
        scroll.pack(side="right", fill="y")
        row = ttk.Frame(card, style="Panel.TFrame"); row.pack(fill="x", pady=(8, 0))
        self.add_workload_repos_btn = ttk.Button(
            row, text="Use recommended source",
            command=self._add_or_enable_recommended_workload_repositories)
        self.add_workload_repos_btn.pack(side="left")
        self.edit_workload_repo_btn = ttk.Button(
            row, text="Edit selected source…",
            command=self._edit_selected_workload_requirement_repository)
        self.edit_workload_repo_btn.pack(side="left", padx=(6, 0))
        self.manual_workload_repo_btn = ttk.Button(
            row, text="Use manual source…", command=self._add_manual_workload_repository)
        self.manual_workload_repo_btn.pack(side="left", padx=(6, 0))

    def _select_workload_from_repositories(self):
        """Compatibility helper: return to the package/workload decision."""
        self.selection_mode_var.set("Workload preset")
        self._selection_mode_changed()
        self.show_pane("packages")
        combo = getattr(self, "workload_combo", None)
        if combo is not None:
            self.after(30, combo.focus_set)

    def _selected_workload_repo_index(self):
        # Compatibility with older repository-editor callers.
        return None

    def _toggle_workload_repo(self, _event=None):
        return

    def _edit_workload_repo(self):
        return

    def _build_package_workload_repository_card(self, pane):
        """Compatibility wrapper retained for external callers."""
        self._build_workload_repositories_card(pane)

    def _build_source_status_card(self, pane):
        # broad repository health belongs
        # to the Repositories stage, including the action that actually probes
        # every enabled source. Package-specific availability is checked on the
        # repository requirement/coverage section below instead.
        status = self._card(pane, "Source status", pady=(18, 0))
        self.source_status = tk.Label(status, text="", anchor="w", font=("Segoe UI", 10),
                                      background=BG_PANEL, foreground=FG_MUTED)
        self.source_status.pack(fill="x")
        self._panel_hint(status, "Test all sources checks every enabled repository URL for broad health. It does not decide package availability or dependency completeness; Selection source coverage below checks only the source scopes required by the selected roots.", pady=(8, 10))
        srow = ttk.Frame(status, style="Panel.TFrame"); srow.pack(fill="x")
        self.test_sources_btn = ttk.Button(srow, text="Test all sources", command=self.probe_all)
        self.test_sources_btn.pack(side="left")
        self._register_operation_control(self.test_sources_btn)

    def _build_repositories_pane(self, pane):
        # Step 3 is content-driven; every repository workflow is derived from Content.
        # Do not build one giant repository editor
        # and hide arbitrary pieces of it: each acquisition intent gets its own
        # complete repository workflow.  The shared domain state survives view
        # changes, but the visible controls are rebuilt from that state.
        self.repositories_title_var = tk.StringVar(value="Repositories")
        self.repositories_hint_var = tk.StringVar(value="")
        ttk.Label(pane, textvariable=self.repositories_title_var,
                  style="PaneTitle.TLabel").pack(anchor="w")
        ttk.Label(pane, textvariable=self.repositories_hint_var, style="Hint.TLabel",
                  wraplength=740).pack(anchor="w", pady=(4, 16))
        self.repository_workflow_host = ttk.Frame(pane)
        self.repository_workflow_host.pack(fill="x")
        self._render_repository_workflow(force=True)

    def _repository_workflow_key_for_target(self) -> str:
        """Cache key for the rendered Repositories view.

        Keying on acquisition intent alone meant that changing distribution,
        release or architecture on step 1 left the previously rendered
        distribution's repository rows on screen: same intent, so the view was
        considered current and never rebuilt. The target tuple is part of what
        the view displays, so it belongs in the key."""
        mode = self._repository_workflow_mode()
        try:
            profile = self._profile().key
        except Exception:
            profile = ""
        release = self.__dict__.get("release_var")
        arch = self.__dict__.get("arch_var")
        init = ""
        try:
            init = self._selected_init_system()
        except Exception:
            init = ""
        return "|".join((
            mode, profile,
            release.get().strip() if release is not None else "",
            arch.get().strip() if arch is not None else "",
            init))

    def _repository_workflow_mode(self) -> str:
        intent = self._acquisition_intent()
        if intent is AcquisitionIntent.REPOSITORY_MIRROR:
            return "mirror"
        if intent is AcquisitionIntent.PACKAGES:
            return "packages"
        return "workload"

    def _clear_repository_workflow_widgets(self):
        host = getattr(self, "repository_workflow_host", None)
        if host is None:
            return
        # Operation-control references to destroyed widgets are pruned by the
        # global lock controller, but remove them eagerly here so rebuilding the
        # page never accumulates dead controls during a long session.
        doomed = set()
        def collect(widget):
            doomed.add(widget)
            for child in widget.winfo_children():
                collect(child)
        for child in host.winfo_children():
            collect(child)
        for widget in doomed:
            self._unregister_operation_control(widget)
        for child in host.winfo_children():
            child.destroy()
        # Drop every stored reference to a widget that was just destroyed.
        #
        # This used to be a hand-maintained list of attribute names, and it had
        # the failure mode every hand-maintained list has: mirror_source_method_combo
        # was added to the pane and never added to the list, so switching source
        # method after the pane rebuilt reached a dead widget and raised
        # "TclError: invalid command name .!frame3...!combobox" out of a Tk
        # callback. Nothing warned, because a stale reference is a perfectly
        # ordinary attribute right up until something configures it.
        #
        # Sweeping by liveness removes the invariant instead of adding one more
        # name to it. A widget the operator can no longer see is not one this
        # object should still be holding.
        for name, value in list(self.__dict__.items()):
            if isinstance(value, tk.Misc) and not _widget_is_live(value):
                setattr(self, name, None)

    def _render_repository_workflow(self, force=False):
        host = getattr(self, "repository_workflow_host", None)
        if host is None:
            return
        mode = self._repository_workflow_mode()
        key = self._repository_workflow_key_for_target()
        if not force and self._repository_workflow_key == key and host.winfo_children():
            return
        self._clear_repository_workflow_widgets()
        self._repository_workflow_key = key

        if mode == "mirror":
            self.repositories_title_var.set("Repositories to mirror")
            self.repositories_hint_var.set(
                "Repository mirror is its own workflow. Choose one starting repository set, then "
                "add/edit/remove sources and select exactly what will be copied. Transaction/workload "
                "repositories are not shown or modified here.")
            self._build_mirror_repository_selection_card(host)
            self._sync_mirror_source_controls()
            self._ensure_mirror_repository_seeded()
            self._refresh_mirror_repos()
            return

        if mode == "packages":
            self._ensure_transaction_base_sources()
            self.repositories_title_var.set("Repositories for package selection")
            self.repositories_hint_var.set(
                "Define the package source universe first. Exact package/version roots are chosen below "
                "from those repositories; no workload-specific repository controls apply in this mode.")
            self._build_sources_pane(host, heading=False, include_status=True, include_workload=False)
            self._build_exact_package_selection_card(host)
            self._build_package_source_coverage_card(host)
            self._refresh_base_repo_tree()
            self._refresh_selected_packages()
            self._refresh_package_source_coverage()
            self._update_source_status()
            return

        self._ensure_transaction_base_sources()
        workload = self._workload()
        self.repositories_title_var.set(f"Repositories for {workload.label}")
        self.repositories_hint_var.set(
            "This view is derived from the selected workload. Workload/vendor root sources are shown "
            "first, distribution repositories provide native roots/dependencies, and optional additions "
            "supplement that source universe.")
        self._build_sources_pane(host, heading=False, include_status=True, include_workload=True)
        self._build_package_source_coverage_card(host)
        self._refresh_base_repo_tree()
        self._refresh_workload_repository_views()
        self._refresh_package_source_coverage()
        self._update_source_status()

    def _build_exact_package_selection_card(self, pane):
        """Exact-package roots are chosen only after repositories exist."""
        card = self._card(pane, "Choose exact packages", pady=(18, 0))
        self.single_panel = ttk.Frame(card, style="Panel.TFrame")
        srp = self.single_panel
        srp.columnconfigure(0, weight=3); srp.columnconfigure(1, weight=2)

        left = ttk.Frame(srp, style="Panel.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        qrow = ttk.Frame(left, style="Panel.TFrame"); qrow.pack(fill="x")
        ttk.Label(qrow, text="Search", style="Panel.TLabel").pack(side="left")
        self.single_browser_query_var = tk.StringVar(value="")
        entry = ttk.Entry(qrow, textvariable=self.single_browser_query_var)
        entry.pack(side="left", fill="x", expand=True, padx=(8, 8))
        entry.bind("<Return>", lambda _e: self.search_single_packages())
        self.package_find_btn = ttk.Button(qrow, text="Find", command=self.search_single_packages)
        self.package_find_btn.pack(side="left")
        self._register_operation_control(self.package_find_btn)
        self.single_browser_tree = ttk.Treeview(
            left, columns=("name", "version", "arch", "repo", "size"),
            show="headings", height=9)
        for col, label, width in (("name", "Package", 190), ("version", "Version", 130),
                                  ("arch", "Arch", 70), ("repo", "Repository", 150),
                                  ("size", "Size", 80)):
            self.single_browser_tree.heading(col, text=label)
            self.single_browser_tree.column(col, width=width, minwidth=50)
        self.single_browser_tree.pack(fill="both", expand=True, pady=(8, 0))
        self.single_browser_tree.bind("<Double-1>", lambda _e: self.use_selected_single_package())
        self.single_browser_status_var = tk.StringVar(
            value="Search the configured repositories by package name.")
        ttk.Label(left, textvariable=self.single_browser_status_var,
                  style="PanelHint.TLabel", wraplength=430).pack(anchor="w", pady=(6, 0))
        ttk.Button(left, text="Add selected  →", style="Primary.TButton",
                   command=self.use_selected_single_package).pack(anchor="w", pady=(8, 0))

        right = ttk.Frame(srp, style="Panel.TFrame")
        right.grid(row=0, column=1, sticky="nsew")
        ttk.Label(right, text="Bundle these packages", style="Panel.TLabel").pack(anchor="w")
        self.selected_tree = ttk.Treeview(right, columns=("pkg", "version", "repo"),
                                          show="headings", height=9)
        self.selected_tree.heading("pkg", text="Package")
        self.selected_tree.heading("version", text="Version")
        self.selected_tree.heading("repo", text="Repository")
        self.selected_tree.column("pkg", width=150, minwidth=90)
        self.selected_tree.column("version", width=140, minwidth=90)
        self.selected_tree.column("repo", width=130, minwidth=80)
        self.selected_tree.pack(fill="both", expand=True, pady=(6, 0))
        self.selected_tree.bind("<Double-1>", lambda _e: self.change_selected_version())
        crow = ttk.Frame(right, style="Panel.TFrame"); crow.pack(fill="x", pady=(8, 0))
        ttk.Button(crow, text="Change version…",
                   command=self.change_selected_version).pack(side="left")
        ttk.Button(crow, text="Remove",
                   command=self.remove_selected_package).pack(side="left", padx=(8, 0))
        ttk.Button(crow, text="Clear",
                   command=self.clear_single_selection).pack(side="left", padx=(8, 0))
        self.single_selected_var = tk.StringVar(value="No packages selected")
        ttk.Label(right, textvariable=self.single_selected_var, style="PanelHint.TLabel",
                  wraplength=320).pack(anchor="w", pady=(6, 0))
        self.single_panel.pack(fill="both", expand=True)
        self.exact_package_selection_card = card
        self.exact_package_selection_holder = card.master.master

    def _sync_exact_package_selection_card_visibility(self):
        # Repository workflow views are rebuilt as a unit from Content intent.
        self._render_repository_workflow()

    def _build_mirror_repository_selection_card(self, pane):
        """Single authoritative repository editor for mirror acquisition.

        Mirror mode is different from a package transaction: the repository set
        *is* the requested content.  Presenting Required/Base/Additional plus a
        second mirror selector made the same repository editable in several
        places.  This card therefore owns population, manual additions, editing,
        health testing and mirror inclusion while mirror intent is active.
        """
        card = self._card(pane, "Mirror repositories", pady=(0, 0))
        self.mirror_selection_card = card
        self._panel_hint(
            card,
            "This is the complete repository set for this mirror. Start from a target source plan "
            "or start empty, then add/edit/remove repositories here. A checked row participates in "
            "this mirror run; unchecked rows are ignored regardless of any normal transaction-mode state.",
            pady=(0, 10))

        plan = ttk.Frame(card, style="Panel.TFrame")
        plan.pack(fill="x", pady=(0, 10))
        ttk.Label(plan, text="Start from", style="Panel.TLabel").pack(side="left")
        if self.mirror_source_method_var is None:
            default_method = self._default_mirror_source_method()
            self.mirror_source_method_var = tk.StringVar(value=default_method)
        self.mirror_source_method_combo = ttk.Combobox(
            plan, textvariable=self.mirror_source_method_var, state="readonly", width=44)
        self.mirror_source_method_combo.pack(side="left", padx=(10, 8), fill="x", expand=True)
        self.mirror_source_method_combo.bind(
            "<<ComboboxSelected>>",
            lambda _e: (self._clear_validation_attention(), self._mirror_source_method_changed()))
        self.mirror_source_config_btn = ttk.Button(
            plan, text="Configure…", command=lambda: (
                self._clear_validation_attention(), self._configure_mirror_source()))
        self.mirror_source_config_btn.pack(side="left")
        self.mirror_source_note = ttk.Label(
            card, style="PanelHint.TLabel", wraplength=700,
            text=("The source plan only populates this table; it does not create a second "
                  "repository list.\nPriority decides which repository supplies a package "
                  "published by more than one of them: the lowest number wins."))
        self.mirror_source_note.pack(anchor="w", pady=(0, 10))

        self.mirror_tree = ttk.Treeview(
            card, columns=("repo", "origin", "role", "priority", "url"),
            show="tree headings", height=9, selectmode="browse")
        self.mirror_tree.heading("#0", text="Mirror")
        self.mirror_tree.column("#0", width=64, minwidth=64, stretch=False, anchor="center")
        for col, label, width, stretch in (
                ("repo", "Repository", 235, True),
                ("origin", "Origin", 105, False),
                ("role", "Role", 105, False),
                ("priority", "Priority \u2193 wins", 92, False),
                ("url", "Location", 390, True)):
            self.mirror_tree.heading(col, text=label)
            self.mirror_tree.column(col, width=width, minwidth=55, stretch=stretch)
        self.mirror_tree.pack(fill="x")
        self.mirror_tree.bind("<Button-1>", self._toggle_mirror_repo, add="+")

        mrow = ttk.Frame(card, style="Panel.TFrame")
        mrow.pack(fill="x", pady=(8, 0))
        for label, action in (("All", "all"), ("None", "none"), ("Invert", "invert")):
            ttk.Button(mrow, text=label, width=9,
                       command=lambda a=action: self._bulk_mirror(a)).pack(
                           side="left", padx=(0 if action == "all" else 6, 0))
        ttk.Separator(mrow, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(mrow, text="Add URL…", command=self._mirror_add_url_repo).pack(side="left")
        ttk.Button(mrow, text="Add local…", command=self._mirror_add_local_repo).pack(side="left", padx=(6, 0))
        ttk.Button(mrow, text="Edit…", command=self._edit_mirror_repo).pack(side="left", padx=(6, 0))
        ttk.Button(mrow, text="Remove", command=self._remove_mirror_repo).pack(side="left", padx=(6, 0))
        self.mirror_test_sources_btn = ttk.Button(
            mrow, text="Test selected repositories", command=self.probe_all)
        self.mirror_test_sources_btn.pack(side="right")
        self._register_operation_control(self.mirror_test_sources_btn)

        self.mirror_status = ttk.Label(card, style="PanelHint.TLabel", wraplength=700, text="")
        self.mirror_status.pack(anchor="w", pady=(8, 0))
        ttk.Label(
            card, style="PanelHint.TLabel", wraplength=700,
            text="There is no separate Base/Additional/Custom repository editor in mirror mode. "
                 "Everything this run will read and copy is visible in the table above.").pack(
                     anchor="w", pady=(4, 0))

        holder = card.master.master if getattr(card, "master", None) is not None else None
        self.mirror_selection_holder = holder

    def _sync_repository_mode_layout(self):
        # Compatibility entry point retained for older call sites.
        self._render_repository_workflow()

    def _default_mirror_source_method(self):
        choices = self._source_choices()
        preferred = (
            "Distribution repositories",
            "Distribution APT repositories",
            "Distribution pacman repositories",
            "Red Hat CDN entitlement (official)",
            "Custom repositories",
            "Installation media / local mirror (ISO, DVD, folder, SMB)",
        )
        for method in preferred:
            if method in choices:
                return method
        return choices[0] if choices else "Custom repositories"

    def _mirror_source_rows_for_method(self, method):
        """Build the mirror preset without touching transaction repositories."""
        if not self.release_var.get().strip():
            return []
        p = self._profile()
        rows = []
        if p.key != "rhel":
            if method in {"Distribution repositories", "Distribution APT repositories", "Distribution pacman repositories"}:
                templates = p.repos_factory(self.release_var.get().strip(), self.arch_var.get())
                workload_roles = set(self._known_workload_repository_roles())
                rows = [self._repo_from_template(x, "base") for x in templates
                        if x.role not in workload_roles]
            return rows

        if method == "Red Hat CDN entitlement (official)":
            crb = self._rhel_cdn_repo(
                f"RHEL {self.release_var.get()} CodeReady Builder (CDN)",
                "codeready-builder", 55)
            crb.optional = True
            return [
                self._set_repo_tier(self._rhel_cdn_repo(
                    f"RHEL {self.release_var.get()} BaseOS (CDN)", "baseos", 40), "base"),
                self._set_repo_tier(self._rhel_cdn_repo(
                    f"RHEL {self.release_var.get()} AppStream (CDN)", "appstream", 45), "base"),
                self._set_repo_tier(crb, "base"),
            ]
        if method in {"Public EL-compatible mirrors (recommended fallback)",
                      "Public EL-compatible + EPEL (broad fallback)"}:
            alma = [self._set_repo_tier(r, "base") for r in self._compatible_repos("alma")]
            rocky = [self._set_repo_tier(r, "base") for r in self._compatible_repos("rocky")]
            for r in alma:
                r.optional = True
            for r in rocky:
                r.priority += 30
                r.optional = True
            rows = alma + rocky
            if method == "Public EL-compatible + EPEL (broad fallback)":
                rows.append(self._set_repo_tier(self._epel_repo(), "base"))
        return rows

    def _replace_mirror_repository_set(self, rows):
        # Reached only in mirror mode, so this assignment lands in the mirror
        # universe by construction rather than by a follow-up assignment.
        self.repo_rows = list(rows)
        self.mirror_repos = {r.source_identity for r in self.repo_rows if r.enabled and r.url.strip()}
        self._mirror_seen = set()
        self.loaded_signature = None
        self.loaded_packages = []
        self.last_result = None
        self.package_source_coverage_signature = None
        self._apply_keystore()
        self._refresh_mirror_repos()
        self._sync_keyring_view()

    def _ensure_mirror_repository_seeded(self):
        if self._repository_universe_mode != "mirror":
            return
        if self.repo_rows:
            return
        if self.mirror_source_method_var is None:
            self.mirror_source_method_var = tk.StringVar(value=self._default_mirror_source_method())
        method = self.mirror_source_method_var.get()
        if method in {"Custom repositories",
                      "Installation media / local mirror (ISO, DVD, folder, SMB)"}:
            return
        self._replace_mirror_repository_set(self._mirror_source_rows_for_method(method))

    def _mirror_source_method_changed(self):
        if self._repository_universe_mode != "mirror":
            return
        method = self.mirror_source_method_var.get()
        # A mirror preset is a complete starting set, not another parallel
        # repository manager. Changing it replaces the table deterministically.
        rows = self._mirror_source_rows_for_method(method)
        self._replace_mirror_repository_set(rows)
        self._sync_mirror_source_controls()

    def _live(self, name):
        """A stored widget, or None if it has been destroyed.

        Defence in depth alongside the sweep in _clear_repository_workflow_widgets:
        the sweep runs on rebuild, but a handler can fire from a Tk callback
        queued before it, and configuring a destroyed widget raises TclError out
        of Tkinter's callback rather than anywhere a user can act on.
        """
        widget = self.__dict__.get(name)
        return widget if widget is not None and _widget_is_live(widget) else None

    def _sync_mirror_source_controls(self):
        combo = self._live("mirror_source_method_combo")
        if combo is not None:
            combo["values"] = self._source_choices()
        if self.mirror_source_method_var is None:
            return
        method = self.mirror_source_method_var.get()
        button = self._live("mirror_source_config_btn")
        if button is not None:
            if method == "Installation media / local mirror (ISO, DVD, folder, SMB)":
                button.configure(text="Choose folder…", state="normal")
            elif method == "Red Hat CDN entitlement (official)":
                button.configure(text="Entitlement files…", state="normal")
            elif method == "Custom repositories":
                button.configure(text="Add below", state="disabled")
            else:
                button.configure(text="Loaded", state="disabled")
        note = getattr(self, "mirror_source_note", None)
        if note is not None:
            if method == "Custom repositories":
                text = ("Start empty and add only the repositories you want in this mirror. "
                        "There is no second custom-repository editor.")
            elif method == "Installation media / local mirror (ISO, DVD, folder, SMB)":
                text = "Choose local repository media; discovered repositories replace this mirror table."
            elif method == "Red Hat CDN entitlement (official)":
                text = ("Uses the RHEL CDN repository set for this target. Configure entitlement "
                        "credentials here before testing or mirroring.")
            else:
                text = ("This preset has populated the complete mirror table below. Change the preset "
                        "to replace the table, or add/edit individual repositories directly.")
            try:
                note.configure(text=text)
            except tk.TclError:
                pass

    def _configure_mirror_source(self):
        method = self.mirror_source_method_var.get() if self.mirror_source_method_var else ""
        if method == "Installation media / local mirror (ISO, DVD, folder, SMB)":
            self.select_media()
        elif method == "Red Hat CDN entitlement (official)":
            self.configure_rhsm()
            # Rebuild the rows so newly chosen entitlement paths are attached to
            # the CDN RepoSpec objects used by the mirror universe.
            self._replace_mirror_repository_set(self._mirror_source_rows_for_method(method))
        self._sync_mirror_source_controls()
        self._refresh_mirror_repos()

    def _mirror_add_url_repo(self):
        self.add_url_repo("additional")
        self._refresh_mirror_repos()

    def _mirror_add_local_repo(self):
        self.add_local_repo("additional")
        self._refresh_mirror_repos()

    def _selected_mirror_repo_index(self):
        tree = getattr(self, "mirror_tree", None)
        if tree is None:
            return None
        selection = tree.selection()
        if not selection:
            return None
        iid = selection[0]
        index = self.__dict__.get("_mirror_iid_to_repo_index", {}).get(iid)
        if index is not None:
            return index
        # Compatibility fallback for lightweight tests/older in-memory rows.
        source_id = self.__dict__.get("_mirror_iid_to_source_identity", {}).get(iid, iid)
        return next((i for i, repo in enumerate(self.repo_rows)
                     if getattr(repo, "source_identity", repo.name) == source_id), None)

    def _edit_mirror_repo(self):
        self._edit_repo_at(self._selected_mirror_repo_index(), self)

    def _remove_mirror_repo(self):
        i = self._selected_mirror_repo_index()
        if i is None or not (0 <= i < len(self.repo_rows)):
            return
        source_id = self.repo_rows[i].source_identity
        del self.repo_rows[i]
        # Keep the identity selected if another configured row still represents
        # the same concrete repository slice; otherwise remove it.
        if not any(r.source_identity == source_id for r in self.repo_rows):
            self.mirror_repos.discard(source_id)
            self._mirror_seen.discard(source_id)
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._refresh_repo_tree_if_open(); self._update_source_status()

    def _build_packages_sources_pane(self, pane):
        """Base sources first, add-ons second, requested contents third.

        source selection already defines
        where a build can come from, so the page now reads top-to-bottom as
        foundation -> supplements -> package request.  A workload may still
        attach a repository after selection; that synchronization happens in
        state, not by putting the selection controls ahead of the base source.
        """
        self._pane_heading(
            pane, "Repositories and Packages",
            "Compatibility wrapper for older callers. The live wizard now separates repository configuration from package selection.")
        self._build_sources_pane(pane, heading=False, include_status=True)
        spacer = ttk.Frame(pane); spacer.pack(fill="x", pady=(6, 0))
        self._build_packages_pane(pane, heading=False)
        self._build_package_source_coverage_card(pane)

    def _build_packages_pane(self, pane, heading=True):
        if heading:
            self._pane_heading(pane, "Content",
                               "Choose what Feathered should acquire. Workloads define semantic roots now; "
                               "exact package identities and repository mirrors are chosen only after the "
                               "repository universe exists on the next step.")
        card = self._card(pane, "Selection")
        self.package_selection_card = card
        selection = ttk.Frame(card, style="Panel.TFrame"); selection.pack(fill="x", pady=(0, 12))
        ttk.Label(selection, text="Mode", style="Panel.TLabel").pack(side="left")
        self.selection_mode_var = tk.StringVar(value="Workload preset")
        self.selection_mode_combo = ttk.Combobox(selection, textvariable=self.selection_mode_var,
                                                 values=["Workload preset", "Choose packages", "Entire repository (mirror)"],
                                                 state="readonly", width=24)
        self.selection_mode_combo.pack(side="left", padx=(10, 0))
        self.selection_mode_combo.bind("<<ComboboxSelected>>", lambda _e: (
            self._clear_validation_attention(), self._selection_mode_changed()))

        self.workload_panel = ttk.Frame(card, style="Panel.TFrame"); self.workload_panel.pack(fill="x")
        pr = self.workload_panel
        self.workload_var = tk.StringVar(value="Docker Engine")
        # Workload labels run to ~45 characters; a narrow combo clipped them.
        # This one spans the pane and the dropdown is widened to match.
        ttk.Label(pr, text="Workload", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        self.workload_combo = ttk.Combobox(pr, textvariable=self.workload_var,
                                           values=self._workload_labels_for_profile(),
                                           state="readonly")
        self.workload_combo.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(3, 0))
        self.workload_combo.bind("<<ComboboxSelected>>", lambda _e: self._workload_changed())
        pr.columnconfigure(0, weight=1); pr.columnconfigure(1, weight=1); pr.columnconfigure(2, weight=1)

        self.package_version_var = tk.StringVar(value="Latest")
        self.package_version_label = ttk.Label(pr, text="Version", style="Panel.TLabel")
        self.package_version_label.grid(row=2, column=0, sticky="w", pady=(12, 0))
        self.package_version_combo = ttk.Combobox(pr, textvariable=self.package_version_var,
                                                  values=["Latest"], state="readonly", width=26)
        self.package_version_combo.grid(row=3, column=0, sticky="ew", pady=(3, 0))
        self.version_scan_btn = ttk.Button(pr, text="Refresh versions", command=self.scan_package_versions)
        self.version_scan_btn.grid(row=3, column=1, padx=(10, 0), sticky="w")
        self._register_operation_control(self.version_scan_btn)

        self.mode_var = tk.StringVar(value=MODES[0])
        ttk.Label(pr, text="Dependencies", style="Panel.TLabel").grid(row=4, column=0, sticky="w", pady=(12, 0))
        self.mode_combo = ttk.Combobox(pr, textvariable=self.mode_var, values=MODES, state="readonly")
        self.mode_combo.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(3, 0))
        self.mode_combo.bind("<<ComboboxSelected>>", lambda _e: self._mode_changed())
        # Reviewing the closure before building is always available: it costs
        # nothing when unused, and having it behind a switch meant an analysis
        # produced without it could not be reviewed without re-running.
        self.review_before_build_var = tk.BooleanVar(value=True)

        self.custom_var = tk.StringVar(value="")
        self.custom_var.trace_add("write", lambda *_a: self._refresh_package_source_plan())
        self.custom_label = ttk.Label(pr, text="Packages (space or comma separated)", style="Panel.TLabel")
        self.custom_label.grid(row=7, column=0, sticky="w", pady=(12, 0))
        self.custom_entry = ttk.Entry(pr, textvariable=self.custom_var, state="disabled")
        self.custom_entry.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(3, 0))
        self.custom_tools = ttk.Frame(pr, style="Panel.TFrame")
        self.custom_tools.grid(row=9, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Button(self.custom_tools, text="Search repositories…",
                   command=lambda: self.open_package_search("names")).pack(side="left")
        ttk.Button(self.custom_tools, text="Check names",
                   command=self._validate_custom_names).pack(side="left", padx=(8, 0))
        ttk.Button(self.custom_tools, text="Clear",
                   command=lambda: self.custom_var.set("")).pack(side="left", padx=(8, 0))
        self.custom_status = ttk.Label(pr, style="PanelHint.TLabel", wraplength=660, text="")
        self.custom_status.grid(row=10, column=0, columnspan=3, sticky="w", pady=(8, 0))
        for widget in (self.custom_label, self.custom_entry, self.custom_tools,
                       self.custom_status):
            widget.grid_remove()

        self._build_kubernetes_content_controls(pr)

        # Exact package identities depend on repository metadata, so Step 2 only
        # records the intent. The actual chooser lives on Repositories, after
        # the source universe has been configured.
        self.single_intent_panel = ttk.Frame(card, style="Panel.TFrame")
        ttk.Label(
            self.single_intent_panel, style="PanelHint.TLabel", wraplength=690,
            text="Configure the repositories on the next step first. Feathered will then load those "
                 "indexes and let you choose exact package/version roots from the source universe "
                 "that actually exists."
        ).pack(anchor="w", pady=(0, 10))
        ttk.Label(self.single_intent_panel, style="Panel.TLabel",
                  text="Next: configure repositories, then choose packages →").pack(anchor="w")
        self.single_intent_panel.pack_forget()

        self.mirror_panel = ttk.Frame(card, style="Panel.TFrame")
        ttk.Label(self.mirror_panel, style="PanelHint.TLabel", wraplength=690,
                  text="Mirror mode copies whole repositories rather than resolving a package closure. "
                       "Repository selection belongs on the next Repositories step, where Feathered can "
                       "first populate the target distribution sources and then let you include or exclude "
                       "them without coming back to this page.").pack(anchor="w", pady=(0, 10))
        ttk.Label(self.mirror_panel, style="Panel.TLabel",
                  text="Next: choose the repositories to mirror →").pack(anchor="w")
        ttk.Label(self.mirror_panel, style="PanelHint.TLabel", wraplength=690,
                  text="When a source plan is selected there, newly populated enabled repositories start "
                       "selected for mirroring. You can deselect optional pockets or add internal/vendor "
                       "repositories on the same page before counting packages.").pack(anchor="w", pady=(5, 0))
        self.mirror_panel.pack_forget()

        self.workload_note = ttk.Label(pane, text="", style="Hint.TLabel", wraplength=740)
        self.workload_note.pack(fill="x", pady=(14, 0))

    def _build_package_source_plan_card(self, pane):
        """Preview the repository topology implied by the package selection."""
        card = self._card(pane, "Repository requirements", pady=(18, 0))
        self.package_source_plan_card = card
        self._panel_hint(
            card,
            "Content declares source policy; it does not configure repositories. Distribution "
            "roots will search the distribution repository set. Explicit workload/vendor roots "
            "will request their declared repository role on the next step.",
            pady=(0, 8))
        self.package_source_plan_status_var = tk.StringVar(value="")
        ttk.Label(card, textvariable=self.package_source_plan_status_var, style="PanelHint.TLabel",
                  wraplength=700).pack(anchor="w", pady=(0, 8))
        frame = ttk.Frame(card, style="Panel.TFrame"); frame.pack(fill="x")
        self.package_source_plan_tree = ttk.Treeview(
            frame, columns=("package", "policy"), show="headings", height=6, selectmode="none")
        self.package_source_plan_tree.heading("package", text="Root package / selection")
        self.package_source_plan_tree.heading("policy", text="Required source policy")
        self.package_source_plan_tree.column("package", width=330, minwidth=130, stretch=True)
        self.package_source_plan_tree.column("policy", width=420, minwidth=180, stretch=True)
        self.package_source_plan_tree.pack(fill="x")
        ttk.Label(
            card, text="Next: configure the source universe on Repositories.",
            style="PanelHint.TLabel").pack(anchor="w", pady=(8, 0))
        self._refresh_package_source_plan()

    def _refresh_package_source_plan(self):
        tree = getattr(self, "package_source_plan_tree", None)
        status = getattr(self, "package_source_plan_status_var", None)
        if tree is None or status is None:
            return
        tree.delete(*tree.get_children())
        if self._mirror_mode():
            tree.insert("", "end", values=(
                "Entire repository mirror",
                "Choose repositories on the next Repositories step"))
            status.set(
                "Mirror mode selected. Continue to Repositories: source-plan changes and mirror "
                "include/exclude choices now happen together on that page, so no double-back is required.")
            return
        if self._single_mode():
            tree.insert("", "end", values=(
                "Specific packages",
                "Configure repositories first; choose exact roots on the next step"))
            if self.selected_packages:
                root_bytes = sum(int(getattr(p, "size", 0) or 0) for p in self.selected_packages)
                status.set(
                    f"{len(self.selected_packages)} exact package root(s) are currently selected "
                    f"({human_size(root_bytes)} root payload); edit them on Repositories. Full closure size is calculated during analysis.")
            else:
                status.set("Exact package identities are intentionally deferred until Repositories has defined the searchable package universe.")
            return
        workload = self._workload()
        plan = self._source_plan()
        if not plan.roots:
            status.set("Enter at least one package name to derive repository requirements.")
            return
        kinds = set()
        for root in plan.roots:
            name, kind, role = root.package, root.source_kind, root.role
            kinds.add(kind)
            if kind == "distribution":
                policy = "Distribution repository set"
            elif kind == "workload":
                policy = f"Workload/vendor role: {role}"
            else:
                policy = "Any enabled repository"
            candidates = list(root.candidates or (name,))
            display_name = root.component or name
            if len(candidates) > 1:
                display_name += "  →  " + " / ".join(candidates)
            tree.insert("", "end", values=(display_name, policy))
        if kinds == {"distribution"}:
            model = "distribution-native"
        elif kinds == {"workload"}:
            model = "workload-specific"
        elif "distribution" in kinds and "workload" in kinds:
            model = "mixed distribution + workload-specific"
        else:
            model = "operator-defined"
        status.set(f"{workload.label}: {model} source model.")

    def _build_package_source_coverage_card(self, pane):
        card = self._card(pane, "Selection source coverage", pady=(18, 0))
        self.package_source_coverage_card = card
        self.package_source_coverage_holder = card.master.master
        self._panel_hint(
            card,
            "This check is specific to the current package/workload selection. Feathered reads the "
            "enabled repository indexes and confirms that each requested root is actually offered "
            "at the requested version, role and architecture. It does not resolve dependencies; "
            "Analyze on Review & build still computes the full closure.",
            pady=(0, 10))
        self.package_source_status_var = tk.StringVar(value="Choose packages or a workload to check source coverage.")
        self.package_source_status = tk.Label(
            card, textvariable=self.package_source_status_var, anchor="w", justify="left",
            font=("Segoe UI", 10), background=BG_PANEL, foreground=FG_MUTED, wraplength=700)
        self.package_source_status.pack(fill="x")

        controls = ttk.Frame(card, style="Panel.TFrame")
        controls.pack(fill="x", pady=(10, 8))
        self.package_source_check_btn = ttk.Button(
            controls, text="Check selected packages", command=self.check_package_source_coverage)
        self.package_source_check_btn.pack(side="left")
        self._register_operation_control(self.package_source_check_btn)
        ttk.Label(
            controls, text="Root availability only; dependency analysis happens later.",
            style="PanelHint.TLabel").pack(side="left", padx=(10, 0))

        table = ttk.Frame(card, style="Panel.TFrame")
        table.pack(fill="x")
        columns = ("request", "status", "source", "candidate")
        self.package_source_tree = ttk.Treeview(
            table, columns=columns, show="headings", height=6, selectmode="browse")
        for col, label, width, stretch in (
                ("request", "Requested item", 230, True),
                ("status", "Coverage", 110, False),
                ("source", "Repository", 230, True),
                ("candidate", "Available candidate", 280, True)):
            self.package_source_tree.heading(col, text=label)
            self.package_source_tree.column(col, width=width, minwidth=75, stretch=stretch)
        self.package_source_tree.tag_configure("coverage-ok", foreground=OK_FG)
        self.package_source_tree.tag_configure("coverage-warn", foreground=WARN_FG)
        self.package_source_tree.tag_configure("coverage-error", foreground=ERR_FG)
        self.package_source_tree.tag_configure("coverage-pending", foreground=FG_MUTED)
        cov_scroll = ttk.Scrollbar(table, orient="vertical", command=self.package_source_tree.yview)
        self.package_source_tree.configure(yscrollcommand=cov_scroll.set)
        self.package_source_tree.pack(side="left", fill="x", expand=True)
        cov_scroll.pack(side="right", fill="y")
        self.package_source_coverage_signature = None
        self.package_source_coverage_rows = []
        self._refresh_package_source_coverage()

    def _package_source_signature(self):
        try:
            requests = tuple(tuple(x) for x in self._package_requests())
        except Exception:
            requests = ()
        mirrors = tuple(sorted(getattr(self, "mirror_repos", set()))) if self._mirror_mode() else ()
        # Reuse the repository metadata-cache signature so a provenance/keying
        # change that alters whether metadata can be loaded also invalidates a
        # previous package-coverage result.
        source_signature = self._signature()
        plan_signature = tuple(
            (root.component, root.package, tuple(root.candidates or (root.package,)),
             root.source_kind, root.role, root.optional)
            for root in self._source_plan().roots) if not self._single_mode() and not self._mirror_mode() else ()
        return (self._profile().package_family, self.selection_mode_var.get(),
                requests, mirrors, plan_signature, source_signature)

    @staticmethod
    def _request_display(request) -> str:
        name = str(request[0]) if request else ""
        version = request[1] if len(request) > 1 else None
        role = request[2] if len(request) > 2 else None
        repo_name = request[3] if len(request) > 3 else None
        source_scope = request[5] if len(request) > 5 else None
        if version and version not in {"Latest", "Follows repositories"}:
            name += f"  {version}"
        if role:
            name += f"  [{role}]"
        if repo_name:
            name += f"  @ {repo_name}"
        if source_scope == "distribution":
            name += "  [distribution]"
        return name

    def _refresh_package_source_coverage(self):
        tree = getattr(self, "package_source_tree", None)
        status_var = getattr(self, "package_source_status_var", None)
        if tree is None or status_var is None:
            return
        current = self._package_source_signature()
        if self.package_source_coverage_signature == current and self.package_source_coverage_rows:
            self._render_package_source_coverage(self.package_source_coverage_rows)
            return
        tree.delete(*tree.get_children())
        self.package_source_coverage_signature = None
        self.package_source_coverage_rows = []
        if self._mirror_mode():
            selected = [r for r in self.repo_rows if r.url.strip() and self._mirror_repo_selected(r)]
            if not selected:
                status_var.set("No repositories are selected for mirroring yet.")
                self.package_source_status.configure(foreground=FG_MUTED)
                return
            for repo in selected:
                tree.insert("", "end", tags=("coverage-pending",),
                            values=(repo.name, "Not checked", repo.name, "Run the selection check"))
            status_var.set(f"Not checked: {len(selected)} selected repository source(s).")
            self.package_source_status.configure(foreground=FG_MUTED)
            return
        try:
            requests = self._package_requests()
        except Exception as exc:
            status_var.set(str(exc))
            self.package_source_status.configure(foreground=FG_MUTED)
            return
        if not requests:
            status_var.set("Choose at least one package or workload root to check source coverage.")
            self.package_source_status.configure(foreground=FG_MUTED)
            return
        optional = self._optional_roots()
        for req in requests:
            label = self._request_display(req)
            suffix = "Optional" if str(req[0]) in optional else "Not checked"
            tree.insert("", "end", tags=("coverage-pending",),
                        values=(label, suffix, "", "Run the selection check"))
        status_var.set(
            f"Not checked: {len(requests)} requested package root(s). Run the check to confirm "
            "that the enabled sources actually offer them.")
        self.package_source_status.configure(foreground=FG_MUTED)

    def _package_matches_request(self, pkg, request) -> bool:
        name, version, role = request[:3]
        repo_name = request[3] if len(request) >= 4 else None
        exact_arch = request[4] if len(request) >= 5 else None
        source_scope = request[5] if len(request) >= 6 else None
        repo_identity = request[6] if len(request) >= 7 else None
        if self._is_deb():
            if pkg.name != name:
                return False
            if version and version not in {"Latest", "Follows repositories"} and pkg.version != version:
                return False
            if pkg.arch not in {self.arch_var.get(), "all"}:
                return False
        elif getattr(getattr(pkg, "repo", None), "repo_format", "") == "pacman":
            names = {pkg.name}
            names.update(getattr(p, "name", "") for p in getattr(pkg, "provides", []) if getattr(p, "name", ""))
            if name not in names:
                return False
            if version and version not in {"Latest", "Follows repositories"} and \
                    arch_core.compare_versions(pkg.version, version) != 0:
                return False
            if pkg.arch not in {self.arch_var.get(), "any"}:
                return False
        else:
            names = {pkg.name}
            names.update(getattr(p, "name", "") for p in getattr(pkg, "provides", []) if getattr(p, "name", ""))
            names.update(getattr(pkg, "files", []) or [])
            if name not in names:
                return False
            if version and version not in {"Latest", "Follows repositories"} and \
                    version not in {pkg.evr_text, pkg.version}:
                return False
            if pkg.arch not in {self.arch_var.get(), "noarch"}:
                return False
        if source_scope == "distribution" and self._repo_tier(pkg.repo) != "base":
            return False
        if role and pkg.repo.role != role:
            return False
        if repo_identity:
            if pkg.repo.source_identity != repo_identity:
                return False
        elif repo_name and pkg.repo.name != repo_name:
            return False
        if exact_arch and pkg.arch != exact_arch:
            return False
        return True

    def _best_coverage_candidate(self, candidates):
        if not candidates:
            return None
        preferred_arch = self.arch_var.get()
        from functools import cmp_to_key

        def cmp(a, b):
            aa = 0 if a.arch == preferred_arch else 1
            ba = 0 if b.arch == preferred_arch else 1
            if aa != ba:
                return -1 if aa < ba else 1
            ap = getattr(a.repo, "priority", 999)
            bp = getattr(b.repo, "priority", 999)
            if ap != bp:
                return -1 if ap < bp else 1
            version_cmp = self._compare_package_versions(a, b)
            if version_cmp:
                return -version_cmp  # newest candidate first
            if a.repo.name != b.repo.name:
                return -1 if a.repo.name < b.repo.name else 1
            return 0

        return sorted(candidates, key=cmp_to_key(cmp))[0]

    def check_package_source_coverage(self):
        if self._busy():
            return
        try:
            # Coverage is allowed to be invoked by tests, restored sessions or
            # alternate UI paths that did not fire the combobox event.  Ensure
            # the workload's explicit side-channel repositories exist before
            # validating the source plan so known requirements never fail as a
            # mere ordering artifact.
            if not self._single_mode() and not self._mirror_mode():
                self._activate_workload_repository_selection()
            self._validate_source_plan()
            requests = self._package_requests()
            # Selection coverage proves only that the requested roots are
            # offered by an eligible source. It does not derive dependencies,
            # so an unrelated base-source plan must not become a prerequisite.
            self._validate_sources(False)
            coverage_repositories = self._package_coverage_repositories()
            coverage_requires_distribution = self._source_plan().distribution_required
        except Exception as exc:
            self._route_validation_error(str(exc))
            messagebox.showerror(APP_TITLE, redact_text(str(exc)))
            return
        if not self._claim_operation(
                "package-source-coverage", "Checking selected packages against repositories", cancellable=True):
            return
        signature = self._package_source_signature()
        self.package_source_status_var.set("Reading repository indexes for the current selection…")
        self.package_source_status.configure(foreground=FG_MUTED)

        def work():
            try:
                rep = Reporter(self._log, self._progress, self.cancel_event)
                packages = self._load_enabled_repos(
                    rep, coverage_repositories,
                    enforce_distribution_plan=coverage_requires_distribution)
                rows = []
                if self._mirror_mode():
                    selected_repos = [r for r in self.repo_rows
                                      if r.url.strip() and self._mirror_repo_selected(r)]
                    for repo in sorted(selected_repos, key=lambda r: (r.name.lower(), r.source_identity)):
                        count = sum(1 for pkg in packages
                                    if pkg.repo.source_identity == repo.source_identity)
                        if count:
                            rows.append((repo.name, "Ready", repo.name,
                                         f"{count:,} package record(s)", "ok", False))
                        else:
                            rows.append((repo.name, "Empty", repo.name,
                                         "No package records found", "error", False))
                else:
                    runtime_requests = requests
                    materialized = None
                    if not self._single_mode() and not self._workload().custom:
                        materialized = self._materialize_selected_workload(packages)
                        runtime_requests = self._package_requests(materialized)
                    optional = (
                        {root.package for root in materialized.roots if root.optional}
                        | {policy.package for policy in materialized.unresolved if policy.optional}
                        if materialized is not None else self._optional_roots())
                    universe_names, universe_provides = workload_resolution.universe_sets(packages)
                    learned_aliases = self._aliases_for_target()
                    resolved_pairs = []
                    for req in runtime_requests:
                        resolution = workload_resolution.resolve_name(
                            str(req[0]), universe_names, universe_provides,
                            getattr(self._profile(), "package_family", "rpm"), learned_aliases)
                        if resolution.substituted:
                            resolved_pairs.append((resolution.requested, resolution.resolved))
                            req = (resolution.resolved,) + tuple(req)[1:]
                        matches = [pkg for pkg in packages if self._package_matches_request(pkg, req)]
                        best = self._best_coverage_candidate(matches)
                        label = self._request_display(req)
                        if resolution.substituted:
                            label = f"{resolution.requested} → {resolution.resolved}"
                        is_optional = str(req[0]) in optional or resolution.requested in optional
                        init_block = ""
                        if self._selected_init_system():
                            init_block = workload_resolution.systemd_conflict(
                                str(req[0]), {p.name: p for p in packages if p.name == str(req[0])})
                        if init_block:
                            rows.append((label, "Blocked (init)", "", init_block, "error", False))
                            continue
                        if best is not None:
                            candidate = getattr(best, "nevra", getattr(best, "name", str(req[0])))
                            status = "Available" if not resolution.substituted else f"Available ({resolution.kind})"
                            rows.append((label, status, best.repo.name, candidate, "ok", is_optional))
                        elif is_optional:
                            rows.append((label, "Optional gap", "", "No approved candidate is offered by the eligible sources", "warn", True))
                        else:
                            rows.append((label, "Missing", "", "No approved workload candidate is offered by the eligible sources", "error", False))
                    if materialized is not None:
                        requested_names = {str(req[0]) for req in runtime_requests}
                        for policy in materialized.unresolved:
                            if policy.optional or policy.package in requested_names:
                                continue
                            candidates = " / ".join(policy.candidates or (policy.package,))
                            rows.append((policy.component or policy.package, "Missing", "",
                                         f"No approved candidate found: {candidates}", "error", False))
                if resolved_pairs:
                    self.events.put(("workload_aliases", resolved_pairs))
                self.events.put(("package_coverage", signature, rows))
                missing = sum(1 for row in rows if row[4] == "error")
                self.events.put(("done", True,
                                 "Package source coverage complete" if not missing
                                 else f"Package source coverage found {missing} required gap(s)"))
            except Cancelled as exc:
                self.events.put(("done", "cancelled", redact_text(str(exc) or "Operation cancelled")))
            except Exception as exc:
                self._log(traceback.format_exc())
                self.events.put(("done", False, redact_text(str(exc))))
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def _apply_package_source_coverage(self, signature, rows):
        # Results are useful only for the exact repository + package selection
        # that was checked. If the operator changed either while the worker ran,
        # leave the new selection in its normal Not checked state.
        if signature != self._package_source_signature():
            self._refresh_package_source_coverage()
            return
        self.package_source_coverage_signature = signature
        self.package_source_coverage_rows = list(rows)
        self._render_package_source_coverage(rows)

    def _render_package_source_coverage(self, rows):
        tree = getattr(self, "package_source_tree", None)
        if tree is None:
            return
        tree.delete(*tree.get_children())
        required_missing = 0
        optional_missing = 0
        available = 0
        for request, status, source, candidate, level, optional in rows:
            tag = {"ok": "coverage-ok", "warn": "coverage-warn",
                   "error": "coverage-error"}.get(level, "coverage-pending")
            tree.insert("", "end", tags=(tag,), values=(request, status, source, candidate))
            if level == "ok":
                available += 1
            elif level == "error":
                required_missing += 1
            elif level == "warn" and optional:
                optional_missing += 1
        total = len(rows)
        if required_missing:
            self.package_source_status_var.set(
                f"Needs attention: {required_missing} required selection item(s) are not offered by "
                f"the enabled repositories. {available} of {total} item(s) are available.")
            self.package_source_status.configure(foreground=ERR_FG)
        elif optional_missing:
            self.package_source_status_var.set(
                f"Ready with optional gaps: {available} of {total} item(s) are available; "
                f"{optional_missing} optional item(s) are absent. Dependency closure is not checked yet.")
            self.package_source_status.configure(foreground=WARN_FG)
        else:
            if bool(getattr(self, "_package_only_acquisition_mode", lambda: False)()):
                self.package_source_status_var.set(
                    f"Root coverage ready: all {available} selected item(s) are offered by the "
                    "workload upstream. No distribution/base repository set is configured, so "
                    "dependency closure cannot be derived; Review will offer package-only download.")
                self.package_source_status.configure(foreground=WARN_FG)
            else:
                self.package_source_status_var.set(
                    f"Ready: all {available} selected item(s) are offered by the enabled sources. "
                    "Dependency closure is checked later by Analyze.")
                self.package_source_status.configure(foreground=OK_FG)

    def _build_keyrings_pane(self, pane):
        """Configure checksum strength and one verification strategy.

        Packages owns the repository set. This page inspects participating
        repositories for supported SHA fields, then configures the minimum
        checksum strength and the policy used when that strength is unavailable.
        """
        self._pane_heading(
            pane, "Provenance and Keying",
            "Feathered inherits the repositories that can participate in the current build. In normal dependency analysis that is the enabled set; package-only acquisition is restricted to the selected workload-root sources. Inspect their checksum support, choose a minimum strength, then choose one verification strategy. Independent evidence is configured only for strategies that use it.")

        checksum = self._card(pane, "Package verification")
        self.prov_checksum_card = checksum
        self._panel_hint(
            checksum,
            "Checksum inspection is independent of archive keyrings. Feathered reads repository metadata, records every strong SHA field it finds, and uses those results to build the choices below.",
            pady=(0, 10))

        self.prov_enabled_sources_var = tk.StringVar(value="")
        ttk.Label(checksum, textvariable=self.prov_enabled_sources_var, style="Panel.TLabel",
                  wraplength=690).pack(anchor="w")

        self.prov_source_tree = ttk.Treeview(
            checksum, columns=("repo", "sha512", "sha384", "sha256", "best", "purpose"),
            show="headings", height=5)
        for col, label, width in (
            ("repo", "Enabled package source", 240),
            ("sha512", "SHA-512", 82),
            ("sha384", "SHA-384", 82),
            ("sha256", "SHA-256", 82),
            ("best", "Strongest found", 130),
            ("purpose", "Build purpose", 135),
        ):
            self.prov_source_tree.heading(col, text=label)
            self.prov_source_tree.column(col, width=width, minwidth=70,
                                         anchor="center" if col != "repo" else "w")
        self.prov_source_tree.pack(fill="x", pady=(8, 0))
        ttk.Label(
            checksum, text="✓ published for all inspected packages   Partial published for some   ✕ not published   ? not inspected",
            style="PanelHint.TLabel", wraplength=690).pack(anchor="w", pady=(4, 0))

        inspect_row = ttk.Frame(checksum, style="Panel.TFrame")
        inspect_row.pack(fill="x", pady=(10, 0))
        self.prov_detected_var = tk.StringVar(
            value="Checksum support has not been inspected for the enabled repositories.")
        ttk.Label(inspect_row, textvariable=self.prov_detected_var, style="PanelHint.TLabel",
                  wraplength=500).pack(side="left", fill="x", expand=True)
        self.prov_inspect_btn = ttk.Button(
            inspect_row, text="Inspect checksum support",
            command=self._inspect_enabled_provenance_metadata)
        self.prov_inspect_btn.pack(side="right", padx=(10, 0))
        self._register_operation_control(self.prov_inspect_btn)
        self.prov_inspect_progress = ttk.Progressbar(
            checksum, mode="determinate", maximum=1, value=0)
        self.prov_inspect_progress.pack(fill="x", pady=(7, 0))
        self.prov_inspect_status_var = tk.StringVar(value="Inspection idle")
        ttk.Label(checksum, textvariable=self.prov_inspect_status_var,
                  style="PanelHint.TLabel", wraplength=690).pack(anchor="w", pady=(3, 0))

        ttk.Separator(checksum, orient="horizontal").pack(fill="x", pady=(15, 12))

        strength_row = ttk.Frame(checksum, style="Panel.TFrame")
        strength_row.pack(fill="x")
        self.prov_digest_label = ttk.Label(
            strength_row, text="Minimum checksum strength", style="Panel.TLabel")
        self.prov_digest_label.pack(side="left")
        self.prov_digest_var = tk.StringVar(value="Automatic")
        self.prov_digest_combo = ttk.Combobox(
            strength_row, textvariable=self.prov_digest_var, state="readonly", width=39,
            values=["Automatic", "SHA-256 or stronger", "SHA-384 or stronger", "SHA-512"])
        self.prov_digest_combo.pack(side="left", padx=(12, 0), fill="x", expand=True)
        self.prov_digest_combo.bind(
            "<<ComboboxSelected>>", lambda _e: self._provenance_policy_changed())
        self.prov_digest_help_var = tk.StringVar(
            value="Automatic uses the strongest strong SHA published by each repository.")
        self.prov_digest_help_label = ttk.Label(
            checksum, textvariable=self.prov_digest_help_var, style="PanelHint.TLabel", wraplength=690)
        self.prov_digest_help_label.pack(anchor="w", pady=(4, 0))

        strategy_row = ttk.Frame(checksum, style="Panel.TFrame")
        strategy_row.pack(fill="x", pady=(13, 0))
        ttk.Label(strategy_row, text="Verification strategy",
                  style="Panel.TLabel").pack(side="left")
        self.prov_strategy_var = tk.StringVar(value="Fill gaps with independent evidence (enhanced)")
        self.prov_strategy_combo = ttk.Combobox(
            strategy_row, textvariable=self.prov_strategy_var, state="readonly", width=39,
            values=[
                "Skip upstream provenance checks (minimal)",
                "Verify what is available (basic)",
                "Require checksum coverage (strict)",
                "Fill gaps with independent evidence (enhanced)",
                "Corroborate every package (maximum)",
            ])
        self.prov_strategy_combo.pack(side="left", padx=(12, 0), fill="x", expand=True)
        self.prov_strategy_combo.bind(
            "<<ComboboxSelected>>", lambda _e: self._provenance_policy_changed())
        self.prov_strategy_help_var = tk.StringVar(value="")
        ttk.Label(checksum, textvariable=self.prov_strategy_help_var, style="PanelHint.TLabel",
                  wraplength=690).pack(anchor="w", pady=(4, 0))

        evidence = self._card(pane, "Independent evidence sources (CONDITIONAL)", pady=(18, 0))
        self.prov_evidence_card = evidence
        evidence_header = ttk.Frame(evidence, style="Panel.TFrame")
        evidence_header.pack(fill="x")
        self.prov_evidence_title = ttk.Label(
            evidence_header, text="Evidence selection", style="PanelGroup.TLabel")
        self.prov_evidence_title.pack(side="left")
        evidence_info = ttk.Label(
            evidence_header, text="ⓘ", style="PanelHint.TLabel", cursor="question_arrow")
        evidence_info.pack(side="left", padx=(7, 0))
        self._attach_tooltip(
            evidence_info,
            "Evidence is enforced per participating package source, not as a one-source global checkbox. "
            "Maximum requires a tested evidence pairing for every participating source. Enhanced requires "
            "checksum inspection first, then tested exact evidence only for sources whose selected "
            "acquisition-checksum minimum is actually missing. Exact mirrors or artifact-only exact endpoints retrieve the corresponding package and compare bytes. "
            "A semantic rebuild peer is different: for RHEL/Rocky/AlmaLinux Maximum can compare package/source "
            "lineage and verify the peer artifact against the peer's own repository checksum even though RPM "
            "bytes may differ. Rebuild peers cannot fill an Enhanced checksum gap.")
        # Match the checksum-inspection row: explanatory/status text owns the
        # flexible left side and the action stays fixed on the right.
        evidence_test_row = ttk.Frame(evidence, style="Panel.TFrame")
        evidence_test_row.pack(fill="x", pady=(4, 9))
        self.prov_evidence_state_var = tk.StringVar(value="")
        self.prov_evidence_help_label = ttk.Label(
            evidence_test_row, textvariable=self.prov_evidence_state_var,
            style="PanelHint.TLabel", wraplength=500)
        self.prov_evidence_help_label.pack(side="left", fill="x", expand=True)
        self.prov_evidence_test_btn = ttk.Button(
            evidence_test_row, text="Test evidence sources", command=self._test_evidence_sources)
        self.prov_evidence_test_btn.pack(side="right", padx=(10, 0))
        self._register_operation_control(self.prov_evidence_test_btn)
        self.prov_evidence_rows_frame = ttk.Frame(evidence, style="Panel.TFrame")
        self.prov_evidence_rows_frame.pack(fill="x")
        self._panel_hint(
            evidence,
            "The status at right shows whether each source actually requires evidence under the current policy. "
            "Exact mirrors/artifact endpoints must reproduce identical bytes. Semantic rebuild peers are Maximum-only: "
            "they provide independent rebuild lineage evidence, not byte identity and not missing-checksum recovery. "
            "Evidence repository metadata is used as a locator; unrelated live-mirror synchronization skew is recorded "
            "but is not allowed to abort the whole transaction before the selected artifact is checked. If a curated "
            "exact mirror is stale or unavailable, Test evidence sources may verify and switch to another curated US "
            "independent exact mirror for the same archive; a byte/checksum mismatch is never auto-bypassed. Hover a "
            "failed status for the exact probe error. Evidence copies are temporary and never added to the bundle.",
            pady=(8, 0))

        # ---- Separate optional provenance/keying layers ------------------
        # Signature layers need a GnuPG verifier. Say so once, at the top of
        # the layers that depend on it, with the concrete remedy, instead of
        # letting the operator configure a keyring that silently cannot work.
        self.openpgp_status_card = self._card(pane, "OpenPGP verifier", pady=(18, 0))
        self.openpgp_status_hint = ttk.Label(
            self.openpgp_status_card, style="PanelHint.TLabel", wraplength=820, justify="left")
        self.openpgp_status_hint.pack(fill="x")
        self.openpgp_install_row = ttk.Frame(self.openpgp_status_card, style="Panel.TFrame")
        self.openpgp_install_row.pack(fill="x", pady=(8, 0))
        ttk.Button(self.openpgp_install_row, text="How to install GnuPG",
                   command=self._show_gnupg_install_help).pack(side="left")
        ttk.Button(self.openpgp_install_row, text="Re-check",
                   command=self._sync_openpgp_availability).pack(side="left", padx=(8, 0))

        operator = self._card(pane, "Bundle attestation (optional)", pady=(18, 0))
        self._panel_hint(
            operator,
            "Sign the canonical finished-file index when you want the receiving side to prove the bundle came from your operator key. This layer is optional and separate from upstream package provenance.", pady=(0, 10))
        og = ttk.Frame(operator, style="Panel.TFrame"); og.pack(fill="x")
        ttk.Label(og, text="GPG key id", style="Panel.TLabel").pack(side="left")
        self.signing_key_var = tk.StringVar(value="")
        self.signing_key_entry = ttk.Entry(og, textvariable=self.signing_key_var)
        self.signing_key_entry.pack(side="left", fill="x", expand=True, padx=(10, 0))
        self._openpgp_dependent_widgets = [self.signing_key_entry]
        self.signing_key_var.trace_add("write", lambda *_a: self._clear_validation_attention())

        vendor = self._card(pane, "Vendor package signatures (optional)", pady=(18, 0))
        self._panel_hint(
            vendor,
            "RPM package signatures are vendor-specific. Feathered keeps one keyring and one enforcement policy per vendor, so a key selected for Red Hat is never tried against Docker, Rocky Linux, or another vendor's packages.",
            pady=(0, 10))
        self.vendor_signature_tree = ttk.Treeview(
            vendor, columns=("vendor", "repos", "keyring", "policy"), show="headings", height=5)
        for col, text, width in (
            ("vendor", "Vendor", 145), ("repos", "Enabled repositories", 235),
            ("keyring", "Package-signature keyring", 270), ("policy", "Policy", 130)):
            self.vendor_signature_tree.heading(col, text=text)
            self.vendor_signature_tree.column(col, width=width, minwidth=90)
        self.vendor_signature_tree.pack(fill="x")
        self.vendor_signature_tree.bind("<<TreeviewSelect>>",
                                        lambda _e: self._vendor_signature_selection_changed())
        vrow = ttk.Frame(vendor, style="Panel.TFrame"); vrow.pack(fill="x", pady=(10, 0))
        ttk.Button(vrow, text="Set selected vendor keyring…",
                   command=self._assign_vendor_keyring).pack(side="left")
        ttk.Button(vrow, text="Clear keyring",
                   command=self._clear_vendor_keyring).pack(side="left", padx=(8, 0))
        ttk.Label(vrow, text="Selected vendor policy", style="Panel.TLabel").pack(side="left", padx=(18, 8))
        self.vendor_signature_policy_var = tk.StringVar(value="Record signature results")
        self.vendor_signature_policy_combo = ttk.Combobox(
            vrow, textvariable=self.vendor_signature_policy_var, state="disabled", width=28,
            values=["Record signature results", "Require valid vendor signatures"])
        self.vendor_signature_policy_combo.pack(side="left", fill="x", expand=True)
        self.vendor_signature_policy_combo.bind(
            "<<ComboboxSelected>>", lambda _e: self._vendor_signature_policy_changed())
        self._panel_hint(
            vendor,
            "Only keyring file references and the policy choice are remembered in your OS user configuration. Keyring contents are not copied into Feathered or the bundle.",
            pady=(8, 0))

        self.entitlement_card_holder = ttk.Frame(pane)
        self.entitlement_card_holder.pack(fill="x", pady=(18, 0))
        entitle = self._card(self.entitlement_card_holder,
                             "Vendor entitlement credentials (optional, advanced)")
        self._panel_hint(
            entitle,
            "Client-certificate credentials are scoped by vendor. Feathered remembers only file references in your OS user configuration and passes the selected files directly to the TLS stack when that vendor's repository is contacted.",
            pady=(0, 10))
        self.entitlement_tree = ttk.Treeview(
            entitle, columns=("vendor", "scope", "status"), show="headings", height=4)
        for col, text, width in (("vendor", "Vendor", 160),
                                 ("scope", "Credential scope", 330),
                                 ("status", "Status", 250)):
            self.entitlement_tree.heading(col, text=text)
            self.entitlement_tree.column(col, width=width, minwidth=110)
        self.entitlement_tree.pack(fill="x")
        erow = ttk.Frame(entitle, style="Panel.TFrame"); erow.pack(fill="x", pady=(10, 0))
        ttk.Button(erow, text="Configure selected vendor…",
                   command=self._configure_selected_entitlement).pack(side="left")
        ttk.Button(erow, text="Forget selected vendor",
                   command=self._forget_selected_entitlement).pack(side="left", padx=(8, 0))
        self._panel_hint(
            entitle,
            "Private-key bytes are never written to Feathered state, logs, manifests, or bundles. Removing a remembered profile deletes only Feathered's path references; it does not modify the source files.",
            pady=(8, 0))

        archive = self._card(pane, "Archive keyrings (optional, advanced)", pady=(18, 0))
        self._panel_hint(
            archive,
            "Authenticate signed repository metadata such as APT InRelease/Release.gpg or RPM repomd.xml.asc when archive keying is available. This layer is optional, and independent mirror evidence never inherits these keyrings.",
            pady=(0, 10))
        self.keyring_tree = ttk.Treeview(archive, columns=("repo", "state", "keyring"),
                                         show="headings", height=6)
        for col, text, width in (("repo", "Repository", 220), ("state", "Archive provenance", 150),
                                 ("keyring", "Keyring", 330)):
            self.keyring_tree.heading(col, text=text)
            self.keyring_tree.column(col, width=width, minwidth=90)
        self.keyring_tree.tag_configure("signed", foreground=OK_FG)
        self.keyring_tree.tag_configure("digest", foreground=FG_MUTED)
        self.keyring_tree.tag_configure("open", foreground=WARN_FG)
        self.keyring_tree.pack(fill="x")
        krow = ttk.Frame(archive, style="Panel.TFrame"); krow.pack(fill="x", pady=(10, 0))
        set_keyring_btn = ttk.Button(krow, text="Set keyring…", command=self._assign_keyring)
        set_keyring_btn.pack(side="left")
        apply_all_btn = ttk.Button(krow, text="Apply to all", command=self._assign_keyring_all)
        apply_all_btn.pack(side="left", padx=(8, 0))
        self._openpgp_dependent_widgets = list(
            getattr(self, "_openpgp_dependent_widgets", [])) + [set_keyring_btn, apply_all_btn]
        self._sync_openpgp_availability()
        ttk.Button(krow, text="Clear", command=self._clear_keyring).pack(side="left", padx=(8, 0))
        ttk.Button(krow, text="Refresh", command=self._refresh_keyring_tree).pack(side="left", padx=(8, 0))
        ttk.Button(krow, text="Key store…", command=self.open_keystore).pack(side="left", padx=(8, 0))

        exceptions = self._card(pane, "Repository exceptions (optional, advanced)", pady=(18, 0))
        self._panel_hint(
            exceptions,
            "Per-repository exceptions belong to the repository itself. Use Manage additional repositories only when a source publishes "
            "an index absent from its signed/rooted checksum manifest. This weakens archive provenance and should normally remain off.",
            pady=(0, 10))
        ttk.Button(exceptions, text="Manage repository exceptions…", command=self.open_repositories).pack(anchor="w")

        self.security_note = ttk.Label(pane, style="Hint.TLabel", wraplength=740, text="")
        self.security_note.pack(fill="x", pady=(14, 0))
        self._refresh_vendor_signature_tree()
        self._refresh_entitlement_state()
        self._refresh_provenance_editor()

    def _build_transfer_pane(self, pane):
        self._pane_heading(pane, "Output Directories",
                           "Choose where Feathered writes the finished bundle, how that directory is "
                           "named, and whether the output includes repository metadata or a delta "
                           "against an existing transfer.")
        out = self._card(pane, "Output folder")
        orow = ttk.Frame(out, style="Panel.TFrame"); orow.pack(fill="x")
        self.out_var = tk.StringVar(value=str(Path.cwd() / "downloads"))
        ttk.Entry(orow, textvariable=self.out_var).pack(side="left", fill="x", expand=True)
        ttk.Button(orow, text="Browse", command=self.browse_output).pack(side="left", padx=(8, 0))

        # Mirror layout lives beside folder naming because that is where its
        # consequence is visible: it decides whether this run produces one
        # directory or one per selected repository.
        self.mirror_layout_card = self._card(pane, "Mirror layout", pady=(18, 0))
        self._panel_hint(
            self.mirror_layout_card,
            "Only used by \"Entire repository (mirror)\". Separate folders keep each repository "
            "as a faithful snapshot of its upstream. One unified repository republishes the "
            "selection as a single repository the target can point at once, removing packages "
            "that appear in more than one source and are provably the same artifact.",
            pady=(0, 10))
        self.mirror_layout_var = tk.StringVar(value=MIRROR_LAYOUT_LABELS[MirrorLayout.SEPARATE])
        ttk.Combobox(self.mirror_layout_card, textvariable=self.mirror_layout_var,
                     state="readonly", width=58,
                     values=[MIRROR_LAYOUT_LABELS[MirrorLayout.SEPARATE],
                             MIRROR_LAYOUT_LABELS[MirrorLayout.UNIFIED]]).pack(anchor="w")
        self.mirror_layout_hint = ttk.Label(self.mirror_layout_card, style="PanelHint.TLabel",
                                            wraplength=680, text="")
        self.mirror_layout_hint.pack(anchor="w", pady=(8, 0))
        self.mirror_conflict_row = tk.Frame(self.mirror_layout_card, background=BG_PANEL)
        self.mirror_conflict_row.pack(anchor="w", fill="x", pady=(12, 0))
        ttk.Label(self.mirror_conflict_row, text="When repositories disagree",
                  style="FieldLabel.TLabel").pack(anchor="w")
        self.mirror_conflict_policy_var = tk.StringVar(
            value=MERGE_POLICY_LABELS[MergePolicy.STRICT])
        ttk.Combobox(self.mirror_conflict_row, textvariable=self.mirror_conflict_policy_var,
                     state="readonly", width=58,
                     values=[MERGE_POLICY_LABELS[MergePolicy.STRICT],
                             MERGE_POLICY_LABELS[MergePolicy.PREFER_PRIORITY]]).pack(
                         anchor="w", pady=(4, 0))
        self.mirror_conflict_hint = ttk.Label(self.mirror_conflict_row, style="PanelHint.TLabel",
                                              wraplength=680, text="")
        self.mirror_conflict_hint.pack(anchor="w", pady=(8, 0))
        self.mirror_conflict_policy_var.trace_add(
            "write", lambda *_a: self._update_folder_preview())
        self.mirror_layout_var.trace_add("write", lambda *_a: self._update_folder_preview())

        naming = self._card(pane, "Folder naming", pady=(18, 0))
        self._panel_hint(naming, "How the bundle folder inside the output directory is named. "
                                 "A date prefix sorts chronologically in Explorer and makes it "
                                 "obvious which transfer a bundle belongs to.", pady=(0, 10))
        nrow = ttk.Frame(naming, style="Panel.TFrame"); nrow.pack(fill="x")
        ttk.Label(nrow, text="Name from", style="Panel.TLabel").pack(side="left")
        # "Target" and "workload" were jargon; spell out what each produces.
        self.folder_scheme_var = tk.StringVar(value=FOLDER_SCHEMES[0])
        ttk.Combobox(nrow, textvariable=self.folder_scheme_var, state="readonly", width=44,
                     values=FOLDER_SCHEMES).pack(side="left", padx=(10, 10))
        self.folder_label_var = tk.StringVar(value="")
        self.folder_label_entry = ttk.Entry(nrow, textvariable=self.folder_label_var)
        self.folder_label_entry.pack(side="left", fill="x", expand=True)
        self.folder_scheme_hint = ttk.Label(naming, style="PanelHint.TLabel", wraplength=680, text="")
        self.folder_scheme_hint.pack(anchor="w", pady=(8, 0))

        # A segmented control rather than ttk radiobuttons: the themed indicator
        # ignores the dark palette on some platforms and renders white-on-white
        # while hovered, which was both ugly and unreadable.
        self.folder_stamp_var = tk.StringVar(value="date")
        ttk.Label(naming, text="Prefix", style="PanelHint.TLabel").pack(anchor="w", pady=(12, 4))
        self._segmented(naming, self.folder_stamp_var,
                        [("none", "None"), ("date", "Date"), ("time", "Date + time")])
        self.folder_preview = ttk.Label(naming, style="Value.TLabel", text="", wraplength=780, justify="left")
        self.folder_preview.pack(anchor="w", pady=(10, 0))
        for var in (self.folder_scheme_var, self.folder_label_var, self.folder_stamp_var):
            var.trace_add("write", lambda *_a: self._update_folder_preview())

        repo = self._card(pane, "Output format", pady=(18, 0))
        # Each description sits directly above the option it describes; they
        # were previously offset by one, so each checkbox appeared under the
        # wrong explanation.
        self.sign_index_var = tk.BooleanVar(value=False)
        self.sign_index_row = self._image_checkbutton(
            repo, self.sign_index_var,
            "Seal the bundle: hash every finished file and sign that index",
            command=self._signing_requested)
        self._panel_hint(repo, "Hashes are computed from the finished files at the end of the "
                               "build, so the signature attests to the exact bundle produced. "
                               "Requires a signing key on the Provenance & Keying step. Adds a final hashing "
                               "pass - seconds for a small bundle, longer for a large mirror.",
                         pady=(4, 14))
        # Off by default. Repository metadata is the point of a mirror and an
        # extra for a workload or exact-package bundle, whose deliverable is the
        # package set plus install-offline.sh. _sync_output_capability_controls
        # turns it on when mirror intent is selected and off again on the way
        # back out, so doubling back to change the dropdown corrects it.
        self.emit_repo_var = tk.BooleanVar(value=False)
        self.emit_repo_row = self._image_checkbutton(
            repo, self.emit_repo_var,
            "Also generate repository metadata (repodata/ for RPM, dists/ for APT, .db for pacman)")
        self._panel_hint(repo, "In addition to the package files and offline installer, Feathered "
                               "can generate real repository metadata beside them, so the bundle "
                               "can be served or mounted as a repository on the target instead of "
                               "installed file-by-file.", pady=(4, 0))

        diff = self._card(pane, "Differential bundle (optional)", pady=(18, 0))
        self._panel_hint(diff, "Select manifest.json from the installed bundle's rpms/, debs/, or packages/ "
                               "folder and Feathered ships only what is new or changed. The result is "
                               "NOT self-contained: it installs correctly only on a target that "
                               "already has the baseline bundle.", pady=(0, 10))
        drow = ttk.Frame(diff, style="Panel.TFrame"); drow.pack(fill="x")
        self.baseline_var = tk.StringVar(value="")
        self.baseline_entry = ttk.Entry(drow, textvariable=self.baseline_var, state="readonly")
        self.baseline_entry.pack(side="left", fill="x", expand=True)
        self.baseline_choose_btn = ttk.Button(drow, text="Choose…", command=self._browse_baseline)
        self.baseline_choose_btn.pack(side="left", padx=(8, 0))
        self.baseline_clear_btn = ttk.Button(drow, text="Clear", command=self._clear_baseline)
        self.baseline_clear_btn.pack(side="left", padx=(8, 0))
        self.output_capability_note = ttk.Label(diff, style="PanelHint.TLabel", wraplength=700, text="")
        self.output_capability_note.pack(anchor="w", pady=(8, 0))

    def _sync_output_capability_controls(self):
        """Make Output controls reflect the derived publication contract."""
        if not self.__dict__.get("emit_repo_var"):
            return
        state = self._acquisition_state()
        previous_capability = getattr(self, "_last_output_capability", None)
        self._last_output_capability = state.capability
        row = self.__dict__.get("emit_repo_row")
        setter = getattr(row, "_feather_set_enabled", None) if row is not None else None
        note = self.__dict__.get("output_capability_note")
        if state.capability is AcquisitionCapability.REPOSITORY_MIRROR:
            # A mirror publication is independently consumable repository data,
            # not a flat package dump. Keep repository metadata mandatory so
            # every selected source fork receives its own index/repodata set.
            self.emit_repo_var.set(True)
            if callable(setter): setter(False)
            # An "entire repository mirror" must remain an entire mirror. A
            # differential payload would be a delta, not the requested object.
            self.baseline_var.set("")
            for widget in (self.__dict__.get("baseline_entry"),
                           self.__dict__.get("baseline_choose_btn"),
                           self.__dict__.get("baseline_clear_btn")):
                if widget is not None:
                    widget.configure(state="disabled")
            if note is not None:
                note.configure(text=(
                    "Repository mirror mode requires generated repository metadata and disables "
                    "differential output. The published object is the complete selected repository "
                    "population, not a package-root transaction or delta."))
        elif state.capability is AcquisitionCapability.PACKAGE_ONLY:
            # Default off on entering this state, but leave the checkbox
            # usable: a repository over one or a few collected artifacts is a
            # legitimate object even without dependency completeness.
            if previous_capability is not AcquisitionCapability.PACKAGE_ONLY:
                self.emit_repo_var.set(False)
            if callable(setter): setter(True)
            for widget in (self.__dict__.get("baseline_entry"),
                           self.__dict__.get("baseline_choose_btn"),
                           self.__dict__.get("baseline_clear_btn")):
                if widget is not None:
                    widget.configure(state="readonly" if widget is self.__dict__.get("baseline_entry") else "normal")
            if note is not None:
                note.configure(text=(
                    "Package-only acquisition cannot emit repository metadata or an offline transaction "
                    "installer because dependency completeness was not derived."))
        else:
            # Dependency-closure acquisition: a workload or exact-package
            # transaction. Repository metadata is optional here, so entering
            # this capability from another one clears it rather than carrying a
            # mirror's forced selection across. Guarded on the transition, so a
            # deliberate tick survives navigating around within the same mode.
            #
            # BLOCKED is excluded on both sides. It means "not enough chosen
            # yet", which every workflow passes through repeatedly while the
            # operator is still configuring; resetting on it would make the
            # checkbox flicker as selections are made and would discard a
            # deliberate tick for no reason the operator could see.
            settled = (state.capability is not AcquisitionCapability.BLOCKED
                       and previous_capability is not AcquisitionCapability.BLOCKED)
            if settled and previous_capability is not state.capability:
                self.emit_repo_var.set(False)
            if callable(setter): setter(True)
            for widget in (self.__dict__.get("baseline_entry"),):
                if widget is not None: widget.configure(state="readonly")
            if note is not None:
                note.configure(text=(
                    "Repository metadata is optional for a workload or exact-package bundle: the "
                    "deliverable is the package set plus install-offline.sh. Tick it to also serve "
                    "or mount this bundle as a repository."))
            for widget in (self.__dict__.get("baseline_choose_btn"), self.__dict__.get("baseline_clear_btn")):
                if widget is not None: widget.configure(state="normal")
            if note is not None: note.configure(text="")

        # Entering Output Directories is a synchronization boundary. Recompute
        # the resolved folder plan from current acquisition state even if no
        # naming variable itself changed since this pane was first constructed.
        self._update_folder_preview()

    def _build_review_pane(self, pane):
        self._pane_heading(pane, "Review and build",
                           "Confirm what will be collected, analyze the dependency closure, then "
                           "write the bundle. Unresolved requirements must be resolved or explicitly waived before building.")
        summary_card = self._card(pane, "Configuration")
        self.review_labels = {}
        grid = ttk.Frame(summary_card, style="Panel.TFrame"); grid.pack(fill="x")
        fields = [("Linux Distribution", 0, 0), ("Sources", 1, 0), ("Selection", 2, 0),
                  ("Verification", 0, 1), ("Bundle path", 1, 1), ("Output", 2, 1)]
        for label, r, c in fields:
            cell = ttk.Frame(grid, style="Panel.TFrame")
            cell.grid(row=r, column=c, sticky="ew", padx=(0, 24) if c == 0 else (0, 0), pady=(0, 10))
            ttk.Label(cell, text=label.upper(), style="PanelHint.TLabel").pack(anchor="w")
            value = ttk.Label(cell, text="-", style="Value.TLabel", wraplength=330)
            value.pack(anchor="w")
            self.review_labels[label] = value
            if label == "Sources":
                # Review exposes the exact
                # repository/evidence URLs that analysis is about to contact.
                # It is intentionally a link rather than another summary value.
                self.review_source_url_link = tk.Label(
                    cell, text="View exact source URLs", background=BG_PANEL,
                    foreground=ACCENT, cursor="hand2", font=("Segoe UI", 9, "underline"))
                self.review_source_url_link.pack(anchor="w", pady=(3, 0))
                self.review_source_url_link.bind(
                    "<Button-1>", lambda _e: self._show_review_source_urls())
        grid.columnconfigure(0, weight=1); grid.columnconfigure(1, weight=1)

        actions = ttk.Frame(pane); actions.pack(fill="x", pady=(18, 0))
        self.analyze_btn = ttk.Button(actions, text="Analyze", style="Primary.TButton",
                                      command=lambda: self.start_build(False), state="disabled")
        self.analyze_btn.pack(side="left")
        self._register_operation_control(self.analyze_btn)
        # The visible Review package list is the build contract.
        self.build_btn = ttk.Button(actions, text="Build bundle",
                                    command=lambda: self.start_build(True), state="disabled")
        self.build_btn.pack(side="left", padx=(10, 0))
        self._register_operation_control(self.build_btn)
        self.cancel_btn = ttk.Button(actions, text="Cancel", command=self.cancel, state="disabled")
        self.cancel_btn.pack(side="left", padx=(10, 0))
        # expose the finished destination as
        # an action only after Feathered has actually published a bundle there.
        # This avoids an "open" button that points at a merely planned path.
        self.open_output_btn = ttk.Button(actions, text="Open output folder",
                                          command=self._open_output_folder, state="disabled")
        self.open_output_btn.pack(side="left", padx=(10, 0))
        self._build_kubernetes_review(pane)
        self.summary_var = tk.StringVar(value="Analyze to verify dependency completeness.")
        self._base_summary = "Analyze to verify dependency completeness."
        ttk.Label(pane, textvariable=self.summary_var, style="Hint.TLabel", wraplength=740).pack(
            anchor="w", pady=(14, 4))
        self.download_size_var = tk.StringVar(
            value="Package payload: analyze to calculate the complete transfer size before download.")
        ttk.Label(pane, textvariable=self.download_size_var, style="Hint.TLabel", wraplength=740).pack(
            anchor="w", pady=(0, 6))

        # Keep trust findings out of the package result table and link to the full log.
        self.trust_review_bar = ttk.Frame(pane)
        self.trust_review_var = tk.StringVar(value="")
        ttk.Label(self.trust_review_bar, textvariable=self.trust_review_var,
                  style="Hint.TLabel").pack(side="left")
        self.trust_details_btn = ttk.Button(
            self.trust_review_bar, text="View trust details",
            command=lambda: self.show_details(focus_trust=True))
        self.trust_details_btn.pack(side="left", padx=(12, 0))

        # unresolved requirements are
        # actionable review items rather than a dead-end error message.  The
        # bar appears only when analysis has unresolved/waived rows.
        self.unresolved_bar = ttk.Frame(pane)
        ttk.Label(self.unresolved_bar, text="Unresolved requirements",
                  style="Hint.TLabel").pack(side="left")
        self.retry_unresolved_btn = ttk.Button(self.unresolved_bar, text="Retry unresolved",
                                               command=self._retry_unresolved)
        self.retry_unresolved_btn.pack(side="left", padx=(12, 0))
        self._register_operation_control(self.retry_unresolved_btn)
        self.ignore_unresolved_btn = ttk.Button(self.unresolved_bar, text="Ignore selected",
                                                command=self._ignore_selected_unresolved,
                                                state="disabled")
        self.ignore_unresolved_btn.pack(side="left", padx=(8, 0))
        self.restore_unresolved_btn = ttk.Button(self.unresolved_bar, text="Restore ignored",
                                                 command=self._restore_ignored_unresolved,
                                                 state="disabled")
        self.restore_unresolved_btn.pack(side="left", padx=(8, 0))

        # keep Review visually stable while
        # Build performs its analysis/preflight.  The outer frame can pulse an
        # accent border without deleting the package contract; transfer start
        # returns it to the normal border.
        self.result_glow_frame = tk.Frame(
            pane, background=BG_APP, highlightbackground=LINE, highlightcolor=LINE,
            highlightthickness=2, bd=0)
        self.result_glow_frame.pack(fill="both", expand=True)
        result_frame = ttk.Frame(self.result_glow_frame)
        result_frame.pack(fill="both", expand=True, padx=1, pady=1)

        # Large analyses are paginated rather than sampled or truncated. Every
        # package remains reachable, while Treeview only renders a bounded page
        # at once so 20k+ repository inventories remain responsive.
        self.result_page_bar = ttk.Frame(result_frame)
        self.result_page_var = tk.StringVar(value="")
        self.result_first_btn = ttk.Button(
            self.result_page_bar, text="First", width=8,
            command=lambda: self._set_result_page(0))
        self.result_first_btn.pack(side="left")
        self.result_prev_btn = ttk.Button(
            self.result_page_bar, text="‹ Prev", width=9,
            command=lambda: self._set_result_page(getattr(self, "result_page", 0) - 1))
        self.result_prev_btn.pack(side="left", padx=(6, 0))
        ttk.Label(self.result_page_bar, textvariable=self.result_page_var,
                  style="Hint.TLabel").pack(side="left", padx=(12, 12))
        self.result_next_btn = ttk.Button(
            self.result_page_bar, text="Next ›", width=9,
            command=lambda: self._set_result_page(getattr(self, "result_page", 0) + 1))
        self.result_next_btn.pack(side="left")
        self.result_last_btn = ttk.Button(
            self.result_page_bar, text="Last", width=8,
            command=self._last_result_page)
        self.result_last_btn.pack(side="left", padx=(6, 0))
        ttk.Label(self.result_page_bar, text="Rows/page",
                  style="Hint.TLabel").pack(side="right", padx=(8, 6))
        self.result_page_size_var = tk.StringVar(
            value=str(getattr(self, "result_page_size", 1000)))
        self.result_page_size_combo = ttk.Combobox(
            self.result_page_bar, textvariable=self.result_page_size_var,
            values=("250", "500", "1000", "2000"), state="readonly", width=6)
        self.result_page_size_combo.pack(side="right")
        self.result_page_size_combo.bind(
            "<<ComboboxSelected>>", self._result_page_size_changed, add="+")
        self.result_page_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=6, pady=(5, 7))
        self.result_page_bar.grid_remove()

        # The tree column (#0) carries a drawn checkbox image in pick mode: a
        # real target to click, rather than a "[x]" typed into the label.
        self.result_tree = ttk.Treeview(result_frame,
                                        columns=("package", "status", "source", "reason"),
                                        show="tree headings", height=12)
        self.result_tree.heading("#0", text="")
        self.result_tree.column("#0", width=0, minwidth=0, stretch=False, anchor="center")
        # Click a heading to sort. A 300-package closure is unreadable in
        # discovery order; grouping by source or by reason is how you actually
        # check that nothing came from an unexpected repository.
        for column, label in (("package", "Package / issue"), ("status", "Status"),
                              ("source", "Source"), ("reason", "Why")):
            self.result_tree.heading(
                column, text=label,
                command=lambda c=column: self._sort_results(c))
        self._result_sort = (None, False)
        self.result_tree.column("package", width=310, minwidth=180)
        self.result_tree.column("status", width=110, minwidth=80)
        self.result_tree.column("source", width=200, minwidth=120)
        self.result_tree.column("reason", width=300, minwidth=160)
        self.result_tree.tag_configure("issue", foreground=ERR_FG)
        self.result_tree.tag_configure("warn", foreground=WARN_FG)
        self.result_tree.tag_configure("ok", foreground=FG_TEXT)
        self.result_tree.tag_configure("active", foreground=ACCENT)
        self.result_tree.tag_configure("done", foreground=OK_FG)
        self.result_tree.tag_configure("failed", foreground=ERR_FG)
        self.result_tree.tag_configure("pending", foreground=FG_MUTED)
        vs = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_tree.yview)
        hs = ttk.Scrollbar(result_frame, orient="horizontal", command=self.result_tree.xview)
        self.result_tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        result_frame.rowconfigure(1, weight=1); result_frame.columnconfigure(0, weight=1)
        self.result_tree.bind("<Button-1>", self._toggle_pick, add="+")
        self.result_tree.bind("<space>", lambda _e: self._toggle_selected_rows(), add="+")
        self.result_tree.bind("<<TreeviewSelect>>", lambda _e: self._update_unresolved_actions(), add="+")

        # Bulk actions, shown only in pick mode.
        self.pick_bar = ttk.Frame(pane)
        ttk.Label(self.pick_bar, text="Selection:", style="Hint.TLabel").pack(side="left")
        for label, action in (("All", "all"), ("None", "none"), ("Invert", "invert"),
                              ("Requested only", "roots"), ("Highlighted", "highlighted")):
            ttk.Button(self.pick_bar, text=label, width=15,
                       command=lambda a=action: self._bulk_pick(a)).pack(side="left", padx=(8, 0))
        self.result_tree.grid(row=1, column=0, sticky="nsew")
        vs.grid(row=1, column=1, sticky="ns"); hs.grid(row=2, column=0, sticky="ew")

    def _build_tools_pane(self, pane):
        """Maintenance tools that do not alter the wizard sequence.

        Repository rebuilds operate on package files already on disk and do not
        download or move payloads.
        """
        self._pane_heading(
            pane, "Repository utilities",
            "Maintenance workflows for package collections and existing Feathered bundles. "
            "These tools are independent of the five-step bundle wizard.")

        rebuild = self._card(pane, "Build repository metadata")
        self._panel_hint(
            rebuild,
            "Choose a folder that already contains RPM, DEB, or Arch .pkg.tar.* files. Feathered reads each package, "
            "computes fresh SHA-256/SHA-512 values, and rebuilds repodata, dists, or pacman database metadata in "
            "place. Package files are not moved or downloaded.", pady=(0, 10))
        choose = ttk.Frame(rebuild, style="Panel.TFrame"); choose.pack(fill="x")
        self.repo_tool_path_var = tk.StringVar(value="")
        self.repo_tool_entry = ttk.Entry(choose, textvariable=self.repo_tool_path_var, state="readonly")
        self.repo_tool_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(choose, text="Choose folder", command=self._choose_repository_tool_folder).pack(
            side="left", padx=(8, 0))
        self.repo_tool_scan_var = tk.StringVar(value="Choose a package folder to inspect it.")
        ttk.Label(rebuild, textvariable=self.repo_tool_scan_var, style="PanelHint.TLabel",
                  wraplength=760).pack(anchor="w", pady=(10, 8))
        self.repo_tool_progress_var = tk.DoubleVar(value=0)
        self.repo_tool_progress = ttk.Progressbar(rebuild, variable=self.repo_tool_progress_var,
                                                  maximum=100)
        self.repo_tool_progress.pack(fill="x", pady=(2, 8))
        action_row = ttk.Frame(rebuild, style="Panel.TFrame"); action_row.pack(fill="x")
        self.repo_tool_build_btn = ttk.Button(action_row, text="Rebuild metadata",
                                              style="Primary.TButton",
                                              command=self._start_repository_rebuild,
                                              state="disabled")
        self.repo_tool_build_btn.pack(side="left")
        self._register_operation_control(self.repo_tool_build_btn)
        self.repo_tool_status_var = tk.StringVar(value="")
        ttk.Label(action_row, textvariable=self.repo_tool_status_var, style="PanelHint.TLabel",
                  wraplength=600).pack(side="left", padx=(12, 0))

        integrity = self._card(pane, "Check sealed bundle files", pady=(18, 0))
        self._panel_hint(
            integrity,
            "Compare an existing Feathered bundle against bundle-index.json. This checks the exact "
            "file set and SHA-256 values; it does not claim the detached signature is trusted.",
            pady=(0, 10))
        irow = ttk.Frame(integrity, style="Panel.TFrame"); irow.pack(fill="x")
        self.bundle_check_path_var = tk.StringVar(value="")
        ttk.Entry(irow, textvariable=self.bundle_check_path_var, state="readonly").pack(
            side="left", fill="x", expand=True)
        ttk.Button(irow, text="Choose bundle", command=self._choose_bundle_check_folder).pack(
            side="left", padx=(8, 0))
        self.bundle_check_btn = ttk.Button(irow, text="Check files", command=self._start_bundle_check,
                                           state="disabled")
        self.bundle_check_btn.pack(side="left", padx=(8, 0))
        self._register_operation_control(self.bundle_check_btn)
        self.bundle_check_status_var = tk.StringVar(value="")
        ttk.Label(integrity, textvariable=self.bundle_check_status_var, style="PanelHint.TLabel",
                  wraplength=760).pack(anchor="w", pady=(10, 0))

        mirrors = self._card(pane, "Provenance mirror catalogs", pady=(18, 0))
        self._panel_hint(
            mirrors,
            "Exact-mirror evidence is derived from editable JSON catalogs rather than one hard-coded mirror. "
            "The files live beside the application (or in the source tree during development), can be edited in Notepad, "
            "and manual evidence can be saved back into them permanently.", pady=(0, 10))
        mrow = ttk.Frame(mirrors, style="Panel.TFrame"); mrow.pack(fill="x")
        self.mirror_catalog_path_var = tk.StringVar(value=str(mirror_catalog.catalog_root()))
        ttk.Entry(mrow, textvariable=self.mirror_catalog_path_var, state="readonly").pack(
            side="left", fill="x", expand=True)
        ttk.Button(mrow, text="Open catalog folder", command=self._open_mirror_catalog_folder).pack(
            side="left", padx=(8, 0))
        ttk.Button(mrow, text="Reload catalogs", command=self._reload_mirror_catalogs).pack(
            side="left", padx=(8, 0))
        self.mirror_catalog_status_var = tk.StringVar(value="Local catalog edits are read when evidence choices are refreshed.")
        ttk.Label(mirrors, textvariable=self.mirror_catalog_status_var, style="PanelHint.TLabel",
                  wraplength=760).pack(anchor="w", pady=(10, 0))
