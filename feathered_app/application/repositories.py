"""Repository editor workflows and repository trust configuration.

"""

import apt_core
import arch_core
import core
from checksum_inspection import inspect_checksums
from feathered_app.repository_advisory import archive_keyring_state, http_repository_advice
from repository_transport import normalize_query_key_names

from feathered_app.context import (
    APP_TITLE,
    AUTH_UNKNOWN,
    BG_APP,
    EvidenceCandidate,
    Path,
    REL_EXACT_ARTIFACT,
    REL_REBUILD_PEER,
    RepoSpec,
    Reporter,
    copy,
    evidence_relationship,
    filedialog,
    gpg_backend,
    mirrors_are_distinct,
    package_digest_map,
    path_to_file_url,
    redact_text,
    redact_url,
    repository_verification_strategy,
    simpledialog,
    threading,
    tk,
    ttk,
)
from feathered_app.ui.theme import messagebox


class RepositoriesMixin:
    """Repository editor workflows and repository trust configuration."""

    def _checksum_inspection_loader(self, repo):
        """Resolve the backend while distribution controls belong to the UI thread."""
        if repo.repo_format == "pacman" or self._is_arch():
            return arch_core.load_repository
        if repo.repo_format == "apt" or self._is_deb():
            return apt_core.load_repository
        return core.load_repository

    def _start_checksum_inspection(self, repo, finish):
        """Snapshot on the UI thread; workers return only through the event queue."""
        snapshot = copy.deepcopy(repo)
        arches = {self.arch_var.get()}
        loader = self._checksum_inspection_loader(repo)

        def work():
            try:
                coverage = inspect_checksums(snapshot, arches, Reporter(self._log), loader)
                result, error = list(coverage.algorithms), ""
                if coverage.package_count:
                    detected = ", ".join(a.upper().replace("SHA", "SHA-") for a in result) or "no strong SHA fields"
                    self._log(f"{snapshot.name}: checksum inspection read {coverage.package_count:,} package records; detected {detected}.")
                else:
                    reason = (apt_core.empty_repository_explanation(snapshot)
                              if snapshot.repo_format == "apt" or self._is_deb()
                              else "the repository currently publishes no package records for the selected target.")
                    self._log(
                        f"{snapshot.name}: checksum inspection read a valid empty package index; "
                        f"there are no package-level digests to inspect. {reason}")
            except Exception as exc:
                result, error = [], redact_text(str(exc))
                self._log(f"{snapshot.name}: checksum inspection failed: {error}")
            self.events.put(("checksum_inspection_finished", finish, result, error))

        threading.Thread(target=work, daemon=True).start()

    def _refresh_repository_transport_warning(self):
        labels = [self.__dict__.get(name) for name in (
            "repository_transport_warning", "provenance_transport_warning")]
        labels = [label for label in labels if label is not None]
        if not labels:
            return
        text = http_repository_advice(self._build_repository_scope())
        for label in labels:
            label.configure(text=text)
            if text:
                label.pack(fill="x", pady=(0, 12))
            else:
                label.pack_forget()

    def _sync_keyring_view(self):
        self._refresh_repository_transport_warning()
        if getattr(self, "keyring_tree", None):
            self._refresh_keyring_tree()
        self._refresh_provenance_tree()

    def _refresh_repo_tree_if_open(self):
        # No universe bookkeeping here any more: repo_rows *is* the active
        # universe's list, so a refresh has nothing to persist.
        self._refresh_base_repo_tree()
        self._refresh_workload_repository_views()
        self._sync_keyring_view()
        self._sync_custom_guidance()
        self._sync_mirror_repos()
        self._sync_entitlement_view()
        if not self.repo_tree or not self.repo_tree.winfo_exists(): return
        self.repo_tree.delete(*self.repo_tree.get_children())
        tier = getattr(self, "repo_window_tier", "additional")
        for i, r in enumerate(self.repo_rows):
            if tier != "all" and self._repo_tier(r) != tier:
                continue
            location = redact_url(r.url) if r.url else "<not configured>"
            if r.repo_format == "apt" and r.suite:
                location += f"  [suite={r.suite}; components={r.components or 'main'}]"
            trust, _tag = archive_keyring_state(r)
            strategy = repository_verification_strategy(r)
            if self._strategy_uses_evidence(strategy) and r.evidence_urls:
                rel = evidence_relationship(r, r.evidence_urls[0])
                rel_label = "rebuild peer" if rel == REL_REBUILD_PEER else "exact evidence"
                evidence = f"{self._strategy_policy_to_ui(strategy)} ({rel_label})"
            elif self._strategy_uses_evidence(strategy):
                evidence = "Evidence source needed"
            else:
                evidence = "Not used"
            compatible = self._repository_target_compatible(r)
            use_state = ("Yes" if r.enabled else "No") if compatible else "Target mismatch"
            status = "Not checked" if compatible else "Inactive for current target"
            self.repo_tree.insert("", "end", iid=str(i),
                                  values=(use_state, r.name, r.role, r.priority,
                                          trust, evidence, location, status))

    def _toggle_repo(self, _event=None):
        if not self.repo_tree: return
        sel = self.repo_tree.selection()
        if not sel: return
        i = int(sel[0]); self.repo_rows[i].enabled = not self.repo_rows[i].enabled
        self.loaded_signature = None; self.loaded_packages = []; self._refresh_repo_tree_if_open(); self._update_source_status()

    def add_url_repo(self, tier="additional", role=None):
        """Add a repository to base, workload, or supplemental source tiers."""
        tier = tier if tier in {"base", "workload", "additional"} else "additional"
        parent = self.repo_window if (tier in {"workload", "additional"} and self.repo_window and self.repo_window.winfo_exists()) else self
        if tier == "workload" and not role:
            role = simpledialog.askstring(
                "Workload repository role", "Role used by the workload (for example docker or gpu-vendor):",
                parent=parent)
            if not role:
                return
        role = (role or "dependency").strip() or "dependency"
        if self._is_deb():
            url = simpledialog.askstring(
                "APT repository URL", "APT archive root (the folder above dists/):", parent=parent)
            if not url:
                return
            suite = simpledialog.askstring(
                "APT suite", "Suite/codename (for example noble, noble-updates, trixie):",
                initialvalue=self._profile().codename(self.release_var.get().strip()), parent=parent)
            if not suite:
                return
            components = simpledialog.askstring(
                "APT components", "Space-separated components:", initialvalue="main", parent=parent)
            if not components:
                return
            name = simpledialog.askstring(
                "Repository name", "Display name:", initialvalue=f"APT {suite}", parent=parent) or f"APT {suite}"
            repo = RepoSpec(
                name, url.strip(), role, 60, True,
                ("User-added base APT repository" if tier == "base" else
                 "User-added workload APT repository" if tier == "workload" else "User-added APT repository"),
                self.release_var.get(), optional=False, repo_format="apt",
                suite=suite.strip(), components=components.strip())
        elif self._is_arch():
            url = simpledialog.askstring(
                "Pacman repository URL", "Repository directory URL containing <name>.db and package files:", parent=parent)
            if not url:
                return
            suite = simpledialog.askstring(
                "Pacman repository name", "Repository name/database prefix (for example core, extra, multilib):",
                initialvalue="custom", parent=parent)
            if not suite:
                return
            name = simpledialog.askstring(
                "Repository name", "Display name:", initialvalue=f"Arch {suite}", parent=parent) or f"Arch {suite}"
            repo = RepoSpec(
                name, url.strip(), role, 60, True,
                ("User-added base pacman repository" if tier == "base" else
                 "User-added workload pacman repository" if tier == "workload" else "User-added pacman repository"),
                "rolling", optional=False, repo_format="pacman", suite=suite.strip())
        else:
            url = simpledialog.askstring(
                "Repository URL", "Repository root containing repodata/repomd.xml:", parent=parent)
            if not url:
                return
            name = simpledialog.askstring(
                "Repository name", "Display name:", initialvalue="Custom repository", parent=parent) or "Custom repository"
            repo = RepoSpec(
                name, url.strip(), role, 60, True,
                ("User-added base repository" if tier == "base" else
                 "User-added workload repository" if tier == "workload" else "User-added repository"),
                self.release_var.get())
        repo = self._scope_operator_repository_to_current_target(repo)
        self.repo_rows.append(self._set_repo_tier(repo, tier))
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._refresh_repo_tree_if_open(); self._update_source_status()

    def add_local_repo(self, tier="additional", role=None):
        tier = tier if tier in {"base", "workload", "additional"} else "additional"
        parent = self.repo_window if (tier in {"workload", "additional"} and self.repo_window and self.repo_window.winfo_exists()) else self
        if tier == "workload" and not role:
            role = simpledialog.askstring(
                "Workload repository role", "Role used by the workload (for example docker or gpu-vendor):",
                parent=parent)
            if not role:
                return
        role = (role or "dependency").strip() or "dependency"
        if self._is_deb():
            path = filedialog.askdirectory(title="Choose APT repository root containing dists/", parent=parent)
            if not path:
                return
            p = Path(path).resolve()
            if not (p / "dists").is_dir():
                messagebox.showerror(APP_TITLE, "That folder does not contain an APT dists/ directory", parent=parent)
                return
            suite = simpledialog.askstring(
                "APT suite", "Suite/codename:",
                initialvalue=self._profile().codename(self.release_var.get().strip()), parent=parent)
            if not suite:
                return
            components = []
            suite_dir = p / "dists" / suite
            if suite_dir.is_dir():
                for comp in suite_dir.iterdir():
                    if comp.is_dir() and (comp / f"binary-{self.arch_var.get()}").is_dir():
                        components.append(comp.name)
            comp_text = simpledialog.askstring(
                "APT components", "Space-separated components:",
                initialvalue=" ".join(components) or "main", parent=parent)
            if not comp_text:
                return
            repo = RepoSpec(
                p.name or f"Local APT {suite}", path_to_file_url(p) + "/", role, 60, True,
                ("Local base APT repository" if tier == "base" else
                 "Local workload APT repository" if tier == "workload" else "Local APT repository"),
                self.release_var.get(), optional=False, repo_format="apt",
                suite=suite, components=comp_text.strip())
        elif self._is_arch():
            path = filedialog.askdirectory(title="Choose pacman repository directory containing <name>.db", parent=parent)
            if not path:
                return
            p = Path(path).resolve()
            dbs = sorted([x for x in p.glob("*.db") if x.is_file()])
            if not dbs:
                messagebox.showerror(APP_TITLE, "That folder does not directly contain a pacman .db repository database", parent=parent)
                return
            initial = dbs[0].name.rsplit(".db", 1)[0]
            suite = simpledialog.askstring(
                "Pacman repository name", "Repository database prefix:", initialvalue=initial, parent=parent)
            if not suite or not (p / f"{suite}.db").is_file():
                messagebox.showerror(APP_TITLE, f"{suite or '<empty>'}.db was not found in that folder", parent=parent)
                return
            repo = RepoSpec(
                p.name or f"Local Arch {suite}", path_to_file_url(p) + "/", role, 60, True,
                ("Local base pacman repository" if tier == "base" else
                 "Local workload pacman repository" if tier == "workload" else "Local pacman repository"),
                "rolling", optional=False, repo_format="pacman", suite=suite.strip())
        else:
            path = filedialog.askdirectory(title="Choose repository root containing repodata", parent=parent)
            if not path:
                return
            p = Path(path)
            if not (p / "repodata" / "repomd.xml").exists():
                messagebox.showerror(
                    APP_TITLE, "That folder does not directly contain repodata/repomd.xml", parent=parent)
                return
            repo = RepoSpec(
                p.name or "Local repository", path_to_file_url(p.resolve()) + "/",
                role, 60, True,
                ("Local base repository" if tier == "base" else
                 "Local workload repository" if tier == "workload" else "Local repository"),
                self.release_var.get())
        repo = self._scope_operator_repository_to_current_target(repo)
        self.repo_rows.append(self._set_repo_tier(repo, tier))
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._refresh_repo_tree_if_open(); self._update_source_status()

    def edit_repo(self):
        if not self.repo_tree:
            return
        sel = self.repo_tree.selection()
        if not sel:
            return
        self._edit_repo_at(int(sel[0]), self.repo_window or self)

    def edit_repo_trust(self, repo_index=None):
        """Configure package provenance first, then optional/manual keying.

        replaces the former Trust & Bond
        checkbox/text-area dialog with explicit SHA selection, missing-digest
        behavior, evidence fallback/corroboration modes, and repository-derived
        evidence choices. Manual URLs and keyring exceptions are deliberately
        placed at the bottom.
        """
        if repo_index is None:
            if not self.repo_tree:
                return
            sel = self.repo_tree.selection()
            if not sel:
                messagebox.showinfo(APP_TITLE, "Select a repository first.")
                return
            repo_index = int(sel[0])
        if repo_index < 0 or repo_index >= len(self.repo_rows):
            return
        repo = self.repo_rows[repo_index]

        win = tk.Toplevel(self.repo_window or self)
        win.configure(background=BG_APP)
        win.title(f"Provenance: {repo.name}")
        win.transient(self.repo_window or self); win.grab_set()
        win.geometry("760x720")
        outer = ttk.Frame(win, padding=14); outer.pack(fill="both", expand=True)
        canvas = tk.Canvas(outer, background=BG_APP, highlightthickness=0, bd=0)
        bar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=bar.set)
        canvas.pack(side="left", fill="both", expand=True); bar.pack(side="right", fill="y")
        frame = ttk.Frame(canvas); window_id = canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window_id, width=e.width))

        ttk.Label(frame, text=repo.name, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(frame, style="Hint.TLabel", wraplength=680, text=(
            "Repository: " + redact_url(repo.normalized_url) + ". This is an advanced per-repository override; "
            "the main Provenance & Keying stage applies common policy to all package sources participating in the current operation automatically."
        )).pack(anchor="w", pady=(4, 12))

        # --- Repository verification override ----------------------------
        quick = self._card(frame, "Repository verification")
        detected = self._detected_digest_algorithms(repo)
        detected_var = tk.StringVar(value=(
            "Detected strong SHA fields  " + ", ".join(a.upper().replace("SHA", "SHA-") for a in detected)
            if detected else
            "Checksum support has not been inspected for this repository."
        ))
        detect_row = ttk.Frame(quick, style="Panel.TFrame")
        detect_row.pack(fill="x", pady=(0, 9))
        ttk.Label(detect_row, textvariable=detected_var, style="PanelHint.TLabel",
                  wraplength=520).pack(side="left", fill="x", expand=True)

        digest_labels = {
            "auto": "Automatic",
            "sha256": "SHA-256 or stronger",
            "sha384": "SHA-384 or stronger",
            "sha512": "SHA-512",
        }
        reverse_digest = {v: k for k, v in digest_labels.items()}
        current_pref = getattr(repo, "digest_preference", "auto") or "auto"
        digest_values = list(digest_labels.values())
        drow = ttk.Frame(quick, style="Panel.TFrame")
        drow.pack(fill="x")
        ttk.Label(drow, text="Minimum checksum strength", style="Panel.TLabel").pack(side="left")
        digest_var = tk.StringVar(value=digest_labels.get(current_pref, digest_labels["auto"]))
        digest_combo = ttk.Combobox(
            drow, textvariable=digest_var, state="readonly", width=36, values=digest_values)
        digest_combo.pack(side="left", padx=(10, 0), fill="x", expand=True)
        self._bind_combobox_widget(digest_combo)

        strategy_labels = {
            "skip-provenance": "Skip upstream provenance checks (minimal)",
            "checksum-available": "Verify what is available (basic)",
            "checksum-required": "Require checksum coverage (strict)",
            "evidence-fallback": "Fill gaps with independent evidence (enhanced)",
            "full-corroboration": "Corroborate every package (maximum)",
        }
        reverse_strategy = {v: k for k, v in strategy_labels.items()}
        current_strategy = repository_verification_strategy(repo)
        srow_policy = ttk.Frame(quick, style="Panel.TFrame")
        srow_policy.pack(fill="x", pady=(10, 0))
        ttk.Label(srow_policy, text="Verification strategy", style="Panel.TLabel").pack(side="left")
        strategy_var = tk.StringVar(value=strategy_labels.get(current_strategy, strategy_labels["checksum-available"]))
        strategy_combo = ttk.Combobox(
            srow_policy, textvariable=strategy_var, state="readonly", width=36,
            values=list(strategy_labels.values()))
        strategy_combo.pack(side="left", padx=(10, 0), fill="x", expand=True)
        self._bind_combobox_widget(strategy_combo)
        strategy_help_var = tk.StringVar(value=self._strategy_help_text(
            reverse_strategy.get(strategy_var.get(), "checksum-available")))
        ttk.Label(quick, textvariable=strategy_help_var, style="PanelHint.TLabel",
                  wraplength=680).pack(anchor="w", pady=(5, 0))

        source_values, candidate_map, curated, auto_label, none_label, manual_label, _session_label = self._evidence_choices_for_repo(repo)
        candidate_specs = self._evidence_candidate_spec_map(repo)
        existing = list(getattr(repo, "evidence_urls", []) or [])
        source_initial = none_label
        if existing:
            source_initial = next((label for label, url in candidate_map.items()
                                   if existing[0].rstrip("/") == url.rstrip("/")), manual_label)
        evidence_row = ttk.Frame(quick, style="Panel.TFrame")
        evidence_row.pack(fill="x", pady=(11, 0))
        evidence_label = ttk.Label(evidence_row, text="Independent evidence source", style="Panel.TLabel")
        evidence_label.pack(side="left")
        source_var = tk.StringVar(value=source_initial)
        source_combo = ttk.Combobox(
            evidence_row, textvariable=source_var, state="readonly", width=36,
            values=source_values, style="Evidence.TCombobox")
        source_combo.pack(side="left", padx=(10, 0), fill="x", expand=True)
        self._bind_combobox_widget(source_combo)
        evidence_help = ttk.Label(
            quick, style="PanelHint.TLabel", wraplength=680,
            text="Exact mirrors are byte-for-byte evidence. A semantic rebuild peer is Maximum-only and answers a different question: whether another independently operated Enterprise Linux rebuild produced the same package/source lineage and a self-consistent signed/checksummed artifact. It does not prove identical RPM bytes and cannot fill an Enhanced checksum gap. Evidence copies are transient and never added to the bundle.")
        evidence_help.pack(anchor="w", pady=(5, 0))

        def inspect_sha_metadata():
            if self._busy():
                return
            if not self._claim_operation(
                    "repository-checksum-inspection",
                    f"Inspecting checksum support for {repo.name}", cancellable=False):
                return
            inspect_progress.start(12)
            detected_var.set("Inspecting checksum support")
            def finish(result, error):
                self.progress_var.set(0 if error else 100)
                self._release_operation(
                    "Checksum inspection failed" if error else "Checksum inspection complete",
                    outcome=("failed" if error else "idle"))
                if not win.winfo_exists():
                    return
                inspect_progress.stop()
                if error:
                    detected_var.set("Inspection failed  " + error)
                    return
                detected_var.set(
                    "Detected strong SHA fields  " + ", ".join(a.upper().replace("SHA", "SHA-") for a in result)
                    if result else "No SHA-256, SHA-384, or SHA-512 package fields were found.")
                digest_combo.configure(values=list(digest_labels.values()))

            self._start_checksum_inspection(repo, finish)

        inspect_btn = ttk.Button(detect_row, text="Inspect checksum support", command=inspect_sha_metadata)
        inspect_btn.pack(side="right", padx=(10, 0))
        self._register_operation_control(inspect_btn)
        win.bind("<Destroy>", lambda e: self._unregister_operation_control(inspect_btn)
                 if e.widget is win else None, add="+")
        inspect_progress = ttk.Progressbar(quick, mode="indeterminate")
        inspect_progress.pack(fill="x", pady=(2, 0))
        self._panel_hint(
            quick,
            "Explicit SHA choices are minimum strengths and stay selectable regardless of direct coverage. Enhanced fills missing coverage by comparing independently downloaded bytes; a local match does not create a publisher-issued checksum.",
            pady=(7, 0))

        # --- Advanced/manual controls -------------------------------------
        advanced = self._card(frame, "Advanced provenance details", pady=(14, 0))
        self._panel_hint(advanced,
            "Manual mirror entry, archive key material, and repository exceptions live here so the common verification path stays simple.", pady=(0, 9))
        ttk.Label(advanced, text="Manual evidence URL (session only)", style="Panel.TLabel").pack(anchor="w")
        manual_url_var = tk.StringVar(value=(existing[0] if existing and source_initial == manual_label else ""))
        manual_url_entry = ttk.Entry(advanced, textvariable=manual_url_var)
        manual_url_entry.pack(fill="x", pady=(4, 10))

        keyring_var = tk.StringVar(value=repo.keyring)
        krow = ttk.Frame(advanced, style="Panel.TFrame"); krow.pack(fill="x")
        ttk.Label(krow, text="Archive keyring (optional)", style="Panel.TLabel").pack(side="left")
        keyring_entry = ttk.Entry(krow, textvariable=keyring_var, width=48)
        keyring_entry.pack(side="left", padx=(8, 6), fill="x", expand=True)
        def browse():
            picked = filedialog.askopenfilename(
                title="Repository signing keyring",
                filetypes=[("Keyring", "*.gpg *.asc *.key *.pgp"), ("All files", "*.*")], parent=win)
            if picked:
                keyring_var.set(picked)
        ttk.Button(krow, text="Browse…", command=browse).pack(side="left")
        self._panel_hint(advanced,
            "Manual evidence URLs are temporary for the current Feathered session and are never added to the reusable evidence choices. "
            "Optional. This authenticates signed archive metadata and remains independent from mirror evidence.",
            pady=(4, 0))

        exception_row = ttk.Frame(advanced, style="Panel.TFrame"); exception_row.pack(fill="x", pady=(12, 0))
        ttk.Label(exception_row, text="Repository index policy", style="Panel.TLabel").pack(side="left")
        unverified_var = tk.StringVar(value=(
            "Permit an unverified index" if repo.allow_unverified_index
            else "Require verifiable index metadata"))
        unverified_combo = ttk.Combobox(
            exception_row, textvariable=unverified_var, state="readonly", width=38,
            values=["Require verifiable index metadata", "Permit an unverified index"])
        unverified_combo.pack(side="left", padx=(10, 0))
        self._panel_hint(advanced,
            "Optional but weakens archive provenance. Use only for a trusted internal mirror that publishes incomplete metadata.",
            pady=(2, 0))

        query_card = self._card(frame, "Endpoint query credentials", pady=(14, 0))
        self._panel_hint(
            query_card,
            "Built-in names such as token, access_token, api_key, password, and signed-URL fields are always protected. "
            "Add vendor-specific query parameter names here so they are treated as credentials and redacted from logs and bundle metadata.",
            pady=(0, 8))
        sensitive_query_var = tk.StringVar(value=", ".join(
            getattr(repo, "sensitive_query_keys", []) or []))
        ttk.Label(query_card, text="Additional sensitive query fields", style="Panel.TLabel").pack(anchor="w")
        sensitive_query_entry = ttk.Entry(query_card, textvariable=sensitive_query_var)
        sensitive_query_entry.pack(fill="x", pady=(4, 8))
        self._panel_hint(
            query_card,
            "Comma- or space-separated names, for example license_token or subscription_key. Values are never written to audit metadata.",
            pady=(0, 8))

        inheritable_query_var = tk.StringVar(value=", ".join(
            getattr(repo, "inheritable_query_credential_keys", []) or []))
        ttk.Label(query_card, text="Same-origin fields safe to inherit", style="Panel.TLabel").pack(anchor="w")
        inheritable_query_entry = ttk.Entry(query_card, textvariable=inheritable_query_var)
        inheritable_query_entry.pack(fill="x", pady=(4, 4))
        self._panel_hint(
            query_card,
            "Leave blank unless the repository expects a bearer field to be copied from its root URL to child metadata and package URLs. "
            "Signed or resource-bound query fields should not be inherited.",
            pady=(0, 0))

        def query_names(text):
            return sorted(normalize_query_key_names(text.replace(",", " ").split()))
        # Never let a verifier-integrity failure abort dialog construction and
        # leave a half-built Toplevel on screen.
        try:
            verifier = gpg_backend()
        except RuntimeError as exc:
            verifier = None
            self._panel_hint(advanced, f"Bundled OpenPGP verifier failed authentication: {exc}",
                             pady=(8, 0))
        else:
            if verifier is None:
                self._panel_hint(advanced,
                    "GnuPG is not installed. Archive-keyring verification will fail if a keyring is configured; "
                    "package digest and independent evidence modes remain available.", pady=(8, 0))

        # Match the main page: minimum checksum strength plus one strategy.
        def update_advanced_state():
            strategy = reverse_strategy.get(strategy_var.get(), "checksum-available")
            active = self._strategy_uses_evidence(strategy)
            skip_upstream = strategy == "skip-provenance"
            digest_combo.configure(state="disabled" if skip_upstream else "readonly")
            source_combo.configure(style="Evidence.TCombobox",
                                   state="readonly" if active else "disabled")
            evidence_label.configure(style="Panel.TLabel" if active else "MutedPanel.TLabel")
            evidence_help.configure(style="PanelHint.TLabel" if active else "MutedPanelHint.TLabel")
            manual_url_entry.configure(
                state="normal" if active and source_var.get() == manual_label else "disabled")
            strategy_help_var.set(self._strategy_help_text(strategy))

        def sync_settings(_event=None):
            old = (
                repo.digest_preference, repo.digest_requirement, repo.evidence_policy,
                getattr(repo, "verification_strategy", ""), tuple(repo.evidence_urls),
                repo.keyring, repo.allow_unverified_index,
                tuple(getattr(repo, "sensitive_query_keys", []) or []),
                tuple(getattr(repo, "inheritable_query_credential_keys", []) or []))
            repo.digest_preference = reverse_digest.get(digest_var.get(), "auto")
            strategy = reverse_strategy.get(strategy_var.get(), "checksum-available")
            repo.verification_strategy = strategy
            repo.digest_requirement, repo.evidence_policy = {
                "checksum-required": ("required", "off"),
                "checksum-available": ("preferred", "off"),
                "evidence-fallback": ("preferred", "fallback"),
                "full-corroboration": ("required", "required"),
                "skip-provenance": ("preferred", "off"),
            }[strategy]
            repo.keyring = keyring_var.get().strip()
            repo.allow_unverified_index = unverified_var.get().startswith("Permit")
            repo.sensitive_query_keys = query_names(sensitive_query_var.get())
            repo.inheritable_query_credential_keys = query_names(inheritable_query_var.get())

            choice = source_var.get()
            urls = list(repo.evidence_urls or [])
            selected_spec = None
            if choice == none_label:
                urls = []
            elif choice == manual_label:
                manual = manual_url_var.get().strip()
                urls = [manual] if manual else []
                if urls:
                    selected_spec = EvidenceCandidate(urls[0], "Manual evidence source",
                                                      REL_EXACT_ARTIFACT, AUTH_UNKNOWN, "manual")
            elif choice in candidate_specs:
                selected_spec = candidate_specs[choice]
                urls = [selected_spec.url]
            elif choice in candidate_map:
                urls = [candidate_map[choice]]
            if urls:
                distinct, _reason = mirrors_are_distinct(repo.normalized_url, urls[0])
                if not distinct:
                    urls = []
                    selected_spec = None
            repo.evidence_urls = urls
            repo.evidence_relationship_hints = {}
            repo.evidence_authority_hints = {}
            if urls and selected_spec is not None:
                repo.evidence_relationship_hints[urls[0]] = selected_spec.relationship
                repo.evidence_authority_hints[urls[0]] = selected_spec.authority

            new = (
                repo.digest_preference, repo.digest_requirement, repo.evidence_policy,
                repo.verification_strategy, tuple(repo.evidence_urls), repo.keyring,
                repo.allow_unverified_index,
                tuple(repo.sensitive_query_keys),
                tuple(repo.inheritable_query_credential_keys))
            if new != old:
                self._invalidate_provenance_analysis()
                self._refresh_repo_tree_if_open()
                self._log(
                    f"Advanced provenance override for {repo.name}. "
                    f"Minimum checksum {repo.digest_preference}; strategy {strategy}; "
                    f"evidence sources {len(repo.evidence_urls)}; archive keyring "
                    f"{'configured' if repo.keyring else 'not configured'}.")
            update_advanced_state()

        digest_combo.bind("<<ComboboxSelected>>", sync_settings)
        strategy_combo.bind("<<ComboboxSelected>>", sync_settings)
        source_combo.bind("<<ComboboxSelected>>", sync_settings)
        manual_url_entry.bind("<FocusOut>", sync_settings)
        manual_url_entry.bind("<Return>", sync_settings)
        keyring_entry.bind("<FocusOut>", sync_settings)
        unverified_combo.bind("<<ComboboxSelected>>", sync_settings)
        sensitive_query_entry.bind("<FocusOut>", sync_settings)
        sensitive_query_entry.bind("<Return>", sync_settings)
        inheritable_query_entry.bind("<FocusOut>", sync_settings)
        inheritable_query_entry.bind("<Return>", sync_settings)
        update_advanced_state()

        # The Browse callback sets keyring_var; apply that selection immediately.
        original_browse = browse
        def browse_live():
            original_browse()
            sync_settings()
        # Replace the first Browse button in the keyring row with a live one.
        for child in krow.winfo_children():
            if isinstance(child, ttk.Button) and child.cget("text") == "Browse…":
                child.configure(command=browse_live)
                break

        actions = ttk.Frame(frame); actions.pack(fill="x", pady=(16, 10))
        ttk.Button(actions, text="Done", command=win.destroy, style="Primary.TButton").pack(side="right")
        ttk.Label(actions, text="Changes apply immediately.", style="PanelHint.TLabel").pack(side="right", padx=(0, 12))

    def remove_repo(self):
        if not self.repo_tree:
            return
        sel = self.repo_tree.selection()
        if not sel:
            return
        del self.repo_rows[int(sel[0])]
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self._refresh_repo_tree_if_open(); self._update_source_status()
