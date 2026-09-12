"""Inventory/output interaction, result rendering, warning confirmation, and trust options.

"""

from feathered_app.build_preparation import BuildPreparationMixin, prepare_job, DecisionDeclined

from feathered_app.context import (
    ACCENT,
    ACCENT_DIM,
    APP_TITLE,
    BG_APP,
    BG_INPUT,
    ERR_FG,
    FG_TEXT,
    FOLDER_SCHEMES,
    LINE,
    OK_FG,
    Path,
    WARN_FG,
    filedialog,
    infer_vendor_id,
    redact_text,
    threading,
    tk,
    ttk,
)
from feathered_app.ui.theme import human_size, messagebox


RESULT_REVIEW_PAGE_SIZE = 1000


def _paginate_packages(packages, *, page: int = 0, page_size: int = RESULT_REVIEW_PAGE_SIZE):
    """Return one complete, contiguous page from a package result sequence.

    Pagination is deliberately different from the old Review preview: every
    package remains addressable through the page controls and ordering is never
    sampled or round-robin rewritten.  The returned page index is clamped so a
    stale page remains valid after a result or page-size change.
    """
    items = list(packages or [])
    page_size = max(1, int(page_size))
    page_count = max(1, (len(items) + page_size - 1) // page_size)
    page = min(max(0, int(page)), page_count - 1)
    start = page * page_size
    return items[start:start + page_size], page, page_count, start


class ResultsMixin(BuildPreparationMixin):
    """Inventory/output interaction, result rendering, warning confirmation, and trust options."""

    def choose_inventory(self):
        p = filedialog.askopenfilename(title="Target inventory", filetypes=[("Inventory/text", "*.txt"), ("All files", "*.*")])
        if not p:
            return
        try:
            inv = self._parse_target_inventory_backend(Path(p))
        except Exception as exc:
            # Target-aware mode REMOVES packages from the bundle, so a
            # rejected inventory must not stay selected: silently resolving
            # against an empty inventory is how an unusable bundle gets built.
            self.inventory_var.set("")
            self._log(f"Rejected target inventory {p}: {exc}")
            messagebox.showerror(APP_TITLE, redact_text(str(exc)))
            return
        count = len(inv.packages) if (self._is_deb() or self._is_arch()) else len(inv.nevras)
        if count == 0:
            self.inventory_var.set("")
            messagebox.showerror(APP_TITLE, "That inventory lists no installed packages. "
                                            "Re-run target_inventory.sh on the target and copy the file it writes.")
            return
        self.inventory_var.set(p); self.mode_var.set("Target-aware complete"); self._mode_changed()
        detected = f"{inv.metadata.get('id', '')} {inv.metadata.get('version_id', '')} {inv.metadata.get('arch', '')}".strip()
        self._log(f"Loaded target inventory: {count} packages" + (f" ({detected})" if detected else ""))
        self._warn_on_inventory_mismatch(inv)

    def _warn_on_inventory_mismatch(self, inv):
        """Flag an inventory collected from a different release or architecture."""
        arch = (inv.metadata.get("arch") or "").strip()
        arch_aliases = {"x86_64": {"x86_64", "amd64"}, "amd64": {"x86_64", "amd64"},
                        "aarch64": {"aarch64", "arm64"}, "arm64": {"aarch64", "arm64"}}
        selected = self.arch_var.get().strip()
        if arch and selected and selected not in arch_aliases.get(arch, {arch}):
            messagebox.showwarning(APP_TITLE, f"The inventory was collected on {arch}, but the selected "
                                              f"target architecture is {selected}. Dependencies may be "
                                              "skipped incorrectly.")
        version_id = (inv.metadata.get("version_id") or "").strip()
        release = self.release_var.get().strip()
        if version_id and release and not (release.startswith(version_id) or version_id.startswith(release)):
            self._log(f"NOTE: inventory reports release {version_id}; the selected target release is {release}.")

    def browse_output(self):
        p = filedialog.askdirectory(title="Output folder")
        if p: self.out_var.set(p)

    def show_details(self, focus_trust: bool = False, warnings=None, decision_callback=None):
        """Show the complete activity log with a dedicated trust-review section.

        1.0.42 replaces terse trust
        message-boxes and package-table pseudo-errors with one scrollable review
        surface. When a build needs an explicit trust decision, the same window
        gains Continue/Cancel controls; closing it is equivalent to cancelling
        that build, while ordinary log viewing remains non-modal.
        """
        trust_findings = list(self.last_warnings if warnings is None else warnings)
        win = tk.Toplevel(self)
        win.title("Activity log")
        win.geometry("1040x680")
        win.minsize(760, 460)
        win.configure(background=BG_APP)

        decision_made = {"value": False}

        def finish_decision(accepted: bool):
            if decision_made["value"]:
                return
            decision_made["value"] = True
            try:
                if decision_callback is not None:
                    decision_callback(bool(accepted))
            finally:
                try:
                    if decision_callback is not None:
                        win.grab_release()
                except tk.TclError:
                    pass
                try:
                    win.destroy()
                except tk.TclError:
                    pass

        if decision_callback is not None:
            # Every escape route is wired BEFORE the grab, not after the window
            # is fully built. A decision dialog grabs all input, and the worker
            # thread is blocked on an Event until this callback fires, so a
            # failure anywhere in the construction below previously left a modal
            # window with no close handler and a build that could never finish:
            # the application was locked and the traceback went to a stderr that
            # does not exist in a windowed build.
            #
            # Closing, Escape, and destruction by any other means all count as
            # cancelling the build, which is the safe answer to a trust question
            # the operator never actually saw.
            win.protocol("WM_DELETE_WINDOW", lambda: finish_decision(False))
            win.bind("<Escape>", lambda _e: finish_decision(False))
            win.bind("<Destroy>",
                     lambda event: finish_decision(False) if event.widget is win else None)
            win.transient(self)
            win.grab_set()

        frame = ttk.Frame(win, padding=12)
        frame.pack(fill="both", expand=True)
        bar = ttk.Frame(frame)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        ttk.Label(bar, text=f"{len(self.log_lines)} activity line(s)",
                  style="Hint.TLabel").pack(side="left")
        if trust_findings:
            ttk.Label(bar, text=f"{len(trust_findings)} trust finding(s)",
                      style="Hint.TLabel").pack(side="left", padx=(16, 0))

        text = tk.Text(frame, wrap="word", font=("Consolas", 9),
                       background=BG_INPUT, foreground=FG_TEXT, insertbackground=FG_TEXT,
                       selectbackground=ACCENT_DIM, selectforeground=FG_TEXT,
                       relief="flat", borderwidth=0, highlightthickness=1,
                       highlightbackground=LINE, highlightcolor=LINE, padx=12, pady=10)
        tv = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=tv.set)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)
        text.grid(row=1, column=0, sticky="nsew")
        tv.grid(row=1, column=1, sticky="ns")

        text.tag_configure("section", foreground=ACCENT,
                           font=("Consolas", 10, "bold"), spacing1=4, spacing3=4)
        text.tag_configure("trust", foreground=WARN_FG, lmargin1=16, lmargin2=16,
                           spacing1=2, spacing3=4)
        text.tag_configure("err", foreground=ERR_FG)
        text.tag_configure("warn", foreground=WARN_FG)
        text.tag_configure("ok", foreground=OK_FG)
        if trust_findings:
            text.insert("end", "TRUST AND PROVENANCE REVIEW\n", "section")
            text.insert("end", "These findings describe repository or provenance confidence; "
                                "they are not Feathered application errors.\n\n")
            for index, finding in enumerate(trust_findings, 1):
                # Preserve the entire reporter message. Long findings wrap in
                # this scrollable view instead of being truncated in a table.
                text.insert("end", f"{index}. {finding}\n", "trust")
            text.insert("end", "\n")

        activity_mark = text.index("end")
        text.insert("end", "ACTIVITY LOG\n", "section")
        for line in self.log_lines:
            lower = line.lower()
            if any(k in lower for k in ("error", "failed", "unresolved", "refus", "traceback")):
                tag = "err"
            elif any(k in lower for k in ("warning", "conflict", "unverified", "stale", "trust:")):
                tag = "warn"
            elif any(k in lower for k in ("verified", "complete", "wrote", "learned")):
                tag = "ok"
            else:
                tag = ""
            text.insert("end", line + "\n", tag)

        def copy_all():
            self.clipboard_clear()
            self.clipboard_append(text.get("1.0", "end-1c"))

        ttk.Button(bar, text="Copy all", command=copy_all).pack(side="right")

        if decision_callback is not None:
            ttk.Button(bar, text="Cancel build",
                       command=lambda: finish_decision(False)).pack(side="right", padx=(8, 0))
            ttk.Button(bar, text="Continue build", style="Primary.TButton",
                       command=lambda: finish_decision(True)).pack(side="right", padx=(8, 0))
        else:
            ttk.Button(bar, text="Close", command=win.destroy).pack(side="right", padx=(8, 0))

        if focus_trust and trust_findings:
            text.see("1.0")
        else:
            text.see(activity_mark)
        text.configure(state="disabled")
        return win

    def _refresh_trust_review_bar(self) -> None:
        """Show a compact pointer to trust findings without polluting results."""
        bar = getattr(self, "trust_review_bar", None)
        if bar is None:
            return
        findings = list(getattr(self, "last_warnings", []) or [])
        if not findings:
            try:
                bar.pack_forget()
            except tk.TclError:
                pass
            if getattr(self, "trust_review_var", None) is not None:
                self.trust_review_var.set("")
            return
        noun = "finding" if len(findings) == 1 else "findings"
        self.trust_review_var.set(
            f"Trust review: {len(findings)} {noun} recorded. Full details are available in the log.")
        try:
            bar.pack(fill="x", pady=(6, 10), before=self.result_glow_frame)
        except (tk.TclError, AttributeError):
            bar.pack(fill="x", pady=(6, 10))

    def _apply_warnings(self, warnings) -> None:
        """Record full trust findings in the log and refresh the compact UI."""
        self.last_warnings = list(warnings or [])
        if self.last_warnings:
            # Reporter.warn() has already written each full finding to the
            # activity stream. Keep one durable marker here rather than
            # duplicating every message a second time.
            self._log(f"TRUST REVIEW: {len(self.last_warnings)} finding(s) retained for review")
        self._refresh_trust_review_bar()

    def _result_package_identity(self, package, *, mirror_rows: bool | None = None) -> str:
        """Stable UI/event identity for a result package."""
        if mirror_rows is None:
            mirror_rows = self._mirror_mode()
        return (f"{package.repo.source_identity}|{package.nevra}"
                if mirror_rows else package.nevra)

    def _ordered_result_packages(self, result):
        """Return the complete package result in the active Review ordering.

        Heading sorts apply to the entire result set, not merely the currently
        rendered page.  With no active sort, resolver/repository order is
        preserved exactly.
        """
        packages = list(getattr(result, "selected", []) or [])
        column, descending = getattr(self, "_result_sort", (None, False))
        if column not in {"package", "status", "source", "reason"}:
            return packages
        mirror_rows = self._mirror_mode()
        states = getattr(self, "_result_item_states", {}) or {}

        def key(package):
            identity = self._result_package_identity(package, mirror_rows=mirror_rows)
            state = states.get(identity) or {}
            reason = state.get("detail") or result.reasons.get(package.nevra, "dependency")
            values = {
                "package": package.nevra,
                "status": state.get("status", "queued"),
                "source": package.repo.name,
                "reason": reason,
            }
            # Deterministic tie-breakers keep page boundaries stable.
            return (str(values[column]).lower(), package.nevra.lower(),
                    str(package.repo.source_identity).lower())

        packages.sort(key=key, reverse=bool(descending))
        return packages

    def _result_page_size_value(self) -> int:
        var = getattr(self, "result_page_size_var", None)
        raw = var.get() if var is not None else getattr(self, "result_page_size", RESULT_REVIEW_PAGE_SIZE)
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            return RESULT_REVIEW_PAGE_SIZE

    def _set_result_page(self, page: int) -> None:
        if self.last_result is None:
            return
        self.result_page = max(0, int(page))
        self._render_result_page(self.last_result)

    def _result_page_size_changed(self, _event=None) -> None:
        self.result_page_size = self._result_page_size_value()
        self.result_page = 0
        if self.last_result is not None:
            self._render_result_page(self.last_result)

    def _last_result_page(self) -> None:
        if self.last_result is None:
            return
        total = len(getattr(self.last_result, "selected", []) or [])
        last = max(0, (total - 1) // self._result_page_size_value())
        self._set_result_page(last)

    def _refresh_result_pagination_controls(self, total: int, page: int,
                                            page_count: int, start: int,
                                            visible_count: int) -> None:
        bar = getattr(self, "result_page_bar", None)
        if bar is None:
            return
        if total <= self._result_page_size_value():
            bar.grid_remove()
            return
        end = start + visible_count
        self.result_page_var.set(
            f"Packages {start + 1:,}–{end:,} of {total:,}   ·   Page {page + 1:,} of {page_count:,}")
        self.result_first_btn.configure(state="disabled" if page <= 0 else "normal")
        self.result_prev_btn.configure(state="disabled" if page <= 0 else "normal")
        last = page >= page_count - 1
        self.result_next_btn.configure(state="disabled" if last else "normal")
        self.result_last_btn.configure(state="disabled" if last else "normal")
        bar.grid()

    def _render_result_page(self, result) -> None:
        """Render one page while retaining the complete result as UI state."""
        self.result_tree.delete(*self.result_tree.get_children())
        self.result_rows = {}
        self.unresolved_rows = {}
        pick = self._pick_mode()
        mirror_rows = self._mirror_mode()
        off, on = self._checkbox_images() if pick else (None, None)

        ordered = self._ordered_result_packages(result)
        page_size = self._result_page_size_value()
        visible_packages, page, page_count, start = _paginate_packages(
            ordered, page=getattr(self, "result_page", 0), page_size=page_size)
        self.result_page = page
        self.result_page_size = page_size
        self._refresh_result_pagination_controls(
            len(ordered), page, page_count, start, len(visible_packages))

        # Actionable issue rows stay pinned on every package page so changing
        # pages cannot hide an unresolved requirement or conflict notice.
        for req in result.unresolved:
            key = self._format_requirement_backend(req)
            ignored = key in self.ignored_unresolved
            if (not self._is_deb()) and req.name.startswith("("):
                fallback_reason = "RPM rich dependency could not be resolved automatically"
            elif self._is_deb():
                fallback_reason = "No matching provider in enabled APT repositories"
            else:
                fallback_reason = "No matching provider in enabled repositories"
            reason = result.unresolved_notes.get(key, fallback_reason)
            if ("Python virtual capability" in reason and
                    self.source_method_var.get() == "Public EL-compatible mirrors (recommended fallback)"):
                reason += " Try the EPEL fallback if this package is outside the base EL set."

            lower_reason = reason.lower()
            if "unsupported" in lower_reason or "ambiguous" in lower_reason:
                source = "resolver syntax"
                status = "needs input"
            elif "version" in lower_reason or "providers exist" in lower_reason:
                source = "provider/version"
                status = "blocked"
            elif req.name.startswith("("):
                source = "dependency choice"
                status = "blocked"
            else:
                source = "missing provider"
                status = "blocked"
            prefix = "IGNORED" if ignored else "UNRESOLVED"
            row_reason = ("Operator waiver. " + reason) if ignored else reason
            iid = self.result_tree.insert(
                "", "end", tags=(("warn",) if ignored else ("issue",)),
                values=(f"{prefix}: {key}", "waived" if ignored else status, source, row_reason))
            self.unresolved_rows[iid] = key

        # Conflict notices are not silently truncated.  They are normally few,
        # and unlike package records they are review blockers/notices rather
        # than a bulk inventory suitable for package pagination.
        for conflict in result.conflicts:
            self.result_tree.insert("", "end", tags=("warn",),
                                    values=(f"CONFLICT: {conflict}", "review",
                                            "target/selection", "Review before installation"))

        states = getattr(self, "_result_item_states", {}) or {}
        for package in visible_packages:
            identity = self._result_package_identity(package, mirror_rows=mirror_rows)
            state = states.get(identity) or {}
            checked = package.nevra in self.picked
            tag = state.get("tag") or (("ok" if checked else "pending") if pick else "pending")
            reason = state.get("detail") or result.reasons.get(package.nevra, "dependency")
            iid = self.result_tree.insert(
                "", "end", image=(on if checked else off) if pick else "",
                tags=(tag,),
                values=(package.nevra, state.get("status", "queued"), package.repo.name, reason))
            self.result_rows[identity] = iid

        self.result_tree.column("#0", width=42 if pick else 0, stretch=False)
        self._update_unresolved_actions()

    def _show_result(self, result):
        # A successful analysis proves the archive served this release, which is
        # the right moment to remember a hand-typed one.
        if result.selected:
            self._remember_release(self.release_var.get())
        same_result = result is getattr(self, "last_result", None)
        self.last_result = result
        # Bind the result to the parameters it was computed from.
        self.analysis_signature = self._parameter_signature()
        current_unresolved_keys = {self._format_requirement_backend(req) for req in result.unresolved}
        self.ignored_unresolved.intersection_update(current_unresolved_keys)
        result.ignored_unresolved = sorted(self.ignored_unresolved)
        pick = self._pick_mode()
        # Everything starts included, so the operator removes rather than adds.
        # But a build re-runs the analysis, and unconditionally resetting here
        # discarded a selection the operator had just made - deselecting
        # everything and pressing Build silently downloaded the whole closure.
        # Keep the previous choice when the closure itself has not changed.
        current = {p.nevra for p in result.selected}
        previous = getattr(self, "picked_closure", None)
        if pick and previous == current and getattr(self, "picked", None) is not None:
            self.picked = {n for n in self.picked if n in current}
        else:
            self.picked = set(current) if pick else set()
        self.picked_closure = current if pick else None
        if not same_result:
            self.result_page = 0
            self._result_item_states = {}
        self._render_result_page(result)

        if pick:
            self.pick_bar.pack(fill="x", pady=(10, 12), before=self.result_glow_frame)
        else:
            self.pick_bar.pack_forget()

        # trust warnings are intentionally
        # not inserted into this table. They are repository-provenance findings,
        # not package failures; the full text is available through the Activity
        # log and the compact trust-review strip above this list.
        self._refresh_trust_review_bar()
        if getattr(self, "panes", None) and self.active_pane != "review":
            self.show_pane("review")
        blocking = self._blocking_unresolved(result)
        ignored_count = len(self.ignored_unresolved)
        complete = len(blocking) == 0
        if result.unresolved or self.ignored_unresolved:
            self.unresolved_bar.pack(fill="x", pady=(6, 10), before=self.result_glow_frame)
            if pick and self.pick_bar.winfo_manager():
                # Keep problem-resolution actions above optional package picking.
                self.pick_bar.pack_forget()
                self.pick_bar.pack(fill="x", pady=(0, 12), after=self.unresolved_bar)
            self.retry_unresolved_btn.configure(state="normal" if blocking else "disabled")
        else:
            self.unresolved_bar.pack_forget()
        self._update_unresolved_actions()
        package_only = bool(getattr(self, "_package_only_acquisition_mode", lambda: False)())
        if package_only and complete:
            status = "PACKAGE ONLY - DEPENDENCIES NOT DERIVED"
        elif complete and ignored_count:
            status = "READY WITH WAIVERS"
        elif complete and result.conflicts:
            status = "CONFLICTS REQUIRE REVIEW"
        elif complete:
            status = "CLOSURE RESOLVED - NATIVE TARGET CHECK REQUIRED"
        else:
            status = "INCOMPLETE"
        noun = "DEBs" if self._is_deb() else "Arch packages" if self._is_arch() else "RPMs"
        warned = len(getattr(self, "last_warnings", []) or [])
        mirror_summaries = list(getattr(result, "mirror_repository_summaries", []) or [])
        if self._mirror_mode() and mirror_summaries:
            parts = [
                f"{status}",
                f"{len(mirror_summaries)} repository mirror(s)",
                f"{len(result.selected)} package record(s)",
                human_size(result.total_size),
                f"{len(blocking)} blocking unresolved",
            ]
        else:
            parts = [
                f"{status}",
                f"{len(result.selected)} {noun}",
                human_size(result.total_size),
                f"{len(blocking)} blocking unresolved",
            ]
        if ignored_count:
            parts.append(f"{ignored_count} ignored")
        parts.append(f"{len(result.conflicts)} conflict notice(s)")
        if warned:
            parts.append(f"{warned} trust finding(s) in log")
        self.summary_var.set("  |  ".join(parts))
        self._refresh_download_size_preview(result)
        self._sync_review_action_states()

    def _apply_probe(self, idx, ok, detail):
        if self.repo_tree and self.repo_tree.winfo_exists() and str(idx) in self.repo_tree.get_children():
            vals = list(self.repo_tree.item(str(idx), "values")); vals[-1] = "Healthy" if ok else "Failed"
            self.repo_tree.item(str(idx), values=vals)
        self._log(f"{'OK' if ok else 'FAIL'} {self.repo_rows[idx].name}: {detail}")

    def _ask_on_ui_thread(self, title: str, message: str, *, wait_status: str | None = None) -> bool:
        """Ask the caller's decision policy a yes/no question.

        The single chokepoint for every mid-build prompt -- conflict notices and
        dependency waivers both arrive here -- so this one seam decouples all of
        them from the UI. Whoever runs the build supplies the policy: the GUI
        asks a person, `feathered_cli.py` declines unless explicitly told
        otherwise, and a test supplies a constant.

        A caller with no policy gets the interactive prompt, so the wizard is
        unchanged.
        """
        policy = self.__dict__.get("_decision_policy")
        if callable(policy):
            return bool(policy(title, message))
        ask = getattr(self, "_gui_ask_on_ui_thread", None)
        if not callable(ask):
            # Nothing can answer, and the safe response to an unreviewed
            # question is no.
            return False
        # Coerced like the policy path: every caller treats this as a yes/no,
        # so neither branch may hand back something merely truthy.
        return bool(ask(title, message, wait_status=wait_status))

    def _gui_ask_on_ui_thread(self, title: str, message: str, *,
                              wait_status: str | None = None) -> bool:
        """The interactive policy: prompt on the main loop and block the worker.

        Tk is not thread-safe, so the dialog is scheduled onto the main loop
        and the worker blocks on an Event until the operator responds.  While
        the worker is blocked, the footer explicitly enters a static amber
        review state instead of continuing to advertise active work.
        """
        answered = threading.Event()
        decision = {"ok": False}

        def ask():
            enter_wait = getattr(self, "_set_operator_wait", None)
            resume_wait = getattr(self, "_resume_after_operator_wait", None)
            if callable(enter_wait):
                enter_wait(wait_status or "Build paused pending your response")
            try:
                decision["ok"] = bool(messagebox.askyesno(title, message, default="no"))
            except Exception:
                # An unanswerable prompt cancels rather than hanging: the worker
                # is blocked on answered.wait() with no timeout.
                decision["ok"] = False
                release = getattr(self, "_release_stuck_grab", None)
                if callable(release):
                    release()
            finally:
                if callable(resume_wait):
                    resume_wait("Continuing build" if decision["ok"] else "Cancelling build")
                answered.set()

        self.after(0, ask)
        answered.wait()
        return decision["ok"]

    def _confirm_conflicts(self, conflicts) -> bool:
        preview = "\n".join(f"  • {c}" for c in conflicts[:8])
        extra = f"\n  … and {len(conflicts) - 8} more" if len(conflicts) > 8 else ""
        return self._ask_on_ui_thread(
            APP_TITLE,
            f"This closure declares {len(conflicts)} conflict notice(s):\n\n{preview}{extra}\n\n"
            "Some are expected (for example podman-docker replacing the Docker CLI); others mean the "
            "transaction will fail on the target. Build the bundle anyway?",
            wait_status="Build paused for the conflict decision")

    def _confirm_warnings(self, warnings) -> bool:
        """Decide whether a build proceeds despite trust findings.

        This is the build worker's only UI dependency, and it is deliberately an
        injection point rather than a call into Tk. Whoever runs the build
        supplies the policy: the GUI shows the findings in the Activity log and
        waits for a person, `feathered_cli.py` declines unless
        `--accept-trust-findings` was passed, and a test supplies a constant.

        Trust confirmation is a policy seam rather than a direct UI dependency,
        allowing the same build path to run under the GUI, CLI, or tests.
        """
        findings = list(warnings)
        if not findings:
            return True
        policy = self.__dict__.get("_trust_policy")
        if not callable(policy):
            # Lightweight hosts in the contract tests supply neither a policy
            # nor the interactive one; with nothing able to answer, the safe
            # response to an unreviewed trust finding is to decline.
            policy = getattr(self, "_gui_trust_review", None)
        if not callable(policy):
            return False
        return bool(policy(findings))

    def _gui_trust_review(self, warnings) -> bool:
        """The interactive policy: pause the build and ask, in the Activity log.

        Trust review is not an application error dialog. The worker waits while
        the UI shows the complete findings in the same scrollable log surface
        used everywhere else, which is why this marshals onto the main thread
        rather than opening a message box from the worker.
        """
        answered = threading.Event()
        decision = {"ok": False}

        def record(value: bool):
            decision["ok"] = bool(value)
            resume_wait = getattr(self, "_resume_after_operator_wait", None)
            if callable(resume_wait):
                resume_wait("Continuing build" if decision["ok"] else "Cancelling build")
            answered.set()

        def open_review():
            enter_wait = getattr(self, "_set_operator_wait", None)
            if callable(enter_wait):
                enter_wait("Build paused pending your decision in Activity log")
            try:
                self.show_details(focus_trust=True, warnings=list(warnings),
                                  decision_callback=record)
            except Exception:
                # The dialog failed to open. Release whatever grab it managed to
                # take before failing, or the main window stays locked while the
                # worker unblocks and the build cancels invisibly.
                release = getattr(self, "_release_stuck_grab", None)
                if callable(release):
                    release()
                resume_wait = getattr(self, "_resume_after_operator_wait", None)
                if callable(resume_wait):
                    resume_wait("Cancelling build")
                self._log("Trust review could not be shown; cancelling the build.")
                answered.set()
                raise

        self.after(0, open_review)
        answered.wait()
        return decision["ok"]


