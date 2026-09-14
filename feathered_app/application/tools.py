"""Repository tools and transfer-view coordination.

"""

from feathered_app.build_mirror import BuildMirrorMixin
from core import SEAL_PHASE_START
from feathered_app.context import (
    APP_TITLE,
    Path,
    filedialog,
    mirror_catalog,
    os,
    repository_tools,
    subprocess,
    sys,
    threading,
    time,
    tk,
)
from feathered_app.ui.theme import human_size, messagebox


class ToolsMixin(BuildMirrorMixin):
    """Repository tools and transfer-view coordination."""

    def _open_mirror_catalog_folder(self):
        root = mirror_catalog.catalog_root()
        root.mkdir(parents=True, exist_ok=True)
        try:
            target = str(root)
            if sys.platform.startswith("win"):
                os.startfile(target)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", target])
            else:
                subprocess.Popen(["xdg-open", target])
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not open the mirror catalog folder.\n\n{exc}")

    def _reload_mirror_catalogs(self):
        try:
            profile_key = self._profile().key
            data = mirror_catalog.load_catalog(profile_key)
            count = sum(1 for item in data.get("mirrors", []) if isinstance(item, dict) and item.get("enabled", True))
            overrides = sum(1 for item in data.get("exact_overrides", []) if isinstance(item, dict) and item.get("enabled", True))
            if getattr(self, "mirror_catalog_status_var", None) is not None:
                self.mirror_catalog_status_var.set(
                    f"Reloaded {profile_key}.json: {count} mirror root(s), {overrides} saved exact override(s).")
            self._refresh_provenance_evidence_rows()
            self._refresh_provenance_source_tree()
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not reload mirror catalogs.\n\n{exc}")

    def _refresh_tools_summary(self):
        path = getattr(self, "repo_tool_path_var", None)
        if path and path.get():
            self._scan_repository_tool_folder(Path(path.get()))

    def _choose_repository_tool_folder(self):
        chosen = filedialog.askdirectory(title="Choose a folder containing RPM, DEB, or Arch packages")
        if not chosen:
            return
        self.repo_tool_path_var.set(chosen)
        self._scan_repository_tool_folder(Path(chosen))

    def _scan_repository_tool_folder(self, path: Path):
        try:
            scan = repository_tools.scan_repository_folder(path)
        except Exception as exc:
            self.repo_tool_scan_var.set(str(exc))
            self.repo_tool_build_btn.configure(state="disabled")
            return
        if scan.family == "mixed":
            text = (f"Found {len(scan.rpm_files)} RPM, {len(scan.deb_files)} DEB, and "
                    f"{len(scan.arch_files)} Arch package files. Choose a folder containing one package family at a time.")
            state = "disabled"
        elif scan.family == "empty":
            text = "No RPM, DEB, or Arch .pkg.tar.* package files were found in this folder or its subfolders."
            state = "disabled"
        else:
            family = "RPM" if scan.family == "rpm" else "DEB" if scan.family == "deb" else "Arch"
            existing = []
            if scan.existing_rpm_metadata:
                existing.append("existing repodata detected")
            if scan.existing_apt_metadata:
                existing.append("existing APT metadata detected")
            if getattr(scan, "existing_arch_metadata", False):
                existing.append("existing pacman metadata detected")
            provenance_count = len(scan.manifests)
            detail = "; ".join(existing) if existing else "metadata will be created"
            text = (f"{scan.count} {family} package file(s) found; {detail}. "
                    f"{provenance_count} Feathered manifest(s) found for provenance recovery.")
            state = "normal"
        self.repo_tool_scan_var.set(text)
        self.repo_tool_build_btn.configure(state=state)

    def _start_repository_rebuild(self):
        if self._busy():
            return
        root = Path(self.repo_tool_path_var.get())
        if not root.is_dir():
            messagebox.showerror(APP_TITLE, "Choose a repository folder first.")
            return
        if not self._claim_operation(
                "repository-rebuild", "Rebuilding repository metadata", cancellable=False):
            return
        self.repo_tool_progress_var.set(0)
        self.repo_tool_status_var.set("Reading package metadata...")

        def progress(label, value):
            self.events.put(("tool_progress", label, value))

        def work():
            try:
                report = repository_tools.rebuild_repository_metadata(
                    root, progress=progress, log=self._log)
                self.events.put(("tool_rebuild_done", True, report))
            except Exception as exc:
                self.events.put(("tool_rebuild_done", False, str(exc)))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def _choose_bundle_check_folder(self):
        chosen = filedialog.askdirectory(title="Choose an existing Feathered bundle")
        if not chosen:
            return
        self.bundle_check_path_var.set(chosen)
        self.bundle_check_btn.configure(
            state="normal" if (Path(chosen) / "bundle-index.json").is_file() else "disabled")
        if (Path(chosen) / "bundle-index.json").is_file():
            self.bundle_check_status_var.set("Sealed bundle index found. Ready to check files.")
        else:
            self.bundle_check_status_var.set("bundle-index.json was not found in that folder.")

    def _start_bundle_check(self):
        if self._busy():
            return
        root = Path(self.bundle_check_path_var.get())
        if not self._claim_operation(
                "bundle-check", "Checking sealed bundle files", cancellable=False):
            return
        self.bundle_check_status_var.set("Checking bundle files...")

        def progress(label, value):
            self.events.put(("tool_progress", label, value))

        def work():
            try:
                report = repository_tools.verify_bundle_files(root, progress=progress)
                self.events.put(("tool_bundle_done", True, report))
            except Exception as exc:
                self.events.put(("tool_bundle_done", False, str(exc)))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def _apply_tool_rebuild_done(self, ok: bool, payload):
        self.worker = None
        if not ok:
            self._release_operation("Repository rebuild failed", outcome="failed")
            self.repo_tool_progress_var.set(0)
            self.repo_tool_status_var.set(str(payload))
            self.status_var.set("Repository rebuild failed")
            messagebox.showerror(APP_TITLE, str(payload))
            return
        report = payload
        self.repo_tool_progress_var.set(100)
        self.repo_tool_status_var.set(
            f"Ready: {report.package_count} {report.family.upper()} package(s); "
            f"{report.provenance_preserved} provenance record(s) preserved; "
            f"{report.local_only} local-only package(s).")
        self._release_operation("Repository metadata rebuilt")
        self._scan_repository_tool_folder(report.root)
        messagebox.showinfo(
            APP_TITLE,
            f"Repository metadata rebuilt for {report.package_count} package(s).\n\n"
            f"Location: {report.root}\n"
            f"Preserved Feathered provenance: {report.provenance_preserved}\n"
            f"Local-content-only: {report.local_only}")

    def _apply_tool_bundle_done(self, ok: bool, payload):
        self.worker = None
        if not ok:
            self._release_operation("Bundle file check failed", outcome="failed")
            self.bundle_check_status_var.set(str(payload))
            self.status_var.set("Bundle file check failed")
            messagebox.showerror(APP_TITLE, str(payload))
            return
        report = payload
        if report.ok:
            text = f"OK: {report.file_count} indexed file(s) match and no unexpected files are present."
            final_status = "Bundle files match the sealed index"
        else:
            text = (f"FAILED: {len(report.missing)} missing, {len(report.modified)} modified, "
                    f"{len(report.unexpected)} unexpected, {len(getattr(report, 'unsafe', []))} unsafe file/path(s).")
            final_status = "Bundle file check found differences"
        self.bundle_check_status_var.set(text)
        self._release_operation(final_status, outcome=("idle" if report.ok else "failed"))

    def _refresh_download_size_preview(self, result=None) -> None:
        """Keep an explicit package-payload total visible before and during build."""
        var = getattr(self, "download_size_var", None)
        if var is None:
            return
        result = result if result is not None else getattr(self, "last_result", None)
        if result is not None:
            selected = list(getattr(result, "selected", []) or [])
            if self._pick_mode() and getattr(self, "picked", None) is not None:
                selected = [p for p in selected if p.nevra in self.picked]
            total = sum(int(getattr(p, "size", 0) or 0) for p in selected)
            mirror_summaries = list(getattr(result, "mirror_repository_summaries", []) or [])
            if self._mirror_mode() and mirror_summaries:
                var.set(
                    f"Planned mirror payload: {human_size(total)} across {len(selected)} package record(s) "
                    f"in {len(mirror_summaries)} repository mirror(s); no cross-repository de-duplication.")
            else:
                var.set(f"Planned package payload: {human_size(total)} across {len(selected)} package(s).")
            return
        if self._single_mode() and getattr(self, "selected_packages", None):
            roots = list(self.selected_packages)
            root_size = sum(int(getattr(p, "size", 0) or 0) for p in roots)
            var.set(
                f"Selected root payload: {human_size(root_size)} across {len(roots)} package(s); "
                "analyze to calculate the full dependency-closure total before download.")
            return
        if self._mirror_mode():
            repo_count = len(getattr(self, "_selected_mirror_repositories", lambda: [])())
            var.set(
                f"Mirror payload: {repo_count} repository source(s) selected; inventory repositories "
                "to calculate each source population and the aggregate transfer size.")
            return
        var.set("Package payload: analyze to calculate the complete transfer size before download.")

    #  How long the worker will wait for the UI to acknowledge the plan before
    #  giving up and continuing. Generous, because a busy main loop may be slow;
    #  bounded, because an unbounded wait on a consumer that is not running
    #  hangs the build forever with nothing in the log to explain it.
    DOWNLOAD_PLAN_ACK_TIMEOUT_S = 30.0

    def _publish_download_plan(self, count: int, expected_bytes: int) -> None:
        """Expose the exact transfer total before payload I/O begins.

        The last of the build worker's UI dependencies. It published the plan to
        the event queue and blocked until the UI drain loop acknowledged it,
        which deadlocks with no diagnostic when nothing is draining -- a
        command-line or test run, or a UI whose pump has stopped.

        Whoever runs the build supplies the sink: the GUI keeps the synchronous
        handshake so the operator sees the total before bytes move, and a
        non-interactive caller records it and continues.
        """
        sink = self.__dict__.get("_download_plan_sink")
        if callable(sink):
            sink(int(count), int(expected_bytes))
            return
        publish = getattr(self, "_gui_publish_download_plan", None)
        if callable(publish):
            publish(int(count), int(expected_bytes))

    def _gui_publish_download_plan(self, count: int, expected_bytes: int) -> None:
        """Hand the plan to the UI and wait, briefly, for it to be shown."""
        acknowledged = threading.Event()
        self.events.put(("download_plan", int(count), int(expected_bytes), acknowledged))
        if not acknowledged.wait(self.DOWNLOAD_PLAN_ACK_TIMEOUT_S):
            self._log(
                "The interface did not acknowledge the transfer plan within "
                f"{self.DOWNLOAD_PLAN_ACK_TIMEOUT_S:.0f}s; continuing without it. "
                "The planned total may not be shown, but the build is unaffected.")

    def _apply_download_plan(self, count: int, expected_bytes: int) -> None:
        if getattr(self, "download_size_var", None) is not None:
            if self._mirror_mode():
                repo_count = len(getattr(self, "_selected_mirror_repositories", lambda: [])())
                self.download_size_var.set(
                    f"Planned mirror payload: {human_size(expected_bytes)} across {count} package record(s) "
                    f"in {repo_count} repository mirror(s).")
            else:
                self.download_size_var.set(
                    f"Planned package payload: {human_size(expected_bytes)} across {count} package(s).")
        if self._mirror_mode():
            repo_count = len(getattr(self, "_selected_mirror_repositories", lambda: [])())
            self._operation_status(
                f"Ready to mirror {repo_count} repository/repositories: {count} package record(s), "
                f"{human_size(expected_bytes)} total")
        else:
            self._operation_status(
                f"Ready to transfer {count} package(s), {human_size(expected_bytes)} total")
        try:
            self.update_idletasks()
        except tk.TclError:
            pass

    def _begin_transfer(self, count: int, expected_bytes: int) -> None:
        # Analysis/preflight is complete. Payload work has its own row-level
        # progress, so return Review to the normal border before downloading.
        self._stop_review_work_glow()
        self._operation_status(f"Downloading {count} package(s)")
        self.transfer_total = count
        self.transfer_done = 0
        self.transfer_failed = 0
        self.transfer_reused = 0
        self.transfer_bytes = 0
        self.transfer_expected_bytes = expected_bytes
        self._transfer_item_bytes = {}
        self._transfer_item_sizes = {}
        self._transfer_terminal_items = set()
        try:
            signing = bool(self.sign_index_var.get())
        except Exception:
            signing = False
        self._transfer_progress_span = SEAL_PHASE_START if signing else 1.0
        self.transfer_started = time.monotonic()
        if getattr(self, "download_size_var", None) is not None:
            if self._mirror_mode():
                repo_count = len(getattr(self, "_selected_mirror_repositories", lambda: [])())
                self.download_size_var.set(
                    f"Mirror payload transfer: {human_size(0)} / {human_size(expected_bytes)} "
                    f"across {count} package record(s) in {repo_count} repository mirror(s)")
            else:
                self.download_size_var.set(
                    f"Package payload transfer: {human_size(0)} / {human_size(expected_bytes)} "
                    f"across {count} package(s)")
        self._log(
            (f"Mirroring {count} package record(s) across "
             f"{len(getattr(self, '_selected_mirror_repositories', lambda: [])())} repository/repositories, "
             f"{human_size(expected_bytes)} expected")
            if self._mirror_mode() else
            f"Transferring {count} package(s), {human_size(expected_bytes)} expected")


    def _apply_item_event(self, identity: str, state: str, info: dict) -> None:
        """Annotate one row and keep terminal transfer counts consistent."""
        announced = max(0, int(info.get("size") or 0))
        item_bytes = self.__dict__.setdefault("_transfer_item_bytes", {})
        item_sizes = self.__dict__.setdefault("_transfer_item_sizes", {})
        terminal = self.__dict__.setdefault("_transfer_terminal_items", set())
        if announced:
            item_sizes[identity] = announced

        if state in ("done", "reused"):
            item_bytes[identity] = announced
            if identity not in terminal:
                self.transfer_done += 1
                if state == "reused":
                    self.transfer_reused += 1
                terminal.add(identity)
        elif state == "failed":
            item_bytes[identity] = 0
            if identity not in terminal:
                self.transfer_failed += 1
                terminal.add(identity)

        self.transfer_bytes = sum(max(0, int(value or 0)) for value in item_bytes.values())
        labels = {"active": ("downloading", "active"), "done": ("downloaded", "done"),
                  "reused": ("already present", "done"), "failed": ("FAILED", "failed"),
                  "pending": ("queued", "pending"),
                  "verifying": ("verifying...", "active"),
                  "stale": ("re-fetching", "warn")}
        text, tag = labels.get(state, (state, "pending"))
        detail = str(info["detail"])[:160] if state == "failed" and info.get("detail") else ""
        states = getattr(self, "_result_item_states", None)
        if states is None:
            self._result_item_states = states = {}
        states[identity] = {"status": text, "tag": tag, "detail": detail}
        iid = getattr(self, "result_rows", {}).get(identity)
        if iid and self.result_tree.exists(iid):
            values = list(self.result_tree.item(iid, "values"))
            values[1] = text
            if detail:
                values[3] = detail
            self.result_tree.item(iid, values=values, tags=(tag,))
            if state == "active":
                self.result_tree.see(iid)
        self._update_transfer_status()

    def _apply_transfer_event(self, identity: str, transferred: int, total: int) -> None:
        """Apply byte progress for one artifact without changing its lifecycle state."""
        current = max(0, int(transferred or 0))
        expected = max(0, int(total or 0))
        item_bytes = self.__dict__.setdefault("_transfer_item_bytes", {})
        item_sizes = self.__dict__.setdefault("_transfer_item_sizes", {})
        item_bytes[identity] = current
        if expected:
            item_sizes[identity] = expected
        self.transfer_bytes = sum(max(0, int(value or 0)) for value in item_bytes.values())

        expected = item_sizes.get(identity, 0)
        text = (f"downloading {human_size(current)} / {human_size(expected)}"
                if expected else f"downloading {human_size(current)}")
        states = getattr(self, "_result_item_states", None)
        if states is None:
            self._result_item_states = states = {}
        states[identity] = {"status": text, "tag": "active", "detail": ""}
        iid = getattr(self, "result_rows", {}).get(identity)
        if iid and self.result_tree.exists(iid):
            values = list(self.result_tree.item(iid, "values"))
            values[1] = text
            self.result_tree.item(iid, values=values, tags=("active",))
            self.result_tree.see(iid)
        self._update_transfer_status()

    def _update_transfer_status(self) -> None:
        """Show count, volume, speed and estimated time remaining."""
        if not self.transfer_total:
            return
        elapsed = max(0.001, time.monotonic() - self.transfer_started)
        rate = self.transfer_bytes / elapsed
        done = self.transfer_done + self.transfer_failed
        volume = (f"{human_size(self.transfer_bytes)} / {human_size(self.transfer_expected_bytes)}"
                  if self.transfer_expected_bytes else human_size(self.transfer_bytes))
        unit = "package records" if self._mirror_mode() else "packages"
        parts = [f"{done}/{self.transfer_total} {unit}", volume]
        if rate > 1024:
            parts.append(f"{human_size(rate)}/s")
        if self.transfer_expected_bytes and rate > 1024 and done < self.transfer_total:
            remaining = max(0, self.transfer_expected_bytes - self.transfer_bytes)
            eta = int(remaining / rate)
            parts.append(f"~{eta // 60}m {eta % 60:02d}s left" if eta >= 60 else f"~{eta}s left")
        if self.transfer_reused:
            parts.append(f"{self.transfer_reused} already present")
        if self.transfer_failed:
            parts.append(f"{self.transfer_failed} failed")
        if self.transfer_expected_bytes and getattr(self, "progress_var", None) is not None:
            fraction = min(1.0, self.transfer_bytes / self.transfer_expected_bytes)
            self.progress_var.set(fraction * float(self.__dict__.get("_transfer_progress_span", 1.0)) * 100)
        if getattr(self, "download_size_var", None) is not None:
            if self._mirror_mode():
                repo_count = len(getattr(self, "_selected_mirror_repositories", lambda: [])())
                self.download_size_var.set("Mirror payload transfer: " + volume +
                                           f" across {self.transfer_total} package record(s) in "
                                           f"{repo_count} repository mirror(s)")
            else:
                self.download_size_var.set("Package payload transfer: " + volume +
                                           f" across {self.transfer_total} package(s)")
        self._operation_status(("Mirroring   " if self._mirror_mode() else "Transferring   ") +
                               "   ".join(parts))
