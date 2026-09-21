"""Source-status evaluation and removable/local media handling.

"""

from feathered_app.context import (
    APP_TITLE,
    BG_APP,
    BG_INPUT,
    ERR_FG,
    FG_TEXT,
    LINE,
    OK_FG,
    Path,
    RepoSpec,
    WARN_FG,
    filedialog,
    os,
    path_to_file_url,
    re,
    subprocess,
    tk,
    ttk,
)
from feathered_app.ui.theme import messagebox


class MediaMixin:
    """Source-status evaluation and removable/local media handling."""

    EXPECTED_RPM_LAYOUT = """\
RPM repository layouts Feathered can discover:

  <root>/repodata/repomd.xml

or installation media / mirrors with repository roots below the selected folder, for example:

  <root>/BaseOS/repodata/repomd.xml
  <root>/AppStream/repodata/repomd.xml

Package payloads referenced by repodata must remain reachable at the paths recorded in the metadata.
"""

    EXPECTED_APT_LAYOUT = """\
APT repository layout Feathered expects:

  <root>/dists/<suite>/Release
  <root>/dists/<suite>/<component>/binary-<arch>/Packages[.gz|.xz|.zst]
  <root>/pool/...

Choose the archive root: the directory directly above dists/.
"""

    def _update_source_status(self):
        """Summarize source topology separately from authentication readiness.

        Selecting a repository establishes source intent. Credentials determine
        whether a selected authenticated source can be contacted, but missing
        credentials must not erase that repository from dependency capability
        derivation.
        """
        self._refresh_repository_transport_warning()
        source_status = getattr(self, "source_status", None)
        if source_status is None:
            if self._mirror_mode():
                self._refresh_mirror_repos()
            return

        enabled = self._participating_transaction_repositories()
        method = self.source_method_var.get()
        distribution_required = bool(
            getattr(self, "_workload_uses_distribution_sources", lambda: False)())
        package_only = bool(
            getattr(self, "_package_only_acquisition_mode", lambda: False)())
        local_pending = bool(getattr(self, "_local_media_pending", lambda: False)())
        entitlement_ready = True
        if method == "Red Hat CDN entitlement (official)":
            ready = getattr(self, "_entitlement_ready", None)
            if callable(ready):
                entitlement_ready = bool(ready())
            else:
                entitlement_ready = bool(
                    getattr(self, "rhsm_cert", "")
                    and getattr(self, "rhsm_key", "")
                    and getattr(self, "rhsm_ca", ""))

        if local_pending and distribution_required:
            self.source_status.configure(
                text="The selected roots require distribution repositories, but local media is selected and no repository folder has been loaded yet.",
                fg=ERR_FG)
        elif not enabled:
            self.source_status.configure(
                text="No repository URLs are enabled for the selected build.",
                fg=ERR_FG)
        else:
            base_count = sum(1 for r in enabled if self._repo_tier(r) == "base")
            workload_count = sum(1 for r in enabled if self._repo_tier(r) == "workload")
            additional_count = sum(1 for r in enabled if self._repo_tier(r) == "additional")

            if (method == "Red Hat CDN entitlement (official)"
                    and not entitlement_ready
                    and not package_only):
                if distribution_required:
                    text = (
                        "RHEL CDN repositories are selected for the required distribution roots, but the Red Hat "
                        "entitlement certificate, private key, and repository CA are not configured. Configure "
                        "entitlement before analysis or build; the selected CDN repositories remain part of the "
                        "source plan.")
                else:
                    text = (
                        f"Configured: {len(enabled)} enabled source(s) ({base_count} base, {workload_count} workload, "
                        f"{additional_count} additional). RHEL CDN BaseOS/AppStream remain selected as dependency "
                        "providers, but Red Hat entitlement is not configured. Dependency analysis will require the "
                        "entitlement certificate, private key, and repository CA before those sources can be read.")
                colour = WARN_FG
            elif package_only:
                if method == "Red Hat CDN entitlement (official)" and not entitlement_ready and base_count:
                    text = (
                        f"Configured: {len(enabled)} enabled source(s) ({base_count} base, {workload_count} workload, "
                        f"{additional_count} additional). Package-only acquisition is selected, so the RHEL CDN "
                        "dependency providers will not be contacted and entitlement is not required for this operation.")
                else:
                    text = (
                        f"Configured: {len(enabled)} enabled source(s) ({base_count} base, {workload_count} workload, "
                        f"{additional_count} additional). Package-only acquisition collects the requested workload "
                        "roots without dependency resolution.")
                colour = WARN_FG
            else:
                text = (
                    f"Configured: {len(enabled)} enabled source(s) ({base_count} base, "
                    f"{workload_count} workload, {additional_count} additional). "
                    "Test all sources for broad reachability; use Check selected packages for root availability.")
                colour = OK_FG
            self.source_status.configure(text=text, fg=colour)
        if self.__dict__.get("package_source_tree") is not None:
            self._refresh_package_source_coverage()

    def _inspect_media_identity(self, base: Path):
        text_parts = []
        for name in (".treeinfo", ".discinfo", "media.repo"):
            f = base / name
            if f.is_file():
                try:
                    text_parts.append(f.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass
        text = "\n".join(text_parts)
        release = None
        arch = None
        # Prefer version strings explicitly near RHEL/Version labels.
        m = re.search(r"(?i)(?:Red Hat Enterprise Linux|RHEL|version\s*=?)\s*[^0-9]{0,20}(10|9|8)\.(\d+)", text)
        if m:
            release = f"{m.group(1)}.{m.group(2)}"
        else:
            m = re.search(r"(?m)^version\s*=\s*((?:8|9|10)\.\d+)", text)
            if m: release = m.group(1)
        m = re.search(r"(?m)^arch\s*=\s*([A-Za-z0-9_]+)", text)
        if m: arch = m.group(1)
        return release, arch

    def _show_layout_help(self, deb: bool):
        layout = self.EXPECTED_APT_LAYOUT if deb else self.EXPECTED_RPM_LAYOUT
        win = tk.Toplevel(self); win.title("Expected repository layout")
        win.geometry("760x520"); win.transient(self); win.configure(background=BG_APP)
        frame = ttk.Frame(win, padding=14); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Nothing usable was found there", style="PaneTitle.TLabel").pack(anchor="w")
        ttk.Label(frame, style="Hint.TLabel", wraplength=700, text=(
            "Feathered reads repository metadata directly; it does not scan loose package files. "
            "A folder full of .rpm or .deb files with no metadata cannot be used as a source."
        )).pack(anchor="w", pady=(4, 10))
        text = tk.Text(frame, wrap="none", font=("Consolas", 9), background=BG_INPUT,
                       foreground=FG_TEXT, relief="flat", borderwidth=0, highlightthickness=1,
                       highlightbackground=LINE, padx=10, pady=8)
        text.pack(fill="both", expand=True)
        text.insert("1.0", layout)
        text.configure(state="disabled")
        ttk.Label(frame, style="Hint.TLabel", wraplength=700, text=(
            "SMB/UNC shares are supported: enter or select \\\\server\\share\\path. Mount the share "
            "first if Windows has not already mapped it."
        )).pack(anchor="w", pady=(10, 0))

    def _resolve_media_root(self, deb: bool):
        """Ask for a media root, accepting a folder, an SMB path, or an ISO.

        Feathered cannot read inside an .iso itself; Windows mounts ISOs natively,
        so the honest handling is to detect the file, explain, and offer to mount
        it rather than silently failing on a path that is not a directory.
        """
        choice = messagebox.askquestion(
            APP_TITLE,
            "Is the installation media already mounted or extracted to a folder?\n\n"
            "Yes  |  choose the folder or SMB share (a mounted DVD drive counts).\n"
            "No   |  choose an .iso/.img file and Feathered will try to mount it.",
            icon="question")
        if choice == "yes":
            root = filedialog.askdirectory(
                title="Select the media, mounted DVD, or repository root")
            return Path(root) if root else None
        image = filedialog.askopenfilename(
            title="Select a disc image",
            filetypes=[("Disc images", "*.iso *.img *.udf"), ("All files", "*.*")])
        if not image:
            return None
        return self._mount_disc_image(Path(image))

    def _mount_disc_image(self, image: Path):
        """Mount an ISO on Windows and return the resulting drive root.

        RELEASE-GATED ON WINDOWS: windows_release_smoke.ps1 invokes this exact
        method against a caller-supplied real ISO fixture, verifies the returned
        drive root, independently confirms the attachment, and dismounts it in
        a finally block. This exercises argument construction, stdin path
        handling, PowerShell return-code handling, and drive-letter parsing.
        """
        if os.name != "nt":
            messagebox.showinfo(
                APP_TITLE,
                f"Mount the image first, then re-run this step and choose the folder:\n\n"
                f"    sudo mount -o loop,ro '{image}' /mnt/media")
            return None
        try:
            # The path is passed as data on stdin and read into a variable,
            # never interpolated into the script text. A filename containing a
            # quote, $(), a backtick or a semicolon would otherwise have been
            # executed as PowerShell.
            script = ("$ErrorActionPreference='Stop';"
                      "$p = [Console]::In.ReadLine();"
                      "$i = Mount-DiskImage -ImagePath $p -PassThru;"
                      "($i | Get-Volume).DriveLetter")
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                                 input=str(image) + "\n",
                                 capture_output=True, text=True, timeout=120)
            letter = (out.stdout or "").strip().splitlines()[-1].strip() if out.stdout.strip() else ""
            if out.returncode != 0 or not letter:
                raise RuntimeError((out.stderr or "no drive letter returned").strip())
        except Exception as exc:
            messagebox.showerror(
                APP_TITLE,
                f"Could not mount {image.name} automatically:\n\n{exc}\n\n"
                "Mount it manually (right-click the .iso and choose Mount), then re-run this "
                "step and select the resulting drive.")
            return None
        root = Path(f"{letter}:\\")
        self._log(f"Mounted {image.name} at {root}. Remember to eject it when the build finishes.")
        messagebox.showinfo(APP_TITLE, f"Mounted {image.name} as drive {letter}:.\n\n"
                                       "Eject it from Explorer when you are finished.")
        return root

    def select_media(self):
        if self._is_deb():
            self.select_apt_media(); return
        if self._is_arch():
            self.select_arch_media(); return
        base = self._resolve_media_root(deb=False)
        if base is None:
            return
        media_release, media_arch = self._inspect_media_identity(base)
        target_release = self.release_var.get().strip()
        target_arch = self.arch_var.get()
        mismatches = []
        if media_release and media_release != target_release:
            mismatches.append(f"media release {media_release} != target {target_release}")
        if media_arch and media_arch != target_arch:
            mismatches.append(f"media architecture {media_arch} != target {target_arch}")
        if mismatches:
            msg = "Repository media mismatch:\n\n" + "\n".join(mismatches) + "\n\nUse it anyway?"
            if not messagebox.askyesno(APP_TITLE, msg):
                return
        try:
            repomds = list(base.rglob("repodata/repomd.xml"))
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"That location could not be read: {exc}\n\n"
                                            "If it is an SMB share, confirm it is reachable and "
                                            "that you have permission to browse it.")
            return
        if not repomds:
            self._log(f"No repodata/repomd.xml found below {base}")
            self._show_layout_help(deb=False)
            return
        # Replace only the source-plan/base tier. User supplements survive
        # switching to local media.
        self.repo_rows = [r for r in self.repo_rows if self._repo_tier(r) != "base"]
        added = 0
        for repomd in sorted(repomds):
            repo_root = repomd.parent.parent
            lower_parts = [p.lower() for p in repo_root.parts]
            if "baseos" in lower_parts:
                name, priority = f"{self._profile().label} BaseOS (local)", 40
            elif "appstream" in lower_parts:
                name, priority = f"{self._profile().label} AppStream (local)", 45
            elif "crb" in lower_parts or "powertools" in lower_parts:
                name, priority = f"{self._profile().label} CRB/PowerTools (local)", 55
            else:
                name, priority = f"Local repo: {repo_root.name}", 60
            self.repo_rows.append(self._set_repo_tier(RepoSpec(
                name, path_to_file_url(repo_root.resolve()) + "/", "dependency", priority, True,
                f"Discovered under {base}", self.release_var.get()), "base"))
            added += 1
        self.selected_packages = []
        self._refresh_selected_packages()
        self.single_catalog_packages = []; self.single_catalog_signature = None
        self._sync_workload_repo_state()
        self.loaded_signature = None; self.loaded_packages = []
        self._update_source_status(); self._refresh_repo_tree_if_open()
        self._log(f"Discovered {added} local repositories under {base}")

    def select_arch_media(self):
        chosen = filedialog.askdirectory(
            title="Choose Arch Linux mirror/media root containing repository .db files", parent=self)
        if not chosen:
            return
        base = Path(chosen).resolve()
        try:
            candidates = []
            for path in base.rglob("*.db"):
                if path.is_file():
                    candidates.append(path)
            # Some copied mirrors keep only the archive name rather than the .db alias.
            for pattern in ("*.db.tar.gz", "*.db.tar.xz", "*.db.tar.zst"):
                for path in base.rglob(pattern):
                    if path.is_file():
                        candidates.append(path)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"That location could not be read: {exc}")
            return
        by_identity = {}
        for db in candidates:
            name = db.name
            suite = name.split(".db", 1)[0].strip()
            if not suite:
                continue
            key = (str(db.parent), suite)
            # Prefer the conventional short .db file when both alias and archive exist.
            current = by_identity.get(key)
            if current is None or (db.name == f"{suite}.db" and current.name != f"{suite}.db"):
                by_identity[key] = db
        if not by_identity:
            messagebox.showerror(
                APP_TITLE,
                "No pacman repository databases were found. Choose a mirror/media folder containing files such as core.db or extra.db.")
            return
        self.repo_rows = [r for r in self.repo_rows if self._repo_tier(r) != "base"]
        priority = 40
        for (_parent, suite), db in sorted(by_identity.items(), key=lambda item: (item[0][1], item[0][0])):
            repo = RepoSpec(
                f"Local Arch {suite}", path_to_file_url(db.parent) + "/", "dependency", priority, True,
                f"Discovered from {db}", "rolling", optional=False, repo_format="pacman", suite=suite)
            self.repo_rows.append(self._set_repo_tier(repo, "base"))
            priority += 5
        self.clear_single_selection(silent=True)
        self._sync_workload_repo_state(); self.loaded_signature = None; self.loaded_packages = []
        self._update_source_status(); self._refresh_repo_tree_if_open()
        self._log(f"Discovered {len(by_identity)} local pacman repository/repositories under {base}")

    def select_apt_media(self):
        chosen = self._resolve_media_root(deb=True)
        if chosen is None:
            return
        base = chosen.resolve()
        dists = base / "dists"
        if not dists.is_dir():
            # Allow choosing a parent folder that contains one repository root.
            try:
                candidates = [p for p in base.rglob("dists") if p.is_dir()]
            except OSError as exc:
                messagebox.showerror(APP_TITLE, f"That location could not be read: {exc}")
                return
            if len(candidates) == 1:
                dists = candidates[0]; base = dists.parent
            else:
                self._log(f"No unambiguous APT dists/ directory below {base} "
                          f"({len(candidates)} candidates)")
                self._show_layout_help(deb=True)
                return
        target_suite = self._profile().codename(self.release_var.get().strip())
        arch = self.arch_var.get()
        suite_dirs = [p for p in dists.iterdir() if p.is_dir() and (p / "Release").exists() or p.is_dir() and (p / "InRelease").exists()]
        # Prefer the target suite and its update/security variants when present.
        preferred = [p for p in suite_dirs if p.name == target_suite or p.name.startswith(target_suite + "-")]
        if preferred:
            suite_dirs = preferred
        if not suite_dirs:
            messagebox.showerror(APP_TITLE, f"No APT suite directories with Release/InRelease metadata were found under {dists}.")
            return
        self.repo_rows = [r for r in self.repo_rows if self._repo_tier(r) != "base"]
        added = 0
        for suite_dir in sorted(suite_dirs):
            components = []
            for comp in suite_dir.iterdir():
                if not comp.is_dir(): continue
                binary = comp / f"binary-{arch}"
                if binary.is_dir() and any((binary / n).exists() for n in ("Packages", "Packages.gz", "Packages.xz", "Packages.zst", "Packages.bz2")):
                    components.append(comp.name)
            if not components:
                continue
            self.repo_rows.append(self._set_repo_tier(RepoSpec(
                f"Local APT {suite_dir.name}", path_to_file_url(base) + "/", "dependency", 40 + added, True,
                f"Discovered under {base}", self.release_var.get(), optional=False, repo_format="apt",
                suite=suite_dir.name, components=" ".join(components)), "base"))
            added += 1
        if not added:
            messagebox.showerror(APP_TITLE, f"No binary-{arch} Packages indexes were found in the selected APT repository.")
            return
        self.clear_single_selection(silent=True)
        self._sync_workload_repo_state(); self.loaded_signature = None; self.loaded_packages = []
        self._update_source_status(); self._refresh_repo_tree_if_open()
        self._log(f"Discovered {added} local APT suite(s) under {base}")
