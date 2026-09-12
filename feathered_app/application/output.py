"""Output-path naming and publication-folder interaction.

"""

from feathered_app.build_output import (BuildOutputMixin, _frozen, _naming_moment,
                                        folder_component, confirm_publication)
from feathered_app.context import (
    APP_TITLE,
    FOLDER_SCHEMES,
    MergePolicy,
    MirrorLayout,
    Path,
    datetime,
    filedialog,
    json,
    os,
    re,
    subprocess,
    sys,
    tk,
)
from feathered_app.ui.theme import messagebox






class OutputMixin(BuildOutputMixin):
    """Output-path naming and publication-folder interaction."""





    @staticmethod
    def _open_folder_path(path: Path) -> None:
        target = str(Path(path))
        if sys.platform.startswith("win"):
            os.startfile(target)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", target])
        else:
            subprocess.Popen(["xdg-open", target])


    def _confirm_output_folder_name(self, folder_name, options=None):
        return confirm_publication(self, folder_name, options,
                                   choose=messagebox.askchoice,
                                   open_existing=lambda path: self._open_folder_path(path))

    def _open_output_folder(self):
        """Open the most recently completed bundle directory in the OS shell."""
        path = self.last_output_path
        if path is None or not Path(path).is_dir():
            messagebox.showerror(APP_TITLE, "The completed output folder is no longer available.")
            if getattr(self, "open_output_btn", None):
                self.open_output_btn.configure(state="disabled")
            return
        try:
            self._open_folder_path(Path(path))
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not open the output folder.\n\n{exc}")

    @staticmethod
    def _folder_component(value: str, fallback: str = "repository") -> str:
        """Kept as a delegate; the implementation lives in the headless core."""
        return folder_component(value, fallback)



    def _layout(self) -> MirrorLayout:
        """Mirror layout, defaulting to the conservative one for partial hosts.

        Folder-naming tests drive these helpers with stubs that predate the
        layout control. Absent state must never be read as a request to merge
        repositories, so anything short of an explicit unified selection is
        treated as the separate layout.
        """
        resolve = getattr(self, "_mirror_layout", None)
        return resolve() if callable(resolve) else MirrorLayout.SEPARATE

    def _sync_mirror_layout_visibility(self):
        """Show the mirror layout control only when it can do anything.

        Hidden outside mirror intent so the Output Directories step does not
        offer a choice that silently applies to nothing, and the hint restates
        the consequence of the current selection rather than the whole rule.
        """
        card = self.__dict__.get("mirror_layout_card")
        if card is None:
            return
        try:
            # winfo_ismapped() on the inner frame answers for the wrong widget:
            # the heading and border belong to the holder, so hiding only the
            # inner frame left "MIRROR LAYOUT" over an empty box.
            self._set_card_visible(card, self._mirror_mode())
        except Exception:
            # Preview refreshes must never take the wizard down over geometry.
            return
        hint = self.__dict__.get("mirror_layout_hint")
        if hint is None:
            return
        if OutputMixin._layout(self) is MirrorLayout.UNIFIED:
            hint.configure(text=(
                "One directory. Packages published by more than one selected repository are kept "
                "once, and only when both sides publish a matching strong digest; anything that "
                "cannot be proven identical stops the build rather than being merged. The result "
                "is a union, not a copy of any upstream."))
        else:
            hint.configure(text=(
                "One directory per selected repository, each a faithful snapshot with its own "
                "metadata. Nothing is de-duplicated across repositories."))
        row = self.__dict__.get("mirror_conflict_row")
        unified = OutputMixin._layout(self) is MirrorLayout.UNIFIED
        if row is not None:
            try:
                if unified and not row.winfo_ismapped():
                    row.pack(anchor="w", fill="x", pady=(12, 0))
                elif not unified and row.winfo_ismapped():
                    row.pack_forget()
            except Exception:
                pass
        conflict_hint = self.__dict__.get("mirror_conflict_hint")
        if conflict_hint is None:
            return
        policy_fn = getattr(self, "_merge_policy", None)
        policy = policy_fn() if callable(policy_fn) else MergePolicy.STRICT
        if policy is MergePolicy.PREFER_PRIORITY:
            conflict_hint.configure(text=(
                "Packages that cannot be proven identical are taken from the higher-priority "
                "repository without an equality check, and every such choice is recorded in "
                "mirror-sources.json. Use this when you know one repository is authoritative."))
        else:
            conflict_hint.configure(text=(
                "Packages that cannot be proven identical stop the build and are listed, rather "
                "than Feathered choosing an artifact on your behalf. Repositories that publish no "
                "digest algorithm in common land here even when the files agree."))

    def _update_folder_preview(self):
        """Show the exact output folder(s) implied by the current naming policy."""
        # Headless contract tests construct App via ``object.__new__`` without
        # a Tk interpreter.  Reading a missing widget through tkinter's
        # ``__getattr__`` recurses, so inspect instance state directly.
        folder_preview = self.__dict__.get("folder_preview")
        if folder_preview is None:
            return
        scheme = self.folder_scheme_var.get()
        release = _frozen(self, "_selected_release", "release_var")
        target = f"{self._profile().key}-{release}-{self.arch_var.get()}"
        workload = ("mirror" if self._mirror_mode()
                    else "your chosen packages" if self._single_mode()
                    else self._workload().key)
        hints = {
            FOLDER_SCHEMES[0]: f"System plus contents, e.g. \"{target}-{workload}\". "
                               "Best when one output folder holds bundles for several systems.",
            FOLDER_SCHEMES[1]: f"Contents only, e.g. \"{workload}\". Use when every bundle "
                               "in this folder is for the same system.",
            FOLDER_SCHEMES[2]: f"System only, e.g. \"{target}\": the distribution, release "
                               "and architecture you selected on Linux Distribution.",
            FOLDER_SCHEMES[3]: "Use the folder label you type here. Prefix is separate: Date or "
                               "Date + time applies to every output. In repository-mirror mode "
                               "Feathered appends each repository name so every mirror remains an "
                               "independent directory. Illegal characters are replaced with hyphens.",
        }
        if self._mirror_mode():
            hints[FOLDER_SCHEMES[0]] = (
                "System plus contents is expanded once per selected repository. The target/date policy "
                "is shared, but each fork includes its repository name and receives independent metadata.")
            hints[FOLDER_SCHEMES[1]] = (
                "Contents-only naming is expanded once per selected repository; each folder is named "
                "for that repository mirror rather than combining package populations.")
            hints[FOLDER_SCHEMES[2]] = (
                "System-only naming still appends the repository name in mirror mode because sibling "
                "mirror outputs must remain unique and independent.")
        self.folder_scheme_hint.configure(text=hints.get(scheme, ""))
        self.folder_label_entry.configure(
            state="normal" if scheme == FOLDER_SCHEMES[3] else "disabled")
        # Stub-driven preview tests supply only the widgets they assert on.
        sync = getattr(self, "_sync_mirror_layout_visibility", None)
        if callable(sync):
            sync()
        if self._mirror_mode() and OutputMixin._layout(self) is MirrorLayout.UNIFIED:
            repos = list(self._selected_mirror_repositories())
            names = ", ".join(r.name for r in repos) or "no repositories selected yet"
            folder_preview.configure(text=(
                f"Output (1 unified repository merged from {len(repos)}):\n"
                f"  {names}\n  \u2192  {self._folder_name()}"))
        elif self._mirror_mode():
            forks = self._mirror_output_folder_names()
            if forks:
                lines = [f"Outputs ({len(forks)} independent repository mirrors):"]
                lines.extend(
                    f"  {getattr(repo, 'name', 'Repository')}  →  {name}"
                    for repo, name in forks)
                folder_preview.configure(text="\n".join(lines))
            else:
                folder_preview.configure(text="Folders: select at least one repository to mirror")
        else:
            folder_preview.configure(text="Folder:  " + self._folder_name())

    def _browse_baseline(self):
        picked = filedialog.askopenfilename(
            title="Baseline bundle manifest",
            filetypes=[("Bundle manifest", "manifest.json"), ("JSON", "*.json"), ("All files", "*.*")])
        if not picked:
            return
        try:
            data = json.loads(Path(picked).read_text(encoding="utf-8"))
            count = len(data.get("packages", []))
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"That file is not a readable bundle manifest: {exc}")
            return
        if not count:
            messagebox.showerror(APP_TITLE, "That manifest lists no packages, so it cannot be used "
                                            "as a differential baseline.")
            return
        self.baseline_var.set(picked)
        self._log(f"Differential baseline: {count} package(s) treated as already present")
        self._refresh_baseline_dependents()

    def _clear_baseline(self):
        """Drop the differential baseline and refresh what depended on it.

        Clearing used to be a bare `baseline_var.set("")`. Nothing traces that
        variable, so the Review step kept showing "Differential against a
        baseline" for a result that was no longer differential.
        """
        if not self.baseline_var.get().strip():
            return
        self.baseline_var.set("")
        self._log("Differential baseline cleared; the next build is self-contained")
        self._refresh_baseline_dependents()

    def _refresh_baseline_dependents(self):
        for name in ("_sync_output_capability_controls", "_update_folder_preview",
                     "_update_source_status"):
            hook = getattr(self, name, None)
            if callable(hook):
                try:
                    hook()
                except tk.TclError:
                    pass
