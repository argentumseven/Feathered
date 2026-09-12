"""Persistent aliases, keystore data, signature profiles, and entitlement state.

"""

import tempfile

from feathered_app.context import (
    APP_TITLE,
    BG_APP,
    ERR_FG,
    FG_MUTED,
    OK_FG,
    Path,
    apt_core,
    compare_evr,
    infer_vendor_id,
    json,
    os,
    simpledialog,
    sys,
    tk,
    ttk,
    urllib,
    vendor_display_name,
)
from feathered_app.ui.theme import human_size, messagebox


class PersistenceMixin:
    """Persistent aliases, keystore data, signature profiles, and entitlement state."""

    def _user_state_dir(self) -> Path:
        """Per-user Feathered state, deliberately outside the program tree.

        remembered trust/credential
        settings contain references only, never key/certificate bytes.  Keeping
        even those references beside the executable made portable builds look
        self-contained when they were not and risked copying local paths with
        the application.  Use the OS user configuration area instead.
        """
        if sys.platform.startswith("win"):
            base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
            root, legacy = base / "Feathered", base / "Feather"
        elif sys.platform == "darwin":
            base = Path.home() / "Library" / "Application Support"
            root, legacy = base / "Feathered", base / "Feather"
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
            root, legacy = base / "feathered", base / "feather"
        # One-time migration from the pre-rename configuration directory so the
        # Feathered rename does not silently discard saved profiles/settings.
        if not root.exists() and legacy.is_dir():
            try:
                legacy.rename(root)
            except OSError:
                pass  # e.g. cross-device or permission issue; start fresh
        root.mkdir(parents=True, exist_ok=True)
        try:
            root.chmod(0o700)
        except OSError:
            pass
        return root

    def _workload_alias_store_path(self) -> Path:
        return self._user_state_dir() / "workload-aliases.json"

    def _learned_workload_aliases(self) -> dict:
        cache = self.__dict__.get("_workload_alias_cache")
        if cache is not None:
            return cache
        try:
            data = json.loads(self._workload_alias_store_path().read_text(encoding="utf-8"))
        except Exception:
            data = {}
        self._workload_alias_cache = data if isinstance(data, dict) else {}
        return self._workload_alias_cache

    def _aliases_for_target(self) -> dict:
        profile = self._profile()
        per_profile = self._learned_workload_aliases().get(profile.key, {})
        family = getattr(profile, "package_family", "rpm")
        return dict(per_profile.get(family, {})) if isinstance(per_profile, dict) else {}

    def _record_workload_aliases(self, resolutions) -> None:
        """Persist derived name mappings for this profile+family.

        Substitutions discovered by workers arrive as events, so this runs on
        the Tk thread and file writes never race."""
        if not resolutions:
            return
        profile = self._profile()
        family = getattr(profile, "package_family", "rpm")
        store = self._learned_workload_aliases()
        bucket = store.setdefault(profile.key, {}).setdefault(family, {})
        changed = False
        for requested, resolved in resolutions:
            if bucket.get(requested) != resolved:
                bucket[requested] = resolved
                changed = True
        if changed:
            self._secure_write_json(self._workload_alias_store_path(), store)

    def _secure_write_json(self, path: Path, payload: dict) -> None:
        """Atomically replace per-user JSON without a world-readable temp window."""
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        tmp = Path(tmp_name)
        try:
            # mkstemp creates the file mode 0600 on POSIX before it is exposed.
            # Flush file contents before publication so os.replace never points
            # the canonical path at data that only exists in a userspace buffer.
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                fd = -1
                json.dump(payload, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
            # On filesystems that support directory fsync, persist the rename as
            # well.  Windows and some network filesystems do not permit this.
            dir_fd = -1
            try:
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                dir_fd = os.open(str(path.parent), flags)
                os.fsync(dir_fd)
            except OSError:
                pass
            finally:
                if dir_fd >= 0:
                    os.close(dir_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def _legacy_program_state_path(self, name: str) -> Path:
        base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) \
            else Path(__file__).resolve().parent
        return base / name

    def _keystore_path(self) -> Path:
        return self._user_state_dir() / "archive-keyrings.json"

    def _keystore_key(self, repo) -> str:
        """Identify an archive independently of credentials used to reach it."""
        try:
            parsed = urllib.parse.urlparse(repo.url)
            hostname = parsed.hostname
            port = parsed.port
        except (TypeError, ValueError):
            return repo.name
        if hostname:
            # urlparse().hostname deliberately excludes userinfo.  Re-bracket an
            # IPv6 literal before appending a port so the archive identity stays
            # unambiguous without ever persisting a password.
            host = f"[{hostname}]" if ":" in hostname else hostname
            if port is not None:
                host += f":{port}"
        else:
            host = "local"
        root = (parsed.path or "/").rstrip("/").split("/")
        prefix = "/".join(root[:3])
        return f"{host}{prefix}"

    def _load_keystore(self) -> dict:
        path = self._keystore_path()
        legacy = self._legacy_program_state_path("keyrings.json")
        source = path if path.is_file() else legacy if legacy.is_file() else None
        if source is None:
            return {}
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
            values = data.get("keyrings", {}) if isinstance(data, dict) else {}
        except Exception as exc:
            self._log(f"Keyring store could not be read ({exc}); starting empty.")
            return {}
        if source == legacy and values:
            try:
                self._secure_write_json(path, {"keyrings": values})
                legacy.unlink(missing_ok=True)
                self._log("Migrated remembered archive-keyring references to the per-user Feathered configuration directory.")
            except OSError as exc:
                self._log(f"Could not migrate the legacy keyring reference store: {exc}")
        return values

    def _save_keystore(self) -> None:
        try:
            self._secure_write_json(self._keystore_path(), {"keyrings": self.keystore})
        except OSError as exc:
            self._log(f"Keyring store could not be saved: {exc}")

    def _vendor_signature_store_path(self) -> Path:
        return self._user_state_dir() / "vendor-signatures.json"

    def _load_vendor_signature_profiles(self) -> dict:
        path = self._vendor_signature_store_path()
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            profiles = data.get("vendors", {}) if isinstance(data, dict) else {}
            return profiles if isinstance(profiles, dict) else {}
        except Exception as exc:
            self._log(f"Vendor keyring reference store could not be read ({exc}); starting empty.")
            return {}

    def _save_vendor_signature_profiles(self) -> None:
        # Only paths and non-secret policy labels are persisted.  Key material
        # remains in the operator-selected files and is passed through to GPG.
        try:
            self._secure_write_json(
                self._vendor_signature_store_path(),
                {"vendors": self.vendor_signature_profiles})
        except OSError as exc:
            self._log(f"Vendor keyring references could not be saved: {exc}")

    def _remember_keyring(self, repo) -> None:
        if repo.keyring:
            self.keystore[self._keystore_key(repo)] = repo.keyring
        else:
            self.keystore.pop(self._keystore_key(repo), None)
        self._save_keystore()

    def _apply_keystore(self) -> int:
        """Reapply remembered keyrings after the repository list is rebuilt."""
        applied = 0
        for repo in self.repo_rows:
            if repo.keyring:
                continue
            remembered = self.keystore.get(self._keystore_key(repo))
            if remembered and Path(remembered).is_file():
                repo.keyring = remembered
                applied += 1
        if applied:
            self._log(f"Reapplied {applied} remembered keyring(s) from the key store")
        return applied

    def open_keystore(self):
        """Curate remembered keyrings, including for targets not selected now."""
        win = tk.Toplevel(self); win.title("Key store")
        win.geometry("880x420"); win.transient(self); win.configure(background=BG_APP)
        frame = ttk.Frame(win, padding=14); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Remembered keyrings", style="PaneTitle.TLabel").pack(anchor="w")
        ttk.Label(frame, style="Hint.TLabel", wraplength=820, text=(
            "Keys are remembered per archive, so they survive switching targets and apply to "
            "every distribution that uses the same archive. Entries here are reapplied "
            "automatically whenever the repository list is rebuilt."
        )).pack(anchor="w", pady=(4, 12))

        tree = ttk.Treeview(frame, columns=("archive", "keyring"), show="headings")
        tree.heading("archive", text="Archive"); tree.heading("keyring", text="Keyring")
        tree.column("archive", width=330, minwidth=160); tree.column("keyring", width=470, minwidth=200)

        def reload_rows():
            tree.delete(*tree.get_children())
            for archive, keyring in sorted(self.keystore.items()):
                missing = not Path(keyring).is_file()
                tree.insert("", "end", iid=archive, tags=("bad",) if missing else (),
                            values=(archive, keyring + ("   (file missing)" if missing else "")))
        tree.tag_configure("bad", foreground=ERR_FG)
        reload_rows()
        tree.pack(fill="both", expand=True)

        def remove():
            for iid in tree.selection():
                self.keystore.pop(iid, None)
            self._save_keystore(); reload_rows()

        def add():
            archive = simpledialog.askstring(
                "Key store", "Archive host and path prefix, for example:\n"
                             "archive.ubuntu.com/ubuntu", parent=win)
            if not archive:
                return
            picked = self._ask_keyring()
            if not picked:
                return
            self.keystore[archive.strip()] = picked
            self._save_keystore(); reload_rows()

        row = ttk.Frame(frame); row.pack(fill="x", pady=(12, 0))
        ttk.Button(row, text="Add…", command=add).pack(side="left")
        ttk.Button(row, text="Remove", command=remove).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Apply to current target", command=lambda: (
            self._apply_keystore(), self._refresh_keyring_tree(), self._refresh_repo_tree_if_open())
        ).pack(side="left", padx=(8, 0))

    def change_selected_version(self):
        """Choose which version of an already-added package to bundle.

        Only versions the configured repositories actually carry are offered.
        An archive normally publishes one version of each package, so reaching
        an older one means pointing Feathered at a vault or snapshot repository
        rather than filtering today's index - the dialog says so when there is
        only one choice.
        """
        sel = self.selected_tree.selection() if getattr(self, "selected_tree", None) else ()
        if not sel:
            messagebox.showinfo(APP_TITLE, "Select a package in the bundle list first.")
            return
        index = int(sel[0])
        current = self.selected_packages[index]
        candidates = [p for p in self.single_catalog_packages
                      if p.name == current.name and p.arch == current.arch]
        if not candidates:
            messagebox.showinfo(
                APP_TITLE,
                "No package catalog is loaded, so alternative versions are unknown. "
                "Search for the package first.")
            return
        deb = self._is_deb()
        def sort_key(pkg):
            return pkg.version if deb else (pkg.epoch, pkg.version, pkg.release)
        from functools import cmp_to_key
        if deb:
            ordered = sorted(candidates,
                             key=cmp_to_key(lambda a, b: apt_core.compare_deb_versions(a.version, b.version)),
                             reverse=True)
        else:
            ordered = sorted(candidates,
                             key=cmp_to_key(lambda a, b: compare_evr(
                                 (a.epoch, a.version, a.release), (b.epoch, b.version, b.release))),
                             reverse=True)

        win = tk.Toplevel(self); win.title(f"Version - {current.name}")
        win.geometry("620x420"); win.transient(self); win.grab_set()
        win.configure(background=BG_APP)
        frame = ttk.Frame(win, padding=14); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=current.name, style="PaneTitle.TLabel").pack(anchor="w")
        if len(ordered) == 1:
            note = ("Your repositories publish only this version. Archives normally carry one "
                    "version of each package; to bundle an older one, add a vault or snapshot "
                    "repository (Rocky/Alma point-release trees, snapshot.debian.org, "
                    "old-releases.ubuntu.com) under Additional repositories and search again.")
        else:
            note = (f"{len(ordered)} versions available across your configured repositories. "
                    "The dependency closure is resolved against the version you pick.")
        ttk.Label(frame, style="Hint.TLabel", wraplength=560, text=note).pack(anchor="w", pady=(4, 12))
        tree = ttk.Treeview(frame, columns=("version", "repo", "size"), show="headings", height=10)
        for col, label, width in (("version", "Version", 240), ("repo", "Repository", 200),
                                  ("size", "Size", 90)):
            tree.heading(col, text=label); tree.column(col, width=width)
        for i, pkg in enumerate(ordered):
            tree.insert("", "end", iid=str(i),
                        values=(pkg.evr_text if not deb else pkg.version,
                                pkg.repo.name, human_size(pkg.size)))
        tree.pack(fill="both", expand=True)
        tree.selection_set(str(next((i for i, p in enumerate(ordered)
                                     if p.nevra == current.nevra), 0)))

        def apply_choice():
            picked = tree.selection()
            if picked:
                self.selected_packages[index] = ordered[int(picked[0])]
                self._refresh_selected_packages()
            win.destroy()

        actions = ttk.Frame(frame); actions.pack(fill="x", pady=(12, 0))
        ttk.Button(actions, text="Use this version", style="Primary.TButton",
                   command=apply_choice).pack(side="right")
        ttk.Button(actions, text="Cancel", command=win.destroy).pack(side="right", padx=(0, 8))

    def _refresh_selected_packages(self):
        """Redraw the chosen-package list and keep dependent state in sync."""
        tree = getattr(self, "selected_tree", None)
        if not tree:
            return
        try:
            if not tree.winfo_exists():
                self.selected_tree = None
                return
        except (tk.TclError, AttributeError):
            pass
        self.selected_tree.delete(*self.selected_tree.get_children())
        deb = self._is_deb()
        for i, pkg in enumerate(self.selected_packages):
            version = pkg.version if deb else pkg.evr_text
            self.selected_tree.insert("", "end", iid=str(i),
                                      values=(pkg.name, version, pkg.repo.name))
        count = len(self.selected_packages)
        self.single_selected_var.set(
            "No packages selected" if not count else
            f"{count} package(s) pinned at the versions shown. Each is resolved to its own "
            "closure and the results are merged; double-click a row to change its version.")
        self._sync_workload_repo_state()
        self.loaded_signature = None
        self.last_result = None
        self.analysis_signature = None
        if getattr(self, "summary_var", None):
            self.summary_var.set(
                "Choose at least one package before analyzing or building." if not count else
                f"{count} package(s) chosen. Analyze to preview dependencies, or build now.")
        self._refresh_download_size_preview(None)
        self._refresh_review_contract()
        self._sync_review_action_states()
        self._refresh_package_source_plan()

    def _live_selected_tree(self):
        """Resolve the bundle list that is actually on screen.

        Adding a package re-renders the Repositories workflow, which clears
        cached widget references; Remove/Clear then operated on a destroyed
        tree and silently did nothing."""
        tree = self.__dict__.get("selected_tree")
        try:
            if tree is not None and tree.winfo_exists():
                return tree
        except (tk.TclError, AttributeError):
            pass
        self.selected_tree = None
        render = getattr(self, "_render_repository_workflow", None)
        if callable(render):
            try:
                render(force=True)
            except Exception:
                pass
        tree = self.__dict__.get("selected_tree")
        try:
            return tree if tree is not None and tree.winfo_exists() else None
        except (tk.TclError, AttributeError):
            return None

    def remove_selected_package(self):
        tree = self._live_selected_tree()
        sel = tree.selection() if tree is not None else ()
        if not sel and tree is not None and tree.focus():
            sel = (tree.focus(),)
        if not sel:
            messagebox.showinfo(APP_TITLE, "Select a package to remove.")
            return
        indexes = []
        for iid in sel:
            try:
                indexes.append(int(iid))
            except (TypeError, ValueError):
                continue
        for index in sorted(indexes, reverse=True):
            if 0 <= index < len(self.selected_packages):
                del self.selected_packages[index]
        self._refresh_selected_packages()

    def _entitlement_vendor_ids(self) -> list[str]:
        vendors = set(self.entitlement_profiles)
        if self._profile().key == "rhel" or any(
                r.enabled and (getattr(r, "vendor_id", "") == "redhat" or
                               r.url.startswith("https://cdn.redhat.com"))
                for r in self.repo_rows):
            vendors.add("redhat")
        # Future client-certificate sources automatically appear as their own
        # vendor row instead of inheriting another vendor's credential tuple.
        # Only current-output participants belong on Provenance & Keying; stale
        # profile-managed side channels remain discoverable elsewhere but do not
        # manifest as credential requirements for another Content intent.
        for repo in self._build_repository_scope():
            if repo.client_cert or repo.client_key or repo.ca_cert:
                vendors.add(getattr(repo, "vendor_id", "") or infer_vendor_id(repo.name, repo.url))
        return sorted(vendors, key=vendor_display_name)

    def _entitlement_required(self) -> bool:
        return bool(self._entitlement_vendor_ids())

    def _refresh_entitlement_state(self):
        tree = getattr(self, "entitlement_tree", None)
        holder = getattr(self, "entitlement_card_holder", None)
        if tree is None or not tree.winfo_exists():
            return
        vendors = self._entitlement_vendor_ids()
        if holder is not None:
            if vendors:
                holder.pack(fill="x", pady=(18, 0))
            else:
                holder.pack_forget()
                return
        tree.delete(*tree.get_children())
        for vendor_id in vendors:
            profile = self.entitlement_profiles.get(vendor_id, {})
            refs = [str(profile.get(k, "")) for k in ("cert", "key", "ca")]
            complete = all(refs) and all(Path(x).is_file() for x in refs)
            partial = any(refs)
            if complete:
                status = "Configured"
                tag = "ok"
            elif partial:
                status = "Incomplete or file missing"
                tag = "bad"
            else:
                status = "Not configured"
                tag = "open"
            if vendor_id == "redhat":
                repos = [r.name for r in self.repo_rows if r.enabled and
                         (getattr(r, "vendor_id", "") == "redhat" or
                          r.url.startswith("https://cdn.redhat.com"))]
                scope = "RHEL CDN" + (f" ({len(repos)} enabled repositories)" if repos else "")
            else:
                repos = [r.name for r in self.repo_rows if r.enabled and
                         getattr(r, "vendor_id", "") == vendor_id and
                         (r.client_cert or r.client_key or r.ca_cert)]
                scope = ", ".join(repos[:2]) if repos else "Client-certificate repositories"
                if len(repos) > 2:
                    scope += f" and {len(repos)-2} more"
            tree.insert("", "end", iid=vendor_id, tags=(tag,),
                        values=(vendor_display_name(vendor_id), scope, status))
        tree.tag_configure("ok", foreground=OK_FG)
        tree.tag_configure("open", foreground=FG_MUTED)
        tree.tag_configure("bad", foreground=ERR_FG)
        if vendors and not tree.selection():
            tree.selection_set(vendors[0])

    def _selected_entitlement_vendor(self) -> str | None:
        tree = getattr(self, "entitlement_tree", None)
        sel = tree.selection() if tree is not None else ()
        if not sel:
            messagebox.showinfo(APP_TITLE, "Select a vendor credential row first.")
            return None
        return str(sel[0])

    def _configure_selected_entitlement(self):
        vendor_id = self._selected_entitlement_vendor()
        if vendor_id:
            self._configure_vendor_entitlement(vendor_id)
            self._refresh_entitlement_state()
            self._clear_validation_attention()

    def _forget_selected_entitlement(self):
        vendor_id = self._selected_entitlement_vendor()
        if vendor_id:
            self.forget_entitlement(vendor_id)
            self._refresh_entitlement_state()

    def _forget_entitlement_and_refresh(self):
        self.forget_entitlement("redhat")
        self._refresh_entitlement_state()

    def _sync_entitlement_view(self):
        if getattr(self, "entitlement_tree", None):
            self._refresh_entitlement_state()
