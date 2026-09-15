"""Release discovery, package-version scans, repository probes, reports, and OpenPGP availability.

"""

import math
from release_seed import RELEASE_SEEDS

from acquisition_model import AcquisitionCapability
from feathered_app.context import (
    ACCENT_DIM,
    APP_TITLE,
    BG_APP,
    BG_INPUT,
    Cancelled,
    ERR_FG,
    FG_MUTED,
    FG_TEXT,
    LINE,
    OK_FG,
    PROFILES,
    RepoSpec,
    Reporter,
    RootSourcePolicy,
    SourcePlan,
    WARN_FG,
    discover_apt_releases,
    extract_versions,
    fetch_text,
    gpg_backend,
    gpg_backend_version,
    json,
    re,
    redact_text,
    repository_purpose,
    threading,
    time,
    tk,
    traceback,
    ttk,
    version_key,
)
from feathered_app.ui.theme import messagebox


_RELEASE_CACHE_SCHEMA = 2
_RELEASE_CACHE_TTL_SECONDS = 6 * 60 * 60
_RELEASE_CACHE_MAX_PROFILES = 64
_RELEASE_CACHE_MAX_ITEMS = 256
_RELEASE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,63}$")


def _empty_release_cache() -> dict:
    return {"schema": _RELEASE_CACHE_SCHEMA, "profiles": {}}


def _release_token(value) -> str:
    if not isinstance(value, str):
        raise ValueError("release cache values must be strings")
    value = value.strip()
    if not _RELEASE_TOKEN_RE.fullmatch(value):
        raise ValueError(f"unsafe release-cache token: {value!r}")
    return value


def _release_observation_is_fresh(observed_at, now=None,
                                  ttl_seconds: int = _RELEASE_CACHE_TTL_SECONDS) -> bool:
    """Return True only for finite, non-future observations inside the TTL."""
    try:
        observed = float(observed_at)
    except (TypeError, ValueError, OverflowError):
        return False
    current = time.time() if now is None else float(now)
    if not math.isfinite(observed) or not math.isfinite(current) or observed <= 0:
        return False
    age = current - observed
    return 0 <= age < ttl_seconds


def _validated_release_cache(data, *, now=None) -> dict:
    """Validate schema-2 last-known-good state without coercing hostile values."""
    if not isinstance(data, dict) or data.get("schema") != _RELEASE_CACHE_SCHEMA:
        raise ValueError("unsupported release cache schema")
    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or len(profiles) > _RELEASE_CACHE_MAX_PROFILES:
        raise ValueError("invalid release cache profiles")
    current = time.time() if now is None else float(now)
    clean = _empty_release_cache()
    for raw_key, raw_bucket in profiles.items():
        key = _release_token(raw_key)
        if not isinstance(raw_bucket, dict):
            raise ValueError(f"invalid release cache bucket for {key}")
        bucket = {}
        for field in ("releases", "verified"):
            raw_values = raw_bucket.get(field, [])
            if not isinstance(raw_values, list) or len(raw_values) > _RELEASE_CACHE_MAX_ITEMS:
                raise ValueError(f"invalid {field} list for {key}")
            bucket[field] = [_release_token(value) for value in raw_values]
        for field in ("codenames", "vendor_suites"):
            raw_map = raw_bucket.get(field, {})
            if not isinstance(raw_map, dict) or len(raw_map) > _RELEASE_CACHE_MAX_ITEMS:
                raise ValueError(f"invalid {field} map for {key}")
            bucket[field] = {
                _release_token(k): _release_token(v) for k, v in raw_map.items()
            }
        if "observed_at" in raw_bucket:
            raw_observed = raw_bucket["observed_at"]
            try:
                observed = float(raw_observed) if not isinstance(raw_observed, bool) else math.nan
            except (TypeError, ValueError, OverflowError):
                observed = math.nan
            # Freshness is an authority bit; corrupt/future values must never
            # suppress refresh. Preserve otherwise valid last-known-good releases
            # for offline use, but drop the invalid observation so it is stale.
            if math.isfinite(observed) and observed > 0 and observed <= current:
                bucket["observed_at"] = observed
        if "source" in raw_bucket:
            source = raw_bucket["source"]
            if not isinstance(source, str) or len(source) > 1024 or any(ord(ch) < 32 for ch in source):
                raise ValueError(f"invalid source for {key}")
            bucket["source"] = source
        clean["profiles"][key] = bucket
    return clean


class DiscoveryMixin:
    """Release discovery, package-version scans, repository probes, reports, and OpenPGP availability."""

    def _release_cache_path(self):
        return self._keystore_path().with_name("releases.json")

    def _read_release_cache(self) -> dict:
        path = self._release_cache_path()
        if not path.is_file():
            return _empty_release_cache()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return _validated_release_cache(data)
        except Exception as exc:
            # Corrupt/old cache state is never authoritative. Keep startup usable
            # offline, but do not coerce malformed values into trusted releases.
            log = getattr(self, "_log", None)
            if callable(log):
                log(f"Release cache ignored ({exc}); using empty last-known-good state.")
            return _empty_release_cache()

    def _write_release_cache(self, data: dict) -> None:
        # Revalidate immediately before persistence so future call sites cannot
        # accidentally turn permissive Python values (NaN/Infinity/non-strings)
        # into authoritative cache state. Use the existing crash-safe writer.
        clean = _validated_release_cache(data)
        self._secure_write_json(self._release_cache_path(), clean)

    def _apply_discovered_codenames(self, profile_key: str, discovered: dict):
        """Apply archive-learned version/codename mappings and persist them."""
        prof = PROFILES.get(profile_key)
        if prof is None:
            return
        added = {k: v for k, v in discovered.items() if prof.release_codenames.get(k) != v}
        prof.release_codenames.update(discovered)
        if added:
            self._log("Codename table updated: " + ", ".join(f"{k}={v}" for k, v in sorted(added.items())))
        try:
            data = self._read_release_cache()
            bucket = data.setdefault("profiles", {}).setdefault(profile_key, {})
            bucket["codenames"] = dict(sorted(prof.release_codenames.items()))
            self._write_release_cache(data)
        except Exception as exc:
            self._log(f"Could not cache discovered releases: {exc}")
        # Repository suites are derived from the codename, so rebuild them.
        self._apply_source_method()
        self._update_source_status()

    def _cache_release_state(self, profile_key: str, releases, verified, source: str, observed: bool) -> None:
        """Persist discovered release state as the offline last-known-good view."""
        profile = PROFILES.get(profile_key)
        if profile is None:
            return
        releases = [str(v) for v in releases if str(v).strip()]
        verified = [str(v) for v in verified if str(v).strip()]
        try:
            data = self._read_release_cache()
            bucket = data.setdefault("profiles", {}).setdefault(profile_key, {})
            bucket["releases"] = releases
            bucket["verified"] = verified
            bucket["codenames"] = dict(sorted(profile.release_codenames.items()))
            if profile_key == "devuan":
                import profiles as profiles_module
                bucket["vendor_suites"] = dict(sorted(profiles_module.DEVUAN_TO_DEBIAN.items()))
            if observed:
                bucket["observed_at"] = time.time()
                bucket["source"] = source
            self._write_release_cache(data)
            profile.discovered_versions = list(releases)
            profile.verified_versions = list(verified)
            if observed:
                profile.release_observed_at = float(bucket["observed_at"])
                profile.release_source = source
        except Exception as exc:
            self._log(f"Could not cache release state: {exc}")

    def _load_cached_releases(self):
        """Load last-known-good release observations before the first online refresh."""
        data = self._read_release_cache()
        for key, bucket in data.get("profiles", {}).items():
            prof = PROFILES.get(key)
            if prof is None or not isinstance(bucket, dict):
                continue
            releases = bucket.get("releases") or []
            verified = bucket.get("verified") or []
            codenames = bucket.get("codenames") or {}
            if isinstance(releases, list):
                prof.discovered_versions = [str(v) for v in releases if str(v).strip()]
            if isinstance(verified, list):
                prof.verified_versions = [str(v) for v in verified if str(v).strip()]
            if isinstance(codenames, dict):
                prof.release_codenames.update({str(k): str(v) for k, v in codenames.items()})
            if key == "devuan" and isinstance(bucket.get("vendor_suites"), dict):
                import profiles as profiles_module
                profiles_module.DEVUAN_TO_DEBIAN.update(
                    {str(k): str(v) for k, v in bucket["vendor_suites"].items()})
            try:
                prof.release_observed_at = float(bucket.get("observed_at") or 0)
            except (TypeError, ValueError):
                prof.release_observed_at = 0.0
            prof.release_source = str(bucket.get("source") or "")

        for key, seed in RELEASE_SEEDS.items():
            prof = PROFILES.get(key)
            if prof is None or prof.known_versions():
                continue
            prof.discovered_versions = list(seed.releases)
            for version, codename in seed.codenames:
                prof.release_codenames.setdefault(version, codename)
            prof.release_source = "Bundled release snapshot (2026-09-10): " + seed.source
            prof.release_observed_at = 0.0
            if seed.vendor_suites:
                import profiles as profiles_module
                for release, vendor in seed.vendor_suites:
                    profiles_module.DEVUAN_TO_DEBIAN.setdefault(release, vendor)

    def _archive_root_for_discovery(self, profile) -> str:
        """Return the authoritative APT archive used for release discovery."""
        configured = (getattr(profile, "archive_discovery_url", "") or "").strip()
        if configured:
            return configured
        for repo in self.repo_rows:
            if repo.repo_format == "apt" and repo.role == "dependency" and repo.url.startswith("http"):
                return repo.url
        return ""

    def _apply_auto_release_state(self, profile_key: str, releases, codenames, source: str) -> None:
        """Apply a bounded background listing refresh on the Tk thread."""
        profile = PROFILES.get(profile_key)
        if profile is None:
            return
        changed = {k: v for k, v in codenames.items() if profile.release_codenames.get(k) != v}
        profile.release_codenames.update(codenames)
        self._cache_release_state(
            profile_key, releases, profile.verified_versions, source, True)
        self._apply_auto_release_ui(profile_key, list(releases), bool(changed))
        if changed:
            self._log("Background codename table updated: " + ", ".join(
                f"{k}={v}" for k, v in sorted(changed.items())))

    def _apply_auto_release_ui(self, profile_key: str, releases, rebuild_sources: bool) -> None:
        """Refresh visible release controls only when no foreground operation owns them."""
        if self._busy():
            after = getattr(self, "after", None)
            if callable(after):
                after(1000, lambda: self._apply_auto_release_ui(
                    profile_key, list(releases), rebuild_sources))
            return
        try:
            if self._profile().key != profile_key:
                return
        except Exception:
            return
        self._set_release_choices(list(releases))
        if rebuild_sources:
            self._apply_source_method()
            self._update_source_status()

    def _finish_auto_release_refresh(self, _profile_key: str = "") -> None:
        inflight = self.__dict__.setdefault("_auto_release_refresh_profiles", set())
        inflight.discard(_profile_key)
        self._auto_release_refresh_inflight = bool(inflight)

    def _auto_refresh_releases(self):
        """Refresh stale release listings without taking the global operation lease.

        Startup discovery is advisory and should never freeze package work on an
        offline/black-holed network. It therefore uses a short per-request timeout,
        a bounded/parallel APT probe set, and only refreshes the listing/cache. The explicit
        Refresh releases action still performs the full availability verification.
        """
        profile = self._profile()
        if profile.package_family == "arch" or profile.key.startswith("custom-"):
            return
        if _release_observation_is_fresh(profile.release_observed_at):
            return
        inflight = self.__dict__.setdefault("_auto_release_refresh_profiles", set())
        if profile.key in inflight:
            return
        if self._busy():
            after = getattr(self, "after", None)
            if callable(after):
                after(1000, self._auto_refresh_releases)
            return

        self._auto_release_refresh_inflight = True
        profile_key = profile.key
        inflight.add(profile_key)

        def work():
            try:
                rep = Reporter()
                codenames = {}
                source = ""
                if profile.package_family == "deb":
                    root = (getattr(profile, "archive_discovery_url", "") or "").strip()
                    if not root:
                        return
                    codenames = discover_apt_releases(root, rep, limit=40, timeout=4, workers=6)
                    if not codenames:
                        return
                    if profile.release_style == "codename":
                        by_codename = {codename: version for version, codename in codenames.items()}
                        releases = sorted(set(codenames.values()),
                                          key=lambda name: version_key(by_codename.get(name, "0")),
                                          reverse=True)
                    else:
                        releases = sorted({v for v in codenames if "." in v},
                                          key=version_key, reverse=True)
                    source = f"background archive metadata at {root}"
                else:
                    if not profile.release_url:
                        return
                    text = fetch_text(profile.release_url, rep, retries=1, timeout=5)
                    releases = extract_versions(text, profile.release_pattern, profile.release_mode)
                    if not releases:
                        return
                    source = f"background release listing at {profile.release_url}"
                self.events.put(("auto_release_state", profile_key, releases, codenames, source))
            except Exception:
                # Automatic healing is best-effort. The explicit refresh path
                # remains the diagnostic surface and preserves detailed errors.
                pass
            finally:
                self.events.put(("auto_release_finished", profile_key))

        threading.Thread(target=work, daemon=True).start()

    def detect_versions(self, interactive: bool = True):
        """Refresh the release list and confirm each entry actually resolves.

        Listing releases and knowing a release is *usable* are different
        questions. A vendor page lists RHEL 9.6 long after its packages move to
        a vault; a mirror index lists directories that carry no metadata for the
        selected architecture. Offering those as choices produces a confusing
        failure three steps later, so every candidate is probed against the
        repository that would actually serve it before it is offered.
        """
        if self._busy():
            return
        profile = self._profile()
        arch = self.arch_var.get()
        current_release = self.release_var.get().strip()
        if profile.package_family == "arch":
            self._set_release_choices(["rolling"], keep_current=False)
            if interactive:
                messagebox.showinfo(APP_TITLE, "Arch Linux is rolling release; the target release is 'rolling'.")
            return
        if profile.package_family != "deb" and not profile.release_url:
            if interactive:
                self._focus_validation(
                    "target", getattr(self, "release_combo", None),
                    "This target has no automatic release source. Type the release directly "
                    "in the highlighted Release field.")
            return
        self._begin_worker("Refreshing releases…" if interactive else "Checking release metadata…")

        def work():
            try:
                rep = Reporter(self._log, self._progress, self.cancel_event)
                candidates, source_note, listing_fresh = self._gather_release_candidates(profile, rep)
                if not candidates:
                    cached = profile.known_versions()
                    self.events.put(("profile_versions", profile.key, cached))
                    message = ("Release discovery is unavailable; using cached last-known-good state"
                               if cached else
                               "Release discovery is unavailable and no cached state exists; type a release directly")
                    self.events.put(("done", True, message))
                    return
                results = self._verify_release_candidates(profile, candidates, arch, rep)
                verified = [r["version"] for r in results if r["state"] == "ok"]
                current = current_release
                if current and current not in candidates:
                    # The operator typed something not on the list; check it too.
                    extra = self._verify_release_candidates(profile, [current], arch, rep)
                    results.extend(extra)
                    verified += [r["version"] for r in extra if r["state"] == "ok"]
                unchecked = [r["version"] for r in results if r["state"] == "unverifiable"]
                failed = [r["version"] for r in results if r["state"] == "failed"]
                # Withhold only releases that were checked and failed. If every
                # probe failed, preserve the candidate set rather than destroying
                # the last-known-good selection on a transient network outage.
                offer = [r["version"] for r in results if r["state"] != "failed"] or candidates
                profile.discovered_versions = list(offer)
                profile.verified_versions = list(verified)
                if interactive:
                    self.events.put(("release_report", {"profile": profile.label, "arch": arch,
                                                        "source": source_note, "results": results}))
                self.events.put(("profile_versions", profile.key, offer))
                # A fresh listing is authoritative even for entitlement-gated
                # targets; successful repository probes are also a fresh online
                # observation when the listing endpoint itself was unavailable.
                observed = bool(listing_fresh or verified)
                self.events.put(("cache_release_state", profile.key, offer, verified, source_note, observed))
                if unchecked and not verified and not failed:
                    note = (f"{len(unchecked)} release(s) listed; none could be checked from here "
                            "(this target's repositories are not public)")
                elif failed:
                    note = (f"{len(verified)} available, {len(failed)} unavailable"
                            + (f", {len(unchecked)} not checkable" if unchecked else ""))
                else:
                    note = f"{len(verified)} of {len(results)} release(s) verified available"
                self.events.put(("done", True, note))
            except Cancelled:
                self.events.put(("done", "cancelled", "Operation cancelled"))
            except Exception as exc:
                self._log(traceback.format_exc())
                self.events.put(("done", False, redact_text(str(exc))))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def _gather_release_candidates(self, profile, rep):
        """Collect release candidates from live upstream metadata or cached state."""
        if profile.package_family == "arch":
            return ["rolling"], "rolling repository model", True
        if profile.package_family == "deb":
            root = self._archive_root_for_discovery(profile)
            discovered = discover_apt_releases(root, rep) if root else {}
            if discovered:
                profile.release_codenames.update(discovered)
                self.events.put(("codenames", profile.key, discovered))
                if profile.key == "devuan" and profile.release_url:
                    try:
                        import profiles as profiles_module
                        relation_text = fetch_text(profile.release_url, rep)
                        profiles_module.DEVUAN_TO_DEBIAN.update(
                            profiles_module.extract_devuan_debian_suites(relation_text))
                    except Exception as exc:
                        rep.log(f"Devuan/Debian release relationship discovery unavailable ({exc}).")
                if profile.release_style == "codename":
                    # The codename is the user-facing release identity for Debian
                    # and Devuan. Order by the version that the archive reports.
                    by_codename = {codename: version for version, codename in discovered.items()}
                    candidates = sorted(set(discovered.values()),
                                        key=lambda name: version_key(by_codename.get(name, "0")),
                                        reverse=True)
                else:
                    candidates = sorted({v for v in discovered if "." in v},
                                        key=version_key, reverse=True)
                return candidates, f"archive metadata at {root}", True
            cached = profile.known_versions()
            return cached, ("cached last-known-good release state" if cached
                            else "archive metadata unavailable"), False
        try:
            text = fetch_text(profile.release_url, rep)
            scraped = extract_versions(text, profile.release_pattern, profile.release_mode)
        except Exception as exc:
            rep.log(f"Release listing unavailable ({exc}); using cached last-known-good state.")
            cached = profile.known_versions()
            return cached, ("cached last-known-good release state" if cached
                            else "release listing unavailable"), False
        if not scraped:
            cached = profile.known_versions()
            return cached, ("cached last-known-good release state" if cached
                            else "release listing contained no matching releases"), False
        return scraped, profile.release_url, True

    def _base_template_for(self, profile, version, arch):
        """The repository whose reachability decides whether a release is usable.

        Returns None when the target has no publicly probeable base. RHEL
        defines BaseOS/AppStream as empty placeholders because its content is
        entitlement gated and comes from media or a subscribed mirror, so there
        is genuinely nothing to contact from here.
        """
        try:
            templates = profile.repos_factory(version, arch)
        except Exception:
            return None
        usable = [t for t in templates if t.role == "dependency" and (t.url or "").strip()]
        if not usable:
            return None
        preferred = [t for t in usable if t.enabled and not t.optional]
        return (preferred or usable)[0]

    def _entitled_probe_repo(self, profile, version, arch):
        """A RepoSpec for probing an entitlement-gated CDN, when certs are set.

        RHEL publishes nothing openly, so without credentials a release can only
        be reported as "not checkable". With an entitlement certificate the CDN
        can be contacted over mutual TLS, which answers the more useful
        question: can *this subscription* actually reach this release?

        NOT VERIFIED IN DEVELOPMENT: cdn.redhat.com is unreachable from the
        build environment used to write this, and no entitlement certificate was
        available, so this path has never executed against the real CDN.
        """
        if profile.key != "rhel":
            return None
        credentials = self._entitlement_credentials()
        if not all(credentials):
            return None
        major_m = re.match(r"(\d+)", version)
        major = major_m.group(1) if major_m else version
        url = f"https://cdn.redhat.com/content/dist/rhel{major}/{version}/{arch}/baseos/os/"
        return RepoSpec("RHEL BaseOS (entitled probe)", url, "dependency", 40, True,
                        "Entitlement-authenticated availability check.", version,
                        credentials[0], credentials[1], credentials[2])

    def _verify_release_candidates(self, profile, candidates, arch, rep, limit: int = 14):
        """Probe each candidate's base repository and report what answered."""
        results = []
        checked = candidates[:limit]
        for index, version in enumerate(checked, 1):
            rep.check_cancel()
            self._progress(f"Verifying {version} ({index}/{len(checked)})", index / len(checked))
            # "Could not be checked" is not "not available": a release with no
            # publicly reachable base repository may be perfectly usable once
            # the operator points Feathered at their media or entitled mirror, so
            # it must not be filtered out of the dropdown.
            entry = {"version": version, "state": "unverifiable", "detail": "", "url": ""}
            # An entitled CDN probe turns "not checkable" into a real answer.
            entitled = self._entitled_probe_repo(profile, version, arch)
            if entitled is not None:
                entry["url"] = entitled.url
                try:
                    ok, detail = self._probe_repository_backend(entitled, rep)
                except Cancelled:
                    raise
                except Exception as exc:
                    ok, detail = False, str(exc)
                entry["state"] = "ok" if ok else "failed"
                if ok:
                    entry["detail"] = detail or "Reachable with your entitlement certificate"
                else:
                    entry["detail"] = (
                        (detail or "No response") + "\n\nA failure here can mean the release does "
                        "not exist, or that your subscription does not entitle you to it, or that "
                        "the entitlement certificate has expired. Check the certificate date "
                        "before assuming the release is unavailable.")
                results.append(entry)
                continue
            base = self._base_template_for(profile, version, arch)
            if base is None:
                entry["detail"] = (
                    f"{profile.label} has no publicly reachable base repository, so this release "
                    "cannot be checked from here. Its content comes from installation media or a "
                    "subscribed/entitled mirror, which you point Feathered at on Repositories."
                    + ("\n\nConfigure a Red Hat entitlement certificate under Sources → "
                       "'Red Hat CDN entitlement' and re-run this check: Feathered can then contact "
                       "the CDN over mutual TLS and confirm which releases your subscription "
                       "actually reaches." if profile.key == "rhel" else ""))
                results.append(entry)
                continue
            repo = self._repo_from_template(base)
            entry["url"] = repo.url
            try:
                ok, detail = self._probe_repository_backend(repo, rep)
            except Cancelled:
                raise
            except Exception as exc:
                ok, detail = False, str(exc)
            entry["state"] = "ok" if ok else "failed"
            entry["detail"] = detail or ("Repository metadata readable" if ok else "No response")
            results.append(entry)
        if len(candidates) > limit:
            rep.log(f"Verified the {limit} newest of {len(candidates)} candidate releases.")
        return results

    def show_release_report(self, payload):
        """Show which releases are actually usable, and why the rest are not."""
        results = payload["results"]
        verified = [r for r in results if r["state"] == "ok"]
        failed = [r for r in results if r["state"] == "failed"]
        unchecked = [r for r in results if r["state"] == "unverifiable"]
        win = tk.Toplevel(self); win.title("Release verification")
        win.geometry("900x600"); win.minsize(700, 460)
        win.transient(self); win.configure(background=BG_APP)
        frame = ttk.Frame(win, padding=14); frame.pack(fill="both", expand=True)
        if unchecked and not verified and not failed:
            headline = f"{len(unchecked)} releases listed - none checkable from here"
            explanation = (
                f"{payload['profile']} does not publish its repositories openly, so Feathered cannot "
                "confirm these releases from this machine. They are all still offered - pick the "
                "one matching your target, then point Feathered at your installation media or "
                "entitled mirror on Repositories and use 'Test all sources'.")
        else:
            parts = []
            if verified:
                parts.append(f"{len(verified)} available")
            if failed:
                parts.append(f"{len(failed)} unavailable")
            if unchecked:
                parts.append(f"{len(unchecked)} not checkable")
            headline = ", ".join(parts) or "No releases checked"
            explanation = (f"{payload['profile']} · {payload['arch']} · candidates from "
                           f"{payload['source']}. Only releases that were checked and failed are "
                           "withheld from the dropdown.")
        ttk.Label(frame, text=headline, style="PaneTitle.TLabel").pack(anchor="w")
        ttk.Label(frame, style="Hint.TLabel", wraplength=840, text=explanation).pack(
            anchor="w", pady=(4, 12))

        top = ttk.Frame(frame); top.pack(fill="x")
        tree = ttk.Treeview(top, columns=("version", "state"), show="headings", height=10)
        tree.heading("version", text="Release"); tree.heading("state", text="Result")
        tree.column("version", width=180, minwidth=90); tree.column("state", width=280, minwidth=120)
        tree.tag_configure("ok", foreground=OK_FG)
        tree.tag_configure("bad", foreground=ERR_FG)
        tree.tag_configure("unknown", foreground=FG_MUTED)
        labels = {"ok": ("Available", "ok"),
                  "failed": ("Not available", "bad"),
                  "unverifiable": ("Offered - not checkable", "unknown")}
        rows = {}
        for i, r in enumerate(results):
            iid = str(i); rows[iid] = r
            text, tag = labels[r["state"]]
            tree.insert("", "end", iid=iid, tags=(tag,), values=(r["version"], text))
        vs = ttk.Scrollbar(top, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vs.set)
        tree.pack(side="left", fill="both", expand=True); vs.pack(side="right", fill="y")

        ttk.Label(frame, text="DETAIL", style="Group.TLabel").pack(anchor="w", pady=(12, 4))
        detail = tk.Text(frame, height=8, wrap="word", font=("Consolas", 9),
                         background=BG_INPUT, foreground=FG_TEXT, insertbackground=FG_TEXT,
                         selectbackground=ACCENT_DIM, selectforeground=FG_TEXT, relief="flat",
                         borderwidth=0, highlightthickness=1, highlightbackground=LINE,
                         highlightcolor=LINE, padx=10, pady=8)
        detail.pack(fill="both", expand=True)
        detail.tag_configure("ok", foreground=OK_FG)
        detail.tag_configure("bad", foreground=ERR_FG)

        def show(_event=None):
            sel = tree.selection()
            detail.configure(state="normal"); detail.delete("1.0", "end")
            if sel:
                r = rows[sel[0]]
                _text, tag = labels[r["state"]]
                detail.insert("end", f"Release {r['version']}\n", tag)
                if r["url"]:
                    detail.insert("end", f"{r['url']}\n")
                detail.insert("end", "\n" + r["detail"] + "\n")
                # Guidance keyed to the actual outcome: suggesting a vault
                # mirror for a release that was never probed is misleading.
                if r["state"] == "failed":
                    detail.insert("end", "\nThis release is withheld from the dropdown. A "
                                         "superseded point release is often moved to a vault "
                                         "mirror - enable the vault repositories under Manage "
                                         "repositories, or type the release directly to override.")
                elif r["state"] == "unverifiable":
                    detail.insert("end", "\nThis release is still offered. Select it, configure "
                                         "your media or mirror on Repositories, then use "
                                         "'Test all sources' to confirm it works.")
            else:
                detail.insert("1.0", "Select a release to see the result.")
            detail.configure(state="disabled")
        tree.bind("<<TreeviewSelect>>", show)
        first_bad = next((k for k, r in rows.items() if r["state"] == "failed"), None)
        target = first_bad or next(iter(rows), None)
        if target:
            tree.selection_set(target)
        show()

    def scan_package_versions(self):
        if self._busy(): return
        if self._workload().version_axis == "kubernetes-minor":
            self._scan_k8s_patch_versions(refresh=True); return
        workload = self._workload()
        names = workload.packages_for(self._profile().package_family)
        if not workload.has_version_axis:
            messagebox.showinfo(
                APP_TITLE,
                f"{workload.label} is a collection of independently versioned tools, so one "
                "version number does not describe it. Each package resolves to the newest "
                "version your repositories offer. To pin an exact version of one of them, use "
                "Exact packages mode.")
            return
        # The nominated version package may be family-specific. Arch presets use
        # the first native mapped root as their version anchor.
        version_package = (names[0] if self._is_arch() and names else
                           workload.version_package if workload.version_package in names else "")
        if not version_package:
            messagebox.showinfo(
                APP_TITLE,
                f"'{workload.version_package}' is not part of this workload on a "
                f"{self._profile().package_family.upper()} target, so its versions cannot be "
                "scanned. The packages still resolve to the newest available.")
            return
        try:
            repos, role = self._version_scan_repositories(workload)
        except Exception as exc:
            messagebox.showerror(APP_TITLE, redact_text(str(exc))); return
        from copy import deepcopy
        from feathered_app.context import apt_core, arch_core
        import core
        family = self._profile().package_family
        backend = arch_core if family == 'arch' else apt_core if family == 'deb' else core
        arch = self.arch_var.get()
        repos = deepcopy(repos)
        context = self._package_version_scan_context()
        self._begin_worker(f"Refreshing {workload.label} versions…")
        def work():
            try:
                rep = Reporter(self._log, self._progress, self.cancel_event)
                packages = []
                for repo in repos:
                    packages.extend(backend.load_repository(repo, {arch, "noarch", "all"}, rep))
                approved = workload.candidate_names_for(family, version_package)
                actual_version_package = next(
                    (candidate for candidate in approved
                     if any(getattr(pkg, "name", "") == candidate for pkg in packages)),
                    "")
                if not actual_version_package:
                    raise RuntimeError(
                        f"None of the approved package identities for {version_package} are present: "
                        + " / ".join(approved))
                versions = backend.package_versions(packages, actual_version_package, role, arch)
                self.events.put(("scoped_package_versions", context, ["Latest"] + versions))
                self.events.put(("done", True,
                                 f"Found {len(versions)} version(s) of {actual_version_package}"))
            except Cancelled as exc:
                self.events.put(("done", "cancelled", redact_text(str(exc) or "Operation cancelled")))
            except Exception as exc:
                self._log(traceback.format_exc()); self.events.put(("done", False, redact_text(str(exc))))
        self.worker = threading.Thread(target=work, daemon=True); self.worker.start()

    def _package_version_scan_context(self):
        return (self._profile().key, self.release_var.get(), self.arch_var.get(), self._workload().key,
                tuple((r.source_identity, r.url, r.enabled) for r in self.repo_rows))

    def _receive_package_versions(self, context, versions):
        if context != self._package_version_scan_context():
            return
        self.package_version_combo['values'] = versions
        if self.package_version_var.get() not in versions:
            self.package_version_var.set('Latest')

    def _version_scan_repositories(self, workload):
        role = workload.repository_role_for(workload.version_package or "")
        if role:
            repos = [r for r in self.repo_rows if r.enabled and r.role == role and r.url]
            if not repos:
                raise RuntimeError(
                    f"No enabled workload repository satisfies role '{role}' for {workload.label}. "
                    "Continue to Repositories to add or enable it first.")
            return repos, role
        repos = [r for r in self.repo_rows
                 if r.enabled and r.url and self._repo_tier(r) == "base"]
        if not repos:
            raise RuntimeError(
                "No enabled distribution repository is available for version discovery. "
                "Continue to Repositories and enable the distribution source set first.")
        return repos, None

    def _probe_source_context(self):
        """Snapshot source-plan semantics for an asynchronous broad probe."""
        try:
            acquisition = self._acquisition_state()
            package_only = acquisition.capability is AcquisitionCapability.PACKAGE_ONLY
            package_only_reason = acquisition.reason
        except Exception:
            package_only = self._package_only_acquisition_mode()
            package_only_reason = ""
        context = {
            "mirror_mode": self._mirror_mode(),
            "single_mode": self._single_mode(),
            "package_only": package_only,
            "package_only_reason": package_only_reason,
            "distribution_required": False,
            "required_roles": [],
            "local_media_pending": self._local_media_pending(),
            "selected_repo_names": [],
        }
        if context["mirror_mode"]:
            context["selected_repo_names"] = [r.name for r in self.repo_rows
                                               if r.url.strip() and self._mirror_repo_selected(r)]
        elif context["single_mode"]:
            context["selected_repo_names"] = [p.repo.name for p in getattr(self, "selected_packages", [])]
        else:
            plan = self._source_plan()
            context["distribution_required"] = plan.distribution_required
            context["required_roles"] = list(plan.required_roles)
        return context

    def _probe_repository_purpose(self, repo, context):
        if context.get("mirror_mode") and repo.name in set(context.get("selected_repo_names", [])):
            return "selected mirror"
        if context.get("single_mode") and repo.name in set(context.get("selected_repo_names", [])):
            return "selected root"
        plan = SourcePlan([
            RootSourcePolicy("<probe>", "distribution")
            for _ in [0] if context.get("distribution_required")
        ] + [
            RootSourcePolicy("<probe>", "workload", role)
            for role in context.get("required_roles", [])
        ])
        return repository_purpose(plan, repo, tier_getter=self._repo_tier)

    def probe_all(self):
        """Probe every enabled URL, then assess it against the selected source plan.

        Broad reachability and root coverage are intentionally separate. An
        missing dependency-provider plan no longer prevents a dedicated workload
        upstream from being tested; the report explains whether package-only mode
        is active or a required root scope is unsatisfied.
        """
        if self._busy(): return
        if self._mirror_mode():
            enabled = [(i, r) for i, r in enumerate(self.repo_rows)
                       if r.url.strip() and self._mirror_repo_selected(r)]
        else:
            participating = set(map(id, self._participating_transaction_repositories()))
            enabled = [(i, r) for i, r in enumerate(self.repo_rows) if id(r) in participating]
        if not enabled:
            detail = "No repository URLs are enabled to test."
            if self._local_media_pending():
                detail += " Local media is selected but no repository folder has been loaded."
            messagebox.showinfo(APP_TITLE, detail)
            return
        context = self._probe_source_context()
        self._begin_worker("Testing sources…")
        def work():
            try:
                rep = Reporter(self._log, self._progress, self.cancel_event)
                results = []
                for n, (i, repo) in enumerate(enabled, 1):
                    ok, detail = self._probe_repository_backend(repo, rep)
                    results.append({"name": repo.name, "url": repo.url, "role": repo.role,
                                    "tier": self._repo_tier(repo),
                                    "purpose": self._probe_repository_purpose(repo, context),
                                    "optional": repo.optional, "signed": bool(repo.keyring),
                                    "ok": ok, "detail": detail})
                    self.events.put(("probe", i, ok, detail))
                    self._progress(f"Testing {n}/{len(enabled)}", n / max(1, len(enabled)))
                healthy = sum(1 for r in results if r["ok"])
                self.events.put(("probe_report", {"results": results, "context": context}))
                self.events.put(("done", True,
                                 f"{healthy} of {len(results)} source(s) responded"))
            except Cancelled as exc:
                self.events.put(("done", "cancelled", redact_text(str(exc) or "Operation cancelled")))
            except Exception as exc:
                self.events.put(("done", False, redact_text(str(exc))))
        self.worker = threading.Thread(target=work, daemon=True); self.worker.start()

    @staticmethod
    def _probe_verdict_lines(results, context):
        """Pure source-plan-aware verdict used by Test all sources and tests."""
        healthy = [r for r in results if r.get("ok")]
        failed = [r for r in results if not r.get("ok")]
        verdict = []
        root_gaps = []
        healthy_names = {r.get("name", "") for r in healthy}
        if context.get("mirror_mode"):
            missing = [n for n in context.get("selected_repo_names", []) if n not in healthy_names]
            if missing:
                root_gaps.append("selected mirror source(s) unreachable: " + ", ".join(missing))
        elif context.get("single_mode"):
            missing = [n for n in context.get("selected_repo_names", []) if n not in healthy_names]
            if missing:
                root_gaps.append("selected package source(s) unreachable: " + ", ".join(missing))
        else:
            if context.get("distribution_required"):
                if context.get("local_media_pending"):
                    root_gaps.append("distribution roots require local media, but no repository folder is loaded")
                elif not any(r.get("ok") and r.get("tier") == "base" for r in results):
                    root_gaps.append("no reachable distribution/base repository remains for distribution-native roots")
            for role in context.get("required_roles", []):
                if not any(r.get("ok") and r.get("role") == role for r in results):
                    root_gaps.append(f"no reachable workload repository remains for role '{role}'")
        if root_gaps:
            verdict.append("Selected root source scope needs attention: " + "; ".join(root_gaps) + ".")
        elif context.get("package_only"):
            reason = str(context.get("package_only_reason") or "").strip()
            verdict.append(
                "Selected root source(s) are reachable. Package-only acquisition is active."
                + ((" " + reason) if reason else ""))
        else:
            verdict.append("The source scopes required by the selected roots have reachable repositories. Package coverage still determines whether the requested package names/versions are actually present.")
        supplemental_failed = [r for r in failed if r.get("purpose") == "dependency/supplement"]
        if supplemental_failed:
            verdict.append(f"{len(supplemental_failed)} supplemental enabled source(s) failed. They will not participate in resolution; the resolver will report any dependency gap that results.")
        root_related_failed = [r for r in failed if r.get("purpose") != "dependency/supplement"]
        if root_related_failed and not root_gaps:
            verdict.append(f"{len(root_related_failed)} source(s) in a required root scope failed, but another repository in the same scope responded.")
        unsigned = [r for r in healthy if not r.get("signed")]
        if unsigned:
            verdict.append(f"{len(unsigned)} reachable source(s) have no archive keyring, so their metadata is not signature-verified.")
        return verdict

    def show_probe_report(self, payload):
        """Per-source health plus a source-plan-aware capability verdict."""
        if isinstance(payload, dict):
            results = list(payload.get("results", []))
            context = dict(payload.get("context", {}))
        else:  # Compatibility with older callers/tests.
            results = list(payload)
            context = self._probe_source_context()
        win = tk.Toplevel(self); win.title("Source test results")
        win.geometry("1020x700"); win.minsize(760, 520)
        win.transient(self); win.configure(background=BG_APP)
        frame = ttk.Frame(win, padding=14); frame.pack(fill="both", expand=True)
        healthy = [r for r in results if r["ok"]]

        headline = f"{len(healthy)} of {len(results)} sources responded"
        ttk.Label(frame, text=headline, style="PaneTitle.TLabel").pack(anchor="w")
        verdict = self._probe_verdict_lines(results, context)
        ttk.Label(frame, text="  ".join(verdict), style="Hint.TLabel", wraplength=920).pack(
            anchor="w", pady=(4, 12))

        # Split view: the list stays scannable while the full text of a
        # failure gets a wrapping pane of its own. Error strings routinely run
        # past any sensible column width, and forcing the operator to drag
        # columns to read a 404 is the wrong trade.
        split = ttk.Frame(frame); split.pack(fill="both", expand=True)
        top = ttk.Frame(split); top.pack(fill="x")
        tree = ttk.Treeview(top, columns=("name", "purpose", "role", "state"), show="headings", height=9)
        for col, text_, width in (("name", "Source", 265), ("purpose", "Used for", 190),
                                  ("role", "Role", 105), ("state", "Result", 170)):
            tree.heading(col, text=text_); tree.column(col, width=width, minwidth=90)
        tree.tag_configure("ok", foreground=OK_FG)
        tree.tag_configure("warn", foreground=WARN_FG)
        tree.tag_configure("bad", foreground=ERR_FG)
        rows = {}
        for i, r in enumerate(results):
            if r["ok"]:
                state, tag = ("Reachable" if r["signed"] else "Reachable, unsigned"), \
                             ("ok" if r["signed"] else "warn")
            else:
                state, tag = ("Failed (optional)" if r["optional"] else "FAILED"), \
                             ("warn" if r["optional"] else "bad")
            iid = str(i)
            rows[iid] = r
            tree.insert("", "end", iid=iid, tags=(tag,), values=(r["name"], r.get("purpose", "dependency/supplement"), r["role"], state))
        vs = ttk.Scrollbar(top, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vs.set)
        tree.pack(side="left", fill="both", expand=True); vs.pack(side="right", fill="y")

        ttk.Label(split, text="DETAIL", style="Group.TLabel").pack(anchor="w", pady=(12, 4))
        detail = tk.Text(split, height=10, wrap="word", font=("Consolas", 9),
                         background=BG_INPUT, foreground=FG_TEXT, insertbackground=FG_TEXT,
                         selectbackground=ACCENT_DIM, selectforeground=FG_TEXT,
                         relief="flat", borderwidth=0, highlightthickness=1,
                         highlightbackground=LINE, highlightcolor=LINE, padx=10, pady=8)
        detail.pack(fill="both", expand=True)
        detail.tag_configure("bad", foreground=ERR_FG)
        detail.tag_configure("ok", foreground=OK_FG)

        def show_detail(_event=None):
            sel = tree.selection()
            detail.configure(state="normal")
            detail.delete("1.0", "end")
            if not sel:
                detail.insert("1.0", "Select a source to see its full result.")
            else:
                r = rows[sel[0]]
                tag = "ok" if r["ok"] else "bad"
                detail.insert("end", f"{r['name']}\n", tag)
                detail.insert("end", f"{r['url']}\n\n")
                detail.insert("end", (r["detail"] or "No further detail reported.") + "\n")
                if not r["ok"]:
                    if r["optional"]:
                        detail.insert("end", "\nThis source is marked optional and will be omitted while unavailable.")
                    elif r.get("purpose") == "dependency/supplement":
                        detail.insert("end", "\nThis enabled supplemental source is unavailable. Feathered will continue with the remaining source set and let dependency resolution report any resulting gap.")
                    else:
                        detail.insert("end", "\nThis source belongs to a selected root source scope. The summary above shows whether another reachable repository still satisfies that scope; package coverage remains the package-presence oracle.")
                elif not r["signed"]:
                    detail.insert("end", "\nNo archive keyring is configured, so this source's "
                                         "metadata is not signature-verified. Set one on the "
                                         "Provenance & Keying stage.")
            detail.configure(state="disabled")

        tree.bind("<<TreeviewSelect>>", show_detail)

        def copy_report():
            lines = [f"{r['name']}\t{r.get('purpose', 'dependency/supplement')}\t{r['role']}\t{'ok' if r['ok'] else 'FAILED'}\t"
                     f"{r['url']}\t{r['detail']}" for r in results]
            self.clipboard_clear(); self.clipboard_append("\n".join(lines))
        buttons = ttk.Frame(split); buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="Copy report", command=copy_report).pack(side="right")

        first_failure = next((k for k, r in rows.items() if not r["ok"]), None)
        target = first_failure or (next(iter(rows), None))
        if target:
            tree.selection_set(target); tree.focus(target)
        show_detail()

    def open_repositories(self, tier="additional"):
        """Open the supplemental repository editor or the all-repository view.

        Base repositories have their own inline editor. The ordinary manager
        defaults to supplemental repositories, while provenance can still open
        the complete set when it needs an advanced per-repository override.
        """
        tier = tier if tier in {"additional", "workload", "base", "all"} else "additional"
        if self.repo_window and self.repo_window.winfo_exists():
            if getattr(self, "repo_window_tier", "additional") == tier:
                self.repo_window.lift(); return
            self.repo_window.destroy()
            self.repo_window = None; self.repo_tree = None
        self.repo_window_tier = tier
        win = tk.Toplevel(self); self.repo_window = win
        win.configure(background=BG_APP)
        title = {"additional": "Additional repositories", "workload": "Workload repositories",
                 "base": "Base repositories", "all": "Repositories"}[tier]
        win.title(title); win.geometry("1000x430"); win.transient(self)
        frame = ttk.Frame(win, padding=12); frame.pack(fill="both", expand=True)
        if tier == "additional":
            ttk.Label(frame, style="Hint.TLabel", wraplength=920, text=(
                "These repositories supplement the editable distribution base and are not tied "
                "to a particular workload. They are preserved when you choose another source plan.")).pack(anchor="w", pady=(0, 8))
        elif tier == "workload":
            ttk.Label(frame, style="Hint.TLabel", wraplength=920, text=(
                "These sources were configured for workload repository roles. Content can seed "
                "recommended sources; this window edits the same repository objects directly.")).pack(anchor="w", pady=(0, 8))
        elif tier == "base":
            ttk.Label(frame, style="Hint.TLabel", wraplength=920, text=(
                "These are foundational distribution-source repositories. In Custom repositories mode "
                "the list starts empty: only repositories you add here become part of the base source "
                "universe; Feathered does not silently mix in distribution defaults.")).pack(anchor="w", pady=(0, 8))
        cols = ("enabled", "name", "role", "priority", "trust", "evidence", "url", "status")
        tree_frame = ttk.Frame(frame); tree_frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings"); self.repo_tree = tree
        widths = {"enabled": 65, "name": 210, "role": 90, "priority": 60, "trust": 125,
                  "evidence": 125, "url": 420, "status": 100}
        for c in cols:
            tree.heading(c, text=c.title()); tree.column(c, width=widths[c], stretch=c in {"name", "url"})
        tv = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        th = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=tv.set, xscrollcommand=th.set)
        tree_frame.rowconfigure(0, weight=1); tree_frame.columnconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew"); tv.grid(row=0, column=1, sticky="ns"); th.grid(row=1, column=0, sticky="ew")
        tree.bind("<Double-1>", self._toggle_repo)
        buttons = ttk.Frame(frame); buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Add URL", command=lambda t=tier: self.add_url_repo(t)).pack(side="left")
        ttk.Button(buttons, text="Add local repo", command=lambda t=tier: self.add_local_repo(t)).pack(side="left", padx=(6, 0))
        ttk.Button(buttons, text="Edit", command=self.edit_repo).pack(side="left", padx=(6, 0))
        ttk.Button(buttons, text="Remove", command=self.remove_repo).pack(side="left", padx=(6, 0))
        ttk.Button(buttons, text="Provenance…", command=self.edit_repo_trust).pack(side="left", padx=(6, 0))
        ttk.Label(buttons, text="Double-click a row to enable/disable.", style="Hint.TLabel").pack(side="right")
        self._refresh_repo_tree_if_open()

    def _sync_mirror_repos(self):
        if getattr(self, "mirror_tree", None) and self._mirror_mode():
            self._refresh_mirror_repos()

    def _sync_custom_guidance(self):
        try:
            if self._workload().custom:
                self._update_custom_guidance()
        except Exception:
            pass

    def _sync_openpgp_availability(self) -> None:
        """Enable or disable the signature layers based on a real verifier.

        Without gpg/gpgv these controls cannot do anything: a configured
        keyring would fail at build time and bundle signing is impossible.
        Greying them with a stated reason is more honest than accepting
        configuration that is guaranteed not to work."""
        hint = self.__dict__.get("openpgp_status_hint")
        if hint is None:
            return
        # A frozen release raises here when its bundled verifier fails
        # authentication. That is a different situation from "GnuPG is not
        # installed" and must not be shown as an install prompt.
        integrity_failure = ""
        try:
            backend = gpg_backend()
        except RuntimeError as exc:
            backend = None
            integrity_failure = str(exc)
        widgets = getattr(self, "_openpgp_dependent_widgets", [])
        if backend:
            version = ""
            try:
                version = gpg_backend_version(backend)
            except Exception:
                version = ""
            hint.configure(
                text=f"Verifier found: {version or backend}. Repository signature verification, "
                     "vendor package signatures and bundle signing are available.",
                foreground=OK_FG)
            row = self.__dict__.get("openpgp_install_row")
            if row is not None:
                row.pack_forget()
            for widget in widgets:
                try:
                    widget.configure(state="normal")
                except tk.TclError:
                    pass
            return
        if integrity_failure:
            hint.configure(text="Bundled OpenPGP verifier failed authentication and will not be "
                                f"used. {integrity_failure} Reinstall Feathered from a trusted "
                                "release; do not attempt to repair the gnupg folder by hand.",
                           foreground=ERR_FG)
            row = self.__dict__.get("openpgp_install_row")
            if row is not None:
                row.pack_forget()
            for widget in widgets:
                try:
                    widget.configure(state="disabled")
                except tk.TclError:
                    pass
            return
        hint.configure(
            text="GnuPG is not installed, so no OpenPGP verifier is available. Repository "
                 "metadata will be reported as unsigned, vendor package signatures cannot be "
                 "checked, and bundles cannot be signed. Package digest verification and "
                 "independent mirror evidence still work and are unaffected. Install GnuPG "
                 "(Gpg4win, or the lighter 'Simple installer for GnuPG' from gnupg.org), then "
                 "press Re-check - no restart needed. Release builds of Feathered ship a "
                 "verifier beside the executable; a source checkout does not.",
            foreground=WARN_FG)
        row = self.__dict__.get("openpgp_install_row")
        if row is not None:
            row.pack(fill="x", pady=(8, 0))
        for widget in widgets:
            try:
                widget.configure(state="disabled")
            except tk.TclError:
                pass

    def _show_gnupg_install_help(self) -> None:
        messagebox.showinfo(
            APP_TITLE,
            "Feathered verifies OpenPGP signatures with GnuPG's gpgv/gpg rather than "
            "reimplementing OpenPGP.\n\n"
            "Install one of:\n"
            "  • Gpg4win - https://gpg4win.org (full suite)\n"
            "  • 'Simple installer for GnuPG' - https://gnupg.org/download (command line only)\n\n"
            "Make sure the install adds gpg.exe to PATH, then press Re-check.\n\n"
            "Feathered does not install software on your machine on its own: it is an airgap "
            "tool, and silently downloading and running an installer would contradict that. "
            "Release builds (build_exe.bat) stage a verifier next to Feathered.exe so end "
            "users need no separate install; you are running from a source checkout, which "
            "uses whatever GnuPG is on the system.")
