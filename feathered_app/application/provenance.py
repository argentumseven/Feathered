"""Provenance policy, evidence selection, digest inspection, and keyring policy.

"""

import apt_core

from checksum_inspection import inspect_checksums
from feathered_app.build_sources import BuildSourcesMixin, _SnapshotSelection  # noqa: F401
from feathered_app.context import (
    APP_TITLE,
    AUTH_INDEPENDENT,
    AUTH_UNKNOWN,
    BG_APP,
    BG_PANEL,
    Cancelled,
    ERR_FG,
    EvidenceCandidate,
    FG_MUTED,
    OK_FG,
    PROFILES,
    Path,
    REL_EXACT_ARTIFACT,
    REL_EXACT_MIRROR,
    REL_REBUILD_PEER,
    RepoSpec,
    Reporter,
    WARN_FG,
    candidate_display_label,
    copy,
    evidence_artifact_candidates,
    evidence_authority_relationship,
    evidence_relationship,
    evidence_repo_for_url,
    filedialog,
    find_independent_peer_package,
    independent_peer_packages_match,
    infer_vendor_id,
    mirror_catalog,
    mirrors_are_distinct,
    package_digest_map,
    redact_text,
    redact_url,
    repo_relative_url,
    repositories_are_exact_mirror_compatible,
    repository_channel,
    repository_verification_strategy,
    spot_compare_artifact_urls,
    spot_compare_peer_artifact_urls,
    threading,
    tk,
    ttk,
    urllib,
    vendor_display_name,
)
from feathered_app.ui.theme import FeatheredActivityPulse, messagebox




class ProvenanceMixin(BuildSourcesMixin):
    """Provenance policy, evidence selection, digest inspection, and keyring policy."""

    def _detected_digest_algorithms(self, repo):
        # retain explicit metadata-inspection
        # results even when no dependency analysis has been run yet.
        cached = getattr(self, "_provenance_detected_cache", {}).get(
            self._provenance_repo_cache_key(repo), [])
        algorithms = set(cached)
        for pkg in getattr(self, "loaded_packages", []) or []:
            pkg_repo = getattr(pkg, "repo", None)
            same_repo = pkg_repo is repo or (pkg_repo is not None and
                getattr(pkg_repo, "name", "") == repo.name and
                getattr(pkg_repo, "normalized_url", "") == repo.normalized_url)
            if same_repo:
                algorithms.update(package_digest_map(pkg))
        order = {"sha512": 0, "sha384": 1, "sha256": 2}
        return sorted(algorithms, key=lambda a: order.get(a, 99))

    def _evidence_catalog_profile_key(self, repo):
        """Return the mirror-catalog distribution that owns *repo*.

        The selected target profile is not necessarily the repository vendor.
        RHEL public-fallback mode deliberately places AlmaLinux and Rocky Linux
        repositories in one plan.  Exact-mirror catalogs must follow each row's
        actual distribution, otherwise a Rocky row can be populated from the
        Alma catalog (and vice versa).
        """
        try:
            active_key = self._profile().key
        except Exception:
            active_key = ""
        repo_text = f"{getattr(repo, 'name', '')} {getattr(repo, 'url', '')}".lower()
        # EPEL is Fedora-operated, so generic vendor inference intentionally
        # returns ``fedora``.  Its mirror layout is nevertheless a separate
        # archive (/pub/epel), and using the Fedora OS catalog leaves EPEL with
        # no derivable evidence candidates.  Route EPEL rows explicitly.
        if "epel" in repo_text:
            return "epel"

        vendor = infer_vendor_id(getattr(repo, "name", ""), getattr(repo, "url", ""))
        vendor_profiles = {
            "almalinux": "alma",
            "rocky": "rocky",
            "redhat": "rhel",
            "ubuntu": "ubuntu",
            "debian": "debian",
            "fedora": "fedora",
            "centos": "centos-stream",
            "arch": "arch",
            "artix": "artix",
            "devuan": "devuan",
            "photon": "photon",
        }
        inferred_key = vendor_profiles.get(vendor, "")
        if inferred_key in PROFILES:
            return inferred_key
        return active_key if active_key in PROFILES else ""

    def _profile_evidence_candidates(self, repo):
        """Derive same-distribution exact mirrors from the local mirror catalog.

        1.1.5 deliberately stops treating a single hard-coded profile URL as the
        distro's evidence model. The editable mirror_catalogs/<distro>.json file
        is now the source of exact-mirror candidates. A listed mirror gives an
        independent copy/transport path, not an independent signing authority.
        """
        profile_key = self._evidence_catalog_profile_key(repo)
        out = mirror_catalog.candidates_for_repository(profile_key, repo)
        # Catalog data is allowed to be user-edited.  Enforce the exact-mirror
        # invariant here as well as in the catalog routing above: a candidate
        # advertised as exact must remain same-vendor under runtime relationship
        # classification and must not point back at the acquisition endpoint.
        safe = []
        for candidate in out:
            if not mirrors_are_distinct(repo.normalized_url, candidate.url)[0]:
                continue
            if candidate.relationship == REL_EXACT_MIRROR:
                primary_vendor = infer_vendor_id(getattr(repo, "name", ""), getattr(repo, "url", ""))
                evidence_vendor = infer_vendor_id(candidate.label, candidate.url)
                if (primary_vendor in {"redhat", "rocky", "almalinux"}
                        and evidence_vendor in {"redhat", "rocky", "almalinux"}
                        and primary_vendor != evidence_vendor):
                    continue
            safe.append(candidate)
        return safe

    def _derived_rebuild_peer_candidates(self, repo):
        """Build explicit same-channel EL rebuild peers from the selected target profile.

        This is intentionally not generic RPM similarity. Only RHEL/Rocky/Alma are
        treated as release-rebuild peers. CentOS Stream and Fedora have different
        release semantics and therefore stay exact-mirror/manual-only evidence.
        """
        if str(getattr(repo, "repo_format", "rpm") or "rpm") != "rpm":
            return []
        primary_vendor = infer_vendor_id(getattr(repo, "name", ""), getattr(repo, "url", ""))
        peer_keys = {
            "redhat": ("rocky", "alma"),
            "rocky": ("alma",),
            "almalinux": ("rocky",),
        }.get(primary_vendor, ())
        if not peer_keys:
            return []
        channel = repository_channel(repo)
        if not channel:
            return []
        try:
            read = getattr(self, "_selected_release", None)
            release = (read() if callable(read)
                       else self.release_var.get().strip())
            arch = self.arch_var.get().strip()
        except Exception:
            release = str(getattr(repo, "target_release", "") or "")
            arch = "x86_64"
        out = []
        primary_variant = (
            "current" if "current stream" in str(getattr(repo, "name", "")).lower() else
            "vault" if "vault" in str(getattr(repo, "name", "")).lower() else "exact")
        for key in peer_keys:
            profile = PROFILES.get(key)
            if profile is None:
                continue
            matches = []
            try:
                templates = profile.repos_factory(release, arch)
            except Exception:
                templates = []
            for template in templates:
                if getattr(template, "role", "") != "dependency" or not str(getattr(template, "url", "")).strip():
                    continue
                if repository_channel(template) != channel:
                    continue
                name = str(getattr(template, "name", ""))
                lname = name.lower()
                variant = "current" if "current stream" in lname else "vault" if "vault" in lname else "exact"
                score = 0 if variant == primary_variant else (1 if variant == "exact" else 2)
                matches.append((score, template))
            if not matches:
                continue
            matches.sort(key=lambda pair: pair[0])
            template = matches[0][1]
            peer_url = str(template.url)
            if not mirrors_are_distinct(repo.normalized_url, peer_url)[0]:
                continue
            out.append(EvidenceCandidate(
                peer_url, str(template.name), REL_REBUILD_PEER,
                AUTH_INDEPENDENT, "derived-peer",
                "Independent Enterprise Linux rebuild; binary bytes may differ while package/source lineage must agree."))
        return out

    def _configured_evidence_candidates(self, repo):
        out = []
        primary_channel = repository_channel(repo)
        for other in self.repository_rows() or []:
            if other is repo or not getattr(other, "url", "").strip():
                continue
            if getattr(other, "repo_format", "") != getattr(repo, "repo_format", ""):
                continue
            distinct, _ = mirrors_are_distinct(repo.normalized_url, other.normalized_url)
            if not distinct:
                continue
            if repositories_are_exact_mirror_compatible(repo, other):
                configured_label = (f"Configured alternate mirror - {other.name}"
                                    if getattr(repo, "repo_format", "") == "apt"
                                    else other.name)
                out.append(EvidenceCandidate(
                    other.normalized_url, configured_label, REL_EXACT_MIRROR, AUTH_UNKNOWN,
                    "configured", "Configured repository describes the same archive slice; operator independence is not inferred."))
                continue
            # Configured cross-vendor EL repositories may be semantic rebuild
            # peers, but only for the same logical channel (BaseOS↔BaseOS etc.).
            relation = evidence_relationship(repo, other.normalized_url)
            if relation == REL_REBUILD_PEER and primary_channel and repository_channel(other) == primary_channel:
                out.append(EvidenceCandidate(
                    other.normalized_url, other.name, REL_REBUILD_PEER, AUTH_INDEPENDENT,
                    "configured", "Configured independent rebuild peer."))
        return out

    def _evidence_candidate_specs(self, repo):
        """All safe explicit evidence choices, exact mirrors first then rebuild peers."""
        combined = (self._profile_evidence_candidates(repo) +
                    self._configured_evidence_candidates(repo) +
                    self._derived_rebuild_peer_candidates(repo))
        seen = set()
        out = []
        for candidate in combined:
            key = candidate.url.rstrip("/")
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(candidate)
        order = {REL_EXACT_MIRROR: 0, REL_EXACT_ARTIFACT: 1, REL_REBUILD_PEER: 2}
        out.sort(key=lambda c: (order.get(c.relationship, 9), c.label.lower(), c.url.lower()))
        return out

    def _curated_exact_mirror_alternatives(self, repo, selected_url: str):
        """Return safe alternate catalog mirrors for a failed exact-mirror test.

        This is deliberately narrow: Feathered may rotate only among curated,
        independently operated exact mirrors of the same archive slice.  It
        never substitutes a rebuild peer, an unknown-authority configured URL,
        or a manual endpoint.  Pressing *Test evidence sources* therefore can
        recover from a stale/mid-sync mirror without weakening the selected
        verification relationship.
        """
        selected = str(selected_url or "").rstrip("/")
        specs = self._evidence_candidate_specs(repo)
        current = next((c for c in specs if c.url.rstrip("/") == selected), None)
        if (current is None or current.relationship != REL_EXACT_MIRROR
                or current.authority != AUTH_INDEPENDENT
                or current.source != "mirror-catalog"):
            return []
        return [c for c in specs
                if c.url.rstrip("/") != selected
                and c.relationship == REL_EXACT_MIRROR
                and c.authority == AUTH_INDEPENDENT
                and c.source == "mirror-catalog"]

    def _preflight_evidence_pair_with_curated_failover(self, repo, url: str, reporter):
        """Test one evidence pair and recover from a stale curated exact mirror.

        Failover is intentionally conservative.  Only another independently
        operated ``mirror-catalog`` candidate for the same exact archive is
        eligible, and evidence-integrity/independence failures are never
        converted into a success by trying a different endpoint.  This keeps
        the operator's selected relationship and authority policy unchanged
        while avoiding needless manual mirror roulette for availability faults.
        """
        result = self._preflight_evidence_pair(repo, url, reporter)
        detail_lower = str(result.get("detail", "") or "").lower()
        can_rotate = (
            result.get("status") == "unusable"
            and "mismatch" not in detail_lower
            and "not independent" not in detail_lower
            and "acquisition repository" not in detail_lower
            and "acquisition artifact" not in detail_lower
        )
        if not can_rotate:
            return result

        original_detail = str(result.get("detail", "") or "")
        for alternate in self._curated_exact_mirror_alternatives(repo, url):
            reporter.check_cancel()
            reporter.log(
                f"Evidence mirror {redact_url(url)} failed for {repo.name}; "
                f"trying curated alternate {redact_url(alternate.url)}")
            alternate_result = self._preflight_evidence_pair(
                repo, alternate.url, reporter,
                relationship_hint=alternate.relationship,
                authority_hint=alternate.authority)
            if alternate_result.get("status") not in {"repository", "artifact-only"}:
                continue
            alternate_result = dict(alternate_result)
            alternate_result["replacement_url"] = alternate.url
            alternate_result["replacement_label"] = alternate.label
            alternate_result["auto_reselected"] = True
            alternate_result["detail"] = (
                f"Selected mirror failed ({original_detail}). "
                f"Feathered verified and selected alternate {alternate.label}: "
                + str(alternate_result.get("detail", "") or ""))
            return alternate_result
        return result

    def _evidence_candidate_spec_map(self, repo):
        mapping = {}
        for candidate in self._evidence_candidate_specs(repo):
            label = candidate_display_label(candidate)
            # The selector should show where the candidate actually points, but
            # a long URL must not become the primary label.
            label = f"{label}  {self._compact_evidence_url(candidate.url, 52)}"
            mapping[label] = candidate
        return mapping

    def _evidence_candidate_map(self, repo):
        """Compatibility view: human-readable label -> URL."""
        return {label: candidate.url
                for label, candidate in self._evidence_candidate_spec_map(repo).items()}

    def _provenance_repo_cache_key(self, repo):
        return (getattr(repo, "name", ""), getattr(repo, "normalized_url", ""))

    def _enabled_provenance_repos(self):
        # Provenance should describe repositories that can participate in the
        # current output. Package-only acquisition deliberately excludes
        # unrelated base/additional sources; normal analysis retains the whole
        # enabled dependency universe.
        try:
            package_only = self._package_only_acquisition_mode()
            return self._build_repository_scope(package_only=package_only)
        except Exception:
            return [r for r in self.repo_rows
                    if getattr(r, "enabled", False) and getattr(r, "url", "").strip()]


    @staticmethod
    def _digest_ui_to_policy(label):
        label = (label or "").strip()
        if label.startswith("SHA-512"):
            return "sha512"
        if label.startswith("SHA-384"):
            return "sha384"
        if label.startswith("SHA-256"):
            return "sha256"
        return "auto"

    @staticmethod
    def _strategy_ui_to_policy(label):
        label = (label or "").strip()
        if label.startswith("Require checksum"):
            return "checksum-required"
        if label.startswith("Verify what"):
            return "checksum-available"
        if label.startswith("Corroborate"):
            return "full-corroboration"
        if label.startswith("Skip upstream"):
            return "skip-provenance"
        return "evidence-fallback"

    @staticmethod
    def _strategy_policy_to_ui(strategy):
        return {
            "skip-provenance": "Skip upstream provenance checks (minimal)",
            "checksum-available": "Verify what is available (basic)",
            "checksum-required": "Require checksum coverage (strict)",
            "evidence-fallback": "Fill gaps with independent evidence (enhanced)",
            "full-corroboration": "Corroborate every package (maximum)",
        }.get(strategy, "Fill gaps with independent evidence (enhanced)")

    @staticmethod
    def _strategy_uses_evidence(strategy):
        return strategy in {"evidence-fallback", "full-corroboration"}

    @staticmethod
    def _minimum_met_by_algorithms(algorithms, preference):
        found = set(algorithms or [])
        if preference == "auto":
            return bool(found & {"sha256", "sha384", "sha512"})
        if preference == "sha256":
            return bool(found & {"sha256", "sha384", "sha512"})
        if preference == "sha384":
            return bool(found & {"sha384", "sha512"})
        if preference == "sha512":
            return "sha512" in found
        return False

    def _digest_inspection_known(self, repo):
        key = self._provenance_repo_cache_key(repo)
        if key in self.__dict__.get("_provenance_detected_cache", {}):
            return True
        for pkg in self.__dict__.get("loaded_packages", []) or []:
            pkg_repo = getattr(pkg, "repo", None)
            if pkg_repo is repo or (pkg_repo is not None and
                    getattr(pkg_repo, "name", "") == repo.name and
                    getattr(pkg_repo, "normalized_url", "") == repo.normalized_url):
                return True
        return False

    def _repo_meets_digest_minimum(self, repo, preference):
        """Whether all inspected package records in a source meet a minimum.

        The detailed inspection cache wins because it tracks package-record
        coverage, not merely whether an algorithm appeared somewhere in the
        index. Loaded analysis metadata is used as a fallback before an explicit
        inspection has been run.
        """
        key = self._provenance_repo_cache_key(repo)
        detail = self.__dict__.get("_provenance_digest_coverage_cache", {}).get(key)
        if detail is not None:
            total = int(detail.get("total", 0) or 0)
            if total <= 0:
                return False
            return int(detail.get(preference, 0) or 0) == total
        loaded = [pkg for pkg in self.__dict__.get("loaded_packages", []) or []
                  if getattr(pkg, "repo", None) is repo or (
                      getattr(pkg, "repo", None) is not None
                      and pkg.repo.name == repo.name
                      and pkg.repo.normalized_url == repo.normalized_url)]
        if loaded:
            return all(self._minimum_met_by_algorithms(package_digest_map(pkg), preference)
                       for pkg in loaded)
        return self._minimum_met_by_algorithms(self._detected_digest_algorithms(repo), preference)

    def _digest_direct_coverage(self, enabled, preference):
        return sum(1 for repo in enabled if self._repo_meets_digest_minimum(repo, preference))

    def _update_provenance_evidence_state(self):
        """Keep explicit diagnostics available independently of build requirements."""
        strategy_var = self.__dict__.get("prov_strategy_var")
        strategy = self._strategy_ui_to_policy(strategy_var.get()) if strategy_var else "evidence-fallback"
        active = self._strategy_uses_evidence(strategy)
        skip_upstream = strategy == "skip-provenance"

        digest_label = self.__dict__.get("prov_digest_label")
        if digest_label is not None and digest_label.winfo_exists():
            digest_label.configure(style="MutedPanel.TLabel" if skip_upstream else "Panel.TLabel")
        digest_help_label = self.__dict__.get("prov_digest_help_label")
        if digest_help_label is not None and digest_help_label.winfo_exists():
            digest_help_label.configure(style="MutedPanelHint.TLabel" if skip_upstream else "PanelHint.TLabel")
        digest_combo = self.__dict__.get("prov_digest_combo")
        if digest_combo is not None and digest_combo.winfo_exists():
            digest_combo.configure(state="disabled" if skip_upstream else "readonly")

        title = self.__dict__.get("prov_evidence_title")
        if title is not None and title.winfo_exists():
            title.configure(style="PanelGroup.TLabel" if active else "MutedPanelGroup.TLabel")
        help_label = self.__dict__.get("prov_evidence_help_label")
        if help_label is not None and help_label.winfo_exists():
            help_label.configure(style="PanelHint.TLabel" if active else "MutedPanelHint.TLabel")
        for label in self.__dict__.get("_prov_evidence_row_labels", []) or []:
            if label.winfo_exists():
                label.configure(style="Panel.TLabel" if active else "MutedPanel.TLabel")
        for combo in self.__dict__.get("_prov_evidence_row_combos", []) or []:
            if combo.winfo_exists():
                combo.configure(style="Evidence.TCombobox",
                                state="readonly" if active else "disabled")

        test_btn = self.__dict__.get("prov_evidence_test_btn")
        if test_btn is not None and test_btn.winfo_exists():
            operation_idle = (
                self.__dict__.get("active_operation") is None
                and self.__dict__.get("worker") is None
            )
            configured = bool(self._evidence_preflight_pairs()) if active and operation_idle else False
            test_btn.configure(
                state="normal"
                if active and configured and operation_idle
                else "disabled")

        hint = self.__dict__.get("prov_evidence_state_var")
        if hint is None:
            return
        if strategy == "skip-provenance":
            hint.set("Independent evidence is inactive because upstream provenance checking is intentionally skipped.")
            return
        if strategy == "checksum-required":
            hint.set("Independent evidence is inactive because this strategy accepts only qualifying checksums from each package source.")
            return
        if strategy == "checksum-available":
            hint.set("Independent evidence is inactive. Feathered verifies qualifying source checksums and records any uncovered packages with reduced assurance.")
            return
        if strategy not in {"full-corroboration", "evidence-fallback"}:
            return

        pending_inspection = self._evidence_pending_inspection_repos(strategy)
        required = self._evidence_required_repos(strategy)
        cache = self.__dict__.get("_evidence_preflight_cache", {})
        selected = 0
        passed = 0
        testing = 0
        invalid_peer = 0
        for repo in required:
            urls = list(getattr(repo, "evidence_urls", []) or [])
            if not urls:
                continue
            selected += 1
            result = cache.get(self._evidence_preflight_key(repo, urls[0]))
            relationship = evidence_relationship(repo, urls[0])
            if strategy == "evidence-fallback" and relationship == REL_REBUILD_PEER:
                invalid_peer += 1
                continue
            state = (result or {}).get("status", "untested")
            if state == "testing":
                testing += 1
            elif state in {"repository", "artifact-only", "peer"}:
                if strategy == "evidence-fallback" and (result or {}).get("relationship") == REL_REBUILD_PEER:
                    invalid_peer += 1
                else:
                    passed += 1

        total = len(required)
        label = "Maximum" if strategy == "full-corroboration" else "Enhanced"
        if pending_inspection:
            hint.set(
                f"You can test selected evidence now. Inspect checksum support for "
                f"{len(pending_inspection)} source(s) before continuing to determine which sources "
                "need fallback for the selected minimum.")
        elif total == 0:
            hint.set(f"{label}: every participating source already satisfies the selected acquisition-checksum requirement; no independent fallback is currently needed. Selected evidence can still be tested; optional failures do not block this coverage.")
        elif invalid_peer:
            hint.set("Enhanced requires byte-identical exact-mirror/artifact evidence for checksum gaps. Semantic rebuild peers are Maximum-only and cannot authenticate missing acquisition integrity.")
        elif passed == total:
            hint.set(f"{label} evidence ready: {passed}/{total} required source(s) passed a representative spot test. Build-time verification still checks each selected package.")
        elif testing:
            hint.set(f"Testing independent evidence: {passed}/{total} required source(s) ready; {testing} currently testing.")
        elif selected < total:
            hint.set(f"Required before continuing: configure evidence for every source that can need it ({selected}/{total} selected, {passed}/{total} tested).")
        else:
            hint.set(f"Required before continuing: test every required evidence pairing ({passed}/{total} passed).")

    def _provenance_requires_evidence_selection(self) -> bool:
        strategy_var = self.__dict__.get("prov_strategy_var")
        if strategy_var is None:
            return False
        strategy = self._strategy_ui_to_policy(strategy_var.get())
        return strategy in {"evidence-fallback", "full-corroboration"}

    def _has_explicit_evidence_selection(self) -> bool:
        try:
            rows = self._enabled_provenance_repos()
        except Exception:
            rows = [r for r in self.repository_rows()
                    if getattr(r, "enabled", False) and str(getattr(r, "url", "")).strip()]
        return any(bool(getattr(repo, "evidence_urls", None)) for repo in rows)

    def _evidence_required_repos(self, strategy: str | None = None):
        """Return sources that must have evidence for the current strategy.

        Maximum corroborates every participating source. Enhanced is genuinely a
        gap-filling policy: a source needs exact evidence only after checksum
        inspection proves the selected acquisition minimum is not fully covered.
        Unknown coverage is a separate "inspect first" state; treating it as a
        failed checksum contract causes Enhanced to test arbitrary evidence before
        Feathered knows whether any fallback is necessary.
        """
        try:
            enabled = list(self._enabled_provenance_repos())
        except Exception:
            enabled = [r for r in self.repository_rows()
                       if getattr(r, "enabled", False) and str(getattr(r, "url", "")).strip()]
        if strategy is None:
            var = self.__dict__.get("prov_strategy_var")
            strategy = self._strategy_ui_to_policy(var.get()) if var is not None else "evidence-fallback"
        if strategy == "full-corroboration":
            return enabled
        if strategy != "evidence-fallback":
            return []
        required = []
        for repo in enabled:
            preference = str(getattr(repo, "digest_preference", "auto") or "auto")
            if self._digest_inspection_known(repo) and not self._repo_meets_digest_minimum(repo, preference):
                required.append(repo)
        return required

    def _evidence_pending_inspection_repos(self, strategy: str | None = None):
        """Return Enhanced sources whose fallback requirement is still unknown."""
        try:
            enabled = list(self._enabled_provenance_repos())
        except Exception:
            enabled = [r for r in self.repository_rows()
                       if getattr(r, "enabled", False) and str(getattr(r, "url", "")).strip()]
        if strategy is None:
            var = self.__dict__.get("prov_strategy_var")
            strategy = self._strategy_ui_to_policy(var.get()) if var is not None else "evidence-fallback"
        if strategy != "evidence-fallback":
            return []
        return [repo for repo in enabled if not self._digest_inspection_known(repo)]

    def _evidence_preflight_key(self, repo, evidence_url: str):
        # A spot-test result is valid only for the verification inputs it actually
        # exercised. Changing checksum strength or the selected root set makes the
        # previous result stale without requiring ad-hoc cache clearing at every UI
        # call site.
        digest = str(getattr(repo, "digest_preference", "auto") or "auto")
        roots = tuple(sorted(self._selected_root_names_for_evidence()))
        return (
            self._provenance_repo_cache_key(repo),
            str(evidence_url or "").rstrip("/"),
            evidence_relationship(repo, evidence_url),
            evidence_authority_relationship(repo, evidence_url),
            digest,
            roots,
        )

    def _selected_root_names_for_evidence(self):
        try:
            return {str(req[0]) for req in self._package_requests() if req and req[0]}
        except Exception:
            return set()

    @staticmethod
    def _package_identity_key(pkg):
        return (
            getattr(pkg, "name", ""), getattr(pkg, "epoch", ""),
            getattr(pkg, "version", ""), getattr(pkg, "release", ""),
            getattr(pkg, "arch", ""),
        )

    def _preflight_evidence_pair(self, repo, evidence_url: str, reporter: Reporter,
                                 *, relationship_hint: str = "", authority_hint: str = ""):
        """Spot-test one evidence relationship without overstating its proof.

        Exact mirrors/artifact mirrors are checked for byte equality. Known RPM
        rebuild peers (for example AlmaLinux vs Rocky Linux) are checked as
        independent semantic peers: package identity/source lineage must agree,
        and each artifact is verified against its own repository digest when one
        is published. Binary equality is explicitly not required for that case.
        """
        distinct, reason = mirrors_are_distinct(repo.normalized_url, evidence_url)
        if not distinct:
            return {"status": "unusable", "detail": f"Not independent: {reason}"}

        relationship = (str(relationship_hint or "").strip()
                        or evidence_relationship(repo, evidence_url))
        authority = (str(authority_hint or "").strip()
                     or evidence_authority_relationship(repo, evidence_url))
        arches = {self.arch_var.get(), "noarch", "all", "any"}
        primary_repo = copy.deepcopy(repo)
        primary_repo.evidence_urls = []
        primary_repo.evidence_suggestions = []
        primary_repo.evidence_policy = "off"
        try:
            primary_packages = self._load_repository_backend(primary_repo, arches, reporter)
        except Exception as exc:
            return {
                "status": "unusable",
                "detail": "Could not inspect the acquisition repository to identify a package: "
                          + redact_text(str(exc)),
            }
        roots = self._selected_root_names_for_evidence()
        candidates = [p for p in primary_packages if getattr(p, "name", "") in roots]
        if not candidates:
            candidates = list(primary_packages[:12])
        if not candidates:
            return {"status": "unusable", "detail": "The acquisition repository exposes no package records to test."}

        evidence_repo = evidence_repo_for_url(repo, evidence_url)
        metadata_ok = False
        evidence_packages = []
        metadata_error = ""
        try:
            evidence_packages = self._load_repository_backend(evidence_repo, arches, reporter)
            metadata_ok = bool(evidence_packages)
        except Exception as exc:
            metadata_error = redact_text(str(exc))

        if relationship == "independent-peer":
            if not metadata_ok:
                detail = "Independent rebuild-peer evidence requires repository metadata; artifact-only mode cannot establish package lineage."
                if metadata_error:
                    detail += " Metadata probe failed: " + metadata_error
                return {"status": "unusable", "detail": detail, "relationship": relationship}
            attempts = []
            for primary_pkg in candidates:
                evidence_pkg = find_independent_peer_package(primary_pkg, evidence_packages)
                ok, semantic_detail, lineage_match = independent_peer_packages_match(primary_pkg, evidence_pkg)
                if not ok:
                    attempts.append(f"{getattr(primary_pkg, 'name', 'package')}: {semantic_detail}")
                    continue
                try:
                    primary_url = repo_relative_url(
                        primary_repo.normalized_url, getattr(primary_pkg, "location", ""))
                    evidence_artifact_url = repo_relative_url(
                        evidence_url, getattr(evidence_pkg, "location", ""))
                except Exception as exc:
                    attempts.append(redact_text(str(exc)))
                    continue
                checksum_policy = str(getattr(repo, "digest_preference", "auto") or "auto")
                ok, detail = spot_compare_peer_artifact_urls(
                    primary_pkg, primary_url, primary_repo,
                    evidence_pkg, evidence_artifact_url, evidence_repo,
                    checksum_policy, reporter)
                attempts.append(detail)
                if ok:
                    return {
                        "status": "peer",
                        "relationship": relationship,
                        "authority": authority,
                        "detail": detail + " This is a representative configuration spot test; build-time Maximum verification repeats peer corroboration per selected package.",
                        "package": getattr(primary_pkg, "name", ""),
                        "artifact_url": evidence_artifact_url,
                        "source_lineage_match": lineage_match,
                    }
            return {
                "status": "unusable",
                "relationship": relationship,
                "authority": authority,
                "detail": "No semantically corresponding package could be corroborated from the independent rebuild peer."
                          + ((" Last probe: " + attempts[-1]) if attempts else ""),
            }

        by_identity = {self._package_identity_key(p): p for p in evidence_packages}
        attempts = []
        for primary_pkg in candidates:
            evidence_pkg = by_identity.get(self._package_identity_key(primary_pkg))
            evidence_location = getattr(evidence_pkg, "location", "") if evidence_pkg is not None else ""
            try:
                primary_url = repo_relative_url(
                    primary_repo.normalized_url, getattr(primary_pkg, "location", ""))
            except Exception as exc:
                attempts.append("Could not derive acquisition artifact URL: " + redact_text(str(exc)))
                continue
            checksum_policy = str(getattr(repo, "digest_preference", "auto") or "auto")
            for url in evidence_artifact_candidates(
                    evidence_url, getattr(primary_pkg, "location", ""), evidence_location):
                ok, detail = spot_compare_artifact_urls(
                    primary_url, primary_repo, url, evidence_repo, checksum_policy, reporter)
                attempts.append(f"{redact_url(url)}: {detail}")
                if ok:
                    prefix = (
                        "Repository metadata recognized; " if metadata_ok else
                        "Repository metadata was not recognized; artifact-only evidence accepted. ")
                    return {
                        "status": "repository" if metadata_ok else "artifact-only",
                        "relationship": relationship,
                        "authority": authority,
                        "detail": prefix + detail +
                            " This is a configuration spot test; full build-time corroboration remains per package.",
                        "package": getattr(primary_pkg, "name", ""),
                        "artifact_url": url,
                        "metadata_error": metadata_error,
                    }
                if "mismatch" in detail.lower():
                    return {
                        "status": "unusable",
                        "relationship": relationship,
                        "authority": authority,
                        "detail": f"Independent exact-artifact spot check failed for {getattr(primary_pkg, 'name', 'package')}: {detail}",
                        "package": getattr(primary_pkg, "name", ""),
                        "artifact_url": url,
                        "metadata_error": metadata_error,
                    }
        detail = "No exact matching package artifact could be read from the evidence endpoint."
        if metadata_ok:
            detail += " Repository metadata was recognized, but it did not yield a usable exact artifact."
        elif metadata_error:
            detail += " Repository metadata was not recognized: " + metadata_error
        if attempts:
            detail += " Last probe: " + attempts[-1]
        return {"status": "unusable", "relationship": relationship, "authority": authority, "detail": detail}

    def _evidence_preflight_pairs(self):
        """Return configured diagnostics, independently of required build evidence.

        Explicit tests include optional sources and sources awaiting inspection.
        Validation still uses _evidence_required_repos so an optional failure
        cannot turn a satisfied checksum requirement into a build failure.
        """
        strategy_var = self.__dict__.get("prov_strategy_var")
        strategy = (self._strategy_ui_to_policy(strategy_var.get())
                    if strategy_var is not None else "evidence-fallback")
        if strategy not in {"evidence-fallback", "full-corroboration"}:
            return []
        rows = list(self._enabled_provenance_repos())
        out = []
        for repo in rows:
            for url in list(getattr(repo, "evidence_urls", []) or []):
                out.append((repo, url))
        return out

    def _test_evidence_sources(self):
        # Defensive semantic guard in addition to the disabled button. This also
        # protects keyboard/programmatic invocation and prevents old evidence
        # selections from launching a long-running probe under Minimal/Basic/Strict.
        if not self._provenance_requires_evidence_selection():
            status = self.__dict__.get("status_var")
            if status is not None:
                status.set(
                    "Evidence testing is available only for Enhanced or Maximum verification.")
            return
        strategy = self._strategy_ui_to_policy(self.prov_strategy_var.get())
        required = list(self._evidence_required_repos(strategy))
        pairs = self._evidence_preflight_pairs()
        configured_repo_keys = {self._provenance_repo_cache_key(repo) for repo, _url in pairs}
        missing_configuration_count = sum(
            1 for repo in required
            if self._provenance_repo_cache_key(repo) not in configured_repo_keys)
        if not pairs:
            self._focus_validation(
                "keyrings", self.__dict__.get("prov_evidence_card"),
                "Select an independent evidence source to test.")
            return
        # Peer diagnostics are useful in Enhanced too, but never qualify as
        # exact-byte fallback. The continuation/build validators enforce that.
        if self._busy():
            return
        if not self._claim_operation("evidence-preflight", "Testing independent evidence sources…", cancellable=True):
            return
        cache = self.__dict__.setdefault("_evidence_preflight_cache", {})
        for repo, url in pairs:
            cache[self._evidence_preflight_key(repo, url)] = {"status": "testing", "detail": "Testing…"}
        self._refresh_provenance_evidence_rows()

        def work():
            reporter = Reporter(self._log, self._progress, self.cancel_event)
            results = []
            try:
                for i, (repo, url) in enumerate(pairs, 1):
                    reporter.check_cancel()
                    reporter.progress(f"Evidence {i}/{len(pairs)}: {repo.name}", (i - 1) / max(1, len(pairs)))
                    result = self._preflight_evidence_pair_with_curated_failover(
                        repo, url, reporter)
                    results.append((self._evidence_preflight_key(repo, url), result))
                self.events.put(("evidence_preflight", results))
                passed_count = sum(
                    1 for _key, result in results
                    if result.get("status") in {"repository", "artifact-only", "peer"})
                failed_count = len(results) - passed_count
                summary = (
                    f"Evidence source test complete: {passed_count} passed, "
                    f"{failed_count} failed")
                if missing_configuration_count:
                    summary += f", {missing_configuration_count} required source(s) not configured"
                summary += ". Build requirements are evaluated separately."
                self.events.put(("done", True, summary))
            except Cancelled:
                self.events.put(("done", "cancelled", "Operation cancelled"))
            except Exception as exc:
                self.events.put(("done", False, redact_text(str(exc))))
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def _apply_evidence_preflight_results(self, results):
        cache = self.__dict__.setdefault("_evidence_preflight_cache", {})
        enabled = list(self._enabled_provenance_repos())
        selection_changed = False
        for key, result in results:
            stored_key = key
            replacement_url = str(result.get("replacement_url", "") or "").strip()
            if replacement_url:
                repo_key = key[0] if isinstance(key, tuple) and key else None
                matched_repo = next(
                    (repo for repo in enabled
                     if self._provenance_repo_cache_key(repo) == repo_key),
                    None)
                if matched_repo is not None:
                    old_url = (list(getattr(matched_repo, "evidence_urls", []) or [""])[0])
                    matched_repo.evidence_urls = [replacement_url]
                    # Preserve the catalog candidate's proof semantics when the
                    # worker rotates to a verified alternate.  Without these
                    # hints a same-vendor URL is conservatively reclassified as
                    # an unknown-authority exact-artifact endpoint, which loses
                    # the operator's selected exact-mirror/independence contract.
                    matched_repo.evidence_relationship_hints = {
                        replacement_url: str(result.get("relationship", "") or REL_EXACT_MIRROR)
                    }
                    matched_repo.evidence_authority_hints = {
                        replacement_url: str(result.get("authority", "") or AUTH_UNKNOWN)
                    }
                    selection_changed = True
                    cache.pop(key, None)
                    stored_key = self._evidence_preflight_key(matched_repo, replacement_url)
                    self._log(
                        f"Evidence source switched for {matched_repo.name}: "
                        f"{redact_url(old_url)} -> {redact_url(replacement_url)}")
            cache[stored_key] = dict(result)
            status = result.get("status", "unusable")
            detail = result.get("detail", "")
            self._log(f"Evidence preflight {status}: {detail}")
        if selection_changed:
            # An automatic verified-mirror rotation is a real provenance-input
            # change and must invalidate any analysis/result created with the
            # previous endpoint, exactly like an operator selection change.
            invalidate = getattr(self, "_invalidate_provenance_analysis", None)
            if callable(invalidate):
                invalidate()
            clear_attention = getattr(self, "_clear_validation_attention", None)
            if callable(clear_attention):
                clear_attention()
            refresh_sources = getattr(self, "_refresh_provenance_source_tree", None)
            if callable(refresh_sources):
                refresh_sources()
            refresh_repos = getattr(self, "_refresh_repo_tree_if_open", None)
            if callable(refresh_repos):
                refresh_repos()
        self._refresh_provenance_evidence_rows()
        self._update_provenance_evidence_state()

    def _validate_provenance_step(self) -> None:
        """Require Step 4 evidence to match the same contract enforced at build time."""
        if not self._provenance_requires_evidence_selection():
            return
        digest_var = self.__dict__.get("prov_digest_var")
        if digest_var is None or not str(digest_var.get()).strip():
            raise RuntimeError(
                "Enhanced or Maximum verification requires a checksum policy. Choose the Minimum "
                "checksum strength before configuring independent evidence.")

        strategy = self._strategy_ui_to_policy(self.prov_strategy_var.get())
        pending_inspection = self._evidence_pending_inspection_repos(strategy)
        if pending_inspection:
            raise RuntimeError(
                "Enhanced verification must inspect checksum support before Feathered can determine "
                "which repositories require fallback evidence. Use Inspect checksum support first. "
                "Not yet inspected: " + ", ".join(repo.name for repo in pending_inspection[:4]))
        required = self._evidence_required_repos(strategy)
        if not required:
            return
        cache = self.__dict__.get("_evidence_preflight_cache", {})
        missing = []
        untested = []
        failed = []
        invalid = []
        for repo in required:
            urls = list(getattr(repo, "evidence_urls", []) or [])
            if not urls:
                missing.append(repo.name)
                continue
            url = urls[0]
            relationship = evidence_relationship(repo, url)
            if strategy == "evidence-fallback" and relationship == REL_REBUILD_PEER:
                invalid.append(repo.name)
                continue
            result = cache.get(self._evidence_preflight_key(repo, url))
            if not result or result.get("status") in {"testing", "untested"}:
                untested.append(repo.name)
                continue
            if result.get("status") not in {"repository", "artifact-only", "peer"}:
                failed.append((repo.name, result.get("detail", "Evidence source is unusable")))
                continue
            if strategy == "evidence-fallback" and result.get("relationship") == REL_REBUILD_PEER:
                invalid.append(repo.name)

        if not (missing or untested or failed or invalid):
            return
        if invalid:
            raise RuntimeError(
                "Enhanced verification can fill checksum gaps only with an exact mirror or exact-artifact source whose bytes match the acquisition artifact. "
                "Semantic rebuild peers are Maximum-only. Replace the evidence source for: " + ", ".join(invalid[:4]))
        if missing:
            scope = "every participating package source" if strategy == "full-corroboration" else "every source that may need checksum fallback"
            raise RuntimeError(
                f"{self._strategy_policy_to_ui(strategy).split(' (')[0]} requires evidence for {scope}. "
                "No evidence source is selected for: " + ", ".join(missing[:4]))
        if untested:
            raise RuntimeError(
                "Every required evidence pairing must pass an explicit spot test before continuing. Use Test evidence sources. "
                "Not yet tested: " + ", ".join(untested[:4]))
        first_name, first_detail = failed[0]
        raise RuntimeError(
            f"Evidence testing failed for {first_name}: {first_detail}")

    def _strategy_help_text(self, strategy):
        return {
            "checksum-required":
                "Every selected package must have a checksum meeting the chosen minimum from its package source. Missing coverage stops the build.",
            "checksum-available":
                "Feathered verifies every qualifying checksum it can find. Packages without the selected minimum continue with explicitly degraded provenance.",
            "evidence-fallback":
                "Feathered verifies qualifying source checksums first. Gaps require independently retrieved, matching bytes from an exact mirror/artifact source. You may test any selected evidence source before or after inspection. Semantic rebuild peers can be tested but cannot fill checksum gaps.",
            "full-corroboration":
                "Every participating package source needs a tested evidence pairing, and every selected package must meet the chosen acquisition checksum minimum. Exact mirrors prove identical bytes; a Maximum-only semantic rebuild peer can instead corroborate package/source lineage and its own repository checksum.",
            "skip-provenance":
                "Do not enforce upstream repository signatures, repository/package checksums, vendor package signatures, or mirror evidence. Feathered still hashes and can sign the finished bundle for transfer integrity.",
        }[strategy]

    def _refresh_provenance_editor(self):
        """Refresh checksum coverage and strategy for the inherited source set."""
        tree = getattr(self, "prov_source_tree", None)
        if tree is None or not tree.winfo_exists():
            return
        enabled = self._enabled_provenance_repos()
        if not enabled:
            self.prov_enabled_sources_var.set(
                "No repositories are enabled. Configure the source universe on Repositories first.")
            tree.delete(*tree.get_children())
            self.prov_detected_var.set("No enabled repositories to inspect.")
            self._refresh_provenance_evidence_rows()
            return

        names = ", ".join(r.name for r in enabled[:4])
        if len(enabled) > 4:
            names += f" and {len(enabled) - 4} more"
        distribution = [r.name for r in enabled if "distribution" in self._repository_build_purposes(r)]
        workload = [r.name for r in enabled if "workload/root" in self._repository_build_purposes(r)]
        refs = []
        if distribution:
            refs.append("distribution=" + ", ".join(distribution[:2]))
        if workload:
            refs.append("workload/root=" + ", ".join(workload[:2]))
        ref_text = ("; " + "; ".join(refs)) if refs else ""
        self.prov_enabled_sources_var.set(
            f"Verification policy covers {len(enabled)} enabled package source(s): {names}{ref_text}")

        preferences = {getattr(r, "digest_preference", "auto") or "auto" for r in enabled}
        strategies = {repository_verification_strategy(r) for r in enabled}
        pref = next(iter(preferences)) if len(preferences) == 1 else "mixed"
        strategy = next(iter(strategies)) if len(strategies) == 1 else "mixed"

        n = len(enabled)
        inspected = sum(1 for r in enabled if self._digest_inspection_known(r))
        coverage = {
            p: self._digest_direct_coverage(enabled, p)
            for p in ("auto", "sha256", "sha384", "sha512")
        }
        all_known = inspected == n

        if inspected:
            self.prov_detected_var.set(
                f"Checksum support inspected for {inspected} of {n} source(s). The table shows every strong SHA field detected; selection coverage is based on the minimum strength each source can satisfy.")
        else:
            self.prov_detected_var.set(
                "Inspect checksum support to measure direct coverage. Your selected checksum policy is retained.")

        strategy_values = [
            "Skip upstream provenance checks (minimal)",
            "Verify what is available (basic)",
            "Require checksum coverage (strict)",
            "Fill gaps with independent evidence (enhanced)",
            "Corroborate every package (maximum)",
        ]
        if strategy == "mixed":
            strategy_values.insert(0, "Mixed (advanced per-repository overrides)")
            self.prov_strategy_var.set(strategy_values[0])
        else:
            self.prov_strategy_var.set(self._strategy_policy_to_ui(strategy))
        self.prov_strategy_combo.configure(values=strategy_values)

        effective_strategy = strategy if strategy != "mixed" else "evidence-fallback"
        strict_direct = effective_strategy in {"checksum-required", "full-corroboration"}

        def label_for(policy):
            base = {
                "auto": "Automatic",
                "sha256": "SHA-256 or stronger",
                "sha384": "SHA-384 or stronger",
                "sha512": "SHA-512",
            }[policy]
            return f"{base} ({coverage[policy]} of {n} direct)" if inspected else base

        # Inspection describes coverage; it must never silently lower policy or
        # hide a minimum for which Enhanced can provide independent fallback.
        digest_values = [label_for(p) for p in ("auto", "sha256", "sha384", "sha512")]
        if pref == "mixed":
            digest_values.insert(0, "Mixed (advanced per-repository overrides)")
            self.prov_digest_var.set(digest_values[0])
        else:
            self.prov_digest_var.set(label_for(pref))
        self.prov_digest_combo.configure(values=digest_values, state="readonly")

        if effective_strategy == "skip-provenance":
            digest_help = "Checksum strength is inactive while upstream provenance checks are skipped. Your selection is retained."
        elif pref == "mixed":
            digest_help = "Sources have different checksum minimums. Each source keeps its own policy until you explicitly choose a shared minimum."
        else:
            digest_help = (
                f"{coverage[pref]} of {n} sources have confirmed complete direct coverage. "
                if inspected else "Direct checksum coverage has not been inspected. ")
            if not all_known and inspected:
                digest_help += f"{n - inspected} source(s) still need inspection. "
            digest_help += "Automatic prefers the strongest published SHA; explicit choices are minimums. "
            if effective_strategy == "evidence-fallback":
                digest_help += (
                    "For a gap, Enhanced compares independently downloaded bytes using the selected minimum "
                    "(SHA-512 for Automatic). A local match is evidence of byte agreement, not a publisher-issued checksum or proof of independent authority.")
            elif strict_direct and all_known and coverage[pref] < n:
                digest_help += "This requirement is currently unmet; the build will stop for packages without a qualifying source checksum. Choose a different minimum or strategy explicitly."
        self.prov_digest_help_var.set(digest_help)

        if strategy == "mixed":
            self.prov_strategy_help_var.set(
                "Enabled repositories currently have different advanced verification strategies. Choose one here to normalize them.")
        else:
            self.prov_strategy_help_var.set(self._strategy_help_text(effective_strategy))
        security_note = self.__dict__.get("security_note")
        if security_note is not None and security_note.winfo_exists():
            if effective_strategy == "skip-provenance":
                security_note.configure(text=(
                    "Upstream provenance is intentionally disabled. Repository keyrings and vendor-signature settings are retained but ignored for package verification until another strategy is selected. Bundle attestation remains independent and available."))
            else:
                security_note.configure(text="")

        self._refresh_provenance_source_tree()
        self._refresh_provenance_evidence_rows()
        self._update_provenance_evidence_state()

    def _refresh_provenance_source_tree(self):
        tree = getattr(self, "prov_source_tree", None)
        if tree is None or not tree.winfo_exists():
            return
        tree.delete(*tree.get_children())
        for i, repo in enumerate(self._enabled_provenance_repos()):
            found = self._detected_digest_algorithms(repo)
            known = self._digest_inspection_known(repo)
            detail = getattr(self, "_provenance_digest_coverage_cache", {}).get(
                self._provenance_repo_cache_key(repo), {})
            total = int(detail.get("total", 0) or 0)
            marks = {}
            for algo in ("sha512", "sha384", "sha256"):
                exact = int(detail.get(f"exact_{algo}", 0) or 0)
                if total and exact == total:
                    marks[algo] = "✓"
                elif exact:
                    marks[algo] = "Partial"
                elif known:
                    # an empty cell looked
                    # like missing UI data rather than a real inspection result.
                    # A visible cross means the repository did not publish that
                    # SHA field for any inspected package.
                    marks[algo] = "✕"
                else:
                    marks[algo] = "?"
            best = (found[0].upper().replace("SHA", "SHA-") if found else
                    ("None" if known else "Not inspected"))
            purpose_fn = getattr(self, "_repository_build_purposes", None)
            purpose = (" + ".join(purpose_fn(repo)) if callable(purpose_fn)
                       else "dependency/supplement")
            tree.insert("", "end", iid=str(i), values=(
                repo.name, marks["sha512"], marks["sha384"], marks["sha256"], best, purpose))

    def _evidence_choices_for_repo(self, repo):
        spec_map = self._evidence_candidate_spec_map(repo)
        candidate_map = {label: spec.url for label, spec in spec_map.items()}
        curated = [spec.url for spec in self._profile_evidence_candidates(repo)]
        # Automatic evidence was intentionally removed: the relationship itself
        # is now an operator-visible choice (exact mirror vs rebuild peer).
        auto_label = ""
        none_label = "No evidence source"
        manual_label = "Enter an exact-artifact URL manually"
        session_label = "Manual source"
        values = list(candidate_map.keys()) + [none_label, manual_label]
        return values, candidate_map, curated, auto_label, none_label, manual_label, session_label

    @staticmethod
    def _compact_evidence_url(url: str, max_chars: int = 76) -> str:
        """Return a bounded, credential-redacted URL for a single-line control."""
        safe = redact_url(str(url or "").strip())
        if len(safe) <= max_chars:
            return safe
        # Preserve both the origin/prefix and the tail, where a mistyped package
        # path is often easiest to spot. This is display-only; the stored URL is
        # never modified.
        tail = max(18, max_chars // 3)
        head = max_chars - tail - 1
        return f"{safe[:head]}…{safe[-tail:]}"

    @staticmethod
    def _tooltip_safe_url(url: str) -> str:
        """Make a long redacted URL wrap naturally inside Feathered's tooltip."""
        safe = redact_url(str(url or "").strip())
        return safe.replace("/", "/\u200b").replace("&", "&\u200b").replace("?", "?\u200b")

    def _is_manual_evidence_source(self, repo, candidate_map, curated) -> bool:
        existing = list(getattr(repo, "evidence_urls", []) or [])
        if not existing:
            return False
        current = existing[0].rstrip("/")
        if curated and current == curated[0].rstrip("/"):
            return False
        return not any(current == url.rstrip("/") for url in candidate_map.values())

    def _current_evidence_choice_label(self, repo, candidate_map, curated, auto_label, none_label, manual_label, session_label="Manual source"):
        existing = list(getattr(repo, "evidence_urls", []) or [])
        if not existing:
            return none_label
        if auto_label and curated and existing[0].rstrip("/") == curated[0].rstrip("/"):
            return auto_label
        for label, url in candidate_map.items():
            if existing[0].rstrip("/") == url.rstrip("/"):
                return label
        # A hand-typed URL stays session-only, but the operator can see what was
        # actually entered. The one-line field is bounded; the full redacted URL
        # is available via the field tooltip.
        return self._compact_evidence_url(existing[0])

    def _prompt_manual_evidence_repository(self, repo):
        """Return (URL, persist-as-mirror) from a Feathered-styled modal."""
        result = {"value": None, "persist": False}
        parent = self
        win = tk.Toplevel(parent)
        win.configure(background=BG_APP)
        win.title("Manual evidence repository")
        win.transient(parent)
        win.grab_set()
        win.resizable(False, False)

        outer = ttk.Frame(win, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Manual evidence repository", style="PaneTitle.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text=f"Use an independent source to corroborate packages acquired from {repo.name}.",
            style="Hint.TLabel", wraplength=620).pack(anchor="w", pady=(4, 14))

        card = self._card(outer, "Evidence source")
        ttk.Label(card, text="Repository or artifact-mirror root URL", style="Panel.TLabel").pack(anchor="w")
        url_var = tk.StringVar(value="")
        entry = ttk.Entry(card, textvariable=url_var, width=78)
        entry.pack(fill="x", pady=(5, 9))
        evidence_vendor = infer_vendor_id(getattr(repo, "name", ""), getattr(repo, "url", ""))
        if getattr(repo, "repo_format", "") == "apt" and evidence_vendor == "ubuntu":
            example = "Example: https://ubuntu.osuosl.org/ubuntu/"
        elif getattr(repo, "repo_format", "") == "apt" and evidence_vendor == "debian":
            example = "Example: https://debian.osuosl.org/debian/"
        else:
            example = "Example: https://mirror.example.org/rocky/9/AppStream/x86_64/os/"
        ttk.Label(card, text=example, style="PanelHint.TLabel", wraplength=590).pack(anchor="w")

        req = self._card(outer, "Requirements", pady=(14, 0))
        requirements = [
            "• Use an absolute http:// or https:// URL. Independent evidence must be a distinct network endpoint.",
            "• The source must be independent from the acquisition repository; Feathered rejects the same effective origin.",
        ]
        if getattr(repo, "repo_format", "") == "apt" and evidence_vendor in {"debian", "ubuntu"}:
            requirements.append(
                f"• For {vendor_display_name(evidence_vendor)}, prefer an alternate mirror of the same archive. "
                "It must publish the same suite/components and exact .deb artifacts; do not substitute a different distribution as a generic peer.")
        requirements.extend([
            "• Normal RPM/APT/pacman repository metadata is preferred, but it is not mandatory.",
            "• Without repository metadata, the mirror must preserve the exact package-relative path so Feathered can retrieve the matching artifact.",
            "• The evidence copy is transient: Feathered hashes it for comparison and never adds it to the bundle.",
        ])
        for text in requirements:
            ttk.Label(req, text=text, style="PanelHint.TLabel", wraplength=600, justify="left").pack(anchor="w", pady=(0, 4))

        ttk.Label(
            req,
            text="By default this entry is session-only. Check the option below only when this URL is an exact mirror of the same distribution repository; Feathered will then write it into the local mirror catalog for reuse.",
            foreground=WARN_FG, background=BG_PANEL, font=("Segoe UI", 9),
            wraplength=600, justify="left").pack(anchor="w", pady=(6, 0))
        persist_var = tk.BooleanVar(value=False)
        self._image_checkbutton(
            req, persist_var,
            "Save permanently as an exact mirror in this distribution's local catalog").pack_configure(
                pady=(8, 0))

        error_var = tk.StringVar(value="")
        error_label = tk.Label(
            outer, textvariable=error_var, background=BG_APP, foreground=ERR_FG,
            font=("Segoe UI", 9), wraplength=620, justify="left")
        error_label.pack(anchor="w", fill="x", pady=(10, 0))

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(14, 0))

        def cancel():
            result["value"] = None
            win.destroy()

        def accept():
            manual = url_var.get().strip()
            if not manual:
                error_var.set("Enter an evidence URL or cancel this dialog.")
                entry.focus_set()
                return
            parsed = urllib.parse.urlsplit(manual)
            if parsed.scheme.lower() not in {"http", "https"}:
                error_var.set("Use an absolute http:// or https:// URL for independent evidence.")
                entry.focus_set()
                return
            if parsed.scheme.lower() in {"http", "https"} and not parsed.netloc:
                error_var.set("The URL must include a host, for example https://mirror.example.org/repo/.")
                entry.focus_set()
                return
            distinct, reason = mirrors_are_distinct(repo.normalized_url, manual)
            if not distinct:
                error_var.set(f"Evidence source is not independent: {reason}.")
                entry.focus_set()
                return
            result["value"] = manual
            result["persist"] = bool(persist_var.get())
            win.destroy()

        ttk.Button(buttons, text="Cancel", command=cancel).pack(side="right")
        ttk.Button(buttons, text="Use for this session", style="Primary.TButton", command=accept).pack(side="right", padx=(0, 8))
        win.protocol("WM_DELETE_WINDOW", cancel)
        win.bind("<Escape>", lambda _e: cancel())
        win.bind("<Return>", lambda _e: accept())
        win.update_idletasks()
        try:
            x = parent.winfo_rootx() + max(24, (parent.winfo_width() - win.winfo_reqwidth()) // 2)
            y = parent.winfo_rooty() + max(24, (parent.winfo_height() - win.winfo_reqheight()) // 3)
            win.geometry(f"+{x}+{y}")
        except tk.TclError:
            pass
        entry.focus_set()
        parent.wait_window(win)
        return result["value"], result["persist"]

    @staticmethod
    def _evidence_row_status(strategy, required, pending, relationship, result):
        status = (result or {}).get("status", "untested")
        outcome = {
            "untested": "Ready to test",
            "repository": "Byte match passed",
            "artifact-only": "Byte match passed",
            "peer": "Peer test passed",
            "testing": "Testing",
        }.get(status, "Test failed")
        if strategy not in {"evidence-fallback", "full-corroboration"}:
            requirement = "inactive"
        elif strategy == "evidence-fallback" and (
                relationship == REL_REBUILD_PEER
                or (result or {}).get("relationship") == REL_REBUILD_PEER):
            requirement = "cannot fill gaps"
        elif pending:
            requirement = "requirement unknown"
        else:
            requirement = "required" if required else "optional"
        return f"{outcome} · {requirement}", status == "testing"

    def _refresh_provenance_evidence_rows(self):
        holder = getattr(self, "prov_evidence_rows_frame", None)
        if holder is None or not holder.winfo_exists():
            return
        for child in holder.winfo_children():
            child.destroy()
        self._prov_evidence_row_vars = {}
        self._prov_evidence_row_combos = []
        self._prov_evidence_row_labels = []
        self._evidence_testing_labels = []
        self._evidence_testing_indicators = []
        enabled = self._enabled_provenance_repos()
        if not enabled:
            ttk.Label(holder, text="No enabled package sources.", style="PanelHint.TLabel").pack(anchor="w")
            return
        strategy_var = self.__dict__.get("prov_strategy_var")
        strategy = self._strategy_ui_to_policy(strategy_var.get()) if strategy_var is not None else "evidence-fallback"
        required_keys = {self._provenance_repo_cache_key(r) for r in self._evidence_required_repos(strategy)}
        pending_keys = {self._provenance_repo_cache_key(r) for r in self._evidence_pending_inspection_repos(strategy)}
        for repo in enabled:
            row = ttk.Frame(holder, style="Panel.TFrame")
            row.pack(fill="x", pady=(3, 0))
            repo_label = ttk.Label(row, text=repo.name, style="Panel.TLabel", width=28)
            repo_label.pack(side="left")
            self._prov_evidence_row_labels.append(repo_label)
            values, candidate_map, curated, auto_label, none_label, manual_label, session_label = self._evidence_choices_for_repo(repo)
            current = self._current_evidence_choice_label(
                repo, candidate_map, curated, auto_label, none_label, manual_label, session_label)
            is_manual = self._is_manual_evidence_source(repo, candidate_map, curated)
            if is_manual and current not in values:
                values.insert(0, current)
            var = tk.StringVar(value=current)

            action_slot = ttk.Frame(row, style="Panel.TFrame", width=68, height=30)
            action_slot.pack(side="right", padx=(6, 0))
            action_slot.pack_propagate(False)
            if is_manual:
                clear_btn = ttk.Button(
                    action_slot, text="Clear", width=7, style="EvidenceClear.TButton",
                    command=lambda r=repo: self._clear_manual_evidence_source(r))
                clear_btn.pack(fill="x")

            selected_urls = list(getattr(repo, "evidence_urls", []) or [])
            required = self._provenance_repo_cache_key(repo) in required_keys
            pending = self._provenance_repo_cache_key(repo) in pending_keys
            state_text = "Awaiting inspection" if pending else ("Required" if required else "Not required")
            testing_row = False
            result = None
            if selected_urls:
                relationship = evidence_relationship(repo, selected_urls[0])
                result = self.__dict__.get("_evidence_preflight_cache", {}).get(
                    self._evidence_preflight_key(repo, selected_urls[0]))
                state_text, testing_row = self._evidence_row_status(
                    strategy, required, pending, relationship, result)
            status_label = ttk.Label(row, text=state_text, style="PanelHint.TLabel", width=30, wraplength=225, anchor="w")
            status_label.pack(side="right", padx=(8, 0))
            if result and str(result.get("detail", "") or "").strip():
                self._attach_tooltip(
                    status_label,
                    str(result.get("detail", "") or "").strip())
            if testing_row:
                testing_indicator = FeatheredActivityPulse(
                    row, width=44, height=18, bg=BG_PANEL, compact=True)
                testing_indicator.pack(side="right", padx=(4, 0))
                testing_indicator.render_frame(int(self.__dict__.get("_activity_frame", 0)), active=True)
                self._evidence_testing_labels.append(status_label)
                self._evidence_testing_indicators.append(testing_indicator)

            combo = ttk.Combobox(row, textvariable=var, state="readonly", values=values,
                                 width=57, style="Evidence.TCombobox")
            combo.pack(side="left", padx=(8, 0), fill="x", expand=True)
            combo.bind("<<ComboboxSelected>>",
                       lambda _e, r=repo, v=var: self._evidence_source_changed(r, v))
            self._bind_combobox_widget(combo)
            if is_manual and selected_urls:
                self._attach_tooltip(
                    combo,
                    "Manual evidence source (session only):\n"
                    + self._tooltip_safe_url(selected_urls[0]))

            self._prov_evidence_row_vars[self._provenance_repo_cache_key(repo)] = var
            self._prov_evidence_row_combos.append(combo)
        self._update_provenance_evidence_state()

    def _evidence_source_changed(self, repo, variable):
        _values, candidate_map, curated, auto_label, none_label, manual_label, session_label = self._evidence_choices_for_repo(repo)
        try:
            spec_map = self._evidence_candidate_spec_map(repo)
        except Exception:
            spec_map = {}
        choice = variable.get()
        previous = list(getattr(repo, "evidence_urls", []) or [])
        urls = previous[:]
        selected_spec = None
        if choice == none_label:
            urls = []
        elif choice == manual_label:
            manual, persist = self._prompt_manual_evidence_repository(repo)
            if not manual:
                self._refresh_provenance_evidence_rows()
                return
            urls = [manual.strip()]
            selected_spec = EvidenceCandidate(
                urls[0], "Manual evidence source", REL_EXACT_ARTIFACT, AUTH_UNKNOWN, "manual",
                "Unknown/manual sources are allowed to prove exact byte equality only.")
            if persist:
                try:
                    profile_key = self._evidence_catalog_profile_key(repo)
                    mirror_catalog.add_exact_mirror_override(profile_key, repo, urls[0])
                    selected_spec = EvidenceCandidate(
                        urls[0], "Saved local mirror", REL_EXACT_MIRROR, AUTH_UNKNOWN,
                        "mirror-catalog-user",
                        "Operator saved this endpoint as an exact mirror in the local distribution catalog.")
                    self._log(f"Saved exact mirror to local {profile_key} catalog: {redact_url(urls[0])}")
                except Exception as exc:
                    messagebox.showerror(APP_TITLE, f"Could not save the mirror catalog entry: {redact_text(str(exc))}")
                    self._refresh_provenance_evidence_rows()
                    return
        elif (previous and self._is_manual_evidence_source(repo, candidate_map, curated)
              and choice == self._compact_evidence_url(previous[0])):
            return
        elif choice in spec_map:
            selected_spec = spec_map[choice]
            strategy_var = self.__dict__.get("prov_strategy_var")
            strategy = (self._strategy_ui_to_policy(strategy_var.get())
                        if strategy_var is not None else repository_verification_strategy(repo))
            if strategy == "evidence-fallback" and selected_spec.relationship == REL_REBUILD_PEER:
                messagebox.showinfo(
                    APP_TITLE,
                    "A semantic rebuild peer is not an exact mirror. It is useful only under Maximum verification, "
                    "where Feathered asks whether another Enterprise Linux rebuild publishes the same package/source "
                    "lineage and verifies that peer against its own repository checksum. Its RPM bytes are allowed to differ.\n\n"
                    "Enhanced verification is filling a missing acquisition-integrity gap, so it requires an exact "
                    "mirror or exact-artifact endpoint whose package bytes match exactly.")
                self._refresh_provenance_evidence_rows()
                return
            urls = [selected_spec.url]
        elif choice in candidate_map:
            urls = [candidate_map[choice]]
            selected_spec = EvidenceCandidate(
                urls[0], choice, evidence_relationship(repo, urls[0]), AUTH_UNKNOWN, "configured")

        for url in urls:
            distinct, reason = mirrors_are_distinct(repo.normalized_url, url)
            if not distinct:
                messagebox.showerror(APP_TITLE, f"Evidence repository is not distinct: {reason}.")
                self._refresh_provenance_evidence_rows()
                return
        if urls != previous:
            cache = self.__dict__.setdefault("_evidence_preflight_cache", {})
            for key in list(cache):
                if key[0] == self._provenance_repo_cache_key(repo):
                    cache.pop(key, None)
            repo.evidence_urls = urls
            # Keep the proof contract next to the active URL. Runtime verification
            # must honor the relationship the operator selected rather than infer
            # a different one later from the hostname alone.
            repo.evidence_relationship_hints = {}
            repo.evidence_authority_hints = {}
            if urls and selected_spec is not None:
                repo.evidence_relationship_hints[urls[0]] = selected_spec.relationship
                repo.evidence_authority_hints[urls[0]] = selected_spec.authority
            self._invalidate_provenance_analysis()
            self._clear_validation_attention()
            self._log(f"Evidence source for {repo.name}: {redact_url(urls[0]) if urls else 'none'}")
        self._refresh_provenance_evidence_rows()
        self._refresh_provenance_source_tree()
        self._refresh_repo_tree_if_open()

    def _clear_manual_evidence_source(self, repo):
        """Discard an unmatched/manual evidence URL without retaining a choice."""
        repo.evidence_urls = []
        repo.evidence_relationship_hints = {}
        repo.evidence_authority_hints = {}
        cache = self.__dict__.setdefault("_evidence_preflight_cache", {})
        for key in list(cache):
            if key[0] == self._provenance_repo_cache_key(repo):
                cache.pop(key, None)
        self._invalidate_provenance_analysis()
        self._clear_validation_attention()
        self._log(f"Evidence source for {repo.name}: none")
        self._refresh_provenance_evidence_rows()
        self._refresh_provenance_source_tree()
        self._refresh_repo_tree_if_open()

    def _invalidate_provenance_analysis(self):
        self.loaded_signature = None
        self.loaded_packages = []
        self.last_result = None

    def _provenance_policy_changed(self):
        enabled = self._enabled_provenance_repos()
        if not enabled:
            return
        digest_label = self.prov_digest_var.get()
        strategy_label = self.prov_strategy_var.get()
        strategy = (None if strategy_label.startswith("Mixed")
                    else self._strategy_ui_to_policy(strategy_label))

        # Programmatic policy changes must not leave a stale diagnostic running.
        if (strategy is not None and strategy not in {"evidence-fallback", "full-corroboration"}
                and self.__dict__.get("active_operation") == "evidence-preflight"):
            self.cancel_event.set()
        # Mixed values are retained per source. Skip keeps the inactive minimum.
        digest = (None if strategy == "skip-provenance" or
                  digest_label.startswith(("Mixed", "Inspect", "No common"))
                  else self._digest_ui_to_policy(digest_label))

        changed = False
        for repo in enabled:
            effective_strategy = strategy or repository_verification_strategy(repo)
            requirement, evidence_policy = {
                "checksum-required": ("required", "off"),
                "checksum-available": ("preferred", "off"),
                "evidence-fallback": ("preferred", "fallback"),
                "full-corroboration": ("required", "required"),
                "skip-provenance": ("preferred", "off"),
            }[effective_strategy]
            if digest is not None and getattr(repo, "digest_preference", "auto") != digest:
                repo.digest_preference = digest
                changed = True
            if getattr(repo, "verification_strategy", "") != effective_strategy:
                repo.verification_strategy = effective_strategy
                changed = True
            # Keep legacy fields synchronized for older callers and saved data.
            if getattr(repo, "digest_requirement", "preferred") != requirement:
                repo.digest_requirement = requirement
                changed = True
            if getattr(repo, "evidence_policy", "off") != evidence_policy:
                repo.evidence_policy = evidence_policy
                changed = True
        if changed:
            self._invalidate_provenance_analysis()
            self._log(
                f"Provenance policy updated for {len(enabled)} enabled source(s). "
                f"Minimum checksum {digest or 'retained per source'}; strategy {strategy or 'retained per source'}.")
        self._refresh_provenance_editor()
        self._refresh_repo_tree_if_open()

    def _inspect_enabled_provenance_metadata(self):
        enabled = self._enabled_provenance_repos()
        if not enabled:
            return
        if self._busy():
            return
        if not self._claim_operation(
                "checksum-inspection", "Inspecting repository checksum support", cancellable=False):
            return
        self.prov_detected_var.set(f"Inspecting {len(enabled)} enabled repositories.")
        self.prov_inspect_progress.configure(maximum=max(1, len(enabled)), value=0)
        self.prov_inspect_status_var.set(f"Starting inspection of {len(enabled)} repositories")

        # Resolve widgets, source identities and dispatch before starting the worker.
        arches = {self.arch_var.get()}
        probes = [(self._provenance_repo_cache_key(repo), copy.deepcopy(repo),
                   self._checksum_inspection_loader(repo)) for repo in enabled]

        def worker():
            results = {}
            coverage_results = {}
            errors = {}
            for index, (key, repo, loader) in enumerate(probes, start=1):
                repo_name = repo.name
                def show_current(i=index, name=repo_name):
                    if self.winfo_exists():
                        step = max(0, i - 0.5)
                        self.prov_inspect_progress.configure(value=step)
                        self.progress_var.set(step / max(1, len(enabled)) * 100)
                        self.prov_inspect_status_var.set(f"Inspecting {i} of {len(enabled)}   {name}")
                        self._operation_status(f"Checksum inspection {i} of {len(enabled)}   {name}")
                self.events.put(("checksum_inspection_progress", show_current))
                try:
                    reporter = Reporter(self._log)
                    coverage = inspect_checksums(repo, arches, reporter, loader)
                    results[key] = list(coverage.algorithms)
                    coverage_results[key] = dict(coverage.counts)
                    if coverage.package_count:
                        detected = ", ".join(a.upper().replace("SHA", "SHA-") for a in results[key]) or "no strong SHA fields"
                        self._log(
                            f"{repo.name}: checksum inspection read {coverage.package_count:,} package records; detected {detected}.")
                    else:
                        reason = (apt_core.empty_repository_explanation(repo)
                                  if repo.repo_format == "apt" or self._is_deb()
                                  else "the repository currently publishes no package records for the selected target.")
                        self._log(
                            f"{repo.name}: checksum inspection read a valid empty package index; "
                            f"there are no package-level digests to inspect. {reason}")
                except Exception as exc:
                    error_text = redact_text(str(exc))
                    errors[key] = error_text
                    self._log(f"{repo.name}: checksum inspection failed: {error_text}")
                finally:
                    def show_complete(i=index, name=repo_name):
                        if self.winfo_exists():
                            self.prov_inspect_progress.configure(value=i)
                            self.progress_var.set(i / max(1, len(enabled)) * 100)
                            self.prov_inspect_status_var.set(f"Completed {i} of {len(enabled)}   {name}")
                    self.events.put(("checksum_inspection_progress", show_complete))

            def finish():
                final = (f"Checksum inspection complete with {len(errors)} error(s)"
                         if errors else "Checksum inspection complete")
                self._release_operation(final, outcome=("failed" if errors else "idle"))
                if not self.winfo_exists():
                    return
                cache = getattr(self, "_provenance_detected_cache", None)
                if cache is None:
                    cache = self._provenance_detected_cache = {}
                cache.update(results)
                coverage_cache = getattr(self, "_provenance_digest_coverage_cache", None)
                if coverage_cache is None:
                    coverage_cache = self._provenance_digest_coverage_cache = {}
                coverage_cache.update(coverage_results)
                self._provenance_inspection_errors = errors
                self._refresh_provenance_editor()
                if errors:
                    self.prov_detected_var.set(
                        f"Read {len(results)} of {len(enabled)} enabled sources. {len(errors)} could not be inspected; see the log for details.")
                    self.prov_inspect_status_var.set(
                        f"Inspection finished with {len(errors)} error(s).")
                else:
                    self.prov_inspect_status_var.set(
                        f"Inspection complete. {len(results)} of {len(enabled)} repositories read successfully.")
            self.events.put(("checksum_inspection_finished", finish))

        threading.Thread(target=worker, daemon=True).start()

    def _refresh_provenance_tree(self):
        self._refresh_provenance_editor()

    def _edit_selected_provenance(self):
        self.open_repositories("all")

    def _refresh_keyring_tree(self):
        if not getattr(self, "keyring_tree", None):
            return
        self.keyring_tree.delete(*self.keyring_tree.get_children())
        participating = set(map(id, self._build_repository_scope()))
        for i, repo in enumerate(self.repo_rows):
            if id(repo) not in participating:
                continue
            if repo.keyring:
                state, tag = "Signed", "signed"
            elif repo.allow_unverified_index:
                state, tag = "Unverified allowed", "open"
            else:
                state, tag = "Digest only", "digest"
            self.keyring_tree.insert("", "end", iid=str(i), tags=(tag,),
                                     values=(repo.name, state, repo.keyring or "-"))

    def _selected_keyring_repo(self):
        sel = self.keyring_tree.selection() if self.keyring_tree else ()
        if not sel:
            messagebox.showinfo(APP_TITLE, "Select a repository first.")
            return None
        return self.repo_rows[int(sel[0])]

    def _ask_keyring(self):
        return filedialog.askopenfilename(
            title="Repository signing keyring",
            filetypes=[("Keyring", "*.gpg *.asc *.key *.pgp"), ("All files", "*.*")])

    def _assign_keyring(self):
        repo = self._selected_keyring_repo()
        if repo is None:
            return
        picked = self._ask_keyring()
        if picked:
            repo.keyring = picked
            self._remember_keyring(repo)
            self.loaded_signature = None
            self._refresh_keyring_tree(); self._refresh_repo_tree_if_open()
            self._log(f"Archive keyring set for {repo.name} and remembered for this archive")

    def _assign_keyring_all(self):
        """Apply one archive keyring to the repositories in the current output."""
        picked = self._ask_keyring()
        if not picked:
            return
        rows = self._build_repository_scope()
        for repo in rows:
            repo.keyring = picked
            self._remember_keyring(repo)
        self.loaded_signature = None
        self._refresh_keyring_tree(); self._refresh_repo_tree_if_open()
        self._log(f"Archive keyring applied to all {len(rows)} participating repositories")

    def _clear_keyring(self):
        repo = self._selected_keyring_repo()
        if repo is None:
            return
        repo.keyring = ""
        self._remember_keyring(repo)
        self.loaded_signature = None
        self._refresh_keyring_tree(); self._refresh_repo_tree_if_open()

    def _enabled_vendor_groups(self) -> dict[str, list[RepoSpec]]:
        groups = {}
        if self._is_deb() or self._is_arch():
            return groups
        for repo in self._build_repository_scope():
            vendor_id = getattr(repo, "vendor_id", "") or infer_vendor_id(repo.name, repo.url)
            groups.setdefault(vendor_id, []).append(repo)
        return groups

    def _refresh_vendor_signature_tree(self):
        tree = getattr(self, "vendor_signature_tree", None)
        if tree is None or not tree.winfo_exists():
            return
        current = tree.selection()
        tree.delete(*tree.get_children())
        groups = self._enabled_vendor_groups()
        for vendor_id, repos in sorted(groups.items(), key=lambda item: vendor_display_name(item[0])):
            profile = self.vendor_signature_profiles.get(vendor_id, {})
            keyring = str(profile.get("keyring", ""))
            if keyring and not Path(keyring).is_file():
                keyring_text = Path(keyring).name + " (missing)"
                tag = "bad"
            else:
                keyring_text = Path(keyring).name if keyring else "Not configured"
                tag = "ok" if keyring else "open"
            policy = "Require" if profile.get("policy") == "require" else "Record"
            names = ", ".join(r.name for r in repos[:2])
            if len(repos) > 2:
                names += f" and {len(repos)-2} more"
            tree.insert("", "end", iid=vendor_id, tags=(tag,),
                        values=(vendor_display_name(vendor_id), names, keyring_text, policy))
        tree.tag_configure("ok", foreground=OK_FG)
        tree.tag_configure("open", foreground=FG_MUTED)
        tree.tag_configure("bad", foreground=ERR_FG)
        wanted = current[0] if current and current[0] in groups else next(iter(groups), None)
        if wanted:
            tree.selection_set(wanted)
        self._vendor_signature_selection_changed()

    def _selected_vendor_signature_id(self, quiet=False) -> str | None:
        tree = getattr(self, "vendor_signature_tree", None)
        sel = tree.selection() if tree is not None else ()
        if not sel:
            if not quiet:
                messagebox.showinfo(APP_TITLE, "Select a vendor first.")
            return None
        return str(sel[0])

    def _vendor_signature_selection_changed(self):
        vendor_id = self._selected_vendor_signature_id(quiet=True)
        combo = getattr(self, "vendor_signature_policy_combo", None)
        if combo is None:
            return
        if not vendor_id:
            combo.configure(state="disabled")
            return
        profile = self.vendor_signature_profiles.get(vendor_id, {})
        self.vendor_signature_policy_var.set(
            "Require valid vendor signatures" if profile.get("policy") == "require"
            else "Record signature results")
        combo.configure(state="readonly")

    def _assign_vendor_keyring(self):
        vendor_id = self._selected_vendor_signature_id()
        if not vendor_id:
            return
        picked = filedialog.askopenfilename(
            title=f"{vendor_display_name(vendor_id)} package-signature keyring",
            filetypes=[("Keyring", "*.gpg *.asc *.key *.pgp"), ("All files", "*.*")])
        if not picked:
            return
        profile = dict(self.vendor_signature_profiles.get(vendor_id, {}))
        profile["keyring"] = picked
        profile.setdefault("policy", "record")
        self.vendor_signature_profiles[vendor_id] = profile
        self._save_vendor_signature_profiles()
        self._refresh_vendor_signature_tree()
        self._log(f"Remembered a package-signature keyring reference for {vendor_display_name(vendor_id)} only.")

    def _clear_vendor_keyring(self):
        vendor_id = self._selected_vendor_signature_id()
        if not vendor_id:
            return
        profile = dict(self.vendor_signature_profiles.get(vendor_id, {}))
        profile.pop("keyring", None)
        if profile.get("policy") == "require":
            profile["policy"] = "record"
        if profile:
            self.vendor_signature_profiles[vendor_id] = profile
        else:
            self.vendor_signature_profiles.pop(vendor_id, None)
        self._save_vendor_signature_profiles()
        self._refresh_vendor_signature_tree()

    def _vendor_signature_policy_changed(self):
        vendor_id = self._selected_vendor_signature_id(quiet=True)
        if not vendor_id:
            return
        profile = dict(self.vendor_signature_profiles.get(vendor_id, {}))
        require = self.vendor_signature_policy_var.get().startswith("Require")
        if require and not str(profile.get("keyring", "")).strip():
            self.vendor_signature_policy_var.set("Record signature results")
            messagebox.showinfo(
                APP_TITLE,
                f"Set a {vendor_display_name(vendor_id)} package-signature keyring before requiring vendor signatures for that vendor.")
            return
        profile["policy"] = "require" if require else "record"
        self.vendor_signature_profiles[vendor_id] = profile
        self._save_vendor_signature_profiles()
        self._refresh_vendor_signature_tree()

    def _browse_vendor_keyring(self):
        self._assign_vendor_keyring()
