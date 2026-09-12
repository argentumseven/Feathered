"""Execute a prepared BuildPlan and return a structured BuildOutcome.

GUI and CLI share this orchestration. Terminal events remain available to the
GUI event loop and service consumers. build_preparation and build_api construct
validated plans; this module performs resolution and publication.
BuildPlan is shallow frozen: its options and repository state belong to one run.
"""
from __future__ import annotations

import copy
import re
import threading
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import workload_resolution
from acquisition_model import AcquisitionCapability
from core import (BuildOptions, Cancelled, Reporter, evidence_authority_relationship,
                  repository_verification_strategy,
                  evidence_relationship, redact_text, redact_url)
from feathered_app.build_request import BuildRequestMixin
from feathered_app.build_outcome import BuildOutcome, BuildStatus
from feathered_app.build_services import BuildServices
from mirror_unification import mirror_sources_record, unified_mirror_note


def _indexed_evidence_records(repo, resolver, value_field: str) -> dict:
    """Preserve one provenance record per evidence URL without secret-key collisions."""
    return {
        str(index): {
            "url": redact_url(url),
            value_field: resolver(repo, url),
        }
        for index, url in enumerate(repo.evidence_urls)
    }


@dataclass(frozen=True)
class BuildPlan:
    """Prepared inputs for one execution.

    Field bindings are frozen. Nested options and repository objects remain
    mutable and belong to this run; callers must not share them concurrently.
    """

    state: object
    opts: BuildOptions
    requests: object
    requested_source_plan: object
    build_repositories: object
    package_only: bool
    picked_at_start: object
    #  start_build's own parameter, captured the same way as its locals.
    do_download: bool = True
    locked_output_folder_name: Optional[str] = None
    locked_mirror_publications: Optional[object] = None


def _complete(app, ok, message, output_path=None):
    status = BuildStatus.SUCCESS if ok is True else (
        BuildStatus.CANCELLED if ok == "cancelled" else BuildStatus.FAILED)
    event = ("done", ok, message) + ((output_path,) if output_path is not None else ())
    app.events.put(event)
    return BuildOutcome(status, message, output_path)


def run(app, job) -> BuildOutcome:
    try:
        rep = Reporter(app._log, app._progress, app.cancel_event,
                       item=app._on_item_event)
        rep.check_cancel()
        if job.state.capability is AcquisitionCapability.REPOSITORY_MIRROR:
            for repo in job.build_repositories:
                repo.preserve_repository_metadata = True
        # Every intent uses the same frozen, validated acquisition set.
        packages = app._load_enabled_repos(
            rep, repositories=job.build_repositories,
            enforce_distribution_plan=not job.package_only)
        runtime_requests = job.requests
        runtime_source_plan = job.requested_source_plan
        materialized_workload = None
        if not app._mirror_mode() and not app._single_mode() and not app._workload().custom:
            materialized_workload = app._materialize_selected_workload(packages)
            missing_required = [p for p in materialized_workload.unresolved if not p.optional]
            if missing_required:
                details = "; ".join(
                    f"{p.component or p.package}: {' / '.join(p.candidates or (p.package,))}"
                    for p in missing_required)
                raise RuntimeError(
                    "The current repositories do not contain an approved package identity for "
                    f"these workload component(s): {details}. Update the workload catalog or "
                    "repository selection; Feathered will not infer an unapproved replacement.")
            runtime_requests = app._package_requests(materialized_workload)
            runtime_source_plan = app._request_source_plan_metadata(runtime_requests)
            job.opts.optional_roots = (
                {root.package for root in materialized_workload.roots if root.optional}
                | {p.package for p in materialized_workload.unresolved if p.optional})
            rep.log(
                "Materialized workload roots: " + ", ".join(
                    f"{root.component}={root.package}" for root in materialized_workload.roots))
        if app._mirror_mode():
            result = app._mirror_result(packages, rep)
        else:
            init_choice = app._selected_init_system()
            if init_choice:
                by_name = {p.name: p for p in packages}
                blocked = [
                    workload_resolution.systemd_conflict(str(r[0]), by_name)
                    for r in runtime_requests]
                blocked = [b for b in blocked if b]
                if blocked:
                    raise RuntimeError(
                        f"This target runs {init_choice}, not systemd. Refusing to build: "
                        + " ".join(blocked[:3])
                        + (" (and others)" if len(blocked) > 3 else ""))
            # Approved catalog candidates were materialized above. Exact
            # job.requests must never be renamed by spelling heuristics.
            alias_subs = []
            for sub in alias_subs:
                rep.log(f"Workload name resolved dynamically: {sub.requested} → {sub.resolved} ({sub.kind}; {sub.note})")
            if alias_subs:
                app.events.put(("workload_aliases", [(s.requested, s.resolved) for s in alias_subs]))
            result = app._resolve_backend(runtime_requests, packages, app._selected_arch(), job.opts, rep)
        app.events.put(("warnings", list(rep.warnings)))
        current_unresolved = {app._format_requirement_backend(req) for req in result.unresolved}
        # Waivers only remain meaningful while the exact requirement is
        # still unresolved after this analysis.
        app.ignored_unresolved.intersection_update(current_unresolved)
        result.ignored_unresolved = sorted(app.ignored_unresolved)
        blocking_unresolved = [req for req in result.unresolved
                               if app._format_requirement_backend(req) not in app.ignored_unresolved]
        app.events.put(("result", result))
        if job.do_download and blocking_unresolved and (job.opts.include_dependencies or job.package_only):
            if job.package_only:
                raise RuntimeError(
                    f"Package-only acquisition could not locate {len(blocking_unresolved)} requested "
                    "workload package(s) in the configured workload upstream. Check source coverage "
                    "or choose another upstream before downloading.")
            raise RuntimeError(
                f"Bundle is incomplete: {len(blocking_unresolved)} requirement(s) are still blocking. "
                "Retry them, choose another source/provider where available, or explicitly ignore the "
                "requirements you accept as incomplete.")
        if job.do_download and result.ignored_unresolved:
            accepted = app._ask_on_ui_thread(
                "Build with ignored dependencies?",
                f"{len(result.ignored_unresolved)} unresolved requirement(s) were explicitly ignored. "
                "The bundle may not install successfully on the target. Feathered will record the waivers "
                "in ignored-unresolved.txt and the manifest.\n\nContinue building?",
                wait_status="Build paused for the dependency-waiver decision")
            if not accepted:
                raise Cancelled("Build cancelled at the unresolved-dependency waiver prompt")
        if job.do_download and result.conflicts and not app._confirm_conflicts(result.conflicts):
            raise Cancelled("Build cancelled at the conflict review prompt")
        if job.do_download and rep.warnings and not app._confirm_warnings(rep.warnings):
            raise Cancelled("Build cancelled at the trust review prompt")
        if job.do_download and app._pick_mode() and job.picked_at_start is not None:
            # Captured before the worker started: _show_result runs on
            # the UI thread during this build and would otherwise race
            # with this filter.
            kept = [p for p in result.selected if p.nevra in job.picked_at_start]
            if not kept:
                raise RuntimeError("No packages are selected. Click rows in the result "
                                   "list to include them.")
            if len(kept) != len(result.selected):
                rep.warn(f"Building a partial bundle: {len(kept)} of "
                         f"{len(result.selected)} packages from the computed closure. "
                         "Excluded dependencies may prevent installation on the target.")
            result.selected = kept
        if job.do_download:
            # Surface the exact aggregate package payload before any
            # package bytes are fetched. The worker waits only until
            # the UI has rendered this plan; there is no extra prompt.
            app._publish_download_plan(len(result.selected), result.total_size)
            app.events.put(("transfer_begin", len(result.selected), result.total_size))
            release = BuildRequestMixin._selected_release(app)
            if app._unified_mirror_mode():
                plan = getattr(result, "mirror_unified_plan", None)
                if plan is None:
                    raise RuntimeError(
                        "Unified mirror inventory did not produce a merge plan. Re-run Analyze.")
                mirrored = app._selected_mirror_repositories()
                folder = job.locked_output_folder_name or app._folder_name()
                dest = app._resolved_output_path(folder)
                repo_records = [
                    app._mirror_repository_record(repo, evidence_relationship,
                                                   evidence_authority_relationship)
                    for repo in mirrored]
                job.opts.unified_mirror_note = unified_mirror_note(plan)
                job.opts.unified_mirror_records = mirror_sources_record(plan)
                meta = app._mirror_bundle_metadata(job.state, release, rep, repo_records)
                meta.update({
                    "workload": (f"Unified repository mirror "
                                 f"({len(repo_records)} repository/repositories)"),
                    "mirror_layout": "unified",
                    "mirror_fork_index": 1,
                    "mirror_fork_count": 1,
                    "mirror_source_count": len(repo_records),
                    "mirror_published_record_count": plan.input_record_count,
                    "mirror_retained_package_count": plan.retained_count,
                    "mirror_duplicate_records_removed": plan.duplicate_record_count,
                    "mirror_deduplicated_identity_count": len(plan.deduplicated),
                    "mirror_disagreement_policy": plan.policy.value,
                    "mirror_priority_resolved_identity_count": plan.unproven_count,
                    "verification_commands": [
                        "# This directory is a UNIFIED mirror: the union of several",
                        "# upstream repositories, and a faithful copy of none of them.",
                        "# See UNIFIED-MIRROR.txt and metadata/mirror-sources.json.",
                    ],
                })
                rep.log(plan.summary())
                rep.log(f"Publishing unified mirror -> {dest}")
                app._write_bundle_backend(result, dest, job.opts, rep, meta)
                return _complete(app, True, f'Unified mirror complete: {len(repo_records)} repositories merged into {plan.retained_count:,} packages at {dest}', str(dest))
            if app._mirror_mode():
                mirror_results = list(getattr(result, "mirror_repository_results", []) or [])
                publication_by_source = {
                    source_id: (folder_name, repo_opts)
                    for source_id, folder_name, repo_opts in job.locked_mirror_publications
                }
                if not mirror_results:
                    raise RuntimeError("Mirror inventory did not produce per-repository publication results.")
                if len(mirror_results) != len(publication_by_source):
                    raise RuntimeError(
                        "Mirror publication plan changed after output folders were locked. Re-run the build.")
                base_output = Path(BuildRequestMixin._selected_output_base(app) or str(Path.cwd())).expanduser()
                base_output.mkdir(parents=True, exist_ok=True)
                total_forks = len(mirror_results)
                for fork_index, (mirror_repo, mirror_result) in enumerate(mirror_results, 1):
                    source_id = mirror_repo.source_identity
                    if source_id not in publication_by_source:
                        raise RuntimeError(
                            f"No locked output directory exists for mirror source {mirror_repo.name}.")
                    folder, repo_opts = publication_by_source[source_id]
                    dest = app._resolved_output_path(folder)
                    repo_record = app._mirror_repository_record(
                        mirror_repo, evidence_relationship, evidence_authority_relationship)
                    meta = app._mirror_bundle_metadata(job.state, release, rep, [repo_record])
                    meta.update({
                        "workload": f"Repository mirror: {mirror_repo.name}",
                        "mirror_layout": "separate",
                        "mirror_fork_index": fork_index,
                        "mirror_fork_count": total_forks,
                        "mirrored_repository": repo_record,
                        "signature_verification": "openpgp" if mirror_repo.keyring else "none",
                        "verification_commands": [
                            "# This directory is one independently published repository mirror.",
                            "# See USE-AS-REPOSITORY.txt for local repository configuration.",
                        ],
                    })
                    rep.log(
                        f"Publishing mirror {fork_index}/{total_forks}: {mirror_repo.name} -> {dest}")
                    # Each backend writer reports local 0..1 progress and
                    # package identities without repository context. Map
                    # both into the aggregate multi-repository operation
                    # so progress stays monotonic and duplicate NEVRAs in
                    # sibling repositories update the correct Review row.
                    fork_base = (fork_index - 1) / total_forks
                    fork_span = 1.0 / total_forks
                    fork_reporter = Reporter(
                        app._log,
                        lambda label, value, base=fork_base, span=fork_span:
                            app._progress(label, base + max(0.0, min(1.0, value)) * span),
                        app.cancel_event,
                        item=lambda identity, item_state, info, sid=source_id:
                            app._on_item_event(f"{sid}|{identity}", item_state, info),
                    )
                    # Preserve the build-wide warning collection even
                    # though each mirror fork has a local progress window.
                    fork_reporter.warnings = rep.warnings
                    app._write_bundle_backend(
                        mirror_result, dest, repo_opts, fork_reporter, meta)
                return _complete(app, True, f'Mirror complete: {total_forks} repositories published as independent folders under {base_output}', str(base_output))
            if app._single_mode():
                roots = list(app.selected_packages)
                folder = job.locked_output_folder_name or app._folder_name()
                dependency_mode = ("Strict APT Depends/Pre-Depends closure" if app._is_deb() else
                                   "Strict pacman Depends closure" if app._is_arch() else
                                   "Strict RPM Requires closure")
                package_version = (roots[0].evr_text if len(roots) == 1 else
                                   f"{len(roots)} explicitly selected versions")
                workload_label = (f"Exact package: {roots[0].nevra}" if len(roots) == 1
                                  else f"Exact package selection ({len(roots)} roots)")
                workload_key = "exact-packages"
                verification_commands = (
                    [f"dpkg-query -W -f='${{Package}} ${{Version}} ${{Architecture}}\n' {root.name}" for root in roots]
                    if app._is_deb() else
                    [f"pacman -Q {root.name}" for root in roots] if app._is_arch() else
                    [f"rpm -q {root.name}" for root in roots])
            else:
                folder = job.locked_output_folder_name or app._folder_name()
                dependency_mode = (
                    "Package-only acquisition (dependency closure not derived)"
                    if job.package_only else
                    "Repository mirror (dependency closure not applicable)"
                    if job.state.capability is AcquisitionCapability.REPOSITORY_MIRROR else
                    BuildRequestMixin._selected_content(app, "dependency_mode", "mode_var"))
                package_version = BuildRequestMixin._selected_content(
                    app, "package_version", "package_version_var")
                if app._mirror_mode():
                    # A mirror is not a workload; labelling it with
                    # whatever the workload dropdown happened to show
                    # put "Docker Engine" in the bundle manifest.
                    mirrored = [r.name for r in app.repo_rows
                                if r.url.strip() and app._mirror_repo_selected(r)]
                    workload_label = (f"Repository mirror ({len(mirrored)} "
                                      "repository/repositories)")
                    workload_key = "repository-mirror"
                    verification_commands = [
                        "# This bundle is a repository mirror, not an application install.",
                        "# See USE-AS-REPOSITORY.txt if repository metadata was generated.",
                    ]
                else:
                    workload_label = app._workload().label
                    workload_key = app._workload().key
                    if app._is_arch():
                        verification_commands = ["pacman -Q " + " ".join(x[0] for x in runtime_requests)]
                    elif not app._workload().custom:
                        verification_commands = app._workload().verification_commands
                    else:
                        verification_commands = (["dpkg-query -W " + " ".join(x[0] for x in runtime_requests)]
                                                 if app._is_deb() else
                                                 ["rpm -q " + " ".join(x[0] for x in runtime_requests)])
            # use the same
            # helper that feeds the Review summary so displayed and
            # actual destinations cannot diverge.
            dest = app._resolved_output_path(folder)
            meta = {
                "distribution": app._profile().label, "release": release, "codename": app._profile().codename(release), "arch": app._selected_arch(),
                "package_family": app._profile().package_family,
                "dependency_mode": dependency_mode, "package_version": package_version,
                "workload": workload_label, "workload_key": workload_key,
                "requested_packages": [x[0] for x in runtime_requests],
                "init_system": app._selected_init_system(),
                "job.requested_source_plan": runtime_source_plan,
                "workload_catalog_revision": (
                    getattr(materialized_workload, "catalog_revision", None)
                    if materialized_workload is not None else None),
                "workload_catalog_sha256": (
                    getattr(materialized_workload, "catalog_sha256", "")
                    if materialized_workload is not None else ""),
                "workload_catalog_signature_verified": (
                    bool(getattr(materialized_workload, "catalog_signature_verified", False))
                    if materialized_workload is not None else False),
                "materialized_workload_roots": ([
                    {"component": root.component, "primary_package": root.primary_package,
                     "package": root.package, "approved_candidates": list(root.candidates),
                     "source_kind": root.source_kind, "repository_role": root.role,
                     "optional": root.optional}
                    for root in materialized_workload.roots]
                    if materialized_workload is not None else []),
                "acquisition_intent": job.state.intent.value,
                "acquisition_capability": job.state.capability.value,
                "analysis_type": job.state.analysis.value,
                "publication_type": job.state.publication.value,
                "verification_scope": job.state.verification_scope.value,
                "repository_mirror": job.state.capability is AcquisitionCapability.REPOSITORY_MIRROR,
                "package_only_acquisition": bool(job.package_only),
                "dependency_completeness": (
                    "not-derived" if job.package_only else
                    "not-applicable" if job.state.capability is AcquisitionCapability.REPOSITORY_MIRROR else
                    "analyzed"),
                "package_only_warning": app._package_only_warning_text() if job.package_only else "",
                "verification_commands": verification_commands,
                "os_dependency_source": app._active_source_method(),
                # Record what was actually trusted, so a bundle can be
                # audited later without re-running the build.
                "signature_verification": "openpgp" if any(r.keyring for r in job.build_repositories) else "none",
                "trust_warnings": list(rep.warnings),
                "repositories": [{"name": r.name, "url": redact_url(r.url), "role": r.role, "priority": r.priority,
                                  "build_purposes": app._repository_build_purposes(r),
                                  "format": r.repo_format, "suite": r.suite, "components": r.components,
                                  "credential_redirect_allow_origins": [redact_url(u) for u in getattr(r, "redirect_allow_origins", [])],
                                  # What was verified, not what was configured.
                                  "keyring_configured": bool(r.keyring),
                                  "signature_verified": bool(
                                      getattr(r, "trust", None)
                                      and r.trust.archive_signature_verified),
                                  "allow_unverified_index": r.allow_unverified_index,
                                  # record source-bond intent without
                                  # exposing credentials in evidence URLs.
                                  "evidence_policy": r.evidence_policy,
                                  "evidence_urls": [redact_url(u) for u in r.evidence_urls],
                                  "evidence_relationships": _indexed_evidence_records(
                                      r, evidence_relationship, "relationship"),
                                  "evidence_authorities": _indexed_evidence_records(
                                      r, evidence_authority_relationship, "authority"),
                                  "digest_preference": r.digest_preference,
                                  "digest_requirement": r.digest_requirement,
                                  "verification_strategy": repository_verification_strategy(r)}
                                 for r in job.build_repositories],
            }
            app._write_bundle_backend(result, dest, job.opts, rep, meta)
            if app._single_mode():
                archive = app._write_archive_backend(dest, rep)
                return _complete(app, True, f'ZIP ready: {archive}', str(dest))
            else:
                if job.package_only:
                    return _complete(app, True, f'Package-only download complete: {dest}', str(dest))
                else:
                    return _complete(app, True, f'Bundle complete: {dest}', str(dest))
        else:
            return _complete(app, True, 'Analysis complete')
    except Cancelled as exc:
        return _complete(app, 'cancelled', redact_text(str(exc) or 'Operation cancelled'))
    except Exception as exc:
        app._log(traceback.format_exc())
        return _complete(app, False, redact_text(str(exc)))
