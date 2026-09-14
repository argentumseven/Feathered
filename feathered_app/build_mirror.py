"""Mirror inventory and publication population construction.

A mirror is not a dependency closure, so it does not go through the resolver.
These methods inventory every published record in each selected repository and,
for the unified layout, merge them into one deduplicated population.

Imports no Tk, enforced by tests/test_build_request_module.py.
"""
from __future__ import annotations

import apt_core
import arch_core
import core
from acquisition_model import MirrorLayout
from core import ResolutionResult, Reporter, human_size
from mirror_unification import MergePolicy, conflict_report, unify_mirror_packages


class BuildMirrorMixin:
    """Mirror inventory and unification. No widget access."""

    def _format_requirement_backend(self, req):
        if self._is_arch():
            return arch_core.format_requirement(req)
        return apt_core.format_requirement(req) if self._is_deb() else core.format_requirement(req)

    def _write_archive_backend(self, dest, reporter):
        if self._is_arch():
            return arch_core.write_bundle_archive(dest, reporter)
        return apt_core.write_bundle_archive(dest, reporter) if self._is_deb() else core.write_bundle_archive(dest, reporter)

    def _mirror_resolution_result(self, selected):
        """Create the backend-native result object for an exact repository inventory.

        Mirror inventory is deliberately not a resolver operation. Every package
        record published by the source repository is retained, including older
        versions and package identities that also exist in another selected
        repository. Cross-repository de-duplication would change the object being
        mirrored and is therefore forbidden here.
        """
        selected = list(selected)
        reasons = {p.nevra: f"mirror artifact from {p.repo.name}" for p in selected}
        if self._is_deb():
            return apt_core.DebResolutionResult(selected, [], list(selected), [], [], reasons, [], {})
        if self._is_arch():
            return arch_core.ArchResolutionResult(selected=selected, unresolved=[], roots=list(selected),
                                                   reasons=reasons)
        return ResolutionResult(selected=selected, unresolved=[], roots=list(selected),
                                reasons=reasons)

    def _unified_mirror_result(self, repos, by_source, reporter):
        """Merge the selected repositories into one deduplicated population.

        Unlike the separate layout this really is one publication, so the merge
        is decided here, at inventory, where the operator can still see the
        outcome on Review and change their mind before a byte is fetched.
        """
        ordered = []
        for repo in repos:
            ordered.extend(by_source[repo.source_identity])
        policy_fn = getattr(self, "_merge_policy", None)
        policy = policy_fn() if callable(policy_fn) else MergePolicy.STRICT
        plan = unify_mirror_packages(ordered, repos, policy)
        if not plan.ok:
            reporter.log(f"Unified mirror refused: {len(plan.conflicts)} unresolved identity conflict(s)")
            raise RuntimeError(conflict_report(plan))
        result = BuildMirrorMixin._mirror_resolution_result(self, list(plan.packages))
        # Runtime-only publication plan, as for the separate layout below.
        result.mirror_repository_results = []
        result.mirror_unified_plan = plan
        result.mirror_repository_summaries = [{
            "source_identity": repo.source_identity,
            "name": repo.name,
            "package_count": len(by_source[repo.source_identity]),
            "total_size": sum(int(getattr(p, "size", 0) or 0)
                              for p in by_source[repo.source_identity]),
        } for repo in repos]
        for row in result.mirror_repository_summaries:
            reporter.log(f"Mirror inventory: {row['name']}: {row['package_count']:,} "
                         f"package record(s), {human_size(row['total_size'])}")
        reporter.log(plan.summary())
        if plan.deduplicated:
            reporter.log(
                f"Unified mirror: {len(plan.deduplicated):,} identity/identities appeared in more "
                f"than one repository ({len(plan.deduplicated) - plan.weakly_proven_count - plan.unproven_count:,} "
                f"proven by strong digest, {plan.weakly_proven_count:,} by weak digest, "
                f"{plan.unproven_count:,} resolved by repository priority)")
        if plan.unproven_count:
            reporter.warn(
                f"{plan.unproven_count:,} unified-mirror identity/identities were resolved by "
                "repository priority with no equality check, because the repositories published "
                "no digest algorithm in common or disagreed. See metadata mirror-sources.json.")
        return result

    def _mirror_result(self, packages, reporter):
        """Inventory every package record from every selected repository.

        In the default separate layout a multi-repository mirror is a set of
        independent mirror jobs, not one dependency/provider universe.  The
        aggregate result exists only for the Review screen and transfer total;
        build publication later forks it back into one output directory and one
        metadata set per source repository.

        In the unified layout it is instead one publication, and the merge is
        performed here so that Review shows the deduplicated population and the
        real transfer total rather than the pre-merge sum.
        """
        repos_fn = getattr(self, "_selected_mirror_repositories", None)
        repos = (list(repos_fn()) if callable(repos_fn) else
                 [r for r in getattr(self, "repo_rows", [])
                  if str(getattr(r, "url", "") or "").strip()
                  and self._mirror_repo_selected(r)])
        if not repos:
            raise RuntimeError("No repositories are selected for mirroring.")

        by_source = {r.source_identity: [] for r in repos}
        for pkg in packages:
            source_id = getattr(getattr(pkg, "repo", None), "source_identity", None)
            if source_id in by_source:
                by_source[source_id].append(pkg)

        # Repository loading has already succeeded for every selected mirror
        # source before this method runs. A valid repository can publish an
        # empty package index, so zero records must remain a real mirror fork.
        # Contract tests drive this against a lightweight stub; an absent layout
        # control means the conservative separate layout, never a silent merge.
        layout_fn = getattr(self, "_mirror_layout", None)
        layout = layout_fn() if callable(layout_fn) else MirrorLayout.SEPARATE
        if layout is MirrorLayout.UNIFIED:
            return BuildMirrorMixin._unified_mirror_result(self, repos, by_source, reporter)

        mirror_results = []
        aggregate = []
        summaries = []
        for repo in repos:
            repo_packages = list(by_source[repo.source_identity])
            # Preserve repository metadata order as loaded. Do not select only
            # the newest name/arch and do not collapse copies found elsewhere.
            repo_result = BuildMirrorMixin._mirror_resolution_result(self, repo_packages)
            mirror_results.append((repo, repo_result))
            aggregate.extend(repo_packages)
            summaries.append({
                "source_identity": repo.source_identity,
                "name": repo.name,
                "package_count": len(repo_packages),
                "total_size": sum(int(getattr(p, "size", 0) or 0) for p in repo_packages),
            })
            reporter.log(
                f"Mirror inventory: {repo.name}: {len(repo_packages):,} package record(s), "
                f"{human_size(summaries[-1]['total_size'])}")

        result = BuildMirrorMixin._mirror_resolution_result(self, aggregate)
        # Runtime-only publication plan used by BuildMixin; result classes are
        # ordinary Python objects and intentionally permit this UI/orchestration
        # metadata without changing resolver-domain dataclasses.
        result.mirror_repository_results = mirror_results
        result.mirror_repository_summaries = summaries
        total = sum(row["total_size"] for row in summaries)
        reporter.log(
            f"Mirror aggregate: {len(repos)} repositories, {len(aggregate):,} package record(s), "
            f"{human_size(total)}; no cross-repository de-duplication applied")
        return result

    def _on_item_event(self, identity: str, state: str, info: dict) -> None:
        """Worker-thread hook: queue a per-package state change for the UI."""
        self.events.put(("item", identity, state, info))

    @staticmethod
    def _package_only_warning_text() -> str:
        return (
            "Only the workload-specific upstream is available. Feathered can download and verify "
            "the requested workload package artifacts, but it cannot derive or prove their "
            "dependency closure without the target distribution/base repositories. This output "
            "is package-only acquisition, not a complete offline installation bundle.")

    @staticmethod
    def _request_source_plan_metadata(requests):
        """Serialize the resolver's root-source constraints for provenance.

        This is the requested policy. Package provenance separately records the
        concrete repository that actually supplied each selected artifact, so
        an audit can compare intent (distribution/role/exact/any-enabled) with
        resolution outcome rather than conflating the two.
        """
        rows = []
        for request in requests:
            name = request[0]
            role = request[2] if len(request) >= 3 else None
            repo_name = request[3] if len(request) >= 4 else None
            exact_arch = request[4] if len(request) >= 5 else None
            source_scope = request[5] if len(request) >= 6 else None
            repo_identity = request[6] if len(request) >= 7 else None
            if repo_name:
                policy = "repository"
            elif source_scope:
                policy = source_scope
            elif role:
                policy = "role"
            else:
                policy = "enabled"
            row = {"package": name, "source_policy": policy}
            if role:
                row["repository_role"] = role
            if repo_name:
                row["repository_name"] = repo_name
            if repo_identity:
                row["repository_identity"] = repo_identity
            if exact_arch:
                row["architecture"] = exact_arch
            rows.append(row)
        return rows
