"""Resolve saved exact identities against current repository metadata.

Only concrete packages returned by the normal backends become GUI selections.
A missing pinned version, architecture or repository is an error; it must not
silently become a different root when the saved request is replayed.
"""
from __future__ import annotations

from core import BuildOptions, Reporter


def resolve_exact_packages(host, reporter: Reporter):
    records = host._build_snapshot.content.exact_packages
    if not records:
        return []
    if not host._single_mode():
        raise ValueError("Exact package identities require an exact-package acquisition mode.")
    reporter.check_cancel()
    repositories = [r for r in host.repo_rows if r.enabled and r.url.strip()]
    packages = host._load_enabled_repos(
        reporter, repositories=repositories, enforce_distribution_plan=False)
    selected = []
    for record in records:
        reporter.check_cancel()
        candidates = [p for p in packages
                      if p.name == record.name
                      and (not record.version or p.evr_text == record.version)
                      and (not record.arch or p.arch == record.arch)
                      and (not record.role or p.repo.role == record.role)
                      and (record.source_identity or not record.repository or p.repo.name == record.repository)
                      and (not record.source_identity or p.repo.source_identity == record.source_identity)]
        result = host._resolve_backend(
            [record.as_request()], candidates, host._selected_arch(),
            BuildOptions(include_dependencies=False), reporter)
        if result.unresolved or len(result.roots) != 1:
            raise ValueError(
                f"Saved exact package is unavailable: {record.name} "
                f"{record.version or '(latest)'} [{record.arch or host._selected_arch()}] "
                f"from {record.repository or record.source_identity or 'enabled repositories'}")
        root = result.roots[0]
        identity = (root.nevra, root.repo.source_identity)
        if not any((p.nevra, p.repo.source_identity) == identity for p in selected):
            selected.append(root)
    return selected
