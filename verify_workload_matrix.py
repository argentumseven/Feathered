"""Verify every workload preset against every distribution's live repositories.

Repository contents and supported releases drift independently of Feathered.
This harness discovers each profile's current release from live upstream metadata,
loads the default enabled repositories (network required), then checks every
mapped package name - including Artix init companions for each init system -
through scoped materialization, optionality, dependency closure and pinned installer roots.
This is a live compatibility observation, not proof of a native target transaction.
No compiled release number selects the matrix target.

Usage:
    python verify_workload_matrix.py [--profiles arch,artix,devuan] [--out report.json]

Exit code is 1 if any required name is missing anywhere, so CI can gate on it.
RHEL is skipped by default (entitlement required); pass --include-rhel with
configured entitlement to cover it.
"""
from __future__ import annotations

import argparse
import json
import sys

import core
import apt_core
import arch_core
import profiles as profiles_module
import workloads as workloads_module
from core import RepoSpec, Reporter, fetch_text


def _repo_from_template(template, family: str) -> RepoSpec:
    return RepoSpec(
        template.name, template.url, template.role, template.priority,
        enabled=template.enabled, target_release=template.target_release,
        repo_format=template.repo_format or ("apt" if family == "deb" else "rpm"),
        suite=getattr(template, "suite", ""), components=getattr(template, "components", ""),
        expected_release_version=getattr(template, "expected_release_version", ""),
        verification_strategy="skip-provenance", optional=getattr(template, "optional", False))


def load_universe(profile, release: str, arch: str, reporter: Reporter):
    """Load every enabled repository; any metadata failure is release-gate evidence."""
    packages = []
    repo_errors = []
    for template in profile.repos_factory(release, arch):
        if not template.enabled:
            continue
        repo = _repo_from_template(template, profile.package_family)
        try:
            if profile.package_family == "arch":
                pkgs = arch_core.load_repository(repo, {arch, "any"}, reporter)
            elif profile.package_family == "deb":
                pkgs = apt_core.load_repository(repo, {arch, "all"}, reporter)
            else:
                pkgs = core.load_repository(repo, {arch, "noarch"}, reporter)
        except Exception as exc:
            message = f"{profile.key}/{repo.name}: {exc}"
            reporter.warn(message)
            repo_errors.append(message)
            continue
        roles = {r.role for w in workloads_module.load_workloads().values()
                 for r in w.source_plan(profile.package_family).roots if r.role}
        repo.source_tier = "workload" if repo.role in roles else "base"
        packages.extend(pkgs)
    return packages, repo_errors


def check_workload(workload, profile, packages, arch, init=""):
    from workload_materialization import materialize_source_plan
    from source_model import SourcePlan, RootSourcePolicy
    from workload_resolution import repository_init_conflict
    from transaction_model import installation_roots
    universe = [p for p in packages if not repository_init_conflict(p.repo.name, p.repo.url, profile.key, init)]
    plan = workload.source_plan(profile.package_family)
    if not plan.roots:
        return {"status":"missing-family-mapping", "error":"No workload roots are mapped to this package family"}
    if profile.init_style == "companion-packages" and init:
        services = workloads_module.ARTIX_SERVICE_COMPANIONS.get(workload.key, [])
        names = {r.package for r in plan.roots}
        companions = [RootSourcePolicy(f"{name}-{init}", "distribution") for name in services if name in names]
        plan = SourcePlan(list(plan.roots) + companions)
    materialized = materialize_source_plan(workload.key, workload.catalog_revision,
        workload.catalog_fingerprint(profile.package_family), profile.package_family, plan, universe,
        arch, lambda repo: getattr(repo, "source_tier", "base"))
    missing = [r.package for r in materialized.unresolved if not r.optional]
    skipped = [r.package for r in materialized.unresolved if r.optional]
    if missing:
        return {"status":"missing-required-roots", "missing":missing, "skipped_optional":skipped}
    requests = [(r.package, None, r.role, None, None, r.source_kind) for r in materialized.roots]
    backend = {"rpm":core,"deb":apt_core,"arch":arch_core}[profile.package_family]
    try:
        result = backend.resolve(requests, universe, arch,
            core.BuildOptions(optional_roots={r.package for r in materialized.roots if r.optional}), Reporter())
        return {"status":"blocked" if result.unresolved or result.conflicts else "ok",
                "skipped_optional":skipped, "selected":len(result.selected),
                "unresolved":[backend.format_requirement(r) for r in result.unresolved],
                "conflicts":result.conflicts, "installation_roots":installation_roots(result, profile.package_family),
                "validation_scope":"forward-closure; target native validation still required"}
    except RuntimeError as exc:
        return {"status":"resolution-error", "error":str(exc), "skipped_optional":skipped}



def discover_current_release(profile, reporter: Reporter) -> str:
    """Resolve the newest live release without consulting compiled version lists."""
    if profile.package_family == "arch":
        return "rolling"
    if profile.package_family == "deb":
        root = (getattr(profile, "archive_discovery_url", "") or "").strip()
        discovered = profiles_module.discover_apt_releases(root, reporter) if root else {}
        if not discovered:
            raise RuntimeError(f"{profile.key}: live APT release discovery returned no releases")
        profile.release_codenames.update(discovered)
        if profile.release_style == "codename":
            by_codename = {codename: version for version, codename in discovered.items()}
            return max(set(discovered.values()),
                       key=lambda name: profiles_module.version_key(by_codename.get(name, "0")))
        versions = [v for v in discovered if "." in v]
        if not versions:
            raise RuntimeError(f"{profile.key}: archive supplied no numbered release")
        return max(versions, key=profiles_module.version_key)
    if not profile.release_url:
        raise RuntimeError(f"{profile.key}: no live release discovery endpoint configured")
    text = fetch_text(profile.release_url, reporter)
    releases = profiles_module.extract_versions(text, profile.release_pattern, profile.release_mode)
    if not releases:
        raise RuntimeError(f"{profile.key}: live release listing contained no matching releases")
    return releases[0]

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profiles", default="")
    parser.add_argument("--out", default="workload-matrix-report.json")
    parser.add_argument("--include-rhel", action="store_true")
    args = parser.parse_args()

    catalog = workloads_module.load_workloads()
    wanted = [k.strip() for k in args.profiles.split(",") if k.strip()] or [
        k for k in profiles_module.PROFILES
        if not k.startswith("custom-") and (args.include_rhel or k != "rhel")]

    report, failures = {}, 0
    for key in wanted:
        profile = profiles_module.PROFILES[key]
        arch = "x86_64" if "x86_64" in profile.arches else profile.arches[0]
        reporter = Reporter()
        try:
            release = discover_current_release(profile, reporter)
        except Exception as exc:
            report[key] = {"error": f"release discovery failed: {exc}",
                           "warnings": reporter.warnings}
            failures += 1
            print(f"== {key}: RELEASE DISCOVERY FAILED: {exc}", flush=True)
            continue
        print(f"== {key} ({release}/{arch})", flush=True)
        packages, repo_errors = load_universe(profile, release, arch, reporter)
        if repo_errors:
            report[key] = {"error": "one or more enabled repositories failed to load",
                           "repository_errors": repo_errors, "warnings": reporter.warnings}
            failures += 1
            print(f"   REPOSITORY LOAD FAILED: {len(repo_errors)} enabled source(s)", flush=True)
            continue
        if not packages:
            report[key] = {"error": "no repository metadata loaded", "warnings": reporter.warnings}
            failures += 1
            continue
        entry = {}
        for wkey, workload in catalog.items():
            if workload.custom:
                continue
            if workload.supported_distros is not None and key not in workload.supported_distros:
                continue
            for init in (profile.init_systems or [""]):
                outcome = check_workload(workload, profile, packages, arch, init)
                entry[f"{wkey}/{init or 'default'}"] = outcome
                if outcome["status"] != "ok":
                    failures += 1
                    print(f"   BLOCKED {wkey}/{init}: {outcome}")
        report[key] = {"release":release,"architecture":arch,"workloads":entry}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print(f"\nReport written to {args.out}; {failures} failing combination(s).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
