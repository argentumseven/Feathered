"""Verify every workload preset against every distribution's live repositories.

Repository contents and supported releases drift independently of Feathered.
This harness discovers each profile's current release from live upstream metadata,
loads the workload-scoped enabled repositories (network required), then checks every
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
    repo = RepoSpec(
        template.name, template.url, template.role, template.priority,
        enabled=template.enabled, target_release=template.target_release,
        repo_format=template.repo_format or ("apt" if family == "deb" else "rpm"),
        suite=getattr(template, "suite", ""), components=getattr(template, "components", ""),
        expected_release_version=getattr(template, "expected_release_version", ""),
        verification_strategy="skip-provenance", optional=getattr(template, "optional", False))
    repo.flat_repo = bool(getattr(template, "flat_repo", False))
    return repo


def _known_workload_roles(catalog) -> set[str]:
    return {role for workload in catalog.values()
            for role in workload.required_repository_roles()}


def _templates_for_workload(profile, release, arch, workload, templates,
                            known_roles, kubernetes_minor):
    """Use the same role boundary as the production repository planner.

    Unrelated vendor repositories must never participate in an OS workload.
    Dynamic Kubernetes sources require an explicit minor like the GUI does.
    """
    required = set(workload.source_plan(profile.package_family).required_roles)
    base = [t for t in templates if t.enabled and t.role not in known_roles]
    vendor = [t for t in templates if t.enabled and t.role in required]
    if "kubernetes" in required:
        if not kubernetes_minor:
            return base, ["Kubernetes minor must be provided with --kubernetes-minor"]
        from kubernetes_workflow import repository_template
        try:
            generated = repository_template(profile.package_family, kubernetes_minor)
        except ValueError as exc:
            return base, [str(exc)]
        # Explicit configured sources remain operator-owned, as in the GUI.
        if not any(t.role == "kubernetes" and t.url for t in vendor):
            vendor.append(generated)
    present = {t.role for t in vendor if t.url}
    missing = sorted(required - present)
    if missing:
        return base + vendor, [f"No configured workload repository for role: {role}"
                               for role in missing]
    return base + vendor, []


def _requires_operator_opt_in(workload, family, templates) -> bool:
    """An explicitly optional, disabled vendor source is not preset drift.

    Keep the preset available for an operator-provided compatible source,
    but never label an untested default repository as a passing matrix row.
    """
    required = set(workload.source_plan(family).required_roles)
    enabled = {t.role for t in templates if t.enabled and t.url}
    disabled_opt_in = {
        t.role for t in templates if not t.enabled and t.url and t.optional
    }
    return bool(required) and not (required & enabled) and required <= disabled_opt_in


def load_universe(profile, release: str, arch: str, reporter: Reporter,
                  templates=None, cache=None):
    """Load selected repositories; retain source identity across cached workloads."""
    packages = []
    repo_errors = []
    for template in (profile.repos_factory(release, arch) if templates is None else templates):
        if not template.enabled:
            continue
        repo = _repo_from_template(template, profile.package_family)
        repo.source_tier = ("workload" if repo.role in _known_workload_roles(
            workloads_module.load_workloads()) else "base")
        key = (repo.name, repo.repo_format, repo.url, repo.role, repo.priority,
               repo.suite, repo.components, arch, repo.flat_repo,
               repo.target_release, repo.expected_release_version)
        if cache is not None and key in cache:
            pkgs = cache[key]
            packages.extend(pkgs)
            continue
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
        if cache is not None:
            cache[key] = pkgs
        packages.extend(pkgs)
    return packages, repo_errors


def cached_rpm_index_builder():
    """Reuse an immutable RPM provider index across matrix workload closures.

    Every workload needs its own dependency transaction, but parsing the same
    large BaseOS universe into millions of ProviderMatch rows on every pass
    wastes time and memory. Only the most recent exact universe is cached;
    changing source packages or their order forces a new index.
    """
    last_identity = None
    last_index = None

    def build(packages, reporter=None):
        nonlocal last_identity, last_index
        identity = tuple(id(package) for package in packages)
        if last_index is None or identity != last_identity:
            last_index = core.build_provider_index(packages, reporter)
            last_identity = identity
        return last_index

    return build


def check_workload(workload, profile, packages, arch, init="", rpm_index_builder=None):
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
        options = core.BuildOptions(optional_roots={r.package for r in materialized.roots if r.optional})
        reporter = Reporter()
        if profile.package_family == "rpm" and rpm_index_builder is not None:
            from transaction_model import resolve_transaction
            import rpm_resolution

            def resolve_once(roots, rows, preferred_arch, opts, local_reporter):
                return rpm_resolution._resolve_once(
                    roots, rows, preferred_arch, opts, local_reporter,
                    build_provider_index_fn=rpm_index_builder)

            result = resolve_transaction(resolve_once, requests, universe, arch,
                                         options, reporter, "rpm")
        else:
            result = backend.resolve(requests, universe, arch, options, reporter)
        blocked = bool(result.unresolved or result.conflicts)
        outcome = {"status":"blocked" if blocked else "ok",
                "skipped_optional":skipped, "selected":len(result.selected),
                "unresolved":[backend.format_requirement(r) for r in result.unresolved],
                "unresolved_notes":result.unresolved_notes,
                "conflicts":result.conflicts, "installation_roots":installation_roots(result, profile.package_family),
                "validation_scope":"forward-closure; target native validation still required"}
        if blocked:
            # These are precise package identities on the failing branches,
            # not every package in the often-large selected closure.
            outcome["unresolved_participants"] = list(getattr(result, "unresolved_participants", ()))
            outcome["conflict_participants"] = list(getattr(result, "conflict_participants", ()))
        return outcome
    except RuntimeError as exc:
        return {"status":"resolution-error", "error":str(exc), "skipped_optional":skipped}



def discover_current_release(profile, reporter: Reporter) -> str:
    """Resolve the newest live release without consulting compiled version lists."""
    if profile.package_family == "arch":
        return "rolling"
    if profile.package_family == "deb":
        root = (getattr(profile, "archive_discovery_url", "") or "").strip()
        prerelease = set()
        discovered = profiles_module.discover_apt_releases(
            root, reporter, prerelease_out=prerelease) if root else {}
        if not discovered:
            raise RuntimeError(f"{profile.key}: live APT release discovery returned no releases")
        profile.release_codenames.update(discovered)
        profile.prerelease_versions = sorted(prerelease)
        discovered = {version: codename for version, codename in discovered.items()
                      if version not in prerelease and codename not in prerelease}
        if not discovered:
            raise RuntimeError(f"{profile.key}: archive supplied no stable release")
        if profile.key == "devuan" and profile.release_url:
            # The GUI discovers the Devuan->Debian vendor-suite relationship
            # from the release table before constructing optional Docker CE
            # rows. The live matrix must do likewise: the package archive only
            # provides Devuan codenames, and without this relationship the
            # disabled opt-in source disappears, falsely failing Docker.
            try:
                rows = profiles_module.extract_devuan_debian_suites(
                    fetch_text(profile.release_url, reporter))
                if rows:
                    profiles_module.DEVUAN_TO_DEBIAN.update(rows)
                else:
                    reporter.warn('Devuan/Debian vendor-suite relationship unavailable; optional Docker source cannot be classified.')
            except Exception as exc:
                reporter.warn(f'Devuan/Debian vendor-suite relationship discovery failed: {exc}')
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
    prerelease = profiles_module.extract_prerelease_versions(
        text, profile.release_pattern, profile.release_mode)
    releases = [release for release in releases if release not in prerelease]
    if not releases:
        raise RuntimeError(f"{profile.key}: live release listing contained no matching releases")
    return releases[0]

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profiles", default="")
    parser.add_argument("--out", default="workload-matrix-report.json")
    parser.add_argument("--include-rhel", action="store_true")
    parser.add_argument("--kubernetes-minor", default="",
                        help="Explicit community package-repository minor, e.g. 1.35")
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
        templates = list(profile.repos_factory(release, arch))
        known_roles = _known_workload_roles(catalog)
        cache = {}
        rpm_index_builder = cached_rpm_index_builder() if profile.package_family == "rpm" else None
        base_templates = [t for t in templates if t.enabled and t.role not in known_roles]
        base_packages, base_errors = load_universe(
            profile, release, arch, reporter, templates=base_templates, cache=cache)
        if base_errors:
            report[key] = {"error": "one or more base repositories failed to load",
                           "repository_errors": base_errors, "warnings": reporter.warnings}
            failures += 1
            print(f"   REPOSITORY LOAD FAILED: {len(base_errors)} base source(s)", flush=True)
            continue
        if not base_packages:
            report[key] = {"error": "no base repository metadata loaded", "warnings": reporter.warnings}
            failures += 1
            continue
        entry = {}
        for wkey, workload in catalog.items():
            if workload.custom:
                continue
            if not workload.supports_target(key, release):
                continue
            scoped_templates, source_errors = _templates_for_workload(
                profile, release, arch, workload, templates, known_roles,
                args.kubernetes_minor)
            workload_templates = [t for t in scoped_templates if t.role in known_roles]
            extra_packages, extra_errors = load_universe(
                profile, release, arch, reporter, templates=workload_templates, cache=cache)
            for init in (profile.init_systems or [""]):
                if source_errors and not extra_errors and _requires_operator_opt_in(
                        workload, profile.package_family, templates):
                    outcome = {"status": "operator-source-required",
                               "roles": workload.source_plan(profile.package_family).required_roles,
                               "note": "Optional vendor repository is disabled until operator opt-in"}
                elif source_errors or extra_errors:
                    outcome = {"status": "source-unavailable",
                               "errors": source_errors + extra_errors}
                else:
                    outcome = check_workload(
                        workload, profile, base_packages + extra_packages, arch, init,
                        rpm_index_builder=rpm_index_builder)
                entry[f"{wkey}/{init or 'default'}"] = outcome
                if outcome["status"] not in {"ok", "operator-source-required"}:
                    failures += 1
                    print(f"   BLOCKED {wkey}/{init}: {outcome}")
        report[key] = {"release":release,"architecture":arch,"workloads":entry}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print(f"\nReport written to {args.out}; {failures} failing combination(s).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
