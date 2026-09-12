"""Runtime transaction contracts shared by the GUI and package backends.

No distribution releases or package aliases belong here. Decisions depend on
the supplied request, repository metadata and captured installed state.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path


# Preserve the historical import paths for public callers and saved Python records.
from root_requests import RootRequest, normalize_requests  # noqa: F401


def architecture_eligible(architecture, target, family):
    independent = {"rpm": "noarch", "deb": "all", "apt": "all", "arch": "any", "pacman": "any"}
    return not target or architecture in {target, independent.get(family, "")}


def root_source_eligible(package, request):
    root = RootRequest.from_value(request)
    repo = package.repo
    return (not root.scope or root.scope != "distribution" or getattr(repo, "source_tier", "base") == "base") and (
        not root.role or repo.role == root.role) and (
        not root.source_identity or repo.source_identity == root.source_identity) and (
        root.source_identity or not root.repository or repo.name == root.repository) and (
        not root.architecture or package.arch == root.architecture)


def retained_inventory(original, selected, family):
    """Compatibility dispatch to the checked family-specific inventory policy."""
    from transaction_inventory import retained_rpm_inventory, retained_deb_inventory, retained_arch_inventory
    if family == "rpm":
        return retained_rpm_inventory(original, selected)
    if family == "deb":
        return retained_deb_inventory(original, selected)
    return retained_arch_inventory(original, selected)


def resolve_transaction(resolve_once, requests, packages, architecture, options, reporter, family):
    """Reconcile inventory and conditional requirements until state stabilizes.

    The backend remains responsible for family syntax and provider selection.
    Never report success from an intermediate, traversal-dependent state.
    """
    requests = normalize_requests(requests)
    full_upgrade = False
    if family == "arch":
        requests, full_upgrade = arch_upgrade_requests(requests, packages, architecture, options)
    if family == "rpm":
        from module_policy import filter_candidates
        packages = filter_candidates(packages, options.target_inventory, architecture)
    from transaction_resolution import TransactionContext, resolve_fixed_point

    def prepare_options(prior):
        opts = replace(options, target_inventory=retained_inventory(options.target_inventory, prior, family))
        opts._transaction_candidates = prior
        return opts

    def record_unresolved(result, requirement, label, reason):
        result.unresolved.append(requirement)
        result.unresolved_notes[label] = reason

    def finalize(result, roots):
        result.arch_full_upgrade = full_upgrade
        result.validation_scope = "captured-relationships" if getattr(options.target_inventory, "relationships_complete", False) else "forward-closure"
        result.target_inventory = options.target_inventory
        result.transaction_family = family
        result.root_contract = roots

    context = TransactionContext(
        resolve_once=lambda roots, rows, opts: resolve_once(roots, rows, architecture, opts, reporter),
        prepare_options=prepare_options,
        selected=lambda result: result.selected,
        retained_failures=lambda result: retained_failures(result, options.target_inventory, family, architecture),
        record_unresolved=record_unresolved,
        finalize=finalize,
        check_cancel=lambda: reporter.check_cancel(),
        max_resolution_passes=lambda: options.max_resolution_passes,
        include_dependencies=lambda: options.include_dependencies,
    )
    return resolve_fixed_point(context, requests, packages)


def installation_roots(result, family):
    """Only concrete resolved roots become native installation arguments."""
    rows = []
    for p in result.roots:
        if hasattr(result, "selected") and not any((q.nevra, q.repo.source_identity) == (p.nevra, p.repo.source_identity) for q in result.selected):
            raise RuntimeError(f"Resolved root {p.nevra} was excluded from the selected payload plan; rebuild its closure before generating an installer")
        if family == "rpm":
            argument = p.nevra
        elif family == "deb":
            argument = f"{p.name}:{p.arch}={p.version}"
        else:
            argument = f"{p.name}={p.version}"
        if any(c in argument for c in "\r\n\0") or argument.startswith("-"):
            raise RuntimeError("Unsafe resolved package identity in installer input")
        if argument not in rows:
            rows.append(argument)
    return rows


def write_installation_contract(directory, result, family, metadata, omitted=()):
    directory = Path(directory)
    contract = {
        "schema": 1, "family": family,
        "captured_target": dict(getattr(getattr(result, "target_inventory", None), "metadata", {})),
        "arch_full_upgrade": bool(getattr(result, "arch_full_upgrade", False)),
        "module_states": getattr(getattr(result, "target_inventory", None), "metadata", {}).get("module_states"),
        "target": {k: metadata.get(k, "") for k in ("distribution", "release", "arch")},
        "roots": [{"name": p.name, "version": p.evr_text, "architecture": p.arch,
                   "package_id": p.nevra, "source_identity": p.repo.source_identity} for p in result.roots],
        "native_arguments": installation_roots(result, family),
        "baseline_required": [{"name": p.name, "version": p.evr_text, "architecture": p.arch,
                              "package_id": p.nevra} for p in omitted],
        "selected": [{"name": p.name, "version": p.evr_text, "architecture": p.arch,
                      "package_id": p.nevra} for p in result.selected],
        "inventory": dict(getattr(getattr(result, "target_inventory", None), "packages", {}) or {})
                     if family == "arch" and getattr(result, "target_inventory", None) is not None else None,
    }
    (directory / "INSTALLATION-CONTRACT.json").write_text(json.dumps(contract, indent=2), encoding="utf-8")
    return contract


def validate_retained_payloads(directory, selected, family, reporter, options=None):
    """Bind inherited evidence to current bytes before publishing an addendum."""
    import core
    from urllib.parse import urlsplit
    directory = Path(directory)
    patterns = {"rpm": "*.rpm", "deb": "*.deb", "arch": "*.pkg.tar.*"}
    current = {Path(urlsplit(p.location).path).name for p in selected}
    retained = [p for p in directory.glob(patterns[family]) if p.name not in current and not p.name.endswith(".sig")]
    if not retained:
        return
    path = directory / "provenance.json"
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
        rows = {r["filename"]: r for r in previous["packages"]}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("Retained package payloads have no usable provenance. Use a fresh output folder or rebuild and verify these packages first.") from exc
    for payload in retained:
        reporter.check_cancel()
        row = rows.get(payload.name, {})
        if payload.is_symlink() or not payload.is_file():
            raise RuntimeError(f"Retained payload is not a regular file: {payload.name}")
        if row.get("package_id") in {p.nevra for p in selected}:
            raise RuntimeError(f"{payload.name}: retained artifact duplicates a selected package identity under a different filename. Use a fresh output folder to preserve exact source selection.")
        digest = str(row.get("sha256", ""))
        if not digest or core.sha256_file(payload) != digest:
            raise RuntimeError(f"Retained payload changed since its provenance was established: {payload.name}. Re-acquire it before additive publication.")
        if options is not None:
            if options.require_package_digests and not (row.get("digest_checked") or row.get("evidence_digest_checked")):
                raise RuntimeError(f"{payload.name}: retained evidence does not meet the current required-digest policy. Re-acquire this package.")
            vendor = core.infer_vendor_id(str(row.get("repository", "")), str(row.get("source_url", "")))
            if options.require_vendor_signatures or vendor in options.require_vendor_signatures_by_vendor:
                raise RuntimeError(f"{payload.name}: inherited signature evidence cannot establish trust under the current key policy. Include this package in the new acquisition so it is reverified.")
    reporter.log(f"Validated prior provenance against {len(retained)} retained payload(s).")


def arch_upgrade_requests(requests, packages, architecture, options):
    from transaction_inventory import arch_upgrade_requests as extend
    return extend(requests, packages, architecture, options)


def retained_failures(result, inventory, family, architecture):
    """Compatibility dispatch; each checked policy preserves its requirement type."""
    if not getattr(inventory, 'relationships_complete', False):
        return []
    from transaction_inventory import rpm_retained_failures, deb_retained_failures, arch_retained_failures
    if family == "rpm":
        return rpm_retained_failures(result.selected, inventory)
    if family == "deb":
        return deb_retained_failures(result.selected, inventory)
    return arch_retained_failures(result.selected, inventory)
