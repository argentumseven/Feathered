from __future__ import annotations

import posixpath
import shutil
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

import artifact_digests
import provenance
from core_models import BuildOptions, ResolutionResult
from evidence_model import AUTH_UNKNOWN, vendor_display_name
from execution_reporter import Reporter
from publication_staging import abandon_staging, commit_staging, invalidate_bundle_seal, open_staging

SEAL_PHASE_START = 0.8


def meta_dict_list(metadata: Dict[str, object], key: str):
    value = metadata.get(key, [])
    return [x for x in value if isinstance(x, dict)] if isinstance(value, (list, tuple)) else []


@dataclass(frozen=True)
class BundleServices:
    load_baseline: Callable
    split_against_baseline: Callable
    payload_filenames: Callable
    verify_package_artifact: Callable
    copy_or_download: Callable
    sha256_file: Callable
    repository_verification_strategy: Callable
    vendor_signature_settings: Callable
    emit_rpm_repository: Callable
    write_unified_mirror_records: Callable
    write_bundle_index: Callable
    trust_summary: Callable
    format_requirement: Callable
    merge_additive_manifest_rows: Callable
    redact_url: Callable
    url_join: Callable
    verifier_integrity_error: type[BaseException]

def write_vendor_key_manifest(metadata_dir: Path, entries) -> None:
    """Record which vendor keys the target must already trust.

    The installer refuses to import a key out of the bundle it is verifying, so
    the operator needs to know which keys to establish through their own
    channel. Signer text comes from the connected-side verification, which is
    the only place the identity behind the key id was actually observed.
    """
    rows: Dict[str, Tuple[str, str]] = {}
    for entry in entries or ():
        if entry.assurance != provenance.VERIFIED_VENDOR or not entry.signing_key_id:
            continue
        rows.setdefault(entry.signing_key_id, (entry.signer, entry.repository))
    if not rows:
        return
    lines = ["Vendor signing keys required on the target", "",
             "install-offline.sh enables gpgcheck and will refuse to run until these keys",
             "are present in the target rpm keyring. Import them from the target",
             "distribution's own material (for example /etc/pki/rpm-gpg) or another",
             "trusted channel. Do not import a key carried by this bundle: it could only",
             "vouch for the bundle that carried it.", ""]
    for key_id, (signer, repo) in sorted(rows.items()):
        short = "".join(c for c in key_id if c in "0123456789abcdefABCDEF")[-8:].lower()
        lines.append(f"  key {key_id}  (rpm: gpg-pubkey-{short})")
        lines.append(f"    signer:     {signer or 'not reported by the verifier'}")
        lines.append(f"    repository: {repo}")
    (Path(metadata_dir) / "VENDOR-SIGNING-KEYS.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


def _write_provenance(bundle_dir: Path, metadata_dir: Path, entries, already_present, options: BuildOptions,
                      reporter: Reporter, metadata: Dict[str, object]) -> None:
    """Emit payload-scoped provenance beside the package artifacts.

    ``bundle_dir`` keeps the stable bundle identity while ``metadata_dir`` is the
    package-family directory (rpms/, debs/, or packages/) that owns these records.
    """
    record = provenance.build_provenance(
        bundle_id=bundle_dir.name,
        target={k: str(v) for k, v in metadata.items()
                if k in {"distribution", "release", "codename", "arch", "package_family",
                         "dependency_mode", "workload", "acquisition_intent",
                         "acquisition_capability", "analysis_type", "publication_type",
                         "verification_scope", "dependency_completeness"}},
        repositories=meta_dict_list(metadata, "repositories"),
        entries=entries,
        warnings=list(reporter.warnings),
    )
    if options.additive_publish and (metadata_dir / "provenance.json").is_file():
        record = provenance.merge_previous_provenance(record, metadata_dir / "provenance.json")
    if already_present:
        record.warnings.append(
            f"Differential bundle: {len(already_present)} package(s) were omitted because the "
            "baseline manifest reports them already present on the target. This bundle is not "
            "self-contained.")
        (metadata_dir / "baseline-omitted.txt").write_text(
            "\n".join(sorted(getattr(p, "nevra", p.name) for p in already_present)) + "\n",
            encoding="utf-8")
    (metadata_dir / "provenance.json").write_text(record.to_json(), encoding="utf-8")
    _write_assurance_legend(metadata_dir, record)
    counts = ", ".join(f"{v} {k}" for k, v in sorted(record.summary().items()))
    reporter.log(f"Provenance recorded: {counts or 'no packages'}")
    if options.signing_key:
        provenance.sign_bundle(metadata_dir / "manifest.json", options.signing_key, reporter)
        provenance.sign_bundle(metadata_dir / "provenance.json", options.signing_key, reporter)


def _write_assurance_legend(metadata_dir: Path, record) -> None:
    """Emit ASSURANCE.txt beside the bundle.

    provenance.json already carries the legend, but the person who has to act on
    it is on the far side of an air gap, often reading files on a console with
    no JSON tooling and no access to Feathered's documentation. The mode names
    are short enough to invite a strength ordering they do not carry -- most
    importantly, "independent-peer-corroboration" reads as stronger than
    "digest-only" and is weaker than a signature or a byte match. Spell it out
    where they will actually see it.
    """
    counts = dict(record.summary())
    for mode, value in record.mode_summary().items():
        counts.setdefault(mode, value)
    rows = provenance.assurance_legend(list(counts))
    if not rows:
        return
    lines = [
        "FEATHERED BUNDLE ASSURANCE LEGEND",
        "",
        "What Feathered proved about the artifacts in this bundle, strongest first.",
        "Counts are the number of packages recording that mode; one package can",
        "record several, because provenance is multi-axis rather than a single tier.",
        "",
        "Read 'DOES NOT PROVE' before relying on any row. A stronger-sounding name",
        "does not mean a stronger guarantee; the rank below is the ordering.",
        "",
    ]
    for row in rows:
        count = counts.get(row["mode"], 0)
        lines.append(f"[rank {row['rank']:3d}] {row['label']}  ({row['mode']})")
        lines.append(f"    packages       : {count}")
        lines.append(f"    authority      : {row['authority']}")
        lines.append(f"    proves         : {row['proves']}")
        lines.append(f"    does not prove : {row['does_not_prove']}")
        lines.append("")
    lines.append("Full per-package detail is in provenance.json.")
    (metadata_dir / "ASSURANCE.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_bundle_archive(bundle_dir: Path, reporter: Optional[Reporter] = None) -> Path:
    """Create a portable ZIP containing the complete generated bundle directory."""
    bundle_dir = bundle_dir.resolve()
    if not bundle_dir.is_dir():
        raise RuntimeError(f"Bundle directory does not exist: {bundle_dir}")
    archive = bundle_dir.with_suffix(".zip")
    rep = reporter or Reporter()
    rep.log(f"PACK {archive.name}")
    made = shutil.make_archive(
        str(bundle_dir), "zip",
        root_dir=str(bundle_dir.parent),
        base_dir=bundle_dir.name,
    )
    return Path(made)


def write_bundle(result: ResolutionResult, output_dir: Path, options: BuildOptions, reporter: Reporter,
                 metadata: Dict[str, object], services: BundleServices) -> Path:
    # Build beside the destination and publish only on success, so a failed or
    # interrupted run cannot leave something that looks like a finished bundle.
    # Transfer occupies the first part of the bar when sealing will follow it.
    reporter.phase(0.0, SEAL_PHASE_START if options.sign_bundle_index else 1.0)
    final_dir = output_dir
    output_dir = open_staging(final_dir, reporter)
    output_dir.mkdir(parents=True, exist_ok=True)
    if not options.sign_bundle_index:
        invalidate_bundle_seal(output_dir, reporter)
    try:
        with artifact_digests.digest_scope():
            return _write_bundle_body(result, output_dir, final_dir, options, reporter, metadata, services)
    except BaseException:
        # Anything short of success leaves the previous bundle untouched and
        # removes the half-built one, so nothing can be mistaken for finished.
        abandon_staging(output_dir, reporter)
        raise


def _write_bundle_body(result: ResolutionResult, output_dir: Path, final_dir: Path, options: BuildOptions,
                       reporter: Reporter, metadata: Dict[str, object], services: BundleServices) -> Path:
    load_baseline = services.load_baseline
    split_against_baseline = services.split_against_baseline
    payload_filenames = services.payload_filenames
    verify_package_artifact = services.verify_package_artifact
    _copy_or_download = services.copy_or_download
    sha256_file = services.sha256_file
    repository_verification_strategy = services.repository_verification_strategy
    vendor_signature_settings = services.vendor_signature_settings
    emit_rpm_repository = services.emit_rpm_repository
    write_unified_mirror_records = services.write_unified_mirror_records
    write_bundle_index = services.write_bundle_index
    _trust_summary = services.trust_summary
    format_requirement = services.format_requirement
    merge_additive_manifest_rows = services.merge_additive_manifest_rows
    redact_url = services.redact_url
    url_join = services.url_join
    VerifierIntegrityError = services.verifier_integrity_error
    rpm_dir = output_dir / "rpms"
    rpm_dir.mkdir(exist_ok=True)
    metadata_dir = rpm_dir  # Payload-scoped records travel with this RPM set.
    from transaction_model import validate_retained_payloads, write_installation_contract, installation_roots
    validate_retained_payloads(metadata_dir, result.selected, 'rpm', reporter, options)

    # Keep rebuilt bundles deterministic. If the same output folder was used
    # for an earlier analysis/build with a different closure, remove RPMs that
    # are no longer part of the current result before writing checksums/ZIPs.
    # Differential bundles: drop anything the baseline says the target already has.
    baseline = load_baseline(options.baseline_manifest, reporter)
    to_ship, already_present = split_against_baseline(result.selected, baseline, reporter)
    # detect payload basename collisions before transfer
    # instead of allowing the later package to overwrite the earlier one.
    filename_map = payload_filenames(to_ship, ".rpm")

    # Existing payloads in staging are retained as an addendum. Same-name
    # artifacts may still be verified and overwritten below, but unrelated
    # packages are never pruned from a previously populated output folder.

    from bundle_writer import acquire_payloads, write_records
    from package_family import RPM
    acquire_payloads(
        to_ship, filename_map, rpm_dir, final_dir.parent, options, reporter, RPM,
        verify=lambda pkg, dest: verify_package_artifact(pkg, dest, options, reporter),
        download=lambda pkg, dest: _copy_or_download(pkg, dest, options, reporter),
    )

    manifest = []
    shipped_ids = {id(p) for p in to_ship}
    for p in result.selected:
        # record the actual shipped SHA-256 plus the upstream source
        # digest used for pre-download differential comparison.
        filename = filename_map.get(id(p), posixpath.basename(urllib.parse.urlparse(p.location).path))
        dest = rpm_dir / filename
        record = getattr(p, "verification", None)
        manifest.append({
            "nevra": p.nevra, "package_id": p.nevra, "name": p.name, "arch": p.arch,
            "version": p.version, "release": p.release, "source_rpm": getattr(p, "source_rpm", ""), "filename": filename,
            "sha256": artifact_digests.payload_sha256(dest, sha256_file) if id(p) in shipped_ids and dest.exists() else "",
            "source_digest_type": p.checksum_type or "", "source_digest": p.checksum or "",
            "repo": p.repo.name, "repo_url": redact_url(p.repo.normalized_url),
            "source": redact_url(url_join(p.repo.normalized_url, p.location, p.repo)), "size": p.size,
            "reason": result.reasons.get(p.nevra, "dependency"),
            "shipped": id(p) in shipped_ids,
            "evidence_status": getattr(record, "evidence_status", "not-configured"),
            "evidence_source": getattr(record, "evidence_source", ""),
            "evidence_digest_type": getattr(record, "evidence_digest_type", ""),
            "evidence_digest": getattr(record, "evidence_digest", ""),
            "evidence_relationship": getattr(record, "evidence_relationship", ""),
            "evidence_authority_relationship": getattr(record, "evidence_authority_relationship", AUTH_UNKNOWN),
            "evidence_peer_identity_match": bool(getattr(record, "evidence_peer_identity_match", False)),
            "evidence_source_lineage_match": bool(getattr(record, "evidence_source_lineage_match", False)),
            "evidence_peer_package_id": getattr(record, "evidence_peer_package_id", ""),
            "evidence_peer_source_rpm": getattr(record, "evidence_peer_source_rpm", ""),
        })
    if options.additive_publish:
        manifest = merge_additive_manifest_rows(metadata_dir / "manifest.json", manifest)
    payload_files = list(rpm_dir.glob("*.rpm"))
    payload = {
        "metadata": metadata,
        "summary": {
            # Bundle-local values describe bytes actually present in rpms/.
            "package_count": len(payload_files) if options.additive_publish else len(to_ship),
            "total_size": (sum(p.stat().st_size for p in payload_files) if options.additive_publish
                           else sum(int(getattr(p, "size", 0) or 0) for p in to_ship)),
            "resolved_package_count": len(result.selected),
            "resolved_total_size": result.total_size,
            "baseline_omitted_count": len(already_present),
            "unresolved_count": len(result.unresolved),
            "ignored_unresolved_count": len(getattr(result, "ignored_unresolved", []) or []),
            "conflict_count": len(result.conflicts),
            "dependency_completeness": metadata.get("dependency_completeness", "analyzed"),
        },
        "packages": manifest,
    }
    write_records(
        metadata_dir, rpm_dir, RPM, payload, manifest,
        unresolved=(format_requirement(req) for req in result.unresolved),
        ignored_unresolved=result.ignored_unresolved,
        conflicts=result.conflicts, skipped_installed=result.skipped_installed,
        installed_satisfied=result.installed_satisfied, hash_file=sha256_file,
    )


    # ---- Provenance -------------------------------------------------------
    # Record, per artifact, exactly what was proven about it. RPMs carry their
    # own vendor signature, so this is the strongest assurance Feathered can
    # report; when a vendor keyring is configured it is enforced here.
    prov_entries = []
    for pkg in to_ship:
        archive_trust = getattr(pkg.repo, "trust", None)
        filename = filename_map[id(pkg)]
        dest = rpm_dir / filename
        entry = provenance.PackageProvenance(
            package_id=pkg.nevra, filename=filename,
            sha256=artifact_digests.payload_sha256(dest, sha256_file) if dest.exists() else "",
            size=dest.stat().st_size if dest.exists() else 0,
            source_url=redact_url(url_join(pkg.repo.normalized_url, pkg.location, pkg.repo)),
            repository=pkg.repo.name,
            # Recorded verification, not inferred from configuration: a
            # keyring being set says an operator intended verification, not
            # that a signature was checked or that it passed.
            index_digest_verified=bool(getattr(pkg, "verification", None)
                                       and pkg.verification.index_digest_verified),
            archive_signature_verified=bool(
                archive_trust and archive_trust.archive_signature_verified),
            # source-bond facts are recorded separately from the
            # acquisition archive's trust chain.
            evidence_status=getattr(getattr(pkg, "verification", None), "evidence_status", "not-configured"),
            evidence_source=getattr(getattr(pkg, "verification", None), "evidence_source", ""),
            evidence_digest_type=getattr(getattr(pkg, "verification", None), "evidence_digest_type", ""),
            evidence_digest=getattr(getattr(pkg, "verification", None), "evidence_digest", ""),
            evidence_digest_checked=bool(getattr(pkg, "verification", None)
                                         and pkg.verification.evidence_digest_checked),
            evidence_metadata_match=bool(getattr(pkg, "verification", None)
                                         and pkg.verification.evidence_metadata_match),
            evidence_artifact_checked=bool(getattr(pkg, "verification", None)
                                           and pkg.verification.evidence_artifact_checked),
            evidence_artifact_digest_type=getattr(getattr(pkg, "verification", None), "evidence_artifact_digest_type", ""),
            evidence_artifact_digest=getattr(getattr(pkg, "verification", None), "evidence_artifact_digest", ""),
            evidence_artifact_size=int(getattr(getattr(pkg, "verification", None), "evidence_artifact_size", 0) or 0),
            evidence_archive_signature_verified=bool(getattr(pkg, "verification", None)
                                                      and pkg.verification.evidence_archive_signature_verified),
            evidence_relationship=getattr(getattr(pkg, "verification", None), "evidence_relationship", ""),
            evidence_authority_relationship=getattr(getattr(pkg, "verification", None), "evidence_authority_relationship", AUTH_UNKNOWN),
            evidence_peer_identity_match=bool(getattr(pkg, "verification", None)
                                              and pkg.verification.evidence_peer_identity_match),
            evidence_source_lineage_match=bool(getattr(pkg, "verification", None)
                                               and pkg.verification.evidence_source_lineage_match),
            evidence_peer_package_id=getattr(getattr(pkg, "verification", None), "evidence_peer_package_id", ""),
            evidence_peer_source_rpm=getattr(getattr(pkg, "verification", None), "evidence_peer_source_rpm", ""),
        )
        if repository_verification_strategy(pkg.repo) == "skip-provenance":
            entry.notes.append("Upstream vendor-signature verification intentionally skipped by operator policy.")
            entry.digest_checked = False
            entry.assurance = provenance.assurance_from(entry)
        else:
            vendor_id, scoped_keyring, scoped_required = vendor_signature_settings(pkg.repo, options)
            if scoped_keyring and dest.exists():
                try:
                    detail = provenance.verify_rpm_package(dest, scoped_keyring, reporter)
                    entry.assurance = provenance.VERIFIED_VENDOR
                    entry.signature_algorithm = detail.get("algorithm", "")
                    entry.signer = detail.get("signer", "")
                    entry.signing_key_id = detail.get("key_id", "")
                except VerifierIntegrityError:
                    # Never downgrade a compromised verifier to a package note.
                    # "This package is unsigned" and "this machine cannot be
                    # trusted to tell you whether it is signed" are not the
                    # same finding, and only the first one is waivable.
                    raise
                except RuntimeError as exc:
                    if scoped_required:
                        raise RuntimeError(
                            f"Vendor signature check failed for {vendor_display_name(vendor_id)} "
                            f"and signatures are required: {exc}") from exc
                    entry.notes.append(str(exc))
                    entry.assurance = provenance.assurance_from(entry)
                    reporter.warn(f"{filename}: {exc}")
            elif scoped_required:
                raise RuntimeError(
                    f"Vendor signatures are required for {vendor_display_name(vendor_id)}, "
                    "but no vendor package keyring is configured for that vendor.")
            else:
                if dest.exists():
                    entry.notes.append(provenance.rpm_signature_summary(dest))
                entry.digest_checked = bool(getattr(pkg, "verification", None)
                                            and pkg.verification.package_digest_checked)
                entry.assurance = provenance.assurance_from(entry)
        prov_entries.append(entry)
    if options.emit_repository:
        repo_packages = to_ship
        preserve_locations = False
        if options.additive_publish:
            from repository_tools import load_local_repository_packages
            _family, repo_packages = load_local_repository_packages(output_dir, "rpm")
            preserve_locations = True
            reporter.log(f"Regenerating RPM repository metadata over {len(repo_packages)} total package(s) in the additive folder.")
        emit_rpm_repository(output_dir, repo_packages, reporter,
                            preserve_package_locations=preserve_locations, supplemental_packages=result.selected)
    _write_provenance(output_dir, metadata_dir, prov_entries, already_present, options, reporter, metadata)

    package_only = bool(metadata.get("package_only_acquisition"))
    repository_mirror = bool(metadata.get("repository_mirror"))
    if package_only:
        warning = str(metadata.get("package_only_warning") or
                      "Dependencies were not derived for this package-only acquisition.")
        (metadata_dir / "PACKAGE-ONLY-WARNING.txt").write_text(
            "PACKAGE-ONLY ACQUISITION - NOT A COMPLETE OFFLINE INSTALLATION BUNDLE\n\n"
            + warning +
            "\n\nThe rpms/ directory contains only the requested root artifacts. "
            "Enable appropriate dependency-provider repositories and rebuild before treating "
            "this package set as install-complete.\n",
            encoding="utf-8")
    elif repository_mirror:
        (metadata_dir / "MIRROR-BUNDLE.txt").write_text(
            "REPOSITORY MIRROR - NO PACKAGE-ROOT TRANSACTION\n\n"
            "This output mirrors the selected repository population. Feathered did not derive a "
            "root-package dependency closure and intentionally did not generate install-offline.sh.\n\n"
            "Use USE-AS-REPOSITORY.txt to expose the generated local repository metadata to DNF/YUM. "
            "Package installation decisions remain the target package manager's responsibility.\n",
            encoding="utf-8")
    else:
        write_installation_contract(metadata_dir, result, 'rpm', metadata, already_present)
        roots = installation_roots(result, 'rpm')
        if roots:
            (metadata_dir / "REQUESTED-ROOTS.txt").write_text("\n".join(roots) + "\n", encoding="utf-8")
            if options.emit_repository:
                from installer import write_installer
                write_vendor_key_manifest(metadata_dir, prov_entries)
                write_installer(output_dir, metadata_dir, result, options, 'rpm', metadata,
                                provenance_entries=prov_entries)
            else:
                (output_dir / "INSTALL-OFFLINE-NOTE.txt").write_text(
                    "Enable local repository metadata to generate the offline installer.\n", encoding="utf-8")
    write_unified_mirror_records(output_dir, metadata_dir, options)
    if reporter.warnings:
        (metadata_dir / "trust-warnings.txt").write_text(
            "Conditions recorded while building this bundle. Review before installing.\n\n"
            + "\n".join(f"- {w}" for w in reporter.warnings) + "\n", encoding="utf-8")
    # Seal and publish. The index is computed from the finished files on disk,
    # so the operator signature attests to the bundle that actually exists.
    _write_workload_artifacts(output_dir, metadata_dir, metadata, result)
    if options.sign_bundle_index:
        # Sealing owns the last slice of the same bar the transfer advanced.
        reporter.phase(SEAL_PHASE_START, 1.0 - SEAL_PHASE_START)
        write_bundle_index(output_dir, reporter, {
            "tool": provenance._tool_identity(),
            # The published name, not the temporary staging directory.
            "bundle_id": final_dir.name,
            "target": {k: str(v) for k, v in metadata.items()
                       if k in {"distribution", "release", "arch", "workload"}},
            "trust": _trust_summary(to_ship),
        }, options.signing_key)
    return commit_staging(output_dir, final_dir, reporter)


def _write_workload_artifacts(output_dir, metadata_dir, metadata, result):
    data = metadata.get('kubernetes')
    if not data:
        return
    assurance = metadata_dir / 'ASSURANCE.txt'
    previous = assurance.read_text(encoding='utf-8') if assurance.exists() else ''
    lines = ['KUBERNETES WORKLOAD OBSERVATIONS', 'PROVES: ' + data['proves'],
             'DOES NOT PROVE: ' + data['does_not_prove'],
             'API server versions assumed: ' + str(data['apiserver_assumed']),
             'Advisories acknowledged: ' + str(data['advisories_acknowledged'])]
    lines += [f"{f['severity']}: {f['package']} {f['version']}: {f['message']}" for f in data['findings'] + data['platform_advisories']]
    assurance.write_text(previous + '\n' + '\n'.join(lines) + '\n', encoding='utf-8')
    if data.get('image_draft_context'):
        from kubernetes_workflow import WorkloadContext, write_image_draft
        write_image_draft(output_dir, WorkloadContext(**data['image_draft_context']), result)

