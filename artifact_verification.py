from __future__ import annotations

import hashlib
import hmac
import posixpath
import urllib.parse
import urllib.request
from dataclasses import replace
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import artifact_digests
from core_models import ArtifactVerification, BuildOptions, RepoTrust
from credential_redaction import redact_text, redact_url
from evidence_model import REL_EXACT_ARTIFACT, REL_REBUILD_PEER, AUTH_UNKNOWN, classify_relationship, infer_vendor_id
from execution_reporter import Reporter
from package_contracts import PackageArtifact
from repository_config import RepoSpec
from repository_paths import repo_relative_url
from runtime_limits import MAX_PACKAGE_DOWNLOAD_BYTES

STRONG_PACKAGE_HASHES = {"sha256", "sha384", "sha512"}
_DIGEST_STRENGTH_ORDER = ("sha512", "sha384", "sha256")

def normalized_hash_algorithm(value: str) -> str:
    algo = (value or "").strip().lower().replace("-", "")
    aliases = {"sha2": "sha256", "sha256sum": "sha256", "sha384sum": "sha384",
               "sha512sum": "sha512", "sha": "sha1"}
    return aliases.get(algo, algo)


def strong_package_digest(checksum_type: str, checksum: str) -> Optional[Tuple[str, str]]:
    algo = normalized_hash_algorithm(checksum_type)
    value = (checksum or "").strip().lower()
    if algo in STRONG_PACKAGE_HASHES and value:
        return algo, value
    return None


def normalized_digest_map(values: Optional[Dict[str, str]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for algo, value in (values or {}).items():
        norm = normalized_hash_algorithm(algo)
        text = str(value or "").strip().lower()
        if norm in STRONG_PACKAGE_HASHES and text:
            result[norm] = text
    return result


def select_digest_from_map(values: Optional[Dict[str, str]], preference: str = "auto")         -> Optional[Tuple[str, str]]:
    """Return the strongest published digest meeting the configured minimum.

    Explicit SHA choices are minimum-strength requirements. This keeps a
    mixed repository set coherent: a SHA-256 minimum accepts a source publishing
    SHA-512 without forcing every source to expose the identical field.
    """
    digests = normalized_digest_map(values)
    pref = normalized_hash_algorithm(preference or "auto")
    accepted: Tuple[str, ...]
    if pref == "auto":
        accepted = _DIGEST_STRENGTH_ORDER
    elif pref == "sha256":
        accepted = ("sha512", "sha384", "sha256")
    elif pref == "sha384":
        accepted = ("sha512", "sha384")
    elif pref == "sha512":
        accepted = ("sha512",)
    else:
        return None
    for algo in accepted:
        if algo in digests:
            return algo, digests[algo]
    return None


def vendor_signature_settings(repo: RepoSpec, options: BuildOptions) -> Tuple[str, str, bool]:
    """Return ``(vendor_id, keyring_path, required)`` for one RPM source.

    once a vendor-scoped mapping is
    supplied there is deliberately no global-key fallback.  This makes the
    isolation rule explicit and independently testable.
    """
    vendor_id = getattr(repo, "vendor_id", "") or infer_vendor_id(repo.name, repo.url)
    keyring = options.vendor_keyrings.get(vendor_id, "")
    required = vendor_id in options.require_vendor_signatures_by_vendor
    if not options.vendor_keyrings:
        keyring = keyring or options.vendor_keyring
        required = required or options.require_vendor_signatures
    return vendor_id, keyring, required


def repository_verification_strategy(repo: RepoSpec) -> str:
    """Return the verification strategy for a repository.

    Older RepoSpec instances may not have an explicit strategy. Infer their
    historical Required?/evidence combination so CLI callers and existing
    profiles remain compatible while the GUI uses the clearer strategy model.
    """
    explicit = (getattr(repo, "verification_strategy", "") or "").strip().lower()
    valid = {"checksum-required", "checksum-available", "evidence-fallback",
             "full-corroboration", "skip-provenance"}
    if explicit in valid:
        return explicit
    required = (getattr(repo, "digest_requirement", "preferred") or "preferred").strip().lower() == "required"
    evidence = (getattr(repo, "evidence_policy", "off") or "off").strip().lower()
    if required and evidence == "required":
        return "full-corroboration"
    if required:
        # Legacy required-checksum mode did not use evidence mirrors.
        return "checksum-required"
    if evidence == "fallback-required":
        return "evidence-fallback"
    if evidence == "required":
        return "legacy-evidence-required"
    if evidence == "fallback":
        return "legacy-fallback"
    if evidence == "best-effort":
        return "legacy-corroborate"
    return "checksum-available"


def package_digest_map(pkg: PackageArtifact) -> Dict[str, str]:
    digests = normalized_digest_map(getattr(pkg, "digests", None))
    legacy = strong_package_digest(getattr(pkg, "checksum_type", ""),
                                   getattr(pkg, "checksum", ""))
    if legacy:
        digests.setdefault(legacy[0], legacy[1])
    return digests


def selected_package_digest(pkg: PackageArtifact) -> Optional[Tuple[str, str]]:
    preference = getattr(getattr(pkg, "repo", None), "digest_preference", "auto")
    return select_digest_from_map(package_digest_map(pkg), preference)


def package_has_selected_digest(pkg: PackageArtifact) -> bool:
    return selected_package_digest(pkg) is not None


def mirrors_are_distinct(primary_url: str, evidence_url: str) -> Tuple[bool, str]:
    """Conservative endpoint-independence check for a source bond.

    Different hostnames are necessary, though not sufficient, evidence of an
    independent mirror operator.  Feathered records that limitation rather than
    claiming organizational independence it cannot prove from URLs alone.
    """
    a = urllib.parse.urlparse(primary_url)
    b = urllib.parse.urlparse(evidence_url)
    if not a.scheme or not b.scheme:
        return False, "both mirror URLs must be absolute"
    if a.scheme == "file" or b.scheme == "file":
        return False, "local file repositories are not independent network mirrors"
    if (a.hostname or "").lower() == (b.hostname or "").lower():
        return False, "same hostname"
    if primary_url.rstrip("/") == evidence_url.rstrip("/"):
        return False, "same repository endpoint"
    return True, "different hostnames"


def _artifact_verification(pkg: PackageArtifact) -> ArtifactVerification:
    record = getattr(pkg, "verification", None)
    if record is None:
        record = ArtifactVerification()
        setattr(pkg, "verification", record)
    return record


def evidence_relationship(primary_repo: RepoSpec, evidence_url: str) -> str:
    """Return the explicit evidence relationship selected for this endpoint.

    Profile/UI hints normally win. Impossible stale exact-mirror hints between
    distinct Enterprise Linux rebuild vendors are downgraded to semantic peers.
    Without a usable hint, Feathered falls back conservatively: known EL
    rebuild-family cross-vendor sources are semantic peers; arbitrary sources
    can prove only exact artifact equality.
    """
    hints = dict(getattr(primary_repo, "evidence_relationship_hints", {}) or {})
    hint = hints.get(str(evidence_url), "")
    return classify_relationship(primary_repo, evidence_url, hint=hint)


def evidence_authority_relationship(primary_repo: RepoSpec, evidence_url: str) -> str:
    return dict(getattr(primary_repo, "evidence_authority_hints", {}) or {}).get(
        str(evidence_url), AUTH_UNKNOWN)


def _rpm_source_lineage(source_rpm: str) -> Optional[Tuple[str, str, str]]:
    """Return conservative (source-name, version, release) lineage from SRPM name."""
    text = posixpath.basename(str(source_rpm or "").strip())
    if text.endswith(".src.rpm"):
        text = text[:-8]
    elif text.endswith(".nosrc.rpm"):
        text = text[:-10]
    else:
        return None
    parts = text.rsplit("-", 2)
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1], parts[2]


def independent_peer_packages_match(primary_pkg, evidence_pkg) -> Tuple[bool, str, bool]:
    """Compare semantic identity for independently rebuilt RPM packages.

    Returns (match, detail, source_lineage_match). Binary release strings and
    byte sizes are deliberately not required to match: rebuild distributions may
    legitimately produce different RPM payloads.
    """
    if evidence_pkg is None:
        return False, "peer does not publish the package", False
    fields = ("name", "arch", "epoch", "version")
    mismatches = [f for f in fields
                  if str(getattr(primary_pkg, f, "") or "") !=
                     str(getattr(evidence_pkg, f, "") or "")]
    if mismatches:
        return False, "peer differs in " + ", ".join(mismatches), False
    p_lineage = _rpm_source_lineage(getattr(primary_pkg, "source_rpm", ""))
    e_lineage = _rpm_source_lineage(getattr(evidence_pkg, "source_rpm", ""))
    if p_lineage and e_lineage:
        if p_lineage != e_lineage:
            return False, (f"source lineage differs: acquisition {p_lineage[0]}-{p_lineage[1]}-{p_lineage[2]} "
                           f"vs peer {e_lineage[0]}-{e_lineage[1]}-{e_lineage[2]}"), False
        return True, "package identity and source lineage agree", True
    # When source-RPM lineage is unavailable on either side, do not silently
    # weaken the comparison all the way to upstream version alone. Require the
    # binary package release to agree as a conservative fallback.
    if str(getattr(primary_pkg, "release", "") or "") != str(getattr(evidence_pkg, "release", "") or ""):
        return False, "source lineage is unavailable and package release differs", False
    return True, "package name/version/release/architecture agree; source lineage unavailable on one side", False


def find_independent_peer_package(primary_pkg, evidence_packages):
    """Find the best semantic peer without fuzzy package-name inference."""
    candidates = [p for p in evidence_packages
                  if getattr(p, "name", "") == getattr(primary_pkg, "name", "")
                  and getattr(p, "arch", "") == getattr(primary_pkg, "arch", "")
                  and str(getattr(p, "epoch", "") or "0") == str(getattr(primary_pkg, "epoch", "") or "0")
                  and getattr(p, "version", "") == getattr(primary_pkg, "version", "")]
    if not candidates:
        return None
    # Exact release is preferred when available, but not required for a rebuild peer.
    exact = [p for p in candidates if getattr(p, "release", "") == getattr(primary_pkg, "release", "")]
    return (exact or candidates)[0]


def evidence_repo_for_url(primary_repo: RepoSpec, evidence_url: str) -> RepoSpec:
    """Create a credential-isolated repository spec for an evidence endpoint."""
    evidence_repo = replace(
        primary_repo, name=f"{primary_repo.name} [evidence]", url=evidence_url, optional=True,
        client_cert="", client_key="", ca_cert="", keyring="",
        vendor_id=infer_vendor_id("", evidence_url),
        evidence_urls=[], evidence_suggestions=[], evidence_policy="off",
        verification_strategy="checksum-available")
    evidence_repo._evidence_distinct_from = primary_repo.normalized_url
    evidence_repo._evidence_distinct_effective_origins = set(
        getattr(primary_repo, "_effective_origins", set()) or set())
    evidence_repo._evidence_distinct_effective_hosts = set(
        getattr(primary_repo, "_effective_hosts", set()) or set())
    return evidence_repo


def evidence_artifact_candidates(evidence_url: str, package_location: str,
                                 evidence_location: str = "") -> List[str]:
    """Return deterministic exact-artifact URLs beneath an evidence endpoint.

    A direct package URL (.rpm/.deb/.pkg.tar.*) is accepted only when its basename matches the exact
    package basename. Otherwise Feathered preserves repository-relative layout; it
    never scrapes directories or guesses similar filenames.
    """
    base = (evidence_url or "").strip()
    if not base:
        return []
    primary_name = posixpath.basename(urllib.parse.urlsplit(package_location or "").path)
    evidence_name = posixpath.basename(urllib.parse.urlsplit(evidence_location or "").path)
    parsed = urllib.parse.urlsplit(base)
    direct_name = posixpath.basename(parsed.path)
    if direct_name.lower().endswith((".rpm", ".deb", ".pkg.tar.zst", ".pkg.tar.xz",
                                     ".pkg.tar.gz", ".pkg.tar.bz2", ".pkg.tar.lz4")):
        expected = evidence_name or primary_name
        return [base] if expected and direct_name == expected else []
    out: List[str] = []
    for location in (evidence_location, package_location):
        if not location:
            continue
        try:
            candidate = repo_relative_url(base, location)
        except RuntimeError:
            continue
        if candidate not in out:
            out.append(candidate)
    return out


def probe_evidence_artifact(url: str, repo: RepoSpec, reporter: Reporter, *, open_url_fn) -> Tuple[bool, str]:
    """Check that an exact evidence artifact is readable without downloading it all."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme == "file":
            local = Path(urllib.request.url2pathname(parsed.path))
            if not local.is_file():
                return False, f"Artifact file does not exist: {local}"
            if local.stat().st_size <= 0:
                return False, f"Artifact file is empty: {local.name}"
            return True, f"Artifact file is readable ({local.stat().st_size:,} bytes)"
        with open_url_fn(url, timeout=25, repo=repo) as response:
            sample = response.read(1)
            if not sample:
                return False, "Artifact endpoint returned an empty response"
            length = response.headers.get("Content-Length", "") if getattr(response, "headers", None) else ""
            detail = "Exact package artifact is readable"
            if str(length).isdigit():
                detail += f" ({int(length):,} bytes advertised)"
            return True, detail
    except Exception as exc:
        return False, redact_text(str(exc))


def _stream_hash_url(url: str, algorithms: Iterable[str], repo: RepoSpec,
                     reporter: Reporter,
                     max_bytes: int = MAX_PACKAGE_DOWNLOAD_BYTES, *, open_url_fn) -> Tuple[Dict[str, str], int]:
    algos = list(dict.fromkeys(normalized_hash_algorithm(a) for a in algorithms if a))
    if not algos:
        raise RuntimeError("No checksum algorithm was selected for independent evidence")
    hashers = {algo: hashlib.new(algo) for algo in algos}
    total = 0
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme == "file":
        stream = Path(urllib.request.url2pathname(parsed.path)).open("rb")
    else:
        stream = open_url_fn(url, timeout=90, repo=repo)
    try:
        if parsed.scheme != "file" and hasattr(stream, "headers"):
            declared = stream.headers.get("Content-Length")
            try:
                declared_size = int(declared) if declared is not None else None
            except (TypeError, ValueError):
                declared_size = None
            if declared_size is not None and declared_size > max_bytes:
                raise RuntimeError(
                    f"Artifact response is {declared_size:,} bytes, above Feathered's "
                    f"{max_bytes:,}-byte per-artifact limit")
        while True:
            reporter.check_cancel()
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError(
                    f"Artifact response exceeded Feathered's {max_bytes:,}-byte per-artifact limit")
            for hasher in hashers.values():
                hasher.update(chunk)
    finally:
        stream.close()
    return {algo: hasher.hexdigest().lower() for algo, hasher in hashers.items()}, total


def spot_compare_artifact_urls(acquisition_url: str, acquisition_repo: RepoSpec,
                               evidence_url: str, evidence_repo: RepoSpec,
                               checksum_policy: str, reporter: Reporter, *, open_url_fn) -> Tuple[bool, str]:
    """Hash one acquisition/evidence artifact pair without persisting either copy.

    This is a configuration spot test used by the GUI. It proves that the selected
    evidence endpoint can independently serve the same exact bytes for one
    representative artifact. It is deliberately not a substitute for the build-time
    per-package corroboration performed by ``_verify_independent_evidence_payload``.
    """
    policy = normalized_hash_algorithm(checksum_policy or "auto")
    algorithm = "sha512" if policy == "auto" else policy
    if algorithm not in STRONG_PACKAGE_HASHES:
        return False, f"Unsupported evidence checksum policy: {checksum_policy or 'unset'}"
    try:
        acquisition_hashes, acquisition_size = _stream_hash_url(
            acquisition_url, [algorithm], acquisition_repo, reporter, open_url_fn=open_url_fn)
    except Exception as exc:
        return False, "Could not hash the acquisition artifact: " + redact_text(str(exc))
    try:
        evidence_hashes, evidence_size = _stream_hash_url(
            evidence_url, [algorithm], evidence_repo, reporter, open_url_fn=open_url_fn)
    except Exception as exc:
        return False, "Could not hash the evidence artifact: " + redact_text(str(exc))
    if acquisition_size != evidence_size:
        return False, (
            f"Artifact size mismatch: acquisition is {acquisition_size:,} bytes and evidence is "
            f"{evidence_size:,} bytes")
    acquisition_digest = acquisition_hashes[algorithm]
    evidence_digest = evidence_hashes[algorithm]
    if not hmac.compare_digest(acquisition_digest, evidence_digest):
        return False, f"Artifact checksum mismatch under {algorithm.upper()}"
    return True, (
        f"Spot check passed: acquisition and evidence artifacts match under {algorithm.upper()} "
        f"({acquisition_size:,} bytes)")


def spot_compare_peer_artifact_urls(primary_pkg, acquisition_url: str, acquisition_repo: RepoSpec,
                                    evidence_pkg, evidence_url: str, evidence_repo: RepoSpec,
                                    checksum_policy: str, reporter: Reporter, *, open_url_fn) -> Tuple[bool, str]:
    """Spot-check an independent rebuild peer without requiring identical bytes.

    The two artifacts are independently hashed and, when their repositories
    publish usable strong digests, each artifact is checked against its own
    repository claim. The cross-source assertion is semantic identity/source
    lineage, not binary equality.
    """
    semantic_ok, semantic_detail, _lineage = independent_peer_packages_match(primary_pkg, evidence_pkg)
    if not semantic_ok:
        return False, "Independent peer disagreement: " + semantic_detail
    policy = normalized_hash_algorithm(checksum_policy or "auto")
    algorithm = "sha512" if policy == "auto" else policy
    if algorithm not in STRONG_PACKAGE_HASHES:
        return False, f"Unsupported evidence checksum policy: {checksum_policy or 'unset'}"
    primary_meta = selected_package_digest(primary_pkg)
    evidence_meta = selected_package_digest(evidence_pkg)
    algos = [algorithm]
    for item in (primary_meta, evidence_meta):
        if item and item[0] not in algos:
            algos.append(item[0])
    try:
        primary_hashes, primary_size = _stream_hash_url(acquisition_url, algos, acquisition_repo, reporter, open_url_fn=open_url_fn)
    except Exception as exc:
        return False, "Could not hash the acquisition artifact: " + redact_text(str(exc))
    try:
        evidence_hashes, evidence_size = _stream_hash_url(evidence_url, algos, evidence_repo, reporter, open_url_fn=open_url_fn)
    except Exception as exc:
        return False, "Could not hash the peer artifact: " + redact_text(str(exc))
    if primary_meta and not hmac.compare_digest(primary_hashes[primary_meta[0]], primary_meta[1].lower()):
        return False, f"Acquisition artifact does not match its published {primary_meta[0].upper()} checksum"
    if evidence_meta and not hmac.compare_digest(evidence_hashes[evidence_meta[0]], evidence_meta[1].lower()):
        return False, f"Peer artifact does not match its published {evidence_meta[0].upper()} checksum"
    binary_note = ("binary bytes also happen to match"
                   if primary_size == evidence_size and hmac.compare_digest(primary_hashes[algorithm], evidence_hashes[algorithm])
                   else "binary bytes differ, as permitted for an independent rebuild")
    own_checks = []
    if primary_meta:
        own_checks.append("acquisition digest verified")
    if evidence_meta:
        own_checks.append("peer digest verified")
    integrity = "; ".join(own_checks) if own_checks else "independent hashes calculated; no repository digest was available"
    return True, (f"Independent peer spot check passed: {semantic_detail}; {binary_note}. "
                  f"{integrity}. {algorithm.upper()} sizes: acquisition {primary_size:,} bytes, "
                  f"peer {evidence_size:,} bytes")


def _evidence_comparison_algorithm(pkg: PackageArtifact, primary: Optional[Tuple[str, str]]) -> str:
    if primary:
        return primary[0]
    preference = normalized_hash_algorithm(getattr(getattr(pkg, "repo", None), "digest_preference", "auto"))
    if preference in STRONG_PACKAGE_HASHES:
        return preference
    # Automatic evidence fallback must be deterministic even when acquisition
    # metadata publishes no usable checksum. Use the strongest supported SHA-2.
    return "sha512"


def _verify_independent_evidence_payload(pkg: PackageArtifact, acquisition_path: Path,
                                         primary: Optional[Tuple[str, str]],
                                         computed: Dict[str, str], reporter: Reporter, *,
                                         open_url_fn, hash_file_fn, mirrors_are_distinct_fn,
                                         evidence_relationship_fn, evidence_authority_relationship_fn) -> None:
    """Verify evidence according to the relationship to the acquisition source.

    Exact mirrors/artifact mirrors must reproduce identical bytes. Independent
    rebuild peers instead must publish a semantically corresponding package and
    the peer artifact must verify against the peer repository's own strong digest.
    """
    record = _artifact_verification(pkg)
    comparison_algo = _evidence_comparison_algorithm(pkg, primary)
    if comparison_algo not in computed:
        computed[comparison_algo] = hash_file_fn(acquisition_path, comparison_algo).lower()
    acquisition_digest = computed[comparison_algo]
    acquisition_size = acquisition_path.stat().st_size
    strategy = repository_verification_strategy(pkg.repo)
    errors: List[str] = []

    for evidence_url in list(getattr(pkg.repo, "evidence_urls", []) or []):
        distinct, reason = mirrors_are_distinct_fn(pkg.repo.normalized_url, evidence_url)
        if not distinct:
            errors.append(f"{redact_url(evidence_url)} ({reason})")
            continue
        relationship = evidence_relationship_fn(pkg.repo, evidence_url)
        authority = evidence_authority_relationship_fn(pkg.repo, evidence_url)
        evidence_repo = evidence_repo_for_url(pkg.repo, evidence_url)

        if relationship == REL_REBUILD_PEER:
            if strategy != "full-corroboration":
                errors.append(
                    f"{redact_url(evidence_url)} (independent rebuild peers cannot fill a missing "
                    "acquisition checksum; Enhanced requires an exact artifact mirror for that gap)")
                continue
            if not record.evidence_peer_identity_match or not record.evidence_location:
                errors.append(
                    f"{redact_url(evidence_url)} (peer metadata did not establish a matching package identity)")
                continue
            metadata_digest = strong_package_digest(record.evidence_digest_type, record.evidence_digest)
            if not metadata_digest:
                errors.append(
                    f"{redact_url(evidence_url)} (peer package publishes no strong checksum meeting the configured policy)")
                continue
            try:
                candidate = repo_relative_url(evidence_url, record.evidence_location)
            except Exception as exc:
                errors.append(f"{redact_url(evidence_url)} ({redact_text(str(exc))})")
                continue
            algorithms = [comparison_algo]
            if metadata_digest[0] not in algorithms:
                algorithms.append(metadata_digest[0])
            try:
                reporter.log(
                    f"EVIDENCE {getattr(pkg, 'nevra', getattr(pkg, 'name', 'package'))}: "
                    f"hashing independent rebuild peer artifact {redact_url(candidate)}")
                digests, size = _stream_hash_url(candidate, algorithms, evidence_repo, reporter, open_url_fn=open_url_fn)
            except Exception as exc:
                errors.append(f"{redact_url(candidate)} ({redact_text(str(exc))})")
                continue
            if not hmac.compare_digest(digests[metadata_digest[0]], metadata_digest[1].lower()):
                raise RuntimeError(
                    f"Independent peer evidence disagreement for {pkg.nevra}: the peer artifact "
                    f"does not match its published {metadata_digest[0].upper()} checksum")
            record.evidence_relationship = REL_REBUILD_PEER
            record.evidence_authority_relationship = authority
            record.evidence_digest_checked = True
            record.evidence_artifact_checked = True
            record.evidence_artifact_digest_type = comparison_algo
            record.evidence_artifact_digest = digests[comparison_algo]
            record.evidence_artifact_size = size
            record.evidence_status = "peer-corroborated"
            binary_same = (size == acquisition_size and
                           hmac.compare_digest(acquisition_digest, digests[comparison_algo]))
            record.notes.append(
                "Independent rebuild peer corroborated package identity"
                + (" and source lineage" if record.evidence_source_lineage_match else "")
                + "; peer artifact verified against its own repository digest; "
                + ("binary bytes also matched." if binary_same
                   else "binary bytes differed as permitted for a rebuild peer."))
            return

        metadata_digest = strong_package_digest(record.evidence_digest_type, record.evidence_digest)
        candidates = evidence_artifact_candidates(
            evidence_url, getattr(pkg, "location", ""), record.evidence_location)
        if not candidates:
            errors.append(f"{redact_url(evidence_url)} (no exact artifact path can be derived)")
            continue
        for candidate in candidates:
            algorithms = [comparison_algo]
            if metadata_digest and metadata_digest[0] not in algorithms:
                algorithms.append(metadata_digest[0])
            try:
                reporter.log(
                    f"EVIDENCE {getattr(pkg, 'nevra', getattr(pkg, 'name', 'package'))}: "
                    f"hashing independent artifact {redact_url(candidate)}")
                digests, size = _stream_hash_url(candidate, algorithms, evidence_repo, reporter, open_url_fn=open_url_fn)
            except Exception as exc:
                errors.append(f"{redact_url(candidate)} ({redact_text(str(exc))})")
                continue

            if size != acquisition_size:
                raise RuntimeError(
                    f"Independent evidence disagreement for {pkg.nevra}: acquisition artifact is "
                    f"{acquisition_size} bytes but {redact_url(candidate)} is {size} bytes")
            evidence_digest = digests[comparison_algo]
            if not hmac.compare_digest(acquisition_digest, evidence_digest):
                raise RuntimeError(
                    f"Independent evidence disagreement for {pkg.nevra}: acquisition and evidence "
                    f"artifacts have different {comparison_algo.upper()} checksums")
            if metadata_digest:
                actual_metadata_digest = digests[metadata_digest[0]]
                if not hmac.compare_digest(actual_metadata_digest, metadata_digest[1].lower()):
                    raise RuntimeError(
                        f"Independent evidence metadata disagreement for {pkg.nevra}: the evidence "
                        f"artifact does not match its published {metadata_digest[0].upper()} checksum")
                record.evidence_digest_checked = True

            record.evidence_relationship = relationship
            record.evidence_authority_relationship = authority
            record.evidence_source = redact_url(evidence_url)
            record.evidence_artifact_checked = True
            record.evidence_artifact_digest_type = comparison_algo
            record.evidence_artifact_digest = evidence_digest
            record.evidence_artifact_size = size
            record.evidence_status = ("digest-corroborated" if record.evidence_digest_checked
                                      else "artifact-corroborated")
            record.notes.append(
                f"Independent artifact matched acquisition bytes using {comparison_algo.upper()}.")
            return

    detail = "; ".join(errors[-3:])
    raise RuntimeError(
        f"{pkg.nevra}: no configured independent evidence source could satisfy the selected evidence policy"
        + (f" ({detail})" if detail else ""))


def apply_mirror_evidence(primary_packages, evidence_packages, evidence_repo: RepoSpec,
                          reporter: Reporter, relationship: str = REL_EXACT_ARTIFACT,
                          authority: str = AUTH_UNKNOWN) -> Dict[str, int]:
    """Attach evidence metadata without treating repository-wide skew as a build failure.

    Evidence repository metadata is a locator/index aid. Live mirrors are not atomic
    snapshots of one another, so an unrelated package that is missing or temporarily
    divergent must not abort metadata loading for the package transaction being built.
    Conflicts are recorded per package and decisive enforcement happens when the
    selected artifact is actually verified. That preserves strict byte equality for
    exact mirrors while avoiding false global failures during mirror synchronization.
    """
    stats = {"matched": 0, "digest": 0, "metadata": 0, "missing": 0,
             "peer": 0, "conflict": 0}
    if relationship == REL_REBUILD_PEER:
        for pkg in primary_packages:
            record = _artifact_verification(pkg)
            other = find_independent_peer_package(pkg, evidence_packages)
            if other is None:
                if record.evidence_status in {"not-configured", "unavailable"}:
                    record.evidence_status = "inconclusive"
                stats["missing"] += 1
                continue
            ok, detail, lineage_match = independent_peer_packages_match(pkg, other)
            record.evidence_relationship = REL_REBUILD_PEER
            record.evidence_authority_relationship = authority
            record.evidence_source = redact_url(evidence_repo.normalized_url)
            record.evidence_location = str(getattr(other, "location", "") or "")
            record.evidence_peer_package_id = getattr(other, "nevra", "")
            record.evidence_peer_source_rpm = str(getattr(other, "source_rpm", "") or "")
            evidence_digest = selected_package_digest(other)
            if evidence_digest:
                record.evidence_digest_type, record.evidence_digest = evidence_digest
            if not ok:
                record.evidence_status = "metadata-conflict"
                record.evidence_metadata_match = False
                record.notes.append("Independent rebuild-peer metadata conflict deferred to selected-package verification: " + detail + ".")
                stats["conflict"] += 1
                continue
            record.evidence_peer_identity_match = True
            record.evidence_source_lineage_match = lineage_match
            record.evidence_metadata_match = True
            evidence_trust: Optional[RepoTrust] = getattr(evidence_repo, "trust", None)
            record.evidence_archive_signature_verified = bool(
                evidence_trust and evidence_trust.archive_signature_verified)
            if evidence_digest:
                stats["digest"] += 1
            else:
                stats["metadata"] += 1
            record.evidence_status = "peer-metadata-corroborated"
            record.notes.append("Independent rebuild peer: " + detail + ".")
            stats["matched"] += 1
            stats["peer"] += 1
        return stats

    by_id = {getattr(p, "nevra", ""): p for p in evidence_packages}
    for pkg in primary_packages:
        record = _artifact_verification(pkg)
        other = by_id.get(getattr(pkg, "nevra", ""))
        if other is None:
            if record.evidence_status in {"not-configured", "unavailable"}:
                record.evidence_status = "inconclusive"
            stats["missing"] += 1
            continue

        record.evidence_relationship = relationship
        record.evidence_authority_relationship = authority
        record.evidence_source = redact_url(evidence_repo.normalized_url)
        record.evidence_location = str(getattr(other, "location", "") or "")
        evidence_trust = getattr(evidence_repo, "trust", None)
        record.evidence_archive_signature_verified = bool(
            evidence_trust and evidence_trust.archive_signature_verified)
        evidence_digest = selected_package_digest(other)
        if evidence_digest:
            record.evidence_digest_type, record.evidence_digest = evidence_digest

        conflicts = []
        psize = int(getattr(pkg, "size", 0) or 0)
        esize = int(getattr(other, "size", 0) or 0)
        if psize and esize and psize != esize:
            conflicts.append(f"size differs ({psize} vs {esize} bytes)")

        p_algo = normalized_hash_algorithm(getattr(pkg, "checksum_type", ""))
        e_algo = normalized_hash_algorithm(getattr(other, "checksum_type", ""))
        p_raw = str(getattr(pkg, "checksum", "") or "").strip().lower()
        e_raw = str(getattr(other, "checksum", "") or "").strip().lower()
        if p_algo and e_algo and p_algo == e_algo and p_raw and e_raw                 and not hmac.compare_digest(p_raw, e_raw):
            conflicts.append(f"published {p_algo.upper()} differs")

        p_strong = package_digest_map(pkg)
        e_strong = package_digest_map(other)
        for shared_algo in sorted(set(p_strong) & set(e_strong)):
            if not hmac.compare_digest(p_strong[shared_algo], e_strong[shared_algo]):
                conflicts.append(f"published {shared_algo.upper()} differs")
                break

        primary_digest = selected_package_digest(pkg)
        if primary_digest and evidence_digest and primary_digest[0] == evidence_digest[0]                 and not hmac.compare_digest(primary_digest[1], evidence_digest[1]):
            detail = f"selected {primary_digest[0].upper()} differs"
            if detail not in conflicts:
                conflicts.append(detail)

        if conflicts:
            record.evidence_status = "metadata-conflict"
            record.evidence_metadata_match = False
            record.notes.append(
                "Exact-mirror metadata conflict deferred to selected-package artifact verification: "
                + "; ".join(conflicts) + ".")
            stats["conflict"] += 1
            continue

        record.evidence_metadata_match = True
        stats["matched"] += 1
        if primary_digest and evidence_digest:
            record.evidence_status = "digest-corroborated"
            stats["digest"] += 1
        elif evidence_digest:
            record.evidence_status = "independent-digest"
            stats["digest"] += 1
        else:
            record.evidence_status = "metadata-corroborated"
            stats["metadata"] += 1
    return stats


def verify_package_artifact(
    pkg: PackageArtifact,
    path: Path,
    options: BuildOptions,
    reporter: Reporter,
    *,
    hash_file_fn: Callable[[Path, str], str],
    verify_independent_fn: Callable[[PackageArtifact, Path, Optional[Tuple[str, str]], Dict[str, str], Reporter], None],
) -> bool:
    """Verify one cached or freshly transferred package under its strategy.

    Enhanced and Maximum treat independent evidence as an independently
    retrieved exact package artifact, not merely a second metadata claim.
    Evidence-repository metadata remains useful extra provenance when present,
    but an artifact-only mirror can still corroborate bytes.
    """
    before = artifact_digests.begin_verification(path)
    record = _artifact_verification(pkg)
    strategy = repository_verification_strategy(pkg.repo)
    primary = selected_package_digest(pkg)
    evidence = strong_package_digest(record.evidence_digest_type, record.evidence_digest)

    if strategy == "skip-provenance":
        record.notes.append("Upstream package provenance checks intentionally skipped by operator policy.")
        record.evidence_status = "skipped"
        return False

    if strategy == "full-corroboration" and not options.verify_checksums:
        raise RuntimeError(f"{pkg.nevra}: full corroboration requires acquisition checksum verification")

    checks: List[Tuple[str, str, str]] = []
    artifact_evidence_required = False

    if strategy == "checksum-required":
        if not options.verify_checksums:
            raise RuntimeError(f"{pkg.nevra}: checksum-required strategy cannot run with checksum verification disabled")
        if not primary:
            raise RuntimeError(
                f"{pkg.nevra}: acquisition metadata does not publish a checksum meeting "
                f"the configured minimum {getattr(pkg.repo, 'digest_preference', 'auto').upper()}")
        checks.append((primary[0], primary[1], "acquisition metadata"))

    elif strategy == "checksum-available":
        if options.verify_checksums and primary:
            checks.append((primary[0], primary[1], "acquisition metadata"))

    elif strategy == "evidence-fallback":
        if options.verify_checksums and primary:
            # Enhanced is a gap-filling policy. A qualifying acquisition digest
            # satisfies it directly; the independent endpoint is retained as an
            # explicitly configured fallback but is not needlessly downloaded.
            checks.append((primary[0], primary[1], "acquisition metadata"))
            record.evidence_status = "not-needed"
        else:
            if not list(getattr(pkg.repo, "evidence_urls", []) or []):
                raise RuntimeError(
                    f"{pkg.nevra}: Enhanced verification needs an independent evidence source "
                    "because acquisition metadata does not meet the selected checksum minimum")
            artifact_evidence_required = True

    elif strategy == "full-corroboration":
        if not primary:
            raise RuntimeError(
                f"{pkg.nevra}: full corroboration requires acquisition metadata to publish a "
                "checksum meeting the selected minimum")
        if not list(getattr(pkg.repo, "evidence_urls", []) or []):
            raise RuntimeError(
                f"{pkg.nevra}: full corroboration requires at least one configured independent evidence source")
        checks.append((primary[0], primary[1], "acquisition metadata"))
        artifact_evidence_required = True

    elif strategy in {"legacy-fallback", "legacy-corroborate", "legacy-evidence-required"}:
        # Compatibility for RepoSpec instances using legacy evidence fields.
        if strategy == "legacy-evidence-required" and not record.evidence_metadata_match:
            raise RuntimeError(f"{pkg.nevra}: required evidence source does not publish this exact package identity")
        if options.verify_checksums and primary:
            checks.append((primary[0], primary[1], "acquisition metadata"))
        if evidence:
            if strategy != "legacy-fallback" or not primary:
                checks.append((evidence[0], evidence[1], "evidence mirror metadata"))
        if strategy == "legacy-evidence-required" and not evidence:
            raise RuntimeError(f"{pkg.nevra}: required evidence source publishes no usable strong digest")

    else:
        raise RuntimeError(f"{pkg.nevra}: unknown verification strategy '{strategy}'")

    computed: Dict[str, str] = {}
    for algo, expected, source in checks:
        if algo not in computed:
            computed[algo] = hash_file_fn(path, algo).lower()
        actual = computed[algo]
        if not hmac.compare_digest(actual, expected.lower()):
            raise RuntimeError(
                f"{pkg.nevra}: {algo.upper()} mismatch against {source}: expected {expected}, got {actual}")
        if source == "acquisition metadata":
            record.package_digest_checked = True
        else:
            record.evidence_digest_checked = True

    if artifact_evidence_required:
        verify_independent_fn(pkg, path, primary, computed, reporter)
        artifact_digests.remember_verified(path, before, computed)
        return True

    if not checks:
        published = package_digest_map(pkg)
        if options.require_package_digests:
            raise RuntimeError(
                f"{pkg.nevra}: no usable SHA-256/SHA-384/SHA-512 package digest meets the configured policy")
        if published:
            reporter.warn(
                f"{pkg.nevra}: no published checksum meets the configured minimum; "
                "continuing with degraded package provenance")
        else:
            reporter.warn(
                f"{pkg.nevra}: acquisition metadata publishes no strong package checksum; "
                "continuing with degraded package provenance")
        record.notes.append("No qualifying strong package digest was checked; artifact accepted by checksum-available strategy.")
        return False

    artifact_digests.remember_verified(path, before, computed)
    return True

