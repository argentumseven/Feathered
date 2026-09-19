from __future__ import annotations

import artifact_digests
import artifact_verification as _artifact_verification_engine
import bundle_baseline
import payload_identity
import rpm_capabilities
import file_hashing
import base64
import binascii
import bz2
import gzip
import hashlib
import hmac
import io
import json
import lzma
import os
import posixpath
import re
import shutil
import shlex
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import unicodedata
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Set, SupportsInt, SupportsIndex, Tuple, TypeVar, Union

if TYPE_CHECKING:
    from root_requests import RootInput

try:
    import compression.zstd as stdlib_zstd  # Python 3.14+
except (ImportError, ModuleNotFoundError):
    stdlib_zstd = None

try:
    import zstandard as zstd
except (ImportError, ModuleNotFoundError):
    zstd = None

import provenance
import repository_transport as _transport
from evidence_model import (
    REL_EXACT_ARTIFACT, REL_EXACT_MIRROR, REL_REBUILD_PEER,
    AUTH_UNKNOWN, classify_relationship, infer_vendor_id, vendor_display_name,
)
from core_models import (
    ArtifactVerification, BuildOptions, Package, ProviderMatch, RepoDataRef,
    RepoTrust, Requirement, ResolutionResult, TargetInventory,
)
from credential_redaction import (
    SENSITIVE_QUERY_KEYS, _KNOWN_SECRET_ORDER, _KNOWN_SECRETS, _KNOWN_SECRETS_LOCK,
    _MAX_KNOWN_SECRETS, _MIN_GLOBAL_SECRET_LENGTH, _remember_secret,
    active_sensitive_query_keys as _active_sensitive_query_keys,
    redact_text, redact_url, register_url_secrets,
)
from execution_reporter import Cancelled, CancellationProbe, Reporter
from package_transfer import copy_package_stream_bounded, package_download_limit
from publication_staging import (
    _publication_backup_path, abandon_staging, commit_staging, invalidate_bundle_seal, open_staging,
)
from repository_config import RepoSpec
from repository_paths import file_url_to_path, human_size, path_to_file_url, repo_relative_url
from runtime_limits import (
    MAX_METADATA_DOWNLOAD_BYTES, MAX_METADATA_EXPANDED_BYTES, MAX_PACKAGE_DOWNLOAD_BYTES,
    positive_env_int as _positive_env_int,
)
import rpm_metadata as _rpm_metadata
import rpm_resolution as _rpm_resolution
import rpm_repository_writer as _rpm_repository_writer
import rpm_target_inventory as _rpm_target_inventory
import rpm_bundle as _rpm_bundle
RPM_NS = _rpm_metadata.RPM_NS

FEATHERED_VERSION = "1.3.0"  # Keep in step with the newest CHANGELOG.md version.

USER_AGENT = f"Feathered-Airgap-Sideloader/{FEATHERED_VERSION}"

# repository metadata is hostile input.
# Bound both transfer size and expanded size so a malformed mirror cannot turn a
# metadata fetch into an unbounded memory allocation. Environment overrides are
# available for unusually large legitimate repositories.




def zstd_backend() -> Optional[str]:
    if zstd is not None:
        return "zstandard-stream"
    if stdlib_zstd is not None:
        return "stdlib"
    return None




# Vendor identity helpers are implemented in evidence_model.py and re-exported here
# for compatibility with existing backend/UI imports.
























class DownloadPackage(Protocol):
    """Package identity and verification state shared by payload acquisition."""

    verification: Optional[ArtifactVerification]

    @property
    def name(self) -> str: ...
    @property
    def size(self) -> int: ...
    @property
    def checksum_type(self) -> str: ...
    @property
    def checksum(self) -> str: ...
    @property
    def digests(self) -> Dict[str, str]: ...

    @property
    def repo(self) -> RepoSpec: ...
    @property
    def location(self) -> str: ...
    @property
    def nevra(self) -> str: ...


class RepositoryWriterReporter(Protocol):
    def log(self, message: str, /) -> None: ...








# Compatibility exports during the transport-boundary migration.  Network
# policy lives in repository_transport.py; core keeps these names so existing
# backend code and external tests do not need a flag-day rewrite.
_RepositoryRedirectHandler = _transport.RepositoryRedirectHandler
_effective_origin = _transport.effective_origin
_effective_hostname = _transport.effective_hostname
_sensitive_query_parts = _transport.sensitive_query_parts
_url_has_endpoint_credentials = _transport.url_has_endpoint_credentials
_repo_has_endpoint_credentials = _transport.repo_has_endpoint_credentials
_credential_redirect_allow_origins = _transport.credential_redirect_allow_origins
_record_effective_origin = _transport.record_effective_origin
_inherit_sensitive_query_credentials = _transport.inherit_sensitive_query_credentials


def _ssl_context(repo: Optional[RepoSpec] = None):
    return _transport.ssl_context(repo)


def _urlopen(url: str, timeout: int, repo: Optional[RepoSpec] = None):
    return _transport.open_url(url, timeout, repo, user_agent=USER_AGENT)


def fetch_bytes(url: str, reporter: Reporter, retries: int = 3, timeout: int = 45,
                repo: Optional[RepoSpec] = None,
                max_bytes: Optional[int] = MAX_METADATA_DOWNLOAD_BYTES) -> bytes:
    return _transport.fetch_bytes(
        url, reporter, retries=retries, timeout=timeout, repo=repo, max_bytes=max_bytes,
        # Keep _urlopen as the compatibility injection seam while the backends
        # migrate to an explicit RepositoryTransport object.
        open_url_fn=lambda target, seconds, source: _urlopen(target, seconds, source),
        redact_url_fn=redact_url,
    )


def fetch_text(url: str, reporter: Optional[Reporter] = None, retries: int = 3, timeout: int = 45) -> str:
    return fetch_bytes(url, reporter or Reporter(), retries=retries, timeout=timeout).decode("utf-8", "replace")


def url_join(base: str, href: str, repo: Optional[RepoSpec] = None) -> str:
    return _transport.url_join(base, href, repo)


def _repo_trust(repo: RepoSpec) -> RepoTrust:
    """The verification record for a repository, created on first use."""
    record = getattr(repo, "trust", None)
    if record is None or record.repo != repo.name:
        record = RepoTrust(repo=repo.name)
        setattr(repo, "trust", record)
    return record




def get_repo_data(repo: RepoSpec, reporter: Reporter, retries: int = 3) -> Dict[str, RepoDataRef]:
    return _rpm_metadata.get_repo_data(
        repo, reporter, retries=retries,
        url_join_fn=url_join,
        fetch_bytes_fn=fetch_bytes,
        verification_strategy_fn=repository_verification_strategy,
        verify_openpgp_fn=verify_openpgp,
        repo_trust_fn=_repo_trust,
        repo_relative_url_fn=repo_relative_url,
    )


# Repository metadata names its own digest algorithm, so an attacker or a
# stale mirror could nominate a broken one. Only collision-resistant digests
# are accepted; anything else is a hard failure rather than a silent downgrade.
STRONG_HASHES = {"sha256", "sha384", "sha512", "sha3_256", "sha3_512"}
_HASH_ALIASES = {"sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512"}
WEAK_HASHES = {"md5", "sha1", "sha"}


def normalize_hash_name(algorithm: str) -> str:
    algo = (algorithm or "sha256").strip().lower().replace("-", "_")
    return _HASH_ALIASES.get(algorithm.strip().lower(), algo)


def load_baseline(manifest_path: str, reporter: Reporter) -> Dict[str, str]:
    """Read a previous bundle manifest into {package_id: sha256-or-version}.

    Differential bundles exist because transfer capacity, not build time, is
    the binding constraint in most airgapped programs: a point upgrade should
    move tens of megabytes, not the whole closure.
    """
    if not manifest_path:
        return {}
    path = Path(manifest_path).expanduser()
    if not path.is_file():
        raise RuntimeError(f"Baseline manifest was not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Baseline manifest {path.name} is not valid JSON: {exc}") from exc
    baseline = bundle_baseline.digest_map(
        payload.get("packages", []),
        digest=lambda algorithm, value: strong_package_digest(algorithm, value))
    reporter.log(f"Baseline loaded: {len(baseline)} package(s) already present at the target")
    return baseline


BaselinePackageT = TypeVar("BaselinePackageT", bound=DownloadPackage)


def split_against_baseline(selected: Iterable[BaselinePackageT], baseline: Dict[str, str],
                           reporter: Reporter) -> Tuple[List[BaselinePackageT], List[BaselinePackageT]]:
    """Partition a closure into (to_ship, already_present) using a baseline."""
    ship, skip, unverifiable = bundle_baseline.partition(
        selected, baseline,
        digest=lambda algorithm, value: strong_package_digest(algorithm, value),
        matches=lambda left, right: hmac.compare_digest(left, right))
    if unverifiable:
        reporter.warn(f"{unverifiable} baseline entry/entries record no digest, so their contents "
                      "could not be compared; those packages are included rather than assumed "
                      "unchanged. Rebuild the baseline with this version of Feathered.")
    if skip:
        reporter.log(f"Differential build: {len(skip)} package(s) byte-identical to the baseline, "
                     f"{len(ship)} to transfer")
    return ship, skip


def _windows_payload_key(name: str) -> str:
    """Return the existing platform-independent Win32-equivalent key."""
    return payload_identity.windows_key(name, normalize=lambda form, value: unicodedata.normalize(form, value))


def write_unified_mirror_records(output_dir: Path, metadata_dir: Path, options) -> None:
    """Write the unified-mirror merge record, if this build is a unified mirror.

    Called by every backend's write_bundle immediately before the seal step so
    both files are covered by bundle-index.json. Writing them afterwards would
    make a sealed unified mirror fail its own verifier.
    """
    note = getattr(options, "unified_mirror_note", "") or ""
    records = getattr(options, "unified_mirror_records", None)
    if not note and not records:
        return
    if note:
        (output_dir / "UNIFIED-MIRROR.txt").write_text(note, encoding="utf-8")
    if records is not None:
        (metadata_dir / "mirror-sources.json").write_text(
            json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def payload_filenames(packages, expected_suffix: str) -> Dict[int, str]:
    """Return Windows-safe names, preserving the core dependency hooks."""
    return payload_identity.payload_filenames(
        packages, expected_suffix,
        location_name=lambda location: posixpath.basename(urllib.parse.urlparse(location).path),
        key=lambda name: _windows_payload_key(name))


def meta_str_list(metadata: Dict[str, object], key: str) -> List[str]:
    """Read a list-of-strings out of the loosely typed metadata dict."""
    value = metadata.get(key, [])
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value if str(x).strip()]
    return []


def meta_dict_list(metadata: Dict[str, object], key: str) -> List[Dict[str, object]]:
    value = metadata.get(key, [])
    return [x for x in value if isinstance(x, dict)] if isinstance(value, (list, tuple)) else []


def diagnose_missing_repository(repo_url: str, reporter: Reporter, retries: int = 1) -> str:
    """Explain *why* a repository has no metadata, by looking at what is there.

    A bare 404 on repodata/repomd.xml cannot distinguish "wrong path", "release
    not published yet" and "placeholder directory". Fetching the directory
    listing separates them: an empty or readme-only directory means the release
    exists on the mirror but carries no content, while a listing full of
    subdirectories usually means the repository root is one level down.
    """
    root = repo_url.rstrip("/") + "/"
    try:
        raw = fetch_bytes(root, reporter, retries=retries).decode("utf-8", "replace")
    except Exception as exc:
        return (f"The directory itself could not be listed either ({exc}). The path is most "
                "likely wrong, or the mirror does not serve this release.")

    hrefs = re.findall(r'href=[\'"]([^\'"]+)[\'"]', raw, re.IGNORECASE)
    entries = []
    for href in hrefs:
        name = href.strip("/").split("/")[-1]
        if not name or name.startswith(("?", "#")) or name in {"..", "."}:
            continue
        if name not in entries:
            entries.append(name)

    if not entries:
        return ("The directory exists but appears to be empty. This usually means the release "
                "has not been published to this mirror.")

    substantive = [e for e in entries if not e.lower().startswith(("readme", "index", "changelog"))]
    if not substantive:
        return (f"The directory exists but contains only {', '.join(entries)} - no repository "
                "content. This release is almost certainly not published yet, or has been "
                "retired and moved to a vault mirror. Try the major-version stream directory "
                "instead of the exact point release.")

    likely = [e for e in substantive
              if any(k in e.lower() for k in ("baseos", "appstream", "os", "release", "updates",
                                              "extras", "crb", "powertools", "main", "everything"))]
    listing = ", ".join(substantive[:12]) + (" …" if len(substantive) > 12 else "")
    if likely:
        return (f"No repodata/ here, but the directory contains: {listing}. The repository root is "
                f"probably one level down - try appending one of: {', '.join(likely[:5])}.")
    return (f"No repodata/ here. The directory contains: {listing}. Check that this is the "
            "repository root (the folder that directly contains repodata/).")










def merge_additive_manifest_rows(manifest_path: Path, current_rows: List[dict]) -> List[dict]:
    """Merge a prior bundle manifest with rows produced by this build.

    Current rows win on filename/package identity. A malformed previous manifest
    is ignored rather than blocking the new build; the old file remains present
    in staging until the new canonical manifest is successfully written.
    """
    try:
        prior = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        old_rows = prior.get("packages", []) if isinstance(prior, dict) else []
    except Exception:
        old_rows = []
    def key(row):
        return str(row.get("filename") or row.get("package_id") or row.get("nevra") or row.get("name") or "")
    merged = {key(row): dict(row) for row in old_rows if isinstance(row, dict) and key(row)}
    for row in current_rows:
        merged[key(row)] = row
    return list(merged.values())


# Root-level artifacts that assert a whole-bundle seal. An unsealed successor
# must never inherit them from a previously sealed additive bundle.




















# Files that describe the bundle rather than belong to it, so they are not
# listed inside the index that describes them.
# Sealing re-reads every byte already written, so it is a substantial share of
# a build rather than a rounding error; giving it the last fifth of the bar
# keeps the whole build monotonic without making small bundles feel stalled.
SEAL_PHASE_START = 0.8

INDEX_FILENAME = "bundle-index.json"
INDEX_SIGNATURE = "bundle-index.json.asc"



def _verify_script() -> str:
    """Load the receiver-side verifier and fail closed if release packaging omitted it."""
    candidates = [Path(__file__).resolve().parent / "verify_bundle_template.py"]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.insert(0, Path(meipass) / "verify_bundle_template.py")
    last_error = None
    for template in candidates:
        try:
            body = template.read_text(encoding="utf-8")
        except OSError as exc:
            last_error = exc
            continue
        if body.strip():
            return body
    detail = f" ({last_error})" if last_error else ""
    raise RuntimeError(
        "Receiver verifier resource verify_bundle_template.py is missing or empty. "
        "Refusing to seal a bundle without verify-bundle.py" + detail)


def write_bundle_index(bundle_dir: Path, reporter: Reporter, metadata: Dict[str, object],
                       signing_key: str = "") -> Path:
    """Hash every finished file and record them in one canonical index.

    The hashes are computed from the bytes on disk at finalisation, not reused
    from download or repository verification, so the index attests to the
    bundle that actually exists rather than to what was intended. Signing this
    one object makes it the single root of trust: the receiver verifies the
    signature, then re-hashes the files and compares.
    """
    bundle_dir = Path(bundle_dir)
    # write the receiver verifier *before* indexing and
    # include it in the signed file set.  A verifier that is not sealed can be
    # replaced with a script that simply prints success.
    body = _verify_script()
    verifier = bundle_dir / "verify-bundle.py"
    verifier.write_text(body, encoding="utf-8", newline="\n")
    make_executable(verifier)
    # Sealing the verifier inside the index is not sufficient by itself: when
    # an operator key is configured, authenticate the bootstrap verifier too.
    if signing_key:
        verifier_signature = _sign_detached(verifier, signing_key, reporter)
        if verifier_signature is None:
            raise RuntimeError(
                "Bundle signing was requested but verify-bundle.py could not be signed. "
                "The bundle has not been published.")

    # Exclusions are root-relative, so a nested file that happens to share the
    # index's name is still sealed. Symlinks are never followed: an "exact
    # bundle" must not be able to hash something outside its own tree.
    excluded = {INDEX_FILENAME, INDEX_SIGNATURE}
    files = []
    for candidate in bundle_dir.rglob("*"):
        relative = candidate.relative_to(bundle_dir).as_posix()
        if relative in excluded:
            continue
        if candidate.is_symlink():
            raise RuntimeError(
                f"Refusing to seal a bundle containing a symlink ({relative}); its target may "
                "lie outside the bundle and would not be covered by the signature.")
        if candidate.is_file():
            files.append(candidate)
    files.sort(key=lambda p: p.relative_to(bundle_dir).as_posix())
    total = sum(p.stat().st_size for p in files) or 1
    done = 0
    entries = []
    for path in files:
        reporter.check_cancel()
        digest = hashlib.sha256()
        hashed = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
                digest.update(chunk)
                hashed += len(chunk)
                done += len(chunk)
                # Weighted by bytes so the bar is meaningful for a 40 GB mirror
                # and does not stutter through thousands of tiny files.
                reporter.progress(f"Sealing bundle ({human_size(done)} of {human_size(total)})",
                                  done / total)
        if path.stat().st_size != hashed:
            # The file changed while it was being read, so the digest describes
            # something that no longer exists on disk.
            raise RuntimeError(f"{path.name} changed while the bundle was being sealed; "
                               "rebuild rather than publishing an index that does not match.")
        entries.append({
            "path": path.relative_to(bundle_dir).as_posix(),
            "sha256": digest.hexdigest(),
            "size": str(hashed),
        })
    total_bytes = sum(int(e["size"]) for e in entries)
    index: Dict[str, object] = {
        "format": "feathered-bundle-index/1",
        "tool": metadata.get("tool", f"Feathered {FEATHERED_VERSION}"),
        "bundle_id": str(metadata.get("bundle_id") or bundle_dir.name),
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": metadata.get("target", {}),
        "trust": metadata.get("trust", {}),
        "openpgp_verifier": gpg_backend_version() or "unavailable",
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "files": entries,
    }
    # sort_keys and a fixed separator keep the bytes reproducible for signing
    # without needing a canonicalisation framework.
    payload = json.dumps(index, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    target = bundle_dir / INDEX_FILENAME
    target.write_bytes(payload)
    if signing_key:
        signature = _sign_detached(target, signing_key, reporter)
        if signature is None:
            raise RuntimeError(
                "Bundle signing was requested but no signature could be produced. The bundle has "
                "not been published; fix the signing key or disable signing and rebuild.")
    return target


def _record_digest_checked(pkg) -> None:
    """Mark that this artifact's own digest was compared against its bytes."""
    record = getattr(pkg, "verification", None)
    if record is None:
        record = ArtifactVerification()
        setattr(pkg, "verification", record)
    record.package_digest_checked = True


def trust_summary(packages) -> Dict[str, int]:
    """Aggregate the recorded verification state of the shipped artifacts."""
    counts: Dict[str, int] = {}
    for pkg in packages:
        record = getattr(pkg, "verification", None)
        signed = bool(getattr(getattr(pkg, "repo", None), "trust", None)
                      and pkg.repo.trust.archive_signature_verified)
        if record is None:
            key = "unverified"
        elif record.vendor_signature_verified:
            key = "vendor-signature"
        elif signed and record.index_digest_verified and record.package_digest_checked:
            # Every link checked: archive signature, index covered by it, and
            # this package's digest actually compared against its bytes.
            key = "archive-chain"
        elif (record.evidence_relationship == "independent-peer"
              and record.evidence_peer_identity_match and record.evidence_digest_checked):
            key = "independent-peer-corroboration"
        elif record.package_digest_checked and record.evidence_digest_checked:
            # both acquisition and evidence
            # strong-digest claims matched the same single downloaded payload.
            key = "corroborated-digest"
        elif record.evidence_metadata_match and record.evidence_digest_checked:
            # the one downloaded payload matched a strong digest
            # independently published by the bonded evidence mirror.
            key = "independent-digest"
        elif record.package_digest_checked:
            key = "digest-only"
        elif record.evidence_metadata_match:
            key = "metadata-corroborated"
        else:
            key = "unverified"
        counts[key] = counts.get(key, 0) + 1
    return counts


_trust_summary = trust_summary


def _sign_detached(path: Path, signing_key: str, reporter: Reporter) -> Optional[Path]:
    """Detached armoured signature over a file, or None when gpg is unavailable."""
    # this helper now signs both the canonical
    # bundle index and the receiver verifier, so diagnostics identify the file
    # rather than incorrectly calling every signature a bundle-index signature.
    if shutil.which("gpg") is None:
        reporter.warn(f"gpg is not installed, so {path.name} could not be signed.")
        return None
    signature = path.with_suffix(path.suffix + ".asc")
    proc = subprocess.run(["gpg", "--batch", "--yes", "--armor", "--local-user", signing_key,
                           "--detach-sign", "--output", str(signature), str(path)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        reporter.warn(f"Signing {path.name} failed: " + (detail[-1] if detail else "unknown error"))
        return None
    reporter.log(f"Signed {path.name}: {signature.name}")
    return signature




def make_executable(path: Path) -> None:
    """Best-effort +x on generated scripts. ZIP transfer can drop the mode bit,
    so the docs also give `bash install-offline.sh` as a fallback."""
    try:
        path.chmod(path.stat().st_mode | 0o111)
    except OSError:
        pass


def _hash_bytes(data: bytes, algorithm: str) -> str:
    algo = normalize_hash_name(algorithm)
    if algo in WEAK_HASHES:
        raise RuntimeError(
            f"Repository metadata requests the {algo} digest, which is not collision resistant. "
            "Refusing to verify with it; use a repository that publishes SHA-256 or stronger."
        )
    if algo not in STRONG_HASHES:
        raise RuntimeError(f"Unsupported metadata digest algorithm: {algorithm!r}")
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def bundled_gpg_dir() -> Optional[Path]:
    """Directory of the GnuPG verifier shipped beside the application, if any.

    Frozen production builds require this directory and authenticate every file
    in it against a verifier-integrity policy embedded inside the signed
    Feathered executable. Source checkouts may use a local gnupg/ directory or
    fall back to PATH for developer convenience.
    """
    try:
        roots = []
        if getattr(sys, "frozen", False):
            roots.append(Path(sys.executable).resolve().parent)
        roots.append(Path(__file__).resolve().parent)
        for root in roots:
            candidate = root / "gnupg"
            if candidate.is_dir():
                return candidate
    except OSError:
        pass
    return None


class VerifierIntegrityError(RuntimeError):
    """The bundled OpenPGP verifier is missing, unauthenticated, or tampered.

    This is deliberately a distinct type. Callers that downgrade an ordinary
    signature failure to a warning (an unsigned package, a missing keyring)
    must never apply that same downgrade to a compromised verifier: the first
    is a property of the artifact, the second means no verification result on
    this machine can be trusted at all.
    """


def _verifier_policy_path() -> Optional[Path]:
    """Locate the verifier policy embedded by the production build."""
    roots = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.append(Path(meipass))
    roots.append(Path(__file__).resolve().parent)
    for root in roots:
        candidate = root / "verifier-integrity.json"
        if candidate.is_file():
            return candidate
    return None


def _sha256_file(path: Path) -> str:
    return file_hashing.stream_digest(path, hashlib.sha256())


_VERIFIER_CACHE_LOCK = threading.Lock()
# (directory -> fingerprint) of the last successful full hash verification.
# The fingerprint is the exact (relpath, size, mtime_ns) set observed at that
# moment, so any write to the directory invalidates it.
_VERIFIER_VERIFIED: dict[str, frozenset] = {}


def _verifier_fingerprint(files: "dict[str, Path]") -> frozenset:
    return frozenset(
        (rel, path.stat().st_size, path.stat().st_mtime_ns)
        for rel, path in files.items()
    )


def _enumerate_verifier_files(directory: Path) -> "dict[str, Path]":
    """List the verifier directory, rejecting symlinks and reparse points."""
    found: dict[str, Path] = {}
    try:
        # Python 3.13 glob does not recurse into symlinked directories by
        # default, so a junction cannot smuggle files past this walk.
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise VerifierIntegrityError(
                    f"Bundled OpenPGP verifier contains a symlink/reparse entry: {path.name}"
                )
            if path.is_file():
                found[path.relative_to(directory).as_posix()] = path
    except OSError as exc:
        raise VerifierIntegrityError(
            "Unable to enumerate bundled OpenPGP verifier files."
        ) from exc
    return found


def _verify_bundled_gpg_integrity(directory: Path) -> None:
    """Authenticate the bundled verifier against the signed executable policy.

    The policy is a PyInstaller data resource. In a frozen release it is inside
    Feathered.exe before Authenticode signing, so a sidecar attacker cannot
    replace both gpgv and its expected hashes. The directory is exact-set
    checked: missing, changed, added, or symlinked files are rejected.

    This runs on every gpg_backend() call, and gpg_backend() is called once per
    package during a vendor-signature pass, so a full re-hash of several
    megabytes of DLLs per package is not affordable. After one successful full
    verification the (relpath, size, mtime_ns) set is recorded; subsequent calls
    re-enumerate and re-stat, and only re-hash when that set has changed.  This
    fast path detects ordinary modification but assumes an attacker able to write
    the verifier directory cannot also restore the original size and nanosecond
    mtime metadata.  gpgv itself is still re-hashed before each execution.  This
    does not close the exec-time TOCTOU window, which the original per-call
    hashing did not close either.
    """
    policy_path = _verifier_policy_path()
    frozen = bool(getattr(sys, "frozen", False))
    if policy_path is None:
        if frozen:
            raise VerifierIntegrityError(
                "Bundled OpenPGP verifier integrity policy is missing from this release. "
                "Refusing to execute an unauthenticated verifier."
            )
        return
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        expected = policy["files"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise VerifierIntegrityError(
            "Bundled OpenPGP verifier integrity policy is invalid."
        ) from exc
    if not isinstance(expected, dict) or not expected:
        raise VerifierIntegrityError(
            "Bundled OpenPGP verifier integrity policy contains no files."
        )

    actual = _enumerate_verifier_files(directory)

    expected_names = set(expected)
    actual_names = set(actual)
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        detail = []
        if missing:
            detail.append("missing: " + ", ".join(missing))
        if extra:
            detail.append("unexpected: " + ", ".join(extra))
        raise VerifierIntegrityError(
            "Bundled OpenPGP verifier file set does not match the signed release policy"
            + (" (" + "; ".join(detail) + ")" if detail else "") + "."
        )

    key = str(directory.resolve())
    try:
        fingerprint = _verifier_fingerprint(actual)
    except OSError as exc:
        raise VerifierIntegrityError(
            "Unable to stat bundled OpenPGP verifier files."
        ) from exc

    with _VERIFIER_CACHE_LOCK:
        cached = _VERIFIER_VERIFIED.get(key) == fingerprint

    def check(rel: str, path: Path) -> None:
        wanted = str(expected[rel]).lower()
        if len(wanted) != 64 or any(c not in "0123456789abcdef" for c in wanted):
            raise VerifierIntegrityError(f"Invalid verifier SHA-256 policy entry for {rel}.")
        if _sha256_file(path).lower() != wanted:
            raise VerifierIntegrityError(
                f"Bundled OpenPGP verifier integrity check failed for {rel}. "
                "Refusing to execute it."
            )

    if cached:
        # The stat fingerprint is unchanged, so the DLLs are taken on trust from
        # the earlier full pass. The binary that is actually about to be
        # executed is still re-hashed every time: it is small, and it is the one
        # file where a same-size, mtime-restored swap would be worth an
        # attacker's effort.
        for rel, path in actual.items():
            if rel.rsplit("/", 1)[-1].lower() in ("gpgv.exe", "gpgv"):
                check(rel, path)
        return

    for rel, path in actual.items():
        check(rel, path)

    with _VERIFIER_CACHE_LOCK:
        _VERIFIER_VERIFIED[key] = fingerprint


def _reset_verifier_integrity_cache() -> None:
    """Drop memoized verifier state. Used by tests and after a policy change."""
    with _VERIFIER_CACHE_LOCK:
        _VERIFIER_VERIFIED.clear()


def gpg_backend_name(backend: Optional[str]) -> str:
    """Comparable tool name ("gpgv"/"gpg") for a backend path or bare name."""
    if not backend:
        return ""
    stem = Path(backend).name.lower()
    return stem[:-4] if stem.endswith(".exe") else stem


def _windows_path_to_msys(value: str) -> str:
    """Translate an absolute Windows path for an MSYS-native GnuPG process."""
    normalized = value.replace("\\", "/")
    match = re.match(r"^([A-Za-z]):/(.*)$", normalized)
    if match:
        return f"/{match.group(1).lower()}/{match.group(2)}"
    return normalized


def _gpg_backend_uses_msys_paths(backend: str) -> bool:
    """Return whether the selected Windows verifier uses MSYS path semantics."""
    if os.name != "nt":
        return False
    resolved = shutil.which(backend) or backend
    normalized = str(resolved).replace("\\", "/").lower()
    if "/git/usr/bin/" in normalized:
        return True
    try:
        return (Path(resolved).resolve().parent / "msys-2.0.dll").is_file()
    except OSError:
        return False


def _gpg_path_arg(path: Union[Path, str], backend: str) -> str:
    value = str(path)
    return _windows_path_to_msys(value) if _gpg_backend_uses_msys_paths(backend) else value


def gpg_backend() -> Optional[str]:
    """Return an authenticated OpenPGP verifier available to this process.

    Frozen releases are fail-closed: they must contain the bundled verifier and
    it must match the integrity policy embedded in the signed executable. PATH
    fallback is intentionally disabled for frozen production builds.
    """
    bundled = bundled_gpg_dir()
    frozen = bool(getattr(sys, "frozen", False))
    if bundled is not None:
        _verify_bundled_gpg_integrity(bundled)
        for candidate in ("gpgv.exe", "gpgv"):
            tool = bundled / candidate
            if tool.is_file():
                return str(tool)
        if frozen:
            raise VerifierIntegrityError(
                "Authenticated OpenPGP verifier directory contains no gpgv executable."
            )
        # A source checkout may keep an incomplete gnupg/ scratch directory.
        # Only a frozen release treats that as fatal; development continues to
        # fall through to PATH exactly as it did before 1.2.2.
    elif frozen:
        raise VerifierIntegrityError(
            "This Feathered release is missing its bundled OpenPGP verifier. "
            "Refusing to fall back to an unauthenticated PATH executable."
        )
    for candidate in ("gpgv", "gpg"):
        if shutil.which(candidate):
            return candidate
    return None


def gpg_backend_or_none() -> Optional[str]:
    """gpg_backend() for status/reporting callers that must not raise.

    Returns None both when no verifier exists and when the bundled one fails
    authentication. Anything on a verification path must call gpg_backend()
    directly so a VerifierIntegrityError propagates instead of being read as
    "GnuPG is not installed".
    """
    try:
        return gpg_backend()
    except VerifierIntegrityError:
        return None


def gpg_backend_version(backend: Optional[str] = None) -> str:
    """First --version line of the active verifier, for provenance records."""
    tool = backend or gpg_backend_or_none()
    if not tool:
        return ""
    try:
        proc = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    first = (proc.stdout or "").strip().splitlines()
    return first[0].strip() if proc.returncode == 0 and first else ""


def verify_openpgp(signed_payload: bytes, signature: Optional[bytes], keyring: str,
                   description: str, reporter: Reporter) -> None:
    """Verify an OpenPGP signature against an explicit keyring.

    Two modes:
      * detached  - `signature` holds a .asc/.gpg signature over `signed_payload`.
      * clearsign - `signature` is None and `signed_payload` is the whole
        clearsigned document (an APT InRelease file). These MUST be verified
        inline: the bytes actually signed are the dash-unescaped, canonicalised
        body, not the armoured file, so handing the file to a detached-mode
        verification always reports a bad signature.

    Fails closed: a configured keyring that cannot be checked is an error.
    """
    keyring_path = Path(keyring).expanduser()
    if not keyring_path.is_file():
        raise RuntimeError(f"{description}: configured keyring was not found: {keyring_path}")
    backend = gpg_backend()
    if backend is None:
        raise RuntimeError(
            f"{description}: a keyring is configured but neither gpgv nor gpg is installed. "
            "Install GnuPG (Gpg4win on Windows) or clear the keyring setting for this repository."
        )
    with tempfile.TemporaryDirectory(prefix="feathered-gpg-") as tmpdir:
        tmp = Path(tmpdir)
        keyring_arg = _prepare_keyring(keyring_path, tmp, backend)
        payload_file = tmp / "payload"
        payload_file.write_bytes(signed_payload)
        if signature is None:
            args = [_gpg_path_arg(payload_file, backend)]
        else:
            sig_file = tmp / "payload.sig"
            sig_file.write_bytes(signature)
            args = [_gpg_path_arg(sig_file, backend), _gpg_path_arg(payload_file, backend)]
        keyring_cli = _gpg_path_arg(keyring_arg, backend)
        if gpg_backend_name(backend) == "gpgv":
            cmd = [backend, "--keyring", keyring_cli, *args]
        else:
            cmd = [backend, "--batch", "--no-default-keyring", "--keyring", keyring_cli,
                   "--verify", *args]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            detail = [x for x in (proc.stderr or proc.stdout or "").strip().splitlines() if x.strip()]
            raise RuntimeError(f"{description}: OpenPGP signature verification FAILED. "
                               + (detail[-1] if detail else "no detail from the verifier"))
        signer = ""
        for line in (proc.stderr or "").splitlines():
            if "Good signature from" in line:
                signer = line.split("Good signature from", 1)[1].strip().strip('"')
                break
    reporter.log(f"{description}: OpenPGP signature verified"
                 + (f" ({signer})" if signer else f" against {keyring_path.name}"))


MAX_ARMORED_KEYRING_BYTES = 32 * 1024 * 1024


def _dearmor_public_keyring(data: bytes) -> bytes:
    """Decode one ASCII-armoured OpenPGP public-key block.

    ``gpgv`` accepts OpenPGP packet bytes as a keyring but does not dearmor
    exported ``.asc`` public keys itself.  Release builds deliberately ship the
    smaller verifier rather than the full key-management utility, so Feathered
    performs the armour transport decoding locally.  Armour headers and the
    optional CRC24 line are not part of the packet stream.

    The decoder is intentionally limited to PUBLIC KEY blocks: repository
    verification never needs private-key material and should not silently accept
    arbitrary armoured message types as a trust store.
    """
    begin = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = b"-----END PGP PUBLIC KEY BLOCK-----"
    lines = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == begin)
    except StopIteration as exc:
        raise RuntimeError("ASCII keyring is missing an OpenPGP public-key armour header") from exc

    body_started = False
    body = []
    armor_crc = None
    saw_end = False
    for raw in lines[start + 1:]:
        line = raw.strip()
        if not body_started:
            # RFC 4880 armour permits descriptive Header: Value lines followed
            # by a mandatory blank separator.  Some exporters emit no headers.
            if not line:
                body_started = True
                continue
            if b":" in line:
                continue
            body_started = True
        if line == end:
            saw_end = True
            break
        if not line:
            continue
        if line.startswith(b"="):
            if armor_crc is not None:
                raise RuntimeError("ASCII keyring contains multiple armour checksums")
            armor_crc = line[1:]
            continue
        body.append(line)

    if not saw_end:
        raise RuntimeError("ASCII keyring is missing its OpenPGP armour footer")
    if not body:
        raise RuntimeError("ASCII keyring contains no OpenPGP public-key data")
    try:
        decoded = base64.b64decode(b"".join(body), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("ASCII keyring contains invalid base64 armour data") from exc
    if not decoded:
        raise RuntimeError("ASCII keyring decoded to an empty OpenPGP keyring")
    if armor_crc is not None:
        try:
            expected_crc = base64.b64decode(armor_crc, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError("ASCII keyring contains an invalid armour checksum") from exc
        if len(expected_crc) != 3:
            raise RuntimeError("ASCII keyring contains an invalid armour checksum")
        crc = 0xB704CE
        for octet in decoded:
            crc ^= octet << 16
            for _ in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= 0x1864CFB
        actual_crc = (crc & 0xFFFFFF).to_bytes(3, "big")
        if not hmac.compare_digest(actual_crc, expected_crc):
            raise RuntimeError("ASCII keyring armour checksum does not match its contents")
    return decoded


def _prepare_keyring(keyring_path: Path, tmpdir: Path, backend: str) -> Path:
    """Return a verifier-compatible keyring, dearmouring ``.asc`` locally.

    Binary keyrings are passed through unchanged.  ASCII-armoured exported
    public keys are decoded without requiring ``gpg.exe`` so the Windows
    release's bundled ``gpgv`` is sufficient on a clean machine.
    """
    try:
        with keyring_path.open("rb") as handle:
            head = handle.read(64)
            if not head.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK"):
                return keyring_path
            handle.seek(0)
            data = handle.read(MAX_ARMORED_KEYRING_BYTES + 1)
    except OSError as exc:
        raise RuntimeError(f"Could not read configured keyring {keyring_path}: {exc}") from exc
    if len(data) > MAX_ARMORED_KEYRING_BYTES:
        raise RuntimeError(
            f"ASCII keyring {keyring_path.name} exceeds Feathered's "
            f"{MAX_ARMORED_KEYRING_BYTES:,}-byte safety limit")
    target = tmpdir / "keyring.gpg"
    target.write_bytes(_dearmor_public_keyring(data))
    return target

















def decompress_metadata(data: bytes, url: str,
                        max_bytes: int = MAX_METADATA_EXPANDED_BYTES) -> bytes:
    return _rpm_metadata.decompress_metadata(
        data, url, max_bytes, zstd_module=zstd, stdlib_zstd_module=stdlib_zstd
    )


def parse_primary(xml: bytes, repo: RepoSpec, arches: Set[str], reporter: Reporter) -> List[Package]:
    return _rpm_metadata.parse_primary(
        xml, repo, arches, reporter,
        normalized_hash_algorithm_fn=normalized_hash_algorithm,
        select_digest_from_map_fn=select_digest_from_map,
        repo_trust_fn=_repo_trust,
    )


def _load_repository_once(repo: RepoSpec, arches: Set[str], reporter: Reporter, retries: int = 3) -> List[Package]:
    reporter.log(f"Loading repository: {repo.name}")
    refs = get_repo_data(repo, reporter, retries=retries)
    primary = refs.get("primary")
    if primary is None:
        raise RuntimeError(f"{repo.name}: repomd.xml contains no primary metadata")
    reporter.log(f"{repo.name}: primary -> {primary.url}")
    compressed = fetch_bytes(primary.url, reporter, retries=retries, repo=repo)
    skip_provenance = repository_verification_strategy(repo) == "skip-provenance"
    if skip_provenance:
        # this mode intentionally parses
        # repository metadata without treating repomd checksums as provenance
        # gates. The bundle still receives Feathered's own transfer hashes later.
        reporter.warn(f"{repo.name}: primary metadata checksum verification skipped by operator policy.")
    elif primary.checksum:
        actual = _hash_bytes(compressed, primary.checksum_type)
        if actual.lower() != primary.checksum.lower():
            raise RuntimeError(f"{repo.name}: primary metadata checksum mismatch")
        _repo_trust(repo).metadata_digest_verified = True
    elif repo.allow_unverified_index:
        reporter.warn(f"{repo.name}: repomd.xml publishes no digest for primary metadata; "
                      "accepted because 'allow unverified indexes' is enabled for this repository.")
    else:
        # Silently accepting an undigested index would break the chain that
        # every per-package checksum depends on.
        raise RuntimeError(
            f"{repo.name}: repomd.xml publishes no checksum for the primary metadata, so the "
            "package digests cannot be trusted. Use a complete mirror, or enable 'Allow unverified "
            "indexes' for this repository in Advanced… if you accept that risk."
        )
    xml = decompress_metadata(compressed, primary.url)
    if primary.open_checksum and not skip_provenance:
        actual_open = _hash_bytes(xml, primary.open_checksum_type)
        if actual_open.lower() != primary.open_checksum.lower():
            raise RuntimeError(f"{repo.name}: decompressed metadata checksum mismatch")
    from module_policy import load_supplemental
    load_supplemental(repo, refs, reporter, retries)
    return parse_primary(xml, repo, arches, reporter)


def load_repository(repo: RepoSpec, arches: Set[str], reporter: Reporter, retries: int = 3) -> List[Package]:
    """Load acquisition metadata and optional evidence metadata; exact artifact corroboration occurs later.

    evidence mirrors are never payload
    sources.  Feathered loads only their repository metadata, matches exact package
    identities, and stores any strong digest for verification of the one package
    copy later downloaded from the acquisition mirror.
    """
    packages = _load_repository_once(repo, arches, reporter, retries=retries)
    # Contact evidence mirrors only when the selected strategy uses them.
    strategy = repository_verification_strategy(repo)
    if strategy in {"checksum-required", "checksum-available", "skip-provenance"}:
        return packages
    if strategy in {"evidence-fallback", "legacy-fallback"} and all(package_has_selected_digest(pkg) for pkg in packages):
        for pkg in packages:
            _artifact_verification(pkg).evidence_status = "not-needed"
        reporter.log(f"{repo.name}: configured checksum strength is available from acquisition metadata; evidence fallback not needed")
        return packages
    if not repo.evidence_urls:
        if strategy in {"evidence-fallback", "full-corroboration", "legacy-evidence-required",
                        "legacy-fallback", "legacy-corroborate"}:
            for pkg in packages:
                _artifact_verification(pkg).evidence_status = "unavailable"
        return packages

    usable = False
    last_error = ""
    for evidence_url in repo.evidence_urls:
        distinct, reason = mirrors_are_distinct(repo.normalized_url, evidence_url)
        if not distinct:
            reporter.warn(f"{repo.name}: evidence source {redact_url(evidence_url)} ignored ({reason}); "
                          "a source bond requires a distinct mirror hostname")
            last_error = reason
            continue
        # an evidence mirror is an
        # independent transport endpoint. Never forward the acquisition
        # repository's mTLS client certificate/private key or custom TLS CA to
        # it implicitly. the evidence
        # path is deliberately independent of the acquisition archive keyring.
        # Do not inherit it: mirror evidence must still be collectable when GPG
        # is absent, disabled, unavailable, or configured only for acquisition.
        evidence_repo = evidence_repo_for_url(repo, evidence_url)
        relationship = evidence_relationship(repo, evidence_url)
        try:
            evidence_packages = _load_repository_once(evidence_repo, arches, reporter, retries=1)
            stats = apply_mirror_evidence(
                packages, evidence_packages, evidence_repo, reporter, relationship=relationship,
                authority=evidence_authority_relationship(repo, evidence_url))
            kind = "independent rebuild peer" if relationship == REL_REBUILD_PEER else "evidence mirror"
            reporter.log(
                f"Source bond {repo.name}: {kind} {redact_url(evidence_url)} matched "
                f"{stats['matched']:,} package identities ({stats['digest']:,} with strong digest, "
                f"{stats['metadata']:,} metadata-only; {stats['missing']:,} not yet present; "
                f"{stats.get('conflict', 0):,} metadata conflict(s) deferred to selected-artifact verification)")
            usable = True
            break
        except RuntimeError as exc:
            # Contradictory exact-package evidence is qualitatively different
            # from an unavailable/lagging mirror and is never bypassed.
            if (("Mirror bond" in str(exc) or "Peer evidence" in str(exc))
                    and "disagreement" in str(exc)):
                raise
            last_error = str(exc)
            reporter.warn(f"{repo.name}: evidence mirror {redact_url(evidence_url)} unavailable/inconclusive: {exc}")

    if not usable:
        # Missing repomd.xml does not make an evidence endpoint useless. A
        # distinct source may intentionally expose package artifacts without
        # repository metadata. Defer the decisive check until the exact selected
        # artifact is known, then fetch/hash that evidence copy transiently.
        for pkg in packages:
            record = _artifact_verification(pkg)
            if record.evidence_status in {"not-configured", "unavailable"}:
                record.evidence_status = "artifact-pending"
            if not record.evidence_source and repo.evidence_urls:
                record.evidence_source = redact_url(repo.evidence_urls[0])
        if repo.evidence_urls:
            reporter.warn(
                f"{repo.name}: evidence endpoint is not a recognizable RPM repository"
                + (f" ({last_error})" if last_error else "")
                + "; Feathered will try the exact package artifact during verification")
    return packages


def probe_repository(repo: RepoSpec, reporter: Optional[Reporter] = None, retries: int = 2) -> Tuple[bool, str]:
    rep = reporter or Reporter()
    if not repo.url.strip():
        return False, "No URL/path configured"
    try:
        refs = get_repo_data(repo, rep, retries=retries)
        primary = refs.get("primary")
        if primary is None:
            return False, "No primary metadata"
        return True, primary.url
    except Exception as exc:
        # A bare 404 does not say whether the path is wrong or the release is
        # simply not published; look at the directory to find out.
        detail = str(exc)
        if "404" in detail or "Not Found" in detail:
            detail += "\n\n" + diagnose_missing_repository(repo.url, rep)
        return False, detail



# RPM version/capability/provider resolution lives in rpm_resolution.py.
# Keep compatibility names here while new code imports the engine directly.
_segments = _rpm_resolution._segments
rpmvercmp = _rpm_resolution.rpmvercmp
compare_evr = _rpm_resolution.compare_evr
_provider_candidates = _rpm_resolution._provider_candidates
_requirement_note = _rpm_resolution._requirement_note
should_ignore = _rpm_resolution.should_ignore
evr_satisfies = _rpm_resolution.evr_satisfies
package_satisfies = _rpm_resolution.package_satisfies
inventory_satisfies = _rpm_resolution.inventory_satisfies
_provider_rank = _rpm_resolution._provider_rank
choose_provider = _rpm_resolution.choose_provider
_detect_default_python_abi = _rpm_resolution._detect_default_python_abi
_python_default_alias = _rpm_resolution._python_default_alias
build_provider_index = _rpm_resolution.build_provider_index
_find_root = _rpm_resolution._find_root
_rich_outer_body = _rpm_resolution._rich_outer_body
_split_top_level_keyword = _rpm_resolution._split_top_level_keyword
_simple_requirement_from_text = _rpm_resolution._simple_requirement_from_text
parse_simple_rich_if = _rpm_resolution.parse_simple_rich_if
parse_simple_rich_or = _rpm_resolution.parse_simple_rich_or
parse_simple_rich_with = _rpm_resolution.parse_simple_rich_with
_package_satisfies_all = _rpm_resolution._package_satisfies_all
_inventory_package_satisfies = _rpm_resolution._inventory_package_satisfies
inventory_satisfies_same_package = _rpm_resolution.inventory_satisfies_same_package
_same_package_provider_candidates = _rpm_resolution._same_package_provider_candidates
_rich_with_note = _rpm_resolution._rich_with_note
_rpm_arch_capability = _rpm_resolution._rpm_arch_capability
format_requirement = _rpm_resolution.format_requirement
_indexed_package_satisfies = _rpm_resolution._indexed_package_satisfies
_selected_or_pending_satisfies = _rpm_resolution._selected_or_pending_satisfies
_constraint_key = _rpm_resolution._constraint_key
_satisfies_constraints = _rpm_resolution._satisfies_constraints
_reject_failed_provider = _rpm_resolution._reject_failed_provider
package_versions = _rpm_resolution.package_versions
_parse_evr_text = _rpm_resolution._parse_evr_text

# These tiny hooks deliberately stay dynamic because downstream tests and
# integrations historically monkeypatch them through core.
_PYDIST_CAP_RE = rpm_capabilities.PYDIST_CAP_RE

def _pep503_name(value: str) -> str:
    return rpm_capabilities.pep503_name(
        value, substitute=lambda pattern, replacement, text: re.sub(pattern, replacement, text))

def canonical_capability_name(name: str) -> str:
    return rpm_capabilities.canonical_capability_name(
        name, pattern=_PYDIST_CAP_RE, normalize=lambda value: _pep503_name(value))

def capability_names_equal(left: str, right: str) -> bool:
    return canonical_capability_name(left) == canonical_capability_name(right)

def _index_keys(name: str) -> Tuple[str, ...]:
    raw = (name or "").strip()
    canonical = canonical_capability_name(raw)
    return (raw,) if canonical == raw else (raw, canonical)

def _resolve_pass(root_requests, packages, preferred_arch, options, reporter, constraints, rejected=None):
    return _rpm_resolution._resolve_pass(
        root_requests, packages, preferred_arch, options, reporter, constraints, rejected,
        build_provider_index_fn=build_provider_index,
    )

def _resolve_once(root_requests, packages, preferred_arch, options, reporter):
    return _rpm_resolution._resolve_once(
        root_requests, packages, preferred_arch, options, reporter,
        build_provider_index_fn=build_provider_index,
    )

def resolve(root_requests, packages, preferred_arch, options, reporter):
    from transaction_model import resolve_transaction
    return resolve_transaction(
        _resolve_once, root_requests, packages, preferred_arch, options, reporter, 'rpm')


def sha256_file(path: Path) -> str:
    return file_hashing.stream_digest(path, hashlib.sha256())


def hash_file(path: Path, algorithm: str) -> str:
    algo = (algorithm or "sha256").lower()
    if algo == "sha": algo = "sha1"
    return file_hashing.stream_digest(path, hashlib.new(algo))


# package-content verification is
# intentionally stricter than generic hashlib support.  Weak repository hashes
# can still be parsed for diagnostics, but they are not accepted as security
# evidence.






# digest selection is a first-class
# provenance control. Keep all published SHA-2 values and choose according to
# repository policy rather than hard-coding SHA-256 or whichever field happened
# to be parsed first.










































# Artifact digest policy and independent-evidence verification live in
# artifact_verification.py.  Transport and hashing remain dynamic core hooks so
# existing callers can still replace them at runtime.
STRONG_PACKAGE_HASHES = _artifact_verification_engine.STRONG_PACKAGE_HASHES
_DIGEST_STRENGTH_ORDER = _artifact_verification_engine._DIGEST_STRENGTH_ORDER
normalized_hash_algorithm = _artifact_verification_engine.normalized_hash_algorithm
strong_package_digest = _artifact_verification_engine.strong_package_digest
normalized_digest_map = _artifact_verification_engine.normalized_digest_map
select_digest_from_map = _artifact_verification_engine.select_digest_from_map
vendor_signature_settings = _artifact_verification_engine.vendor_signature_settings
repository_verification_strategy = _artifact_verification_engine.repository_verification_strategy
package_digest_map = _artifact_verification_engine.package_digest_map
selected_package_digest = _artifact_verification_engine.selected_package_digest
package_has_selected_digest = _artifact_verification_engine.package_has_selected_digest
mirrors_are_distinct = _artifact_verification_engine.mirrors_are_distinct
_artifact_verification = _artifact_verification_engine._artifact_verification
evidence_relationship = _artifact_verification_engine.evidence_relationship
evidence_authority_relationship = _artifact_verification_engine.evidence_authority_relationship
_rpm_source_lineage = _artifact_verification_engine._rpm_source_lineage
independent_peer_packages_match = _artifact_verification_engine.independent_peer_packages_match
find_independent_peer_package = _artifact_verification_engine.find_independent_peer_package
evidence_repo_for_url = _artifact_verification_engine.evidence_repo_for_url
evidence_artifact_candidates = _artifact_verification_engine.evidence_artifact_candidates
_evidence_comparison_algorithm = _artifact_verification_engine._evidence_comparison_algorithm
apply_mirror_evidence = _artifact_verification_engine.apply_mirror_evidence

def probe_evidence_artifact(url: str, repo: RepoSpec, reporter: Reporter) -> Tuple[bool, str]:
    return _artifact_verification_engine.probe_evidence_artifact(
        url, repo, reporter, open_url_fn=_urlopen)

def _stream_hash_url(url: str, algorithms: Iterable[str], repo: RepoSpec,
                     reporter: Reporter, max_bytes: int = MAX_PACKAGE_DOWNLOAD_BYTES) -> Tuple[Dict[str, str], int]:
    return _artifact_verification_engine._stream_hash_url(
        url, algorithms, repo, reporter, max_bytes, open_url_fn=_urlopen)

def spot_compare_artifact_urls(acquisition_url: str, acquisition_repo: RepoSpec,
                               evidence_url: str, evidence_repo: RepoSpec,
                               checksum_policy: str, reporter: Reporter) -> Tuple[bool, str]:
    return _artifact_verification_engine.spot_compare_artifact_urls(
        acquisition_url, acquisition_repo, evidence_url, evidence_repo, checksum_policy, reporter,
        open_url_fn=_urlopen)

def spot_compare_peer_artifact_urls(primary_pkg, acquisition_url: str, acquisition_repo: RepoSpec,
                                    evidence_pkg, evidence_url: str, evidence_repo: RepoSpec,
                                    checksum_policy: str, reporter: Reporter) -> Tuple[bool, str]:
    return _artifact_verification_engine.spot_compare_peer_artifact_urls(
        primary_pkg, acquisition_url, acquisition_repo, evidence_pkg, evidence_url, evidence_repo,
        checksum_policy, reporter, open_url_fn=_urlopen)

def _verify_independent_evidence_payload(pkg, acquisition_path: Path, primary,
                                         computed: Dict[str, str], reporter: Reporter) -> None:
    return _artifact_verification_engine._verify_independent_evidence_payload(
        pkg, acquisition_path, primary, computed, reporter,
        open_url_fn=_urlopen, hash_file_fn=hash_file,
        mirrors_are_distinct_fn=mirrors_are_distinct,
        evidence_relationship_fn=evidence_relationship,
        evidence_authority_relationship_fn=evidence_authority_relationship)

def verify_package_artifact(pkg, path: Path, options: BuildOptions, reporter: Reporter) -> bool:
    return _artifact_verification_engine.verify_package_artifact(
        pkg, path, options, reporter, hash_file_fn=hash_file,
        verify_independent_fn=_verify_independent_evidence_payload)

def _copy_or_download(pkg: DownloadPackage, dest: Path, options: BuildOptions, reporter: Reporter,
                      *, opener=None, verifier=None) -> None:
    # Resolve defaults at call time; backend wrappers retain their local hooks.
    opener = _urlopen if opener is None else opener
    verifier = verify_package_artifact if verifier is None else verifier
    # Confined join: a hostile index cannot redirect this off-origin.
    src = repo_relative_url(pkg.repo.normalized_url, pkg.location, pkg.repo)
    tmp = dest.with_suffix(dest.suffix + ".partial")
    for attempt in range(1, options.retries + 1):
        reporter.check_cancel()
        try:
            if tmp.exists(): tmp.unlink()
            reporter.transfer(pkg.nevra, 0, int(getattr(pkg, "size", 0) or 0))
            parsed = urllib.parse.urlparse(src)
            if parsed.scheme == "file":
                local = Path(urllib.request.url2pathname(parsed.path))
                reporter.log(f"COPY {local} -> {dest.name}")
                limit, expected = package_download_limit(pkg)
                actual = local.stat().st_size
                if actual > limit:
                    raise RuntimeError(
                        f"{pkg.nevra}: local package is {actual:,} bytes, above the allowed "
                        f"{limit:,}-byte package limit")
                if expected and actual != expected:
                    raise RuntimeError(
                        f"{pkg.nevra}: local package size {actual:,} does not match repository "
                        f"metadata size {expected:,}")
                with local.open("rb") as source, tmp.open("wb") as target:
                    copy_package_stream_bounded(source, target, pkg, reporter, actual)
                shutil.copystat(local, tmp)
            else:
                reporter.log(f"DOWNLOAD {redact_url(src)}")
                with opener(src, timeout=90, repo=pkg.repo) as response, tmp.open("wb") as f:
                    declared = response.headers.get("Content-Length") if hasattr(response, "headers") else None
                    copy_package_stream_bounded(response, f, pkg, reporter, declared)
            # use the shared strong-digest/evidence
            # verifier, eliminating RPM's previous missing/MD5 fail-open path.
            verifier(pkg, tmp, options, reporter)
            artifact_digests.publish_payload(tmp, dest)
            return
        except Exception as exc:
            if tmp.exists(): tmp.unlink()
            # An operator cancel raised mid-download must surface as Cancelled,
            # not be retried or reported as a per-package failure on the final
            # attempt.  Re-checking re-raises Cancelled if the event is set.
            reporter.check_cancel()
            # Certificate validation failures are deterministic; fail fast with
            # the concrete remedy instead of burning retries.
            cert_advice = _transport.certificate_failure_advice(exc, src)
            if cert_advice:
                raise RuntimeError(f"Failed {pkg.nevra}: {cert_advice}") from exc
            if attempt == options.retries:
                raise RuntimeError(f"Failed {pkg.nevra}: {exc}") from exc
            reporter.log(redact_text(f"Healing download failure for {pkg.nevra}: {exc}; "
                                     f"retry {attempt + 1}/{options.retries}"))
            time.sleep(min(2 ** (attempt - 1), 5))

# RPM repository emission, target-inventory parsing, and bundle publication now
# live behind dedicated Tk-free modules.  core keeps the historical names as a
# compatibility façade while supplying its dynamic hooks at call time.
emit_rpm_repository = _rpm_repository_writer.emit_rpm_repository
declared_inventory_family = _rpm_target_inventory.declared_inventory_family
parse_target_inventory = _rpm_target_inventory.parse_target_inventory
write_vendor_key_manifest = _rpm_bundle.write_vendor_key_manifest
_write_provenance = _rpm_bundle._write_provenance
_write_assurance_legend = _rpm_bundle._write_assurance_legend
write_bundle_archive = _rpm_bundle.write_bundle_archive
_write_workload_artifacts = _rpm_bundle._write_workload_artifacts

def _rpm_bundle_services():
    return _rpm_bundle.BundleServices(
        load_baseline=load_baseline,
        split_against_baseline=split_against_baseline,
        payload_filenames=payload_filenames,
        verify_package_artifact=verify_package_artifact,
        copy_or_download=_copy_or_download,
        sha256_file=sha256_file,
        repository_verification_strategy=repository_verification_strategy,
        vendor_signature_settings=vendor_signature_settings,
        emit_rpm_repository=emit_rpm_repository,
        write_unified_mirror_records=write_unified_mirror_records,
        write_bundle_index=write_bundle_index,
        trust_summary=_trust_summary,
        format_requirement=format_requirement,
        merge_additive_manifest_rows=merge_additive_manifest_rows,
        redact_url=redact_url,
        url_join=url_join,
        verifier_integrity_error=VerifierIntegrityError,
    )

def write_bundle(result: ResolutionResult, output_dir: Path, options: BuildOptions, reporter: Reporter,
                 metadata: Dict[str, object]) -> Path:
    return _rpm_bundle.write_bundle(
        result, output_dir, options, reporter, metadata, _rpm_bundle_services())

def _write_bundle_body(result: ResolutionResult, output_dir: Path, final_dir: Path, options: BuildOptions,
                       reporter: Reporter, metadata: Dict[str, object]) -> Path:
    return _rpm_bundle._write_bundle_body(
        result, output_dir, final_dir, options, reporter, metadata, _rpm_bundle_services())

