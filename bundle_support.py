"""Package-family-neutral bundle support helpers.

These helpers operate on already-resolved package objects and metadata.  They
contain no transport, GUI, or repository loading logic, which keeps the bundle
writers focused on publication rather than identity/baseline bookkeeping.
"""
from __future__ import annotations

import hmac
import json
import posixpath
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Literal, Protocol, Tuple, TypeVar

import bundle_baseline
import payload_identity
from artifact_verification import strong_package_digest
from core_models import ArtifactVerification


class BundleReporter(Protocol):
    def log(self, message: str, /) -> None: ...
    def warn(self, message: str, /) -> None: ...


class BaselinePackage(Protocol):
    @property
    def name(self) -> str: ...


BaselinePackageT = TypeVar("BaselinePackageT", bound=BaselinePackage)


def load_baseline(
    manifest_path: str,
    reporter: BundleReporter,
    *,
    digest_fn: Callable[[str, str], tuple[str, str] | None] = strong_package_digest,
) -> Dict[str, str]:
    """Read a previous bundle manifest into ``{package_id: digest}``."""
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
        digest=lambda algorithm, value: digest_fn(algorithm, value),
    )
    reporter.log(f"Baseline loaded: {len(baseline)} package(s) already present at the target")
    return baseline


def split_against_baseline(
    selected: Iterable[BaselinePackageT],
    baseline: Dict[str, str],
    reporter: BundleReporter,
    *,
    digest_fn: Callable[[str, str], tuple[str, str] | None] = strong_package_digest,
    compare_fn: Callable[[str, str], bool] = hmac.compare_digest,
) -> Tuple[List[BaselinePackageT], List[BaselinePackageT]]:
    """Partition a closure into ``(to_ship, already_present)`` using a baseline."""
    incomparable: List[str] = []
    ship, skip, unverifiable = bundle_baseline.partition(
        selected,
        baseline,
        digest=lambda algorithm, value: digest_fn(algorithm, value),
        matches=lambda left, right: compare_fn(left, right),
        incomparable=incomparable,
    )
    if incomparable:
        reporter.warn(
            f"{len(incomparable)} package(s) present in the baseline were recorded with a "
            "different digest algorithm than the current repository publishes, so their "
            "contents could not be compared and they are included in full"
            + (" (this differential build is effectively a full bundle)" if not skip else "")
            + ". Rebuild the baseline from the same repositories to restore differential savings.")
    if unverifiable:
        reporter.warn(
            f"{unverifiable} baseline entry/entries record no digest, so their contents "
            "could not be compared; those packages are included rather than assumed "
            "unchanged. Rebuild the baseline with this version of Feathered."
        )
    if skip:
        reporter.log(
            f"Differential build: {len(skip)} package(s) byte-identical to the baseline, "
            f"{len(ship)} to transfer"
        )
    return ship, skip


def windows_payload_key(
    name: str,
    *,
    normalize_fn: Callable[[Literal["NFC"], str], str] = unicodedata.normalize,
) -> str:
    return payload_identity.windows_key(
        name,
        normalize=lambda form, value: normalize_fn(form, value),
    )


def write_unified_mirror_records(output_dir: Path, metadata_dir: Path, options: object) -> None:
    """Write unified-mirror records before the bundle seal is calculated."""
    note = getattr(options, "unified_mirror_note", "") or ""
    records = getattr(options, "unified_mirror_records", None)
    if not note and not records:
        return
    if note:
        (output_dir / "UNIFIED-MIRROR.txt").write_text(note, encoding="utf-8")
    if records is not None:
        (metadata_dir / "mirror-sources.json").write_text(
            json.dumps(records, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def payload_filenames(
    packages: Iterable[object],
    expected_suffix: str,
    *,
    location_name_fn: Callable[[str], str] = lambda location: posixpath.basename(urllib.parse.urlparse(location).path),
    key_fn: Callable[[str], str] = windows_payload_key,
) -> Dict[int, str]:
    """Return platform-independent Windows-safe payload destination names."""
    return payload_identity.payload_filenames(
        packages,
        expected_suffix,
        location_name=location_name_fn,
        key=key_fn,
    )


def meta_str_list(metadata: Dict[str, object], key: str) -> List[str]:
    value = metadata.get(key, [])
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item).strip()]
    return []


def meta_dict_list(metadata: Dict[str, object], key: str) -> List[Dict[str, object]]:
    value = metadata.get(key, [])
    return [item for item in value if isinstance(item, dict)] if isinstance(value, (list, tuple)) else []


def merge_additive_manifest_rows(manifest_path: Path, current_rows: List[dict]) -> List[dict]:
    """Merge a prior bundle manifest with rows produced by this build."""
    try:
        prior = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        old_rows = prior.get("packages", []) if isinstance(prior, dict) else []
    except Exception:
        old_rows = []

    def key(row: dict) -> str:
        return str(
            row.get("filename")
            or row.get("package_id")
            or row.get("nevra")
            or row.get("name")
            or ""
        )

    merged = {
        key(row): dict(row)
        for row in old_rows
        if isinstance(row, dict) and key(row)
    }
    for row in current_rows:
        merged[key(row)] = row
    return list(merged.values())


def record_digest_checked(pkg: object) -> None:
    """Mark that this artifact's own digest was compared against its bytes."""
    record = getattr(pkg, "verification", None)
    if record is None:
        record = ArtifactVerification()
        setattr(pkg, "verification", record)
    record.package_digest_checked = True


def trust_summary(packages: Iterable[object]) -> Dict[str, int]:
    """Aggregate the recorded verification state of shipped artifacts."""
    counts: Dict[str, int] = {}
    for pkg in packages:
        record = getattr(pkg, "verification", None)
        repo = getattr(pkg, "repo", None)
        repo_trust = getattr(repo, "trust", None)
        signed = bool(repo_trust and repo_trust.archive_signature_verified)
        if record is None:
            key = "unverified"
        elif record.vendor_signature_verified:
            key = "vendor-signature"
        elif signed and record.index_digest_verified and record.package_digest_checked:
            key = "archive-chain"
        elif (
            record.evidence_relationship == "independent-peer"
            and record.evidence_peer_identity_match
            and record.evidence_digest_checked
        ):
            key = "independent-peer-corroboration"
        elif record.package_digest_checked and record.evidence_digest_checked:
            key = "corroborated-digest"
        elif record.evidence_metadata_match and record.evidence_digest_checked:
            key = "independent-digest"
        elif record.package_digest_checked:
            key = "digest-only"
        elif record.evidence_metadata_match:
            key = "metadata-corroborated"
        else:
            key = "unverified"
        counts[key] = counts.get(key, 0) + 1
    return counts
