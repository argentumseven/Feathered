"""Fail-closed verification for a staged Feathered release distribution.

The release checksum list is audit/evidence metadata, not an authentication root;
Authenticode remains mandatory for Feathered.exe.  This verifier exists so the
build and CI can mechanically prove that SHA256SUMS.txt exactly describes every
other regular file in dist/ and that none of those files changed after the list
was written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

ROW_RE = re.compile(r"^([0-9A-Fa-f]{64})  (.+)$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_relative(raw: str) -> PurePosixPath:
    # write_release_manifest.py deliberately emits POSIX separators so the file
    # is deterministic and portable.  Do not silently reinterpret backslashes,
    # drive letters, absolute paths, or traversal components on Windows.
    if not raw or "\\" in raw or "\x00" in raw:
        raise RuntimeError(f"Unsafe checksum path: {raw!r}")
    rel = PurePosixPath(raw)
    if rel.is_absolute() or not rel.parts or any(part in {"", ".", ".."} for part in rel.parts):
        raise RuntimeError(f"Unsafe checksum path: {raw!r}")
    if ":" in rel.parts[0]:
        raise RuntimeError(f"Unsafe checksum path: {raw!r}")
    return rel


def verify_distribution(dist: Path) -> int:
    dist = dist.resolve()
    sums = dist / "SHA256SUMS.txt"
    if not dist.is_dir():
        raise RuntimeError(f"Release directory does not exist: {dist}")
    if not sums.is_file():
        raise RuntimeError(f"Missing release checksum list: {sums}")

    entries: dict[str, str] = {}
    casefolded: dict[str, str] = {}
    lines = sums.read_text(encoding="utf-8", errors="strict").splitlines()
    if not lines:
        raise RuntimeError("SHA256SUMS.txt is empty")
    for line_no, line in enumerate(lines, 1):
        match = ROW_RE.fullmatch(line)
        if not match:
            raise RuntimeError(f"Malformed SHA256SUMS row {line_no}: {line!r}")
        expected, raw_path = match.groups()
        rel = _safe_relative(raw_path)
        normalized = rel.as_posix()
        key = normalized.casefold()
        if normalized == "SHA256SUMS.txt":
            raise RuntimeError("SHA256SUMS.txt must not contain a self-referential checksum entry")
        if normalized in entries:
            raise RuntimeError(f"Duplicate checksum entry: {normalized}")
        if key in casefolded:
            raise RuntimeError(
                f"Case-insensitive checksum path collision: {casefolded[key]!r} and {normalized!r}")
        entries[normalized] = expected.lower()
        casefolded[key] = normalized

    actual_files: dict[str, Path] = {}
    actual_casefolded: dict[str, str] = {}
    for path in dist.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(f"Release distribution contains a symlink: {path.relative_to(dist).as_posix()}")
        if not path.is_file() or path.resolve() == sums.resolve():
            continue
        rel = path.relative_to(dist).as_posix()
        key = rel.casefold()
        if key in actual_casefolded:
            raise RuntimeError(
                f"Case-insensitive release path collision: {actual_casefolded[key]!r} and {rel!r}")
        actual_files[rel] = path
        actual_casefolded[key] = rel

    listed = set(entries)
    actual = set(actual_files)
    missing = sorted(actual - listed, key=str.casefold)
    stale = sorted(listed - actual, key=str.casefold)
    if missing:
        raise RuntimeError("Release files missing from SHA256SUMS.txt: " + ", ".join(missing))
    if stale:
        raise RuntimeError("SHA256SUMS.txt references missing release files: " + ", ".join(stale))

    failures = []
    for rel in sorted(entries, key=str.casefold):
        observed = sha256(actual_files[rel])
        if observed != entries[rel]:
            failures.append(f"{rel}: expected {entries[rel]}, got {observed}")
    if failures:
        raise RuntimeError("SHA-256 verification failed: " + "; ".join(failures))

    # RELEASE-MANIFEST.json is itself covered by SHA256SUMS.txt.  Requiring it
    # here prevents a partial/old distribution from being mistaken for a modern
    # production release whose evidence set happened to hash correctly.
    if "RELEASE-MANIFEST.json" not in entries:
        raise RuntimeError("SHA256SUMS.txt does not cover RELEASE-MANIFEST.json")
    if "Feathered.exe" not in entries:
        raise RuntimeError("SHA256SUMS.txt does not cover Feathered.exe")

    # Validate the manifest semantically as well as hashing its bytes.  Otherwise
    # a generator bug could produce a self-consistent SHA256SUMS.txt whose signed
    # release evidence contains stale sizes/hashes inside RELEASE-MANIFEST.json.
    manifest_path = actual_files["RELEASE-MANIFEST.json"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Invalid RELEASE-MANIFEST.json: {exc}") from exc
    rows = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError("RELEASE-MANIFEST.json does not contain a files list")

    manifest_rows: dict[str, tuple[int, str]] = {}
    manifest_casefolded: dict[str, str] = {}
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise RuntimeError(f"Invalid RELEASE-MANIFEST.json file row {index}")
        raw_path = row.get("path")
        byte_count = row.get("bytes")
        digest = row.get("sha256")
        if not isinstance(raw_path, str) or not isinstance(byte_count, int) or byte_count < 0:
            raise RuntimeError(f"Invalid RELEASE-MANIFEST.json file row {index}")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9A-Fa-f]{64}", digest) is None:
            raise RuntimeError(f"Invalid RELEASE-MANIFEST.json SHA-256 in row {index}")
        normalized = _safe_relative(raw_path).as_posix()
        if normalized in {"RELEASE-MANIFEST.json", "SHA256SUMS.txt"}:
            raise RuntimeError(f"RELEASE-MANIFEST.json must not list itself or SHA256SUMS.txt: {normalized}")
        key = normalized.casefold()
        if normalized in manifest_rows or key in manifest_casefolded:
            raise RuntimeError(f"Duplicate/colliding RELEASE-MANIFEST.json path: {normalized}")
        manifest_rows[normalized] = (byte_count, digest.lower())
        manifest_casefolded[key] = normalized

    payload_files = {rel: path for rel, path in actual_files.items()
                     if rel != "RELEASE-MANIFEST.json"}
    manifest_names = set(manifest_rows)
    payload_names = set(payload_files)
    missing_manifest = sorted(payload_names - manifest_names, key=str.casefold)
    stale_manifest = sorted(manifest_names - payload_names, key=str.casefold)
    if missing_manifest:
        raise RuntimeError("Release files missing from RELEASE-MANIFEST.json: " + ", ".join(missing_manifest))
    if stale_manifest:
        raise RuntimeError("RELEASE-MANIFEST.json references missing release files: " + ", ".join(stale_manifest))

    for rel, path in payload_files.items():
        expected_bytes, expected_digest = manifest_rows[rel]
        observed_bytes = path.stat().st_size
        if observed_bytes != expected_bytes:
            raise RuntimeError(
                f"RELEASE-MANIFEST.json size mismatch for {rel}: expected {expected_bytes}, got {observed_bytes}")
        # Reuse the already-verified SHA256SUMS digest instead of hashing every
        # payload a second time.  The manifest must report that same digest.
        if entries[rel] != expected_digest:
            raise RuntimeError(
                f"RELEASE-MANIFEST.json SHA-256 mismatch for {rel}: "
                f"manifest {expected_digest}, SHA256SUMS.txt {entries[rel]}")
    return len(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Feathered release SHA-256 evidence")
    parser.add_argument("dist", nargs="?", default="dist", help="staged release directory (default: dist)")
    args = parser.parse_args(argv)
    count = verify_distribution(Path(args.dist))
    print(f"Verified {count} release file(s) against SHA256SUMS.txt")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
