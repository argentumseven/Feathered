"""Fail-closed verification that SOURCE-SHA256.json describes this source tree.

The source manifest is generated release evidence, not an authentication root
and not a tracked merge input. Release jobs generate it from the final merged
tree and then verify the same tree before publication or source packaging.

Three failure classes are reported separately because they mean different
things: a MODIFIED file is a stale manifest or a substitution, a MISSING file
is a truncated archive, and an UNLISTED file is content that arrived outside
the release source set.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

from source_manifest import MANIFEST_NAME, is_excluded, iter_source_files


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(raw: str) -> str:
    # The writer emits POSIX separators.  Do not silently reinterpret
    # backslashes, drive letters, absolute paths or traversal components.
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise RuntimeError(f"Unsafe manifest path: {raw!r}")
    relative = PurePosixPath(raw)
    if relative.is_absolute() or not relative.parts:
        raise RuntimeError(f"Unsafe manifest path: {raw!r}")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise RuntimeError(f"Unsafe manifest path: {raw!r}")
    if ":" in relative.parts[0]:
        raise RuntimeError(f"Unsafe manifest path: {raw!r}")
    return relative.as_posix()


def load_manifest(path: Path) -> dict[str, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Unreadable source manifest {path}: {exc}") from exc
    if not isinstance(raw, dict) or not raw:
        raise RuntimeError(f"Source manifest is not a non-empty object: {path}")

    entries: dict[str, str] = {}
    casefolded: dict[str, str] = {}
    for key, value in raw.items():
        relative = _safe_relative(key)
        if not isinstance(value, str) or len(value) != 64:
            raise RuntimeError(f"Malformed SHA-256 for {relative!r}")
        try:
            int(value, 16)
        except ValueError as exc:
            raise RuntimeError(f"Malformed SHA-256 for {relative!r}") from exc
        if relative == MANIFEST_NAME:
            raise RuntimeError("The source manifest must not contain a self-referential entry")
        if is_excluded(relative):
            raise RuntimeError(f"Manifest lists an out-of-scope path: {relative}")
        if relative in entries:
            raise RuntimeError(f"Duplicate manifest entry: {relative}")
        folded = relative.casefold()
        if folded in casefolded:
            # Windows and macOS checkouts cannot hold both, so a colliding pair
            # would verify on Linux and be unrepresentable elsewhere.
            raise RuntimeError(
                f"Case-insensitive manifest path collision: {casefolded[folded]!r} and {relative!r}")
        entries[relative] = value.lower()
        casefolded[folded] = relative
    return entries


def verify_source(root: Path) -> int:
    root = Path(root).resolve()
    if not root.is_dir():
        raise RuntimeError(f"Source directory does not exist: {root}")
    manifest_path = root / MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError(f"Missing source manifest: {manifest_path}")

    entries = load_manifest(manifest_path)
    present = set(iter_source_files(root))

    missing = sorted(set(entries) - present)
    unlisted = sorted(present - set(entries))
    modified = sorted(
        relative for relative in sorted(set(entries) & present)
        if sha256(root / relative) != entries[relative]
    )

    for label, items in (("MISSING", missing), ("MODIFIED", modified), ("UNLISTED", unlisted)):
        for item in items:
            print(f"{label}: {item}")

    if missing or modified or unlisted:
        print(f"\nFAILED: {len(missing)} missing, {len(modified)} modified, "
              f"{len(unlisted)} unlisted. Run write_source_manifest.py after the final "
              "source change and republish.")
        return 1
    print(f"OK: {len(entries)} source files match {MANIFEST_NAME}, and nothing else is present.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parent),
                        help="source tree to verify (default: this checkout)")
    arguments = parser.parse_args()
    try:
        return verify_source(Path(arguments.root))
    except RuntimeError as exc:
        print(f"FAILED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
