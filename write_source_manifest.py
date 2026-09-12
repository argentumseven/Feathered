"""Write SOURCE-SHA256.json for the current Feathered source tree.

Run this as the last source-affecting step of a release.  ``verify_source_
checksums.py`` runs in the release gate and fails closed when the result does
not describe the tree that is about to be published, so a manifest generated
before the final edit cannot ship.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from source_manifest import MANIFEST_NAME, iter_source_files

ROOT = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path) -> dict[str, str]:
    root = Path(root).resolve()
    return {relative: sha256(root / relative) for relative in iter_source_files(root)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=str(ROOT),
                        help="source tree to describe (default: this checkout)")
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero if the existing manifest is already out of date")
    arguments = parser.parse_args()

    root = Path(arguments.root).resolve()
    manifest = build_manifest(root)
    target = root / MANIFEST_NAME
    # Sorted keys and a trailing newline keep the file byte-stable, so an
    # unrelated rerun produces no diff and a real diff means real drift.
    body = json.dumps(manifest, indent=2, sort_keys=True) + "\n"

    if arguments.check:
        current = target.read_text(encoding="utf-8") if target.is_file() else ""
        if current != body:
            print(f"{MANIFEST_NAME} is out of date; run write_source_manifest.py")
            return 1
        print(f"{MANIFEST_NAME} is current ({len(manifest)} files).")
        return 0

    target.write_text(body, encoding="utf-8", newline="\n")
    print(f"Wrote {MANIFEST_NAME}: {len(manifest)} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
