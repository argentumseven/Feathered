#!/usr/bin/env python3
"""Verify a sealed Feathered bundle against its signed index.

Checks three things: that every file listed still matches its recorded digest,
that nothing listed is missing, and that no unexpected file has appeared since
the bundle was sealed. Symlinks and path traversal are rejected: indexed bytes
must be regular files physically contained within this bundle directory.

Files are read in chunks, so a 50 GB artifact costs a few megabytes of memory
rather than being loaded whole.

Verify the signature FIRST - this script only compares hashes, it does not
establish that the index itself is authentic:

    gpgv --keyring operator-keyring.gpg bundle-index.json.asc bundle-index.json
    python3 verify-bundle.py
"""
import hashlib
import json
import pathlib
import sys

CHUNK = 4 * 1024 * 1024
INDEX = "bundle-index.json"
IGNORED = {INDEX, INDEX + ".asc", "verify-bundle.py"}


def digest(path):
    accumulator = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            accumulator.update(block)
    return accumulator.hexdigest()


def safe_target(root, relative):
    """Map one index path to a regular path without following symlinks."""
    text = str(relative)
    posix = pathlib.PurePosixPath(text)
    windows = pathlib.PureWindowsPath(text)
    if (not text or "\\" in text or posix.is_absolute() or windows.is_absolute() or windows.drive
            or any(part in {"", ".", ".."} for part in posix.parts)):
        return None
    if posix.as_posix() != text:
        return None
    target = root.joinpath(*posix.parts)
    current = root
    for part in posix.parts:
        current = current / part
        try:
            if current.is_symlink():
                return None
        except OSError:
            return None
    try:
        target.resolve(strict=False).relative_to(root)
    except (OSError, ValueError):
        return None
    return target


def main():
    root = pathlib.Path(__file__).resolve().parent
    index_path = root / INDEX
    if index_path.is_symlink() or not index_path.is_file():
        print(f"No regular in-bundle {INDEX} here: this bundle was not safely sealed, so there is nothing to verify against.")
        return 2
    # A truncated or malformed index must produce a sentence the receiver can
    # act on, not a traceback.  This script runs on the far side of an air gap
    # where nobody can debug it, and "could not read the index" and "the
    # bundle is intact" must never be confusable.
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        print(f"Unreadable {INDEX}: {error}. This bundle cannot be verified; do not install it.")
        return 2
    if not isinstance(index, dict) or not isinstance(index.get("files"), list):
        print(f"Malformed {INDEX}: no file list. This bundle cannot be verified; do not install it.")
        return 2

    listed = {}
    for entry in index["files"]:
        if (not isinstance(entry, dict) or not isinstance(entry.get("path"), str)
                or not isinstance(entry.get("sha256"), str) or not entry["path"]):
            print(f"Malformed {INDEX}: bad file entry. This bundle cannot be verified; "
                  "do not install it.")
            return 2
        if entry["path"] in listed:
            print(f"Malformed {INDEX}: duplicate entry for {entry['path']}. This bundle "
                  "cannot be verified; do not install it.")
            return 2
        listed[entry["path"]] = entry
    if not listed:
        print(f"Malformed {INDEX}: it lists no files. This bundle cannot be verified; "
              "do not install it.")
        return 2

    missing = []
    modified = []
    unsafe = []
    for relative, entry in sorted(listed.items()):
        target = safe_target(root, relative)
        if target is None:
            unsafe.append(relative)
            continue
        if not target.exists():
            missing.append(relative)
            continue
        try:
            if not target.is_file():
                unsafe.append(relative)
                continue
        except OSError:
            unsafe.append(relative)
            continue
        if digest(target) != entry["sha256"]:
            modified.append(relative)

    present = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if relative in IGNORED:
            continue
        if path.is_symlink():
            unsafe.append(relative)
            continue
        if path.is_file():
            present.add(relative)
    unexpected = sorted(present - set(listed))
    unsafe = sorted(set(unsafe))

    for label, items in (("MISSING", missing), ("MODIFIED", modified),
                         ("UNEXPECTED", unexpected), ("UNSAFE", unsafe)):
        for item in items:
            print(f"{label}: {item}")

    if missing or modified or unexpected or unsafe:
        print(f"\nFAILED: {len(missing)} missing, {len(modified)} modified, "
              f"{len(unexpected)} unexpected, {len(unsafe)} unsafe. Do not install this bundle.")
        return 1
    print(f"OK: {len(listed)} files match the signed index for '{index.get('bundle_id', '?')}', "
          "and nothing else is present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
