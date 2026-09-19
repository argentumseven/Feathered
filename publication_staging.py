"""Transactional output-directory staging and publication.

A build mutates an isolated sibling snapshot and publishes with a directory swap;
the previously published bundle is restored if the final swap fails.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil

from execution_reporter import Reporter

_BUNDLE_SEAL_PATHS = frozenset({
    "bundle-index.json",
    "bundle-index.json.asc",
    "verify-bundle.py",
    "verify-bundle.py.asc",
})


def _publication_backup_path(dest: Path) -> Path:
    return Path(dest).parent / f".{Path(dest).name}.feathered-previous"

def _recover_interrupted_publication(dest: Path, reporter: Reporter) -> None:
    """Recover/clean the reserved sibling left by an interrupted directory swap."""
    dest = Path(dest)
    backup = _publication_backup_path(dest)
    if not (backup.exists() or backup.is_symlink()):
        return
    if backup.is_symlink() or not backup.is_dir():
        raise RuntimeError(
            f"Reserved publication backup path is not a directory: {backup}. "
            "Move it aside manually before building.")
    if dest.exists() or dest.is_symlink():
        if dest.is_symlink() or not dest.is_dir():
            raise RuntimeError(f"Output destination exists but is not a directory: {dest}")
        # The new directory made it into place and only cleanup was interrupted.
        # This path is reserved exclusively for Feathered's transaction backup.
        try:
            shutil.rmtree(backup)
        except OSError as exc:
            raise RuntimeError(
                f"A prior publication completed, but its transaction backup could not be removed: {backup}: {exc}") from exc
        reporter.log(f"Cleaned prior publication backup: {backup}")
        return
    try:
        os.replace(backup, dest)
    except OSError as exc:
        raise RuntimeError(
            f"A prior publication was interrupted after moving the old bundle. "
            f"Automatic recovery from {backup} failed: {exc}") from exc
    reporter.warn(f"Recovered the previous published bundle after an interrupted final swap: {dest}")

def open_staging(dest: Path, reporter: Reporter) -> Path:
    """Begin a build beside its destination without mutating published data.

    When a destination already exists, staging receives a complete snapshot of
    it. Immutable package payloads are hard-linked where possible; every other
    file is copied so rewriting generated manifests/repository metadata cannot
    mutate the published folder through a shared inode. This lets a subsequent
    build behave as an addendum while still keeping incomplete work isolated.
    """
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    _recover_interrupted_publication(dest, reporter)
    staging = dest.parent / f".{dest.name}.feathered-building"
    if staging.exists() or staging.is_symlink():
        if staging.is_symlink() or not staging.is_dir():
            raise RuntimeError(
                f"Reserved staging path is not a directory: {staging}. Move it aside manually before building.")
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        return staging
    if dest.is_symlink() or not dest.is_dir():
        raise RuntimeError(f"Output destination exists but is not a directory: {dest}")

    def is_payload(relative: Path) -> bool:
        if len(relative.parts) != 2:
            return False
        directory, name = relative.parts
        lower = name.lower()
        if directory == "rpms":
            return lower.endswith(".rpm")
        if directory == "debs":
            return lower.endswith(".deb")
        if directory == "packages":
            return ".pkg.tar." in lower and not lower.endswith(".sig")
        return False

    linked = copied = 0
    for source in sorted(dest.rglob("*"), key=lambda x: str(x).lower()):
        relative = source.relative_to(dest)
        target = staging / relative
        if source.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.symlink_to(os.readlink(source), target_is_directory=source.is_dir())
            except OSError:
                # Windows privilege/policy can reject symlink creation. Copy the
                # resolved object instead; the published source remains untouched.
                if source.is_dir():
                    shutil.copytree(source, target, dirs_exist_ok=True)
                else:
                    shutil.copy2(source, target)
                    copied += 1
            continue
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not source.is_file():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if is_payload(relative):
            try:
                os.link(source, target)
                linked += 1
                continue
            except OSError:
                pass
        shutil.copy2(source, target)
        copied += 1
    if linked or copied:
        reporter.log(
            f"Prepared additive staging from the existing folder: {linked} package payload(s) reused "
            f"and {copied} other file(s) copied; published files remain untouched until final publication.")
    return staging

def invalidate_bundle_seal(staging: Path, reporter: Reporter) -> None:
    """Remove seal artifacts inherited from an older bundle before an unsealed build."""
    staging = Path(staging)
    removed = []
    for name in sorted(_BUNDLE_SEAL_PATHS):
        path = staging / name
        if path.is_symlink() or path.is_file():
            path.unlink()
            removed.append(name)
        elif path.exists():
            raise RuntimeError(
                f"Cannot invalidate stale bundle seal because {name} is a directory. "
                "Resolve the output-folder conflict manually.")
    if removed:
        reporter.warn(
            "Removed stale whole-bundle seal artifacts inherited from the previous bundle because "
            "this build is not being sealed: " + ", ".join(removed))

def _path_present(path: Path) -> bool:
    return path.exists() or path.is_symlink()

def _preflight_additive_snapshot(staging: Path, dest: Path) -> None:
    """Reject merge conflicts before the published directory is moved."""
    for source in sorted(staging.rglob("*"), key=lambda p: (len(p.relative_to(staging).parts), str(p).lower())):
        relative = source.relative_to(staging)
        target = dest / relative
        if not _path_present(target):
            continue
        if source.is_symlink() or target.is_symlink():
            if not (source.is_symlink() and target.is_symlink()
                    and os.readlink(source) == os.readlink(target)):
                raise RuntimeError(
                    f"Cannot publish {relative}: a symlink conflicts with the staged/output path. "
                    "Open the output folder and resolve it manually.")
            continue
        if source.is_dir() and not target.is_dir():
            raise RuntimeError(
                f"Cannot publish {relative}: a file already exists where a directory is required. "
                "Open the output folder and resolve it manually.")
        if source.is_file() and target.is_dir():
            raise RuntimeError(
                f"Cannot publish {relative}: a directory already exists where a file is required. "
                "Open the output folder and resolve it manually.")

def _preserve_destination_only_entries(staging: Path, dest: Path) -> int:
    """Complete staging with destination-only entries before the directory swap."""
    preserved = 0
    for source in sorted(dest.rglob("*"), key=lambda p: (len(p.relative_to(dest).parts), str(p).lower())):
        relative = source.relative_to(dest)
        relative_text = relative.as_posix()
        target = staging / relative
        if _path_present(target):
            continue
        # Missing seal files are deliberate tombstones produced by
        # invalidate_bundle_seal(); carrying them back would recreate a stale
        # signature beside changed bundle contents.
        if relative_text in _BUNDLE_SEAL_PATHS:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source), target_is_directory=source.is_dir())
        elif source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif source.is_file():
            # These entries appeared only in the published destination after
            # staging began (or were deliberately omitted from staging). Copy
            # rather than hard-link so the completed successor cannot be
            # mutated through the still-published inode before the swap.
            shutil.copy2(source, target)
            preserved += 1
    return preserved

def commit_staging(staging: Path, dest: Path, reporter: Reporter) -> Path:
    """Publish a completed additive snapshot with rollback-safe directory swapping.

    Staging begins as a snapshot of the prior destination. Before publication we
    preflight all type/symlink conflicts and restore any destination-only files
    that appeared or were intentionally omitted from staging, except invalidated
    whole-bundle seal artifacts. The old destination is then moved to a reserved
    sibling and the completed staging directory is moved into place. If the
    second move fails, the old directory is restored before the error escapes.
    """
    staging = Path(staging)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if staging.is_symlink() or not staging.is_dir():
        raise RuntimeError(f"Completed staging directory does not exist: {staging}")
    _recover_interrupted_publication(dest, reporter)
    if not dest.exists():
        try:
            os.replace(staging, dest)
        except OSError as exc:
            raise RuntimeError(f"Could not publish completed bundle to {dest}: {exc}") from exc
        reporter.log(f"Bundle published transactionally: {dest} (new destination)")
        return dest
    if dest.is_symlink() or not dest.is_dir():
        raise RuntimeError(f"Output destination exists but is not a directory: {dest}")

    _preflight_additive_snapshot(staging, dest)
    preserved = _preserve_destination_only_entries(staging, dest)
    # Re-run after preservation so a concurrently appeared type conflict cannot
    # slip into the final snapshot after the first check.
    _preflight_additive_snapshot(staging, dest)

    backup = _publication_backup_path(dest)
    if backup.exists() or backup.is_symlink():
        raise RuntimeError(
            f"Reserved publication backup path is unexpectedly occupied: {backup}. "
            "Move it aside manually before building.")

    try:
        os.replace(dest, backup)
    except OSError as exc:
        raise RuntimeError(
            f"Could not begin transactional publication; the previous bundle is untouched: {exc}") from exc

    try:
        os.replace(staging, dest)
    except BaseException as publish_exc:
        try:
            os.replace(backup, dest)
        except BaseException as rollback_exc:
            reporter.warn(
                f"CRITICAL: publication failed and automatic rollback also failed. The previous bundle is "
                f"retained at {backup}; restore it to {dest} before using this output. Rollback error: {rollback_exc}")
            raise RuntimeError(
                f"Bundle publication failed and the previous bundle could not be restored automatically; "
                f"it remains at {backup}") from publish_exc
        reporter.warn("Final publication failed; restored the previous bundle unchanged.")
        raise

    try:
        shutil.rmtree(backup)
    except OSError as exc:
        # The new bundle is already fully in place. Retaining the hidden prior
        # snapshot is a cleanup issue, not a reason to report a failed build.
        reporter.warn(
            f"Bundle published, but the previous transaction snapshot could not be removed ({backup}): {exc}. "
            "Feathered will clean it before the next build.")
    reporter.log(
        f"Bundle published transactionally: {dest}; preserved {preserved} destination-only file(s), "
        "with no per-file in-place mutation of the previously published bundle.")
    return dest

def abandon_staging(staging: Path, reporter: Reporter) -> None:
    """Discard an incomplete build so it cannot be mistaken for a bundle."""
    try:
        if staging and Path(staging).exists():
            shutil.rmtree(staging, ignore_errors=True)
            reporter.log("Discarded the incomplete build; the previous bundle is untouched.")
    except OSError as exc:
        reporter.warn(f"Could not remove the incomplete build directory: {exc}")

__all__ = [
    "abandon_staging",
    "commit_staging",
    "invalidate_bundle_seal",
    "open_staging",
]
