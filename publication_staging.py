"""Transactional output-directory staging and publication.

A build mutates an isolated sibling snapshot and publishes with a directory swap;
the previously published bundle is restored if the final swap fails.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
import shutil
import stat
import sys

from execution_reporter import Reporter

_BUNDLE_SEAL_PATHS = frozenset({
    "bundle-index.json",
    "bundle-index.json.asc",
    "verify-bundle.py",
    "verify-bundle.py.asc",
})

_INSTALLER_PATHS = (
    "install-offline.sh", "receiver-preflight.py", "INSTALL-OFFLINE-NOTE.txt",
    "USE-AS-REPOSITORY.txt",
)
_TRANSACTION_PATHS = (
    "INSTALLATION-CONTRACT.json", "TRANSACTION-ARGS.txt", "REQUESTED-ROOTS.txt",
    "PACKAGE-ONLY-WARNING.txt", "MIRROR-BUNDLE.txt", "VENDOR-SIGNING-KEYS.txt",
)
_MANAGED_OUTPUT_PATHS = _BUNDLE_SEAL_PATHS | frozenset(_INSTALLER_PATHS) | frozenset(
    f"{directory}/{name}"
    for directory in ("rpms", "debs", "packages")
    for name in _TRANSACTION_PATHS
)


@dataclass
class _PublicationSession:
    destination: Path
    lock_fd: int
    snapshot: dict[str, tuple[int, ...]] | None = None
    preserved: int = 0


_SESSIONS: dict[Path, _PublicationSession] = {}


def _canonical_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    return absolute.parent.resolve() / absolute.name


def _session_key(path: Path) -> Path:
    return Path(os.path.normcase(str(_canonical_path(path))))


def _is_link(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _validate_tree(root: Path) -> None:
    if not (root.exists() or root.is_symlink()):
        return
    if _is_link(root) or not root.is_dir():
        raise RuntimeError(f"Output path must be a regular directory: {root}")
    for path in root.rglob("*"):
        if _is_link(path):
            raise RuntimeError(f"Output contains a symlink or reparse point: {path}")
        if not (path.is_dir() or path.is_file()):
            raise RuntimeError(f"Output contains an unsupported file type: {path}")


def _destination_snapshot(dest: Path) -> dict[str, tuple[int, ...]]:
    _validate_tree(dest)
    if not dest.exists():
        return {}
    result: dict[str, tuple[int, ...]] = {"": (stat.S_IFDIR,)}
    for path in dest.rglob("*"):
        info = path.stat()
        result[path.relative_to(dest).as_posix()] = (
            stat.S_IFMT(info.st_mode), info.st_dev, info.st_ino,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        )
    return result


def _release_session(staging: Path) -> None:
    session = _SESSIONS.pop(_session_key(staging), None)
    if session is not None:
        os.close(session.lock_fd)


def _session(staging: Path, dest: Path) -> _PublicationSession:
    session = _SESSIONS.get(_session_key(staging))
    if session is None or _session_key(session.destination) != _session_key(dest):
        raise RuntimeError("Publication requires an active staging session for this destination.")
    return session


def _acquire_destination_lock(dest: Path) -> int:
    lock = dest.parent / f".{dest.name}.feathered-lock"
    if lock.exists() or lock.is_symlink():
        if _is_link(lock) or not lock.is_file():
            raise RuntimeError(f"Publication lock is not a regular file: {lock}")
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if _is_link(lock) or not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError(f"Publication lock is not a regular file: {lock}")
        if sys.platform == "win32":
            import msvcrt
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(descriptor)
        raise RuntimeError(f"Another build is publishing to {dest}. Wait for it to finish.") from exc
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


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
    """Lock the destination until this build commits or abandons its staging."""
    dest = _canonical_path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = dest.parent / f".{dest.name}.feathered-building"
    if _session_key(staging) in _SESSIONS:
        raise RuntimeError(f"Another build is publishing to {dest}. Wait for it to finish.")
    descriptor = _acquire_destination_lock(dest)
    _SESSIONS[_session_key(staging)] = _PublicationSession(dest, descriptor)
    try:
        return _open_staging_snapshot(dest, reporter)
    except BaseException:
        try:
            if staging.is_dir() and not _is_link(staging):
                shutil.rmtree(staging, ignore_errors=True)
        finally:
            _release_session(staging)
        raise


def _open_staging_snapshot(dest: Path, reporter: Reporter) -> Path:
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
    _validate_tree(dest)
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


def reset_installation_outputs(staging: Path, metadata_dir: Path) -> None:
    """Remove generated transaction files before writing the current output mode."""
    for path in (
        *(Path(staging) / name for name in _INSTALLER_PATHS),
        *(Path(metadata_dir) / name for name in _TRANSACTION_PATHS),
    ):
        if path.is_file() or path.is_symlink():
            path.unlink()
        elif path.exists():
            raise RuntimeError(f"Generated output path is occupied by a directory: {path}")

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

def _preserve_destination_only_entries(staging: Path, dest: Path, *, sealed: bool = False) -> int:
    """Complete staging with destination-only entries before the directory swap."""
    preserved = 0
    for source in sorted(dest.rglob("*"), key=lambda p: (len(p.relative_to(dest).parts), str(p).lower())):
        if _is_link(source):
            raise RuntimeError(f"Output contains a symlink or reparse point: {source}")
        relative = source.relative_to(dest)
        relative_text = relative.as_posix()
        target = staging / relative
        if _path_present(target):
            continue
        # Missing generated outputs are deliberate removals, not user files.
        if relative_text in _MANAGED_OUTPUT_PATHS:
            continue
        if sealed:
            raise RuntimeError(
                f"Output changed after sealing: {relative}. Rebuild before publishing.")
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif source.is_file():
            # These entries appeared only in the published destination after
            # staging began (or were deliberately omitted from staging). Copy
            # rather than hard-link so the completed successor cannot be
            # mutated through the still-published inode before the swap.
            shutil.copy2(source, target)
            preserved += 1
    return preserved


def prepare_publication(staging: Path, dest: Path, reporter: Reporter, *, will_seal: bool = False) -> None:
    """Complete preservation before sealing and freeze the destination snapshot."""
    session = _session(staging, dest)
    _validate_tree(staging)
    _validate_tree(dest)
    if dest.exists():
        _preflight_additive_snapshot(staging, dest)
        session.preserved = _preserve_destination_only_entries(
            staging, dest, sealed=(Path(staging) / "bundle-index.json").exists() and not will_seal)
        _preflight_additive_snapshot(staging, dest)
    session.snapshot = _destination_snapshot(dest)

def commit_staging(staging: Path, dest: Path, reporter: Reporter) -> Path:
    """Publish a completed additive snapshot with rollback-safe directory swapping.

    Preservation finishes before sealing, and publication refuses changes to
    the destination after preparation. Removed generated outputs remain absent.
    The old destination is moved to a reserved sibling before staging is moved
    into place. If the second move fails, the old directory is restored.
    """
    staging = Path(staging)
    dest = _canonical_path(dest)
    session = _session(staging, dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if staging.is_symlink() or not staging.is_dir():
        raise RuntimeError(f"Completed staging directory does not exist: {staging}")
    _recover_interrupted_publication(dest, reporter)
    if session.snapshot is None:
        prepare_publication(staging, dest, reporter)
    if _destination_snapshot(dest) != session.snapshot:
        raise RuntimeError("Output changed after publication was prepared. Rebuild before publishing.")
    _validate_tree(staging)
    if not dest.exists():
        try:
            os.replace(staging, dest)
        except OSError as exc:
            raise RuntimeError(f"Could not publish completed bundle to {dest}: {exc}") from exc
        _release_session(staging)
        reporter.log(f"Bundle published transactionally: {dest} (new destination)")
        return dest
    if dest.is_symlink() or not dest.is_dir():
        raise RuntimeError(f"Output destination exists but is not a directory: {dest}")

    _preflight_additive_snapshot(staging, dest)
    preserved = session.preserved

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
        if _destination_snapshot(backup) != session.snapshot:
            raise RuntimeError("Output changed during publication. Rebuild before publishing.")
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
    _release_session(staging)
    reporter.log(
        f"Bundle published transactionally: {dest}; preserved {preserved} destination-only file(s), "
        "with no per-file in-place mutation of the previously published bundle.")
    return dest

def abandon_staging(staging: Path, reporter: Reporter) -> None:
    """Discard an incomplete build so it cannot be mistaken for a bundle."""
    if _session_key(staging) not in _SESSIONS:
        return
    try:
        if staging and Path(staging).exists():
            shutil.rmtree(staging, ignore_errors=True)
            reporter.log("Discarded the incomplete build; the previous bundle is untouched.")
    except OSError as exc:
        reporter.warn(f"Could not remove the incomplete build directory: {exc}")
    finally:
        _release_session(staging)

__all__ = [
    "abandon_staging",
    "commit_staging",
    "invalidate_bundle_seal",
    "open_staging",
    "prepare_publication",
    "reset_installation_outputs",
]
