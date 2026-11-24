"""Verified payload cache independent of transactional publication staging.

The cache exists so a build that fails or is cancelled does not throw away
payloads it already downloaded: staging is discarded on failure, so this is the
only place they survive. It is an optimisation and is treated as one:

* It is bounded. Entries a build used are kept; everything older is pruned by
  age and then by size (least recently used first), so refreshing a bundle for
  months cannot fill the disk. ``FEATHERED_PAYLOAD_CACHE_BYTES`` and
  ``FEATHERED_PAYLOAD_CACHE_DAYS`` tune this; a size of 0 turns the cache off.
* It is best effort. An unusable cache directory, a full disk, or a bad entry
  degrades to downloading again; it never fails a build or takes the last of
  the free space from the output being written.
* Entries that cannot be restored (tampered, dangling, failing verification)
  are removed instead of being retried on every build.
"""
from __future__ import annotations
from artifact_digests import payload_sha256
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import time

import runtime_limits

_ENTRY_RE = re.compile(r"[0-9a-f]{64}")
# Temporary files are named so cleanup can recognise them. The older unprefixed
# form (tempfile's default) is matched too, to clear leftovers of earlier builds.
_TEMP_PREFIX = ".tmp-"
_LEGACY_TEMP_RE = re.compile(r"tmp[a-z0-9_]{8}")
# Files younger than this are never treated as abandoned: another build may be
# between writing a payload and writing the index entry that refers to it.
_GRACE_SECONDS = 3600
# Never let the cache take the last of the free space from the bundle being built.
_MIN_FREE_BYTES = 512 * 1024 * 1024

# One log line per problem per process, not one per package.
_reported: set[tuple[str, str]] = set()


def _key(pkg):
    payload = (pkg.repo.source_identity, pkg.location, pkg.nevra,
               pkg.checksum_type, pkg.checksum)
    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()


def _enabled() -> bool:
    return runtime_limits.PAYLOAD_CACHE_MAX_BYTES > 0


def _root(parent):
    root = Path(parent) / ".feathered-cache"
    try:
        info = root.lstat()
    except FileNotFoundError:
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass  # a concurrent build created it first; validate it below
        info = root.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError("Payload cache must not be a symlink")
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("Payload cache must be a directory")
    if os.name != "nt" and hasattr(os, "geteuid"):
        if info.st_uid != os.geteuid():
            raise RuntimeError("Payload cache must be owned by the current user")
        if info.st_mode & 0o022:
            raise RuntimeError("Payload cache must not be group- or world-writable")
        if info.st_mode & 0o077:
            root.chmod(0o700)
    return root


def _open(parent, reporter):
    """Return the validated cache root, or None when it cannot be used.

    The strict checks in ``_root`` still decide whether the directory is
    trustworthy; a failure just means this build goes without a cache.
    """
    try:
        return _root(parent)
    except (OSError, RuntimeError) as exc:
        reporter.check_cancel()  # a cancellation is a RuntimeError too
        _unavailable(reporter, parent, exc)
        return None


def _unavailable(reporter, parent, exc) -> None:
    mark = (str(parent), str(exc))
    if mark in _reported:
        return
    _reported.add(mark)
    reporter.log(f"Payload cache not used ({exc}); packages are downloaded as needed.")


def _discard(*paths) -> None:
    for path in paths:
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            pass


def _touch(*paths) -> None:
    """Record use, which is what least-recently-used pruning goes by."""
    for path in paths:
        try:
            os.utime(path, None)
        except OSError:
            pass


def restore(pkg, destination, parent, options, reporter):
    import core
    destination = Path(destination)
    if destination.exists() or not _enabled():
        return
    root = _open(parent, reporter)
    if root is None:
        return
    entry = root / (_key(pkg) + ".json")
    try:
        if entry.is_symlink():
            return
        try:
            digest = json.loads(entry.read_text())["sha256"]
        except FileNotFoundError:
            return  # an ordinary cache miss
        except (ValueError, KeyError, TypeError):
            _discard(entry)
            return
        if not isinstance(digest, str) or not _ENTRY_RE.fullmatch(digest):
            _discard(entry)
            return
        source = root / (digest + ".payload")
        if source.is_symlink() or not source.is_file():
            _discard(entry)  # points at nothing; it can never restore
            return
        if core.sha256_file(source) != digest:
            _discard(entry, source)  # the bytes changed since they were verified
            return
        try:
            core.verify_package_artifact(pkg, source, options, reporter)
        except core.VerifierIntegrityError:
            raise
        except RuntimeError:
            reporter.check_cancel()
            _discard(entry)  # would be refused again on every build
            return
        shutil.copyfile(source, destination)
        _touch(entry, source)
        reporter.log(f"Restored verified payload cache: {pkg.nevra}")
    except core.VerifierIntegrityError:
        raise
    except (OSError, ValueError, KeyError, RuntimeError):
        # A partly copied file must not be mistaken for a payload.
        _discard(destination)
        reporter.check_cancel()
        return


def _has_headroom(root, size) -> bool:
    try:
        return shutil.disk_usage(root).free - size >= _MIN_FREE_BYTES
    except OSError:
        return True  # cannot tell; the copy itself will fail cleanly if it must


def remember(pkg, source, parent, reporter):
    import core
    reporter.check_cancel()
    if not _enabled():
        return
    root = _open(parent, reporter)
    if root is None:
        return
    try:
        digest = payload_sha256(source, core.sha256_file)
        target = root / (digest + ".payload")
        if target.is_symlink():
            raise RuntimeError("Payload cache entry must not be a symlink")
        if target.is_file() and core.sha256_file(target) == digest:
            _touch(target)
        else:
            if not _has_headroom(root, Path(source).stat().st_size):
                _unavailable(reporter, parent, "not enough free space to keep a copy")
                return
            fd, name = tempfile.mkstemp(dir=root, prefix=_TEMP_PREFIX)
            try:
                os.close(fd)
                shutil.copyfile(source, name)
                os.replace(name, target)
            finally:
                Path(name).unlink(missing_ok=True)
        fd, name = tempfile.mkstemp(dir=root, prefix=_TEMP_PREFIX)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"sha256": digest}, f)
            os.replace(name, root / (_key(pkg) + ".json"))
        finally:
            Path(name).unlink(missing_ok=True)
    except (OSError, RuntimeError) as exc:
        reporter.check_cancel()
        _unavailable(reporter, parent, exc)


def prune(parent, packages, reporter, *, now=None) -> None:
    """Bound the cache after a build, whether it succeeded or not.

    Entries for ``packages`` (what this build used) are never removed, so a
    failed build can still be resumed. Everything else expires by age and is
    then trimmed oldest-use-first to the size limit. Abandoned temporary
    files, payloads nothing refers to, and entries referring to nothing are
    removed as well. This never raises: it is housekeeping.
    """
    if not _enabled():
        return
    try:
        _prune(parent, packages, reporter, time.time() if now is None else now)
    except Exception as exc:  # housekeeping must never turn a build into a failure
        reporter.log(f"Payload cache cleanup skipped: {exc}")


def _prune(parent, packages, reporter, now) -> None:
    root = _open(parent, reporter)
    if root is None:
        return
    limit = runtime_limits.PAYLOAD_CACHE_MAX_BYTES
    max_age = runtime_limits.PAYLOAD_CACHE_MAX_AGE_DAYS * 86400

    entries: dict[str, tuple[str, float]] = {}    # entry name -> (digest, last use)
    payloads: dict[str, tuple[int, float]] = {}   # digest -> (size, last use)
    removed = freed = 0

    def remove(path, size=0):
        nonlocal removed, freed
        try:
            Path(path).unlink()
        except FileNotFoundError:
            return
        except OSError:
            return
        removed += 1
        freed += size

    with os.scandir(root) as scan:
        found = list(scan)
    for item in found:
        # Only regular files we recognise are touched. Symlinks and directories
        # are left alone, and nothing is followed out of the cache.
        if item.is_symlink() or not item.is_file(follow_symlinks=False):
            continue
        info = item.stat(follow_symlinks=False)
        stem, dot, suffix = item.name.rpartition(".")
        if dot and suffix == "json" and _ENTRY_RE.fullmatch(stem):
            try:
                digest = json.loads(Path(item.path).read_text())["sha256"]
                if not isinstance(digest, str) or not _ENTRY_RE.fullmatch(digest):
                    raise ValueError("bad digest")
            except FileNotFoundError:
                continue
            except (OSError, ValueError, KeyError, TypeError):
                if now - info.st_mtime > _GRACE_SECONDS:
                    remove(item.path, info.st_size)
                continue
            entries[item.name] = (digest, info.st_mtime)
        elif dot and suffix == "payload" and _ENTRY_RE.fullmatch(stem):
            payloads[stem] = (info.st_size, info.st_mtime)
        elif item.name.startswith(_TEMP_PREFIX) or _LEGACY_TEMP_RE.fullmatch(item.name):
            if now - info.st_mtime > _GRACE_SECONDS:
                remove(item.path, info.st_size)

    protected = {_key(pkg) + ".json" for pkg in packages}

    # An entry whose payload is gone can never restore anything.
    for name, (digest, _used) in list(entries.items()):
        if digest not in payloads:
            remove(root / name)
            del entries[name]

    # Expire what has not been used for a long time.
    if max_age:
        for name, (_digest, used) in list(entries.items()):
            if name not in protected and now - used > max_age:
                remove(root / name)
                del entries[name]

    # Payloads nothing refers to are abandoned, unless a build is mid-write.
    live = {digest for digest, _used in entries.values()}
    for digest, (size, used) in list(payloads.items()):
        if digest not in live and now - used > _GRACE_SECONDS:
            remove(root / (digest + ".payload"), size)
            del payloads[digest]

    # Then trim to the size limit, least recently used first. What this build
    # used is kept even when it alone exceeds the limit.
    pinned = {digest for name, (digest, _used) in entries.items() if name in protected}
    total = sum(size for digest, (size, _used) in payloads.items() if digest in live)
    if total > limit:
        last_use: dict[str, float] = {}
        for digest, used in entries.values():
            last_use[digest] = max(used, last_use.get(digest, 0.0))
        for digest in sorted((d for d in live if d not in pinned), key=lambda d: last_use.get(d, 0.0)):
            if total <= limit:
                break
            size = payloads[digest][0]
            for name, (entry_digest, _used) in list(entries.items()):
                if entry_digest == digest:
                    remove(root / name)
                    del entries[name]
            remove(root / (digest + ".payload"), size)
            total -= size

    if removed:
        reporter.log(f"Payload cache cleanup: removed {removed} file(s), freed {freed / 1e6:,.1f} MB; "
                     f"{total / 1e6:,.1f} MB kept.")
