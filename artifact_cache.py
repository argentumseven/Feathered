"""Verified payload cache independent of transactional publication staging."""
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


def _key(pkg):
    payload = (pkg.repo.source_identity, pkg.location, pkg.nevra,
               pkg.checksum_type, pkg.checksum)
    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()


def _root(parent):
    root = Path(parent) / ".feathered-cache"
    try:
        info = root.lstat()
    except FileNotFoundError:
        root.mkdir(mode=0o700)
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


def restore(pkg, destination, parent, options, reporter):
    import core
    destination = Path(destination)
    if destination.exists():
        return
    root = _root(parent)
    try:
        entry = root / (_key(pkg) + ".json")
        if entry.is_symlink():
            return
        digest = json.loads(entry.read_text())["sha256"]
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
            return
        source = root / (digest + ".payload")
        if source.is_symlink() or not source.is_file() or core.sha256_file(source) != digest:
            return
        core.verify_package_artifact(pkg, source, options, reporter)
        shutil.copyfile(source, destination)
        reporter.log(f"Restored verified payload cache: {pkg.nevra}")
    except core.VerifierIntegrityError:
        raise
    except (OSError, ValueError, KeyError, RuntimeError):
        reporter.check_cancel()
        return


def remember(pkg, source, parent, reporter):
    import core
    reporter.check_cancel()
    root = _root(parent)
    digest = payload_sha256(source, core.sha256_file)
    target = root / (digest + ".payload")
    if target.is_symlink():
        raise RuntimeError("Payload cache entry must not be a symlink")
    if not target.is_file() or core.sha256_file(target) != digest:
        fd, name = tempfile.mkstemp(dir=root)
        try:
            os.close(fd)
            shutil.copyfile(source, name)
            os.replace(name, target)
        finally:
            Path(name).unlink(missing_ok=True)
    fd, name = tempfile.mkstemp(dir=root)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"sha256": digest}, f)
        os.replace(name, root / (_key(pkg) + ".json"))
    finally:
        Path(name).unlink(missing_ok=True)
