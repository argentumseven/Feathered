"""Scope rules for Feathered's source integrity manifest.

``SOURCE-SHA256.json`` records the SHA-256 of every tracked source file so a
recipient of a source archive can prove the tree was not altered in transit.
It is evidence metadata, not an authentication root: an attacker who can edit
the tree can edit the manifest.  Its value is that the release gate refuses to
publish when the manifest and the tree disagree, so a stale manifest cannot
quietly ship alongside changed code.

Writer and verifier share this module deliberately.  When the two sides carry
their own copies of the walk rules they drift, and a manifest that silently
stops covering a directory looks exactly like a manifest that passes.
"""
from __future__ import annotations

from pathlib import Path

MANIFEST_NAME = "SOURCE-SHA256.json"

# Directories that do not contain release source.  Byte-compiled caches are
# excluded because they are derived, interpreter-version specific, and were
# historically packaged by accident.
EXCLUDED_DIRECTORIES = frozenset({
    "__pycache__",
    ".git",
    ".github/.cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    ".release-venv",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
})

# ``validation/`` holds captured output from running the gates against this
# tree.  It is deliberately outside the manifest: the logs are produced by a
# run that includes the manifest check itself, so covering them would mean the
# manifest could only be correct for a tree whose evidence describes a
# different manifest.  Evidence of a run cannot hash the record of itself.
# The logs are still published; their integrity is carried by the release
# distribution's own SHA256SUMS.txt when they are shipped.
EXCLUDED_TOP_LEVEL = frozenset({"validation"})

EXCLUDED_SUFFIXES = frozenset({".pyc", ".pyo", ".pyd", ".so", ".coverage"})

EXCLUDED_NAMES = frozenset({MANIFEST_NAME, ".coverage", ".DS_Store", "Thumbs.db"})


def is_excluded(relative: str) -> bool:
    """True when a root-relative POSIX path is outside the manifest's scope."""
    parts = relative.split("/")
    if len(parts) > 1 and parts[0] in EXCLUDED_TOP_LEVEL:
        return True
    if any(part in EXCLUDED_DIRECTORIES for part in parts[:-1]):
        return True
    if any(part.startswith(".") and part.endswith("-venv") for part in parts[:-1]):
        return True
    name = parts[-1]
    if name in EXCLUDED_NAMES:
        return True
    return Path(name).suffix in EXCLUDED_SUFFIXES


def iter_source_files(root: Path):
    """Yield root-relative POSIX paths for every in-scope regular file.

    Symlinks are refused rather than skipped.  A skipped symlink would leave a
    path both absent from the manifest and present in the tree, which is the
    shape of an undetected substitution.
    """
    root = Path(root).resolve()
    for candidate in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        relative = candidate.relative_to(root).as_posix()
        if is_excluded(relative):
            continue
        if candidate.is_symlink():
            raise RuntimeError(f"Source tree contains a symlink: {relative}")
        if candidate.is_file():
            yield relative
