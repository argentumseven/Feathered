"""Shared payload acquisition and record emission, without resolver dispatch.

Backends supply their current download/verification hooks and build manifest rows
and summaries themselves. That preserves family-specific trust and field order.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
import json
from pathlib import Path
from typing import TypeVar

import artifact_cache
from artifact_digests import payload_sha256
from core import BuildOptions, Cancelled, DownloadPackage, Reporter
from package_family import PackageFamily

P = TypeVar('P', bound=DownloadPackage)
I = TypeVar('I')


def acquire_payloads(
    packages: Sequence[P], filenames: Mapping[int, str], payload_dir: Path,
    cache_parent: Path, options: BuildOptions[I], reporter: Reporter,
    family: PackageFamily, *, verify: Callable[[P, Path], object],
    download: Callable[[P, Path], None],
) -> None:
    """Acquire staged payloads while retaining the backend's ordered events."""
    total = max(1, len(packages))
    for i, pkg in enumerate(packages, 1):
        reporter.check_cancel()
        dest = payload_dir / filenames[id(pkg)]
        artifact_cache.restore(pkg, dest, cache_parent, options, reporter)
        if dest.exists() and dest.stat().st_size > 0:
            reporter.item(pkg.nevra, 'verifying', size=dest.stat().st_size)
            try:
                verify(pkg, dest)
            except RuntimeError:
                valid = False
            else:
                valid = True
            # Reporting callbacks deliberately sit outside the verifier catch.
            if valid:
                if family.log_reuse:
                    reporter.log(f'REUSE {dest.name} (already present, verification policy satisfied)')
                reporter.item(pkg.nevra, 'reused', size=dest.stat().st_size)
                reporter.progress(f'{family.progress_label} {i}/{total}', i / total)
                continue
            if family.stale_log_first:
                reporter.log(family.stale_message + dest.name)
            reporter.item(pkg.nevra, 'stale', size=dest.stat().st_size)
            if not family.stale_log_first:
                reporter.log(family.stale_message + dest.name)
            dest.unlink()
        reporter.item(pkg.nevra, 'active', size=pkg.size)
        try:
            download(pkg, dest)
            artifact_cache.remember(pkg, dest, cache_parent, reporter)
        except Cancelled:
            reporter.item(pkg.nevra, 'pending')
            raise
        except Exception as exc:
            reporter.item(pkg.nevra, 'failed', detail=str(exc))
            raise
        reporter.item(pkg.nevra, 'done', size=dest.stat().st_size if dest.exists() else pkg.size)
        reporter.progress(f'{family.progress_label} {i}/{total}', i / total)


def write_records(
    metadata_dir: Path, payload_dir: Path, family: PackageFamily,
    payload: Mapping[str, object], rows: Sequence[Mapping[str, object]], *,
    unresolved: Iterable[str], ignored_unresolved: Sequence[str],
    conflicts: Sequence[str], skipped_installed: Sequence[str],
    installed_satisfied: Sequence[str], hash_file: Callable[[Path], str],
) -> None:
    """Write the existing wire format, including optional-file and newline rules.

    The checksum glob is independent of summary counting: pacman signatures
    belong in SHA256SUMS even though they are not counted as package payloads.
    """
    (metadata_dir / 'manifest.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')
    (metadata_dir / 'manifest.txt').write_text(
        '\n'.join(f"{row[family.manifest_identity]}\t{row['repo']}\t{row['reason']}\t{row['source']}"
                  for row in rows) + '\n', encoding='utf-8')
    unresolved_lines = list(unresolved)
    for filename, lines, always in (
        ('unresolved.txt', unresolved_lines, True),
        ('ignored-unresolved.txt', ignored_unresolved, False),
        ('conflicts.txt', conflicts, True),
        ('skipped-installed.txt', skipped_installed, False),
        ('satisfied-by-target.txt', installed_satisfied, False),
    ):
        if lines or always:
            (metadata_dir / filename).write_text(
                '\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')
    with (metadata_dir / 'SHA256SUMS.txt').open('w', encoding='utf-8') as output:
        for path in sorted(payload_dir.glob(family.checksum_glob)):
            output.write(f'{payload_sha256(path, hash_file)}  {path.name}\n')
