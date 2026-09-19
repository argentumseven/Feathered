"""Bounded package payload transfer helpers."""
from __future__ import annotations

from typing import Optional, SupportsIndex, SupportsInt, Tuple, Union

from execution_reporter import Reporter
from runtime_limits import MAX_PACKAGE_DOWNLOAD_BYTES


def package_download_limit(pkg) -> Tuple[int, int]:
    """Return (hard transfer ceiling, advertised payload size).

    Package metadata for RPM, DEB, and ALPM records describes the compressed
    artifact byte size.  Treat that value as an exact post-transfer invariant
    when present, and always retain a configurable global ceiling for records
    that omit size metadata.
    """
    try:
        expected = int(getattr(pkg, "size", 0) or 0)
    except (TypeError, ValueError):
        expected = 0
    if expected < 0:
        expected = 0
    if expected > MAX_PACKAGE_DOWNLOAD_BYTES:
        raise RuntimeError(
            f"{getattr(pkg, 'nevra', 'Package')}: advertised size {expected:,} bytes exceeds "
            f"Feathered's configured {MAX_PACKAGE_DOWNLOAD_BYTES:,}-byte per-package limit")
    return (expected if expected > 0 else MAX_PACKAGE_DOWNLOAD_BYTES), expected

def copy_package_stream_bounded(stream, target, pkg, reporter: Reporter,
                                declared_length: Optional[Union[str, bytes, bytearray, SupportsInt, SupportsIndex]] = None) -> int:
    """Copy one package payload while enforcing metadata/global byte ceilings."""
    limit, expected = package_download_limit(pkg)
    try:
        declared = int(declared_length) if declared_length is not None else None
    except (TypeError, ValueError):
        declared = None
    if declared is not None:
        if declared < 0:
            declared = None
        elif declared > limit:
            raise RuntimeError(
                f"{pkg.nevra}: server declared {declared:,} bytes, above the allowed "
                f"{limit:,}-byte package transfer limit")
        elif expected and declared != expected:
            raise RuntimeError(
                f"{pkg.nevra}: server Content-Length {declared:,} does not match repository "
                f"metadata size {expected:,}")
    total = 0
    reported_size = expected or declared or 0
    while True:
        reporter.check_cancel()
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise RuntimeError(
                f"{pkg.nevra}: package transfer exceeded the allowed {limit:,}-byte limit")
        target.write(chunk)
        reporter.transfer(pkg.nevra, total, reported_size)
    if expected and total != expected:
        raise RuntimeError(
            f"{pkg.nevra}: downloaded size {total:,} does not match repository metadata "
            f"size {expected:,}")
    return total

__all__ = ["copy_package_stream_bounded", "package_download_limit"]
