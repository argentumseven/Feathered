"""Pure payload destination naming, independent of platform and package family.

Callers own URL interpretation and normalization hooks. This module retains the
existing refusal rules and object-identity mapping; it does not write any files.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Dict, Literal, Tuple


def windows_key(name: str, *, normalize: Callable[[Literal["NFC"], str], str]) -> str:
    """Return the Win32-equivalent destination key for a bundle payload.

    Feathered is primarily built and staged on Windows.  NTFS/Win32 paths are
    normally case-insensitive and Win32 also ignores trailing spaces/dots, so
    checking raw Python strings can accept two logical payloads that address
    the same physical file.  Unicode NFC + casefold is deliberately stricter
    and platform-independent so Linux CI can regression-test Windows staging.
    """
    return normalize("NFC", str(name)).rstrip(" .").casefold()


def payload_filenames(packages: Iterable[object], expected_suffix: str, *,
                      location_name: Callable[[str], str], key: Callable[[str], str]) -> Dict[int, str]:
    """Return Windows-safe, collision-free destination payload names."""
    # Object identity distinguishes equal package names/versions from different
    # repositories. Callers retain the original package objects through writing;
    # copying, streaming or releasing them would invalidate these id() keys.
    seen: Dict[str, Tuple[str, object]] = {}
    result: Dict[int, str] = {}
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    for pkg in packages:
        name = location_name(getattr(pkg, "location", ""))
        if not name or (expected_suffix and not name.lower().endswith(expected_suffix.lower())):
            raise RuntimeError(f"{getattr(pkg, 'nevra', getattr(pkg, 'name', 'package'))}: "
                               f"repository location has no usable {expected_suffix} filename")
        # posixpath.basename only splits on '/', so a location carrying Windows
        # separators survives it intact. Path('rpms') / r'\Windows\evil.rpm' is
        # drive-absolute on Windows, and 'C:x.rpm' is drive-relative, so either
        # would place the payload outside the bundle. repo_relative_url refuses
        # these before a fetch is attempted, but this function is what actually
        # names the destination and must not rely on a check in another module.
        if "\\" in name or ":" in name or "/" in name:
            raise RuntimeError(
                f"Bundle filename is not Windows-safe: {name!r} contains a path separator "
                "or drive marker; refusing to write a payload outside the bundle directory.")
        if name.rstrip(" .") != name:
            raise RuntimeError(f"Bundle filename is not Windows-safe: {name!r} ends in a space or dot.")
        stem = name.split(".", 1)[0].casefold()
        if stem in reserved:
            raise RuntimeError(f"Bundle filename is not Windows-safe: {name!r} uses a reserved device name.")
        identity = getattr(pkg, "nevra", None) or getattr(pkg, "name", name)
        destination_key = key(name)
        previous = seen.get(destination_key)
        if previous and previous[1] != identity:
            raise RuntimeError(
                f"Bundle filename collision: {previous[1]} ({previous[0]}) and {identity} ({name}) "
                "map to the same Windows destination. Feathered refuses to overwrite either artifact.")
        seen[destination_key] = (name, identity)
        result[id(pkg)] = name
    return result
