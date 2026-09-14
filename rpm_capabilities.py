"""RPM Python capability spelling, separate from package/version ordering.

Only the Python distribution namespace is normalized. Other capability names
retain their spelling; this is not a shared RPM/DEB/pacman version parser.
"""
from __future__ import annotations

from collections.abc import Callable
import re

PYDIST_CAP_RE = re.compile(r"^(python(?:\d+(?:\.\d+)?)?dist)\((.+)\)$", re.IGNORECASE)


def pep503_name(value: str, *, substitute: Callable[[str, str, str], str]) -> str:
    """Normalize a Python distribution name using the PEP 503 convention.

    RPM's Python dependency generator uses this namespace for python3dist(...)
    and pythonX.Ydist(...) virtual capabilities. RHEL 9 can contain both legacy
    dotted spellings and canonical spellings in Provides while generated
    Requires use the canonical form. Treat those spellings as the same
    capability during lookup without inventing a package-name mapping.
    """
    return substitute(r"[-_.]+", "-", (value or "").strip()).lower()


def canonical_capability_name(name: str, *, pattern: re.Pattern[str],
                              normalize: Callable[[str], str]) -> str:
    raw = (name or "").strip()
    m = pattern.fullmatch(raw)
    if not m:
        return raw
    prefix, dist = m.groups()
    extra = ""
    if "[" in dist and dist.endswith("]"):
        base, raw_extra = dist[:-1].split("[", 1)
        extras = [x for x in raw_extra.split(",") if x.strip()]
        dist = normalize(base)
        extra = "[" + ",".join(normalize(x) for x in extras) + "]"
    else:
        dist = normalize(dist)
    return f"{prefix.lower()}({dist}{extra})"
