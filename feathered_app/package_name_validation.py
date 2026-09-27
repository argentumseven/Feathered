"""Headless advisory validation of free-form package-name selections.

This checks whether a root name exists in the *loaded* index; it is neither
package dependency resolution nor an authorization to proceed with a build.
"""
from __future__ import annotations

from dataclasses import dataclass
import difflib
import re
from typing import Iterable


@dataclass(frozen=True)
class PackageNameValidation:
    status: str  # empty | index-required | valid | missing
    message: str
    missing: tuple[str, ...] = ()


class PackageNameValidationService:
    @staticmethod
    def check(raw_names: str, packages: Iterable[object] | None) -> PackageNameValidation:
        names = [name for name in re.split(r"[\s,]+", raw_names) if name]
        if not names:
            return PackageNameValidation("empty", "No package names entered.")
        packages = tuple(packages or ())
        if not packages:
            return PackageNameValidation(
                "index-required",
                f"{len(names)} name(s) entered. Use 'Search repositories…' to load the "
                "package index and confirm they exist.",
            )
        known = {pkg.name for pkg in packages}
        provided = {prov.name for pkg in packages
                    for prov in (getattr(pkg, "provides", None) or ())}
        missing = tuple(name for name in names if name not in known and name not in provided)
        if not missing:
            return PackageNameValidation(
                "valid", f"All {len(names)} package name(s) exist in the configured repositories.")
        hints = []
        for name in missing[:4]:
            close = difflib.get_close_matches(name, sorted(known), n=2, cutoff=0.7)
            hints.append(name + (f" (did you mean {', '.join(close)}?)" if close else ""))
        more = f" and {len(missing) - 4} more" if len(missing) > 4 else ""
        return PackageNameValidation(
            "missing",
            f"{len(missing)} name(s) not found: " + "; ".join(hints) + more +
            ". They will be reported as unresolved unless another repository provides them.",
            missing,
        )
