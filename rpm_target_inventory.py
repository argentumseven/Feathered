from __future__ import annotations

from pathlib import Path

from core_models import Requirement, TargetInventory
from rpm_resolution import _index_keys, _parse_evr_text

def declared_inventory_family(text: str) -> str:
    """Read META|package_family from an inventory file, if present."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if parts[0] == "META" and len(parts) >= 3 and parts[1] == "package_family":
            return parts[2].strip().lower()
    return ""


def parse_target_inventory(path: Path) -> TargetInventory:
    """Parse inventory v2 or legacy exact-NEVRA inventory.

    v2 format is produced by target_inventory.sh:
      META|key|value
      PKG|name|epoch|version|release|arch
      PROVIDE|name|flags|evr
    PROVIDE lines belong to the most recent PKG line only for reporting; the
    dependency resolver indexes them globally by capability.
    """
    inv = TargetInventory()
    current_pkg = ""
    text = path.read_text(encoding="utf-8", errors="replace")
    declared = declared_inventory_family(text)
    if declared and declared != "rpm":
        raise RuntimeError(
            f"{path.name} is a '{declared}' target inventory, but the selected target uses RPM. "
            "Re-run target_inventory.sh on the intended RHEL/Fedora-family host."
        )
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("DETAIL|"):
            continue
        parts = line.split("|")
        if parts[0] == "ERROR":
            raise RuntimeError(f"{path.name} records a collection failure on the target: "
                               + "|".join(parts[1:]))
        if parts[0] == "DEB":
            # A dpkg record has five fields and used to fall through to the
            # legacy NEVRA branch below, injecting a bogus package named "DEB"
            # and a garbage capability into the resolver index.
            raise RuntimeError(f"{path.name} contains dpkg inventory records, but the selected target "
                               "uses RPM. Re-run target_inventory.sh on the intended host.")
        if parts[0] == "META" and len(parts) >= 3:
            inv.metadata[parts[1]] = "|".join(parts[2:])
            continue
        if parts[0] == "PKG" and len(parts) == 6:
            _, name, epoch, version, release, arch = parts
            ep = "" if epoch in {"", "0", "(none)"} else f"{epoch}:"
            current_pkg = f"{name}-{ep}{version}-{release}.{arch}"
            inv.nevras.add(current_pkg)
            cap = Requirement(name, "EQ", epoch or "0", version, release, "installed")
            inv.package_capabilities[current_pkg].append(cap)
            for key in _index_keys(name):
                inv.capabilities[key].append(cap)
            continue
        if parts[0] == "PROVIDE" and len(parts) >= 4:
            _, name, flags, evr_text = parts[:4]
            epoch, version, release = _parse_evr_text(evr_text)
            normalized_flags = flags.strip() or None
            cap = (Requirement(name, normalized_flags or "EQ", epoch, version, release, "installed")
                   if version else Requirement(name, None, kind="installed"))
            if current_pkg:
                inv.package_capabilities[current_pkg].append(cap)
            for key in _index_keys(name):
                inv.capabilities[key].append(cap)
            continue
        # Legacy NAME|EPOCH|VERSION|RELEASE|ARCH
        if len(parts) == 5 and (parts[1].isdigit() or parts[1] in {"", "(none)"}):
            name, epoch, version, release, arch = parts
            ep = "" if epoch in {"", "0", "(none)"} else f"{epoch}:"
            legacy_nevra = f"{name}-{ep}{version}-{release}.{arch}"
            inv.nevras.add(legacy_nevra)
            cap = Requirement(name, "EQ", epoch or "0", version, release, "installed")
            inv.package_capabilities[legacy_nevra].append(cap)
            for key in _index_keys(name):
                inv.capabilities[key].append(cap)
            continue
        # Anything else is unrecognised. Adding it to the NEVRA set (the old
        # behaviour) made malformed inventories look like valid ones.
        inv.unparsed.append(line)
    if inv.unparsed and not inv.nevras:
        raise RuntimeError(f"{path.name} contains no recognisable package records "
                           f"({len(inv.unparsed)} unparsed line(s)). Re-generate it with target_inventory.sh.")
    from inventory_relationships import attach
    return attach(inv, text, 'rpm')

