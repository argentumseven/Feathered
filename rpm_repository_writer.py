from __future__ import annotations

import gzip
import hashlib
import posixpath
import time
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Protocol

from core_models import Requirement


class RepositoryWriterReporter(Protocol):
    def log(self, message: str, /) -> None: ...


def _emit_requirement_entries(
    fmt: ET.Element,
    rpm_ns: str,
    tag: str,
    requirements: Iterable[Requirement],
) -> None:
    entries = list(requirements)
    if not entries:
        return

    parent = ET.SubElement(fmt, f"{{{rpm_ns}}}{tag}")
    for requirement in entries:
        attrs = {"name": requirement.name}
        if requirement.flags:
            attrs["flags"] = requirement.flags
        if requirement.version is not None:
            attrs.update(
                {
                    "epoch": requirement.epoch or "0",
                    "ver": requirement.version or "",
                    "rel": requirement.release or "",
                }
            )
        ET.SubElement(parent, f"{{{rpm_ns}}}entry", attrs)


def emit_rpm_repository(output_dir: Path, packages, reporter: RepositoryWriterReporter, preserve_package_locations: bool = False, supplemental_packages=None) -> None:
    """Write repodata/ so the bundle is itself a usable RPM repository.

    Each package's upstream <package> element is re-emitted verbatim with only
    <location> rewritten, so dependency data and digests match exactly what the
    resolver used. Packages whose metadata was not captured are reconstructed
    from the fields Feathered holds, which is enough for dnf to install them.
    """
    packages = list(packages)
    from module_policy import validate_modular_payloads
    # The payload header, not a filename heuristic, identifies modular RPMs.
    for package in packages:
        filename = posixpath.basename(urllib.parse.urlparse(package.location).path)
        payload = output_dir / package.location if preserve_package_locations else output_dir / "rpms" / filename
        if payload.is_file():
            with payload.open("rb") as handle:
                is_rpm = handle.read(4) == b"\xed\xab\xee\xdb"
            if is_rpm:
                from repository_tools import _rpm_header_tags
                labels = _rpm_header_tags(payload).get(5096, [])  # RPMTAG_MODULARITYLABEL
                package.modularity_label = str(labels[0]) if labels else ""
    validate_modular_payloads(packages, supplemental_packages or [])
    ns = "http://linux.duke.edu/metadata/common"
    rpm_ns = "http://linux.duke.edu/metadata/rpm"
    # libsolv/DNF expects the common metadata namespace to be serialized as
    # the default namespace and RPM extensions with the conventional ``rpm``
    # prefix.  ElementTree otherwise invents ns0/ns1 prefixes for detached
    # <package> chunks; those are XML-equivalent but are silently ignored by
    # libsolv's primary.xml reader.
    ET.register_namespace("", ns)
    ET.register_namespace("rpm", rpm_ns)
    chunks = []
    for pkg in packages:
        filename = posixpath.basename(urllib.parse.urlparse(pkg.location).path)
        href = (pkg.location.replace("\\", "/").lstrip("./")
                if preserve_package_locations else f"rpms/{filename}")
        raw = pkg.raw_metadata
        if raw:
            # ElementTree serializes upstream metadata
            # with namespace prefixes (for example <ns0:location>), so regexes
            # looking only for <location> miss the real element.  Modify the
            # namespace-qualified XML structurally instead.
            try:
                element = ET.fromstring(raw)
                location = element.find(f"{{{ns}}}location")
                if location is None:
                    location = next((child for child in element.iter()
                                     if child.tag.rsplit("}", 1)[-1] == "location"), None)
                if location is None:
                    raise ValueError("package metadata contains no <location> element")
                location.set("href", href)
                raw = ET.tostring(element, encoding="unicode")
            except (ET.ParseError, ValueError) as exc:
                raise RuntimeError(f"{pkg.nevra}: cannot rewrite RPM repository location: {exc}") from exc
            chunks.append(raw)
            continue
        # Local repository rebuilds construct Package objects directly from RPM headers. When
        # no upstream raw XML exists, emit the dependency/file metadata Feathered
        # actually parsed instead of writing an empty <format/> element.
        package_el = ET.Element(f"{{{ns}}}package", {"type": "rpm"})
        ET.SubElement(package_el, f"{{{ns}}}name").text = pkg.name
        ET.SubElement(package_el, f"{{{ns}}}arch").text = pkg.arch
        ET.SubElement(package_el, f"{{{ns}}}version", {
            "epoch": pkg.epoch or "0", "ver": pkg.version, "rel": pkg.release or ""})
        checksum_el = ET.SubElement(package_el, f"{{{ns}}}checksum", {
            "type": pkg.checksum_type or "sha256", "pkgid": "YES"})
        checksum_el.text = pkg.checksum or ""
        ET.SubElement(package_el, f"{{{ns}}}size", {"package": str(pkg.size or 0)})
        ET.SubElement(package_el, f"{{{ns}}}location", {"href": href})
        fmt = ET.SubElement(package_el, f"{{{ns}}}format")

        _emit_requirement_entries(fmt, rpm_ns, "provides", pkg.provides)
        _emit_requirement_entries(fmt, rpm_ns, "requires", pkg.requires)
        _emit_requirement_entries(fmt, rpm_ns, "recommends", pkg.recommends)
        _emit_requirement_entries(fmt, rpm_ns, "conflicts", pkg.conflicts)
        _emit_requirement_entries(fmt, rpm_ns, "obsoletes", pkg.obsoletes)
        for file_path in pkg.files:
            ET.SubElement(fmt, f"{{{ns}}}file").text = file_path
        chunks.append(ET.tostring(package_el, encoding="unicode"))

    primary = (f'<?xml version="1.0" encoding="UTF-8"?>\n'
               f'<metadata xmlns="{ns}" xmlns:rpm="{rpm_ns}" packages="{len(chunks)}">\n'
               + "\n".join(chunks) + "\n</metadata>\n").encode("utf-8")
    repodata = output_dir / "repodata"
    repodata.mkdir(parents=True, exist_ok=True)
    compressed = gzip.compress(primary, mtime=0)
    (repodata / "primary.xml.gz").write_bytes(compressed)

    stamp = int(time.time())
    repomd = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<repomd xmlns="http://linux.duke.edu/metadata/repo" '
        'xmlns:rpm="http://linux.duke.edu/metadata/rpm">\n'
        f'  <revision>{stamp}</revision>\n'
        '  <data type="primary">\n'
        f'    <checksum type="sha256">{hashlib.sha256(compressed).hexdigest()}</checksum>\n'
        f'    <open-checksum type="sha256">{hashlib.sha256(primary).hexdigest()}</open-checksum>\n'
        '    <location href="repodata/primary.xml.gz"/>\n'
        f'    <timestamp>{stamp}</timestamp>\n'
        f'    <size>{len(compressed)}</size>\n'
        f'    <open-size>{len(primary)}</open-size>\n'
        '  </data>\n</repomd>\n')
    (repodata / "repomd.xml").write_text(repomd, encoding="utf-8")
    from module_policy import emit_supplemental
    emit_supplemental(output_dir, list(packages) + list(supplemental_packages or []), reporter)
    reporter.log(f"Wrote RPM repository metadata for {len(chunks)} package(s)")
    (output_dir / "USE-AS-REPOSITORY.txt").write_text(
        "This bundle also contains RPM repository metadata.\n\n"
        "On the target, add it as a local repository:\n\n"
        "  sudo tee /etc/yum.repos.d/feathered.repo <<'EOF'\n"
        "  [feathered]\n"
        "  name=Feathered offline bundle\n"
        "  baseurl=file:///path/to/this/bundle\n"
        "  enabled=1\n"
        "  gpgcheck=0\n"
        "  repo_gpgcheck=0\n"
        "  EOF\n\n"
        "baseurl is a URL, not a path. If this bundle lives under a directory containing a\n"
        "space, '#' or '%', percent-encode those characters (a space becomes %20). The\n"
        "generated install-offline.sh does this for you.\n\n"
        "The metadata is unsigned, hence gpgcheck=0 for the repository itself. Individual\n"
        "packages keep their vendor signatures; set gpgcheck=1 and import the vendor key\n"
        "if you want those enforced. Verify rpms/SHA256SUMS.txt before trusting the contents.\n",
        encoding="utf-8")

