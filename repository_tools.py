"""Sidecar repository-maintenance workflows for Feathered.

1.0.39 introduces repository utilities that
operate on package files already on disk.  They deliberately do not participate
in the five-step acquisition wizard: rebuilding metadata is a maintenance task,
not a new bundle transaction.
"""
from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import shutil
import struct
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import apt_core
import arch_core
import core
import provenance

try:
    import zstandard as zstd  # type: ignore
except Exception:  # pragma: no cover - optional fallback
    zstd = None


Progress = Callable[[str, float], None]
Log = Callable[[str], None]
LocalPackage = core.Package | apt_core.DebPackage | arch_core.ArchPackage

# sidecar repository rebuilds parse package
# files supplied from disk, which may be just as untrusted as network metadata.
# Control/header metadata should stay small even when package payloads are huge.
MAX_CONTROL_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_CONTROL_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_DEB_CONTROL_FILE_BYTES = 8 * 1024 * 1024


@dataclass
class RepositoryScan:
    root: Path
    rpm_files: List[Path] = field(default_factory=list)
    deb_files: List[Path] = field(default_factory=list)
    arch_files: List[Path] = field(default_factory=list)
    manifests: List[Path] = field(default_factory=list)
    existing_rpm_metadata: bool = False
    existing_apt_metadata: bool = False
    existing_arch_metadata: bool = False

    @property
    def family(self) -> str:
        families = [name for name, values in (("rpm", self.rpm_files), ("deb", self.deb_files),
                                               ("arch", self.arch_files)) if values]
        if len(families) > 1:
            return "mixed"
        return families[0] if families else "empty"

    @property
    def count(self) -> int:
        return len(self.rpm_files) + len(self.deb_files) + len(self.arch_files)


@dataclass
class RebuildReport:
    family: str
    package_count: int
    root: Path
    metadata_paths: List[str]
    provenance_preserved: int = 0
    local_only: int = 0
    warnings: List[str] = field(default_factory=list)


def scan_repository_folder(root: Path) -> RepositoryScan:
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise RuntimeError(f"Repository folder does not exist: {root}")
    rpm_files: List[Path] = []
    deb_files: List[Path] = []
    arch_files: List[Path] = []
    manifests: List[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(
                f"Repository maintenance refuses symbolic links inside the selected root: {path.relative_to(root)}")
        if not path.is_file():
            continue
        lower = path.name.lower()
        if lower.endswith(".rpm"):
            rpm_files.append(path)
        elif lower.endswith(".deb"):
            deb_files.append(path)
        elif ".pkg.tar." in lower and not lower.endswith(".sig"):
            arch_files.append(path)
        elif lower == "manifest.json":
            manifests.append(path)
    return RepositoryScan(
        root=root,
        rpm_files=sorted(rpm_files),
        deb_files=sorted(deb_files),
        arch_files=sorted(arch_files),
        manifests=sorted(manifests),
        existing_rpm_metadata=(root / "repodata" / "repomd.xml").is_file(),
        existing_apt_metadata=(root / "dists").is_dir(),
        existing_arch_metadata=any(root.glob("*.db")),
    )


def _hashes(path: Path) -> Dict[str, str]:
    digests = {"sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            for digest in digests.values():
                digest.update(block)
    return {name: digest.hexdigest() for name, digest in digests.items()}


# ---------------------------------------------------------------------------
# DEB metadata
# ---------------------------------------------------------------------------

def _find_ar_member(path: Path, prefix: str) -> Tuple[str, bytes]:
    """Return one ar member without reading the complete .deb into memory."""
    with path.open("rb") as handle:
        if handle.read(8) != b"!<arch>\n":
            raise RuntimeError(f"{path.name}: not a Debian ar archive")
        while True:
            header = handle.read(60)
            if not header:
                break
            if len(header) != 60 or header[58:60] != b"`\n":
                raise RuntimeError(f"{path.name}: malformed ar member header")
            raw_name = header[:16].decode("utf-8", "replace").strip()
            try:
                size = int(header[48:58].decode("ascii", "replace").strip())
            except ValueError as exc:
                raise RuntimeError(f"{path.name}: malformed ar member size") from exc
            name = raw_name.rstrip("/")
            if name.startswith(prefix):
                if size > MAX_CONTROL_ARCHIVE_BYTES:
                    raise RuntimeError(
                        f"{path.name}: {name} is {size:,} bytes, above Feathered's "
                        f"{MAX_CONTROL_ARCHIVE_BYTES:,}-byte package-control limit")
                payload = handle.read(size)
                if len(payload) != size:
                    raise RuntimeError(f"{path.name}: truncated ar member {raw_name}")
                return name, payload
            handle.seek(size + (size % 2), 1)
    raise RuntimeError(f"{path.name}: {prefix} archive not found")


def _ar_members(path: Path) -> Iterable[Tuple[str, bytes]]:
    """Compatibility iterator; streams members instead of reading the whole DEB."""
    with path.open("rb") as handle:
        if handle.read(8) != b"!<arch>\n":
            raise RuntimeError(f"{path.name}: not a Debian ar archive")
        while True:
            header = handle.read(60)
            if not header:
                break
            if len(header) != 60 or header[58:60] != b"`\n":
                raise RuntimeError(f"{path.name}: malformed ar member header")
            raw_name = header[:16].decode("utf-8", "replace").strip()
            try:
                size = int(header[48:58].decode("ascii", "replace").strip())
            except ValueError as exc:
                raise RuntimeError(f"{path.name}: malformed ar member size") from exc
            name = raw_name.rstrip("/")
            payload = handle.read(size)
            if len(payload) != size:
                raise RuntimeError(f"{path.name}: truncated ar member {raw_name}")
            yield name, payload
            if size % 2:
                handle.seek(1, 1)


def _decompress_control(name: str, payload: bytes) -> bytes:
    lower = name.lower()
    if lower.endswith((".gz", ".xz", ".bz2", ".zst", ".zstd")):
        return core.decompress_metadata(payload, name, max_bytes=MAX_CONTROL_EXPANDED_BYTES)
    if lower.endswith(".tar"):
        if len(payload) > MAX_CONTROL_EXPANDED_BYTES:
            raise RuntimeError(f"Debian control archive exceeds Feathered's package-control limit: {name}")
        return payload
    raise RuntimeError(f"Unsupported Debian control archive compression: {name}")


def _read_deb_control(path: Path) -> Dict[str, str]:
    name, payload = _find_ar_member(path, "control.tar")
    tar_bytes = _decompress_control(name, payload)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
        # Strip "./" prefixes, not the characters "." and "/": lstrip("./")
        # also turned ".control" and "..control" into "control".
        def _control_name(name: str) -> str:
            while name.startswith("./"):
                name = name[2:]
            return name
        member = next((m for m in tf.getmembers()
                       if m.isfile() and _control_name(m.name) == "control"), None)
        if member is None:
            raise RuntimeError(f"{path.name}: control file not found")
        extracted = tf.extractfile(member)
        if extracted is None:
            raise RuntimeError(f"{path.name}: cannot read control file")
        if member.size > MAX_DEB_CONTROL_FILE_BYTES:
            raise RuntimeError(
                f"{path.name}: control file is {member.size:,} bytes, above Feathered's "
                f"{MAX_DEB_CONTROL_FILE_BYTES:,}-byte package-control limit")
        text = extracted.read(MAX_DEB_CONTROL_FILE_BYTES + 1).decode("utf-8", "replace")
    records = apt_core._parse_deb822(text)
    if not records:
        raise RuntimeError(f"{path.name}: package control metadata is empty")
    return records[0]


def _deb_package_from_file(path: Path, root: Path, repo: core.RepoSpec) -> apt_core.DebPackage:
    fields = _read_deb_control(path)
    name = fields.get("Package", "").strip()
    version = fields.get("Version", "").strip()
    arch = fields.get("Architecture", "").strip()
    if not (name and version and arch):
        raise RuntimeError(f"{path.name}: Package, Version, or Architecture is missing")
    hashes = _hashes(path)
    location = path.relative_to(root).as_posix()
    fields = dict(fields)
    fields["Filename"] = location
    fields["Size"] = str(path.stat().st_size)
    fields["SHA256"] = hashes["sha256"]
    fields["SHA512"] = hashes["sha512"]
    return apt_core.DebPackage(
        name=name, arch=arch, version=version, location=location,
        checksum_type="sha512", checksum=hashes["sha512"], repo=repo,
        digests=hashes,
        provides=apt_core.parse_provides(fields.get("Provides", "")),
        depends=apt_core.parse_dependency_field(fields.get("Depends", ""), "depends"),
        pre_depends=apt_core.parse_dependency_field(fields.get("Pre-Depends", ""), "pre-depends"),
        recommends=apt_core.parse_dependency_field(fields.get("Recommends", ""), "recommends"),
        conflicts=apt_core.parse_dependency_field(fields.get("Conflicts", ""), "conflicts"),
        breaks=apt_core.parse_dependency_field(fields.get("Breaks", ""), "breaks"),
        size=path.stat().st_size, multi_arch=fields.get("Multi-Arch", "").strip(),
        raw_fields=fields,
    )


# ---------------------------------------------------------------------------
# RPM metadata
# ---------------------------------------------------------------------------

RPMTAG_NAME = 1000
RPMTAG_VERSION = 1001
RPMTAG_RELEASE = 1002
RPMTAG_EPOCH = 1003
RPMTAG_SIZE = 1009
RPMTAG_ARCH = 1022
RPMTAG_PROVIDENAME = 1047
RPMTAG_REQUIREFLAGS = 1048
RPMTAG_REQUIRENAME = 1049
RPMTAG_REQUIREVERSION = 1050
RPMTAG_CONFLICTFLAGS = 1053
RPMTAG_CONFLICTNAME = 1054
RPMTAG_CONFLICTVERSION = 1055
RPMTAG_OBSOLETENAME = 1090
RPMTAG_PROVIDEFLAGS = 1112
RPMTAG_PROVIDEVERSION = 1113
RPMTAG_OBSOLETEFLAGS = 1114
RPMTAG_OBSOLETEVERSION = 1115
RPMTAG_DIRINDEXES = 1116
RPMTAG_BASENAMES = 1117
RPMTAG_DIRNAMES = 1118
# Modern dependency-generator weak-dependency tags.
RPMTAG_RECOMMENDNAME = 5046
RPMTAG_RECOMMENDVERSION = 5047
RPMTAG_RECOMMENDFLAGS = 5048

_TYPE_INT8 = 2
_TYPE_INT16 = 3
_TYPE_INT32 = 4
_TYPE_INT64 = 5
_TYPE_STRING = 6
_TYPE_BIN = 7
_TYPE_STRING_ARRAY = 8
_TYPE_I18NSTRING = 9


def _rpm_values(data: bytes, store: int, entry: Tuple[int, int, int, int]):
    _tag, typ, offset, count = entry
    start = store + offset
    if start < 0 or start > len(data):
        return []
    if typ in (_TYPE_STRING, _TYPE_STRING_ARRAY, _TYPE_I18NSTRING):
        values: List[str] = []
        cursor = start
        wanted = max(1, count if typ != _TYPE_STRING else 1)
        for _ in range(wanted):
            end = data.find(b"\0", cursor)
            if end < 0:
                break
            values.append(data[cursor:end].decode("utf-8", "replace"))
            cursor = end + 1
        return values
    if typ in (_TYPE_INT8, _TYPE_INT16, _TYPE_INT32, _TYPE_INT64):
        widths = {_TYPE_INT8: 1, _TYPE_INT16: 2, _TYPE_INT32: 4, _TYPE_INT64: 8}
        width = widths[typ]
        numbers: List[int] = []
        for i in range(count):
            chunk = data[start + i * width:start + (i + 1) * width]
            if len(chunk) != width:
                break
            numbers.append(int.from_bytes(chunk, "big", signed=False))
        return numbers
    if typ == _TYPE_BIN:
        return [data[start:start + count]]
    return []


def _rpm_header_tags(path: Path) -> Dict[int, list]:
    # repository repair needs only the RPM
    # immutable header. Reuse provenance's bounded header reader instead of
    # loading a potentially multi-gigabyte payload into RAM.
    with path.open("rb") as handle:
        lead = handle.read(provenance._RPM_LEAD_SIZE)
    if len(lead) != provenance._RPM_LEAD_SIZE or lead[:4] != b"\xed\xab\xee\xdb":
        raise RuntimeError(f"{path.name}: not an RPM file")
    _sig_blob, _sig_entries, _sig_store, sig_end = provenance._read_header_at(
        path, provenance._RPM_LEAD_SIZE)
    main_offset = sig_end + (-sig_end % 8)
    data, entries, store, _main_end = provenance._read_header_at(path, main_offset)
    tags: Dict[int, list] = {}
    for entry in entries:
        tags[entry[0]] = _rpm_values(data, store, entry)
    return tags


def _first(tags: Dict[int, list], tag: int, default=""):
    values = tags.get(tag) or []
    return values[0] if values else default


def _sense(flag: int) -> Optional[str]:
    mask = int(flag or 0) & 0x0E
    return {2: "LT", 4: "GT", 8: "EQ", 10: "LE", 12: "GE"}.get(mask)


def _rpm_requirements(tags: Dict[int, list], name_tag: int, version_tag: int,
                      flags_tag: int, kind: str) -> List[core.Requirement]:
    names = [str(x) for x in tags.get(name_tag, [])]
    versions = [str(x) for x in tags.get(version_tag, [])]
    flags = [int(x) for x in tags.get(flags_tag, [])]
    out: List[core.Requirement] = []
    for i, name in enumerate(names):
        evr_text = versions[i] if i < len(versions) else ""
        sense = _sense(flags[i] if i < len(flags) else 0)
        if sense and evr_text:
            epoch, version, release = core._parse_evr_text(evr_text)
            out.append(core.Requirement(name, sense, epoch, version, release, kind))
        else:
            out.append(core.Requirement(name, kind=kind))
    return out


def _rpm_files(tags: Dict[int, list]) -> List[str]:
    bases = [str(x) for x in tags.get(RPMTAG_BASENAMES, [])]
    dirs = [str(x) for x in tags.get(RPMTAG_DIRNAMES, [])]
    indexes = [int(x) for x in tags.get(RPMTAG_DIRINDEXES, [])]
    files = []
    for i, base in enumerate(bases):
        idx = indexes[i] if i < len(indexes) else -1
        prefix = dirs[idx] if 0 <= idx < len(dirs) else ""
        files.append(prefix + base)
    return files


def _rpm_package_from_file(path: Path, root: Path, repo: core.RepoSpec) -> core.Package:
    tags = _rpm_header_tags(path)
    name = str(_first(tags, RPMTAG_NAME)).strip()
    version = str(_first(tags, RPMTAG_VERSION)).strip()
    release = str(_first(tags, RPMTAG_RELEASE)).strip()
    arch = str(_first(tags, RPMTAG_ARCH)).strip()
    epoch_value = _first(tags, RPMTAG_EPOCH, 0)
    epoch = str(epoch_value or 0)
    if not (name and version and arch):
        raise RuntimeError(f"{path.name}: Name, Version, or Arch is missing from the RPM header")
    hashes = _hashes(path)
    # RPMTAG_SIZE is the installed payload size.  primary.xml's
    # <size package="..."> is the downloadable RPM archive size, which DNF's
    # librepo transport validates.  Local repository rebuilds therefore must
    # use the actual file size rather than the header's installed-size tag.
    package_size = path.stat().st_size
    pkg = core.Package(
        name=name, arch=arch, epoch=epoch, version=version, release=release,
        location=path.relative_to(root).as_posix(), checksum_type="sha512",
        checksum=hashes["sha512"], repo=repo, digests=hashes,
        provides=_rpm_requirements(tags, RPMTAG_PROVIDENAME, RPMTAG_PROVIDEVERSION,
                                   RPMTAG_PROVIDEFLAGS, "provides"),
        requires=_rpm_requirements(tags, RPMTAG_REQUIRENAME, RPMTAG_REQUIREVERSION,
                                   RPMTAG_REQUIREFLAGS, "requires"),
        recommends=_rpm_requirements(tags, RPMTAG_RECOMMENDNAME, RPMTAG_RECOMMENDVERSION,
                                     RPMTAG_RECOMMENDFLAGS, "recommends"),
        conflicts=_rpm_requirements(tags, RPMTAG_CONFLICTNAME, RPMTAG_CONFLICTVERSION,
                                    RPMTAG_CONFLICTFLAGS, "conflicts"),
        obsoletes=_rpm_requirements(tags, RPMTAG_OBSOLETENAME, RPMTAG_OBSOLETEVERSION,
                                    RPMTAG_OBSOLETEFLAGS, "obsoletes"),
        files=_rpm_files(tags), size=package_size,
    )
    pkg.modularity_label = str(_first(tags, 5096, ""))  # RPMTAG_MODULARITYLABEL
    if not any(p.name == name for p in pkg.provides):
        pkg.provides.append(core.Requirement(name, "EQ", epoch, version, release, "provides"))
    return pkg


# ---------------------------------------------------------------------------
# Arch / pacman package metadata
# ---------------------------------------------------------------------------

def _arch_pkginfo(path: Path) -> Dict[str, List[str]]:
    """Read .PKGINFO from one Arch package without expanding payload files."""
    stream = None
    source = None
    try:
        if path.name.lower().endswith(".zst"):
            backend = getattr(core, "zstd", None)
            if backend is None:
                raise RuntimeError(f"{path.name}: zstandard support is required to inspect this Arch package")
            source = path.open("rb")
            stream = backend.ZstdDecompressor().stream_reader(source)
            tf = tarfile.open(fileobj=stream, mode="r|")
        else:
            tf = tarfile.open(path, mode="r:*")
        with tf:
            for member in tf:
                normalized = member.name.replace("\\", "/")
                while normalized.startswith("./"):
                    normalized = normalized[2:]
                if Path(normalized).name != ".PKGINFO":
                    continue
                if member.size > MAX_DEB_CONTROL_FILE_BYTES:
                    raise RuntimeError(f"{path.name}: .PKGINFO is unreasonably large")
                handle = tf.extractfile(member)
                if handle is None:
                    break
                raw = handle.read(MAX_DEB_CONTROL_FILE_BYTES + 1)
                if len(raw) > MAX_DEB_CONTROL_FILE_BYTES:
                    raise RuntimeError(f"{path.name}: .PKGINFO exceeds the metadata limit")
                fields: Dict[str, List[str]] = {}
                for line in raw.decode("utf-8", "replace").splitlines():
                    if not line or line.startswith("#") or " = " not in line:
                        continue
                    key, value = line.split(" = ", 1)
                    fields.setdefault(key.strip().lower(), []).append(value.strip())
                return fields
        raise RuntimeError(f"{path.name}: .PKGINFO was not found")
    finally:
        if stream is not None:
            try: stream.close()
            except Exception: pass
        if source is not None:
            try: source.close()
            except Exception: pass


def _arch_package_from_file(path: Path, root: Path, repo: core.RepoSpec) -> arch_core.ArchPackage:
    fields = _arch_pkginfo(path)
    def first(key: str, default: str = "") -> str:
        values = fields.get(key) or []
        return values[0] if values else default
    name, version, arch = first("pkgname"), first("pkgver"), first("arch", "any")
    if not name or not version:
        raise RuntimeError(f"{path.name}: .PKGINFO is missing pkgname or pkgver")
    try:
        installed_size = int(first("size", "0") or 0)
    except ValueError:
        installed_size = 0
    digest = core.sha256_file(path)
    sig = ""
    sig_path = Path(str(path) + ".sig")
    if sig_path.is_file():
        raw_sig = sig_path.read_bytes()
        if len(raw_sig) > 16 * 1024 * 1024:
            raise RuntimeError(f"{sig_path.name}: detached signature is unreasonably large")
        sig = base64.b64encode(raw_sig).decode("ascii")
    rel = path.relative_to(root).as_posix()
    verification = core.ArtifactVerification(index_digest_verified=False, package_digest_declared=True)
    return arch_core.ArchPackage(
        name=name, arch=arch, version=version, location=rel, checksum_type="sha256", checksum=digest,
        repo=repo, digests={"sha256": digest},
        provides=[arch_core.parse_relation(x, "provides") for x in fields.get("provides", [])],
        depends=[arch_core.parse_relation(x, "depends") for x in fields.get("depend", [])],
        optdepends=[arch_core.parse_relation(x.split(": ", 1)[0], "optdepends") for x in fields.get("optdepend", [])],
        conflicts=[arch_core.parse_relation(x, "conflicts") for x in fields.get("conflict", [])],
        replaces=[arch_core.parse_relation(x, "replaces") for x in fields.get("replaces", [])],
        size=path.stat().st_size, installed_size=installed_size, pgpsig=sig,
        description=first("pkgdesc"), base=first("pkgbase", name), url=first("url"),
        licenses=list(fields.get("license", [])), build_date=first("builddate"),
        packager=first("packager"), verification=verification)

def load_local_repository_packages(root: Path, expected_family: str | None = None):
    """Parse package payloads already present beneath ``root``.

    This is used by additive publication when repository metadata must be
    regenerated over both old and newly downloaded packages. It never moves or
    deletes payloads and returns package objects whose locations are relative to
    ``root``.
    """
    scan = scan_repository_folder(Path(root))
    if scan.family in {"empty", "mixed"}:
        raise RuntimeError(
            "Cannot regenerate repository metadata over this folder because it contains "
            + ("no package payloads" if scan.family == "empty" else "more than one package family"))
    if expected_family and scan.family != expected_family:
        raise RuntimeError(
            f"Expected {expected_family} package payloads but found {scan.family} files in {scan.root}")
    repo_format = "apt" if scan.family == "deb" else "pacman" if scan.family == "arch" else "rpm"
    repo = core.RepoSpec(name="Local additive repository", url=core.path_to_file_url(scan.root) + "/",
                         role="dependency", priority=50, repo_format=repo_format,
                         suite="feathered" if scan.family == "arch" else "")
    files = scan.rpm_files if scan.family == "rpm" else scan.deb_files if scan.family == "deb" else scan.arch_files
    packages: List[LocalPackage] = []
    for path in files:
        if scan.family == "rpm":
            packages.append(_rpm_package_from_file(path, scan.root, repo))
        elif scan.family == "deb":
            packages.append(_deb_package_from_file(path, scan.root, repo))
        else:
            packages.append(_arch_package_from_file(path, scan.root, repo))
    return scan.family, packages


# ---------------------------------------------------------------------------
# Provenance preservation and rebuild
# ---------------------------------------------------------------------------

def _existing_provenance_by_sha(root: Path) -> Dict[str, dict]:
    records: Dict[str, dict] = {}
    for provenance_path in root.rglob("provenance.json"):
        try:
            payload = json.loads(provenance_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for item in payload.get("packages", []):
            digest = str(item.get("sha256") or "").lower()
            if digest:
                records.setdefault(digest, item)
    return records


def _write_rebuild_inventory(root: Path, packages: Sequence, existing: Dict[str, dict],
                             family: str) -> Tuple[int, int]:
    rows = []
    preserved = 0
    local_only = 0
    for pkg in packages:
        path = root / pkg.location
        digest = core.sha256_file(path)
        prior = existing.get(digest.lower())
        if prior:
            preserved += 1
            provenance_modes = list(prior.get("provenance_modes") or [prior.get("assurance", "unverified")])
            source = "preserved-feathered-provenance"
        else:
            local_only += 1
            provenance_modes = ["local-content-only"]
            source = "local-repository-rebuild"
        rows.append({
            "package_id": pkg.nevra,
            "filename": pkg.location,
            "sha256": digest,
            "size": path.stat().st_size,
            "source": source,
            "provenance_modes": provenance_modes,
        })
    payload = {
        "operation": "repository-metadata-rebuild",
        "tool": f"Feathered {core.FEATHERED_VERSION}",
        "package_family": family,
        "package_count": len(rows),
        "packages": rows,
    }
    (root / "repository-rebuild.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return preserved, local_only


def rebuild_repository_metadata(root: Path, progress: Optional[Progress] = None,
                                log: Optional[Log] = None) -> RebuildReport:
    """Rebuild repository metadata around package files already present on disk.

    Package payloads are never moved or downloaded. Existing Feathered provenance
    is preserved only when its SHA-256 still matches the current bytes; otherwise
    the package is explicitly labelled local-content-only.
    """
    progress = progress or (lambda _label, _value: None)
    log = log or (lambda _message: None)
    scan = scan_repository_folder(root)
    if scan.family == "empty":
        raise RuntimeError("No .rpm, .deb, or Arch .pkg.tar.* package files were found in that folder or its subfolders")
    if scan.family == "mixed":
        if scan.rpm_files and scan.deb_files and not scan.arch_files:
            raise RuntimeError("That folder contains both RPM and DEB packages. Rebuild one package family at a time")
        raise RuntimeError("That folder contains more than one package family. Rebuild RPM, DEB, or Arch packages separately")

    repo_format = "apt" if scan.family == "deb" else "pacman" if scan.family == "arch" else "rpm"
    repo = core.RepoSpec(name="Local repository rebuild", url=core.path_to_file_url(scan.root) + "/",
                         role="dependency", priority=50, repo_format=repo_format,
                         suite="feathered" if scan.family == "arch" else "")
    files = scan.rpm_files if scan.family == "rpm" else scan.deb_files if scan.family == "deb" else scan.arch_files
    packages: List[LocalPackage] = []
    rpm_packages: List[core.Package] = []
    deb_packages: List[apt_core.DebPackage] = []
    arch_packages: List[arch_core.ArchPackage] = []
    total = len(files)
    for index, path in enumerate(files, 1):
        progress(f"Reading {index} of {total}: {path.name}", (index - 0.5) / max(1, total + 1))
        if scan.family == "rpm":
            rpm_packages.append(_rpm_package_from_file(path, scan.root, repo))
            packages.append(rpm_packages[-1])
        elif scan.family == "deb":
            deb_packages.append(_deb_package_from_file(path, scan.root, repo))
            packages.append(deb_packages[-1])
        else:
            arch_packages.append(_arch_package_from_file(path, scan.root, repo))
            packages.append(arch_packages[-1])
        progress(f"Read {index} of {total}: {path.name}", index / max(1, total + 1))

    class _Reporter:
        def log(self, message): log(str(message))
        def progress(self, label, value): progress(str(label), 0.85 + 0.14 * float(value))

    reporter = _Reporter()
    progress("Writing repository metadata", 0.86)
    if scan.family == "rpm":
        # Overwrite the canonical metadata files in place. Old, unreferenced
        # metadata artifacts are deliberately left for the operator to remove
        # manually; repository rebuilds never delete user-folder content.
        core.emit_rpm_repository(scan.root, rpm_packages, reporter, preserve_package_locations=True)
        metadata_paths = ["repodata/repomd.xml", "repodata/primary.xml.gz"]
    elif scan.family == "deb":
        # Feathered owns only the `feathered` suite and overwrites its canonical
        # indexes without deleting any pre-existing files or suites.
        apt_core.emit_apt_repository(scan.root, deb_packages, reporter, preserve_package_locations=True)
        metadata_paths = ["dists/feathered/Release", "dists/feathered/main/"]
    else:
        arch_core.emit_arch_repository(scan.root, arch_packages, reporter, preserve_package_locations=True)
        metadata_paths = ["feathered.db", "feathered.db.tar.gz"]

    existing = _existing_provenance_by_sha(scan.root)
    preserved, local_only = _write_rebuild_inventory(scan.root, packages, existing, scan.family)
    progress("Repository metadata rebuilt", 1.0)
    return RebuildReport(scan.family, len(packages), scan.root, metadata_paths,
                         provenance_preserved=preserved, local_only=local_only)

@dataclass
class BundleCheckReport:
    file_count: int
    missing: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)
    unexpected: List[str] = field(default_factory=list)
    unsafe: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.missing or self.modified or self.unexpected or self.unsafe)


def _safe_bundle_target(root: Path, relative: str) -> Optional[Path]:
    """Return a regular in-bundle target path, rejecting traversal/symlinks.

    Bundle indexes use POSIX relative paths on every platform.  Every existing
    path component is checked with lstat semantics so a symlink cannot redirect
    hashing outside the sealed tree (or even to another file inside it).
    """
    text = str(relative)
    posix = PurePosixPath(text)
    windows = PureWindowsPath(text)
    if (not text or "\\" in text or posix.is_absolute() or windows.is_absolute() or windows.drive
            or any(part in {"", ".", ".."} for part in posix.parts)):
        return None
    if posix.as_posix() != text:
        return None
    target = root.joinpath(*posix.parts)
    current = root
    for part in posix.parts:
        current = current / part
        try:
            if current.is_symlink():
                return None
        except OSError:
            return None
    try:
        target.resolve(strict=False).relative_to(root)
    except (OSError, ValueError):
        return None
    return target


def verify_bundle_files(root: Path, progress: Optional[Progress] = None) -> BundleCheckReport:
    """Check the exact sealed file set without making a signature claim.

    The UI deliberately calls this a file-integrity check. Authenticating the
    detached signature remains a separate keying operation because the operator
    must choose which signing key is trusted.
    """
    progress = progress or (lambda _label, _value: None)
    root = Path(root).expanduser().resolve()
    index_path = root / "bundle-index.json"
    if index_path.is_symlink() or not index_path.is_file():
        raise RuntimeError("bundle-index.json was not found as a regular in-bundle file; this folder is not a sealed Feathered bundle")
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    listed = {str(entry["path"]): entry for entry in payload.get("files", [])}
    missing: List[str] = []
    modified: List[str] = []
    unsafe: List[str] = []
    total = max(1, len(listed))
    for index, (relative, entry) in enumerate(sorted(listed.items()), 1):
        progress(f"Checking {index} of {len(listed)}: {relative}", index / total)
        target = _safe_bundle_target(root, relative)
        if target is None:
            unsafe.append(relative)
            continue
        if not target.exists():
            missing.append(relative)
            continue
        try:
            if not target.is_file():
                unsafe.append(relative)
                continue
        except OSError:
            unsafe.append(relative)
            continue
        if core.sha256_file(target).lower() != str(entry.get("sha256", "")).lower():
            modified.append(relative)
    ignored = {"bundle-index.json", "bundle-index.json.asc"}
    present = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if relative in ignored:
            continue
        if path.is_symlink():
            unsafe.append(relative)
            continue
        if path.is_file():
            present.add(relative)
    unexpected = sorted(present - set(listed))
    unsafe = sorted(set(unsafe))
    return BundleCheckReport(len(listed), missing, modified, unexpected, unsafe)
