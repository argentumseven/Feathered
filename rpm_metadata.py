"""RPM repository metadata acquisition primitives and primary XML parsing.

The module owns parsing/decompression mechanics but receives trust/transport policy
as explicit callables. That keeps metadata mechanics independently testable without
creating a dependency back into the legacy ``core`` compatibility facade.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tempfile
from typing import Dict, List, Optional, Set
import urllib.parse
import xml.etree.ElementTree as ET

from core_models import ArtifactVerification, Package, RepoDataRef, Requirement, RepoTrust
from execution_reporter import Reporter
from repository_config import RepoSpec

RPM_NS = {
    "repo": "http://linux.duke.edu/metadata/repo",
    "common": "http://linux.duke.edu/metadata/common",
    "rpm": "http://linux.duke.edu/metadata/rpm",
}


def get_repo_data(repo: RepoSpec, reporter: Reporter, retries: int = 3, *, url_join_fn, fetch_bytes_fn, verification_strategy_fn, verify_openpgp_fn, repo_trust_fn, repo_relative_url_fn) -> Dict[str, RepoDataRef]:
    if not repo.normalized_url:
        raise RuntimeError(f"{repo.name}: no repository URL/path configured")
    repomd_url = url_join_fn(repo.normalized_url, "repodata/repomd.xml", repo)
    raw = fetch_bytes_fn(repomd_url, reporter, retries=retries, repo=repo)
    # repomd.xml is the trust root for an RPM repository: every other digest in
    # the repository is chained from it. Verify its detached signature when a
    # keyring is configured, unless the operator explicitly selected the
    # skip-upstream-provenance strategy.
    if verification_strategy_fn(repo) == "skip-provenance":
        reporter.warn(f"{repo.name}: upstream provenance checks are intentionally skipped by policy; "
                      "repomd.xml signature/keyring verification was not attempted.")
        repo_trust_fn(repo).notes.append("Upstream provenance checks intentionally skipped by operator policy.")
    elif repo.keyring:
        try:
            signature = fetch_bytes_fn(repomd_url + ".asc", reporter, retries=1, repo=repo)
        except Exception as exc:
            raise RuntimeError(f"{repo.name}: a keyring is configured but repodata/repomd.xml.asc "
                               f"could not be retrieved: {exc}") from exc
        verify_openpgp_fn(raw, signature, repo.keyring, f"{repo.name} repomd.xml", reporter)
        repo_trust_fn(repo).archive_signature_verified = True
    else:
        reporter.warn(f"{repo.name}: repository metadata is NOT signature-verified "
                      "(no keyring configured). Package digests are only as trustworthy as the transport.")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise RuntimeError(f"{repo.name}: invalid repomd.xml: {exc}") from exc
    refs: Dict[str, RepoDataRef] = {}
    for data_el in root.findall("repo:data", RPM_NS):
        kind = data_el.attrib.get("type", "")
        loc = data_el.find("repo:location", RPM_NS)
        if not kind or loc is None or not loc.attrib.get("href"):
            continue
        checksum = data_el.find("repo:checksum", RPM_NS)
        open_checksum = data_el.find("repo:open-checksum", RPM_NS)
        refs[kind] = RepoDataRef(
            data_type=kind,
            # repomd.xml is still repository
            # input. Apply the same repository-root confinement used for RPM
            # package payload locations; an absolute file:/ URL, another host,
            # or ../ traversal must never be followed merely because repomd
            # advertised it.
            url=repo_relative_url_fn(repo.normalized_url, loc.attrib["href"], repo),
            checksum_type=checksum.attrib.get("type", "") if checksum is not None else "",
            checksum=(checksum.text or "").strip() if checksum is not None else "",
            open_checksum_type=open_checksum.attrib.get("type", "") if open_checksum is not None else "",
            open_checksum=(open_checksum.text or "").strip() if open_checksum is not None else "",
        )
    return refs

def _read_bounded_stream(reader, max_bytes: int, description: str) -> bytes:
    total = 0
    # A list of chunks followed by b"".join() can transiently hold nearly two
    # copies of a very large metadata document.  Spool after 64 MiB so the
    # bounded result needs only one in-memory bytes object when returned.
    with tempfile.SpooledTemporaryFile(max_size=min(max_bytes, 64 * 1024 * 1024)) as spool:
        while True:
            chunk = reader.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError(
                    f"{description} expands beyond Feathered's {max_bytes:,}-byte metadata limit")
            spool.write(chunk)
        spool.seek(0)
        return spool.read()

def decompress_metadata(data: bytes, url: str, max_bytes: int, *, zstd_module, stdlib_zstd_module) -> bytes:
    """Decompress repository metadata with an explicit expanded-size ceiling.

    the old gzip/bzip2/xz helpers expanded
    the whole frame in one call and Zstd accumulated without a limit. A small
    compression bomb could therefore consume arbitrary RAM before Feathered ever
    parsed the metadata. All supported formats now stream into the same bound.
    """
    lower = urllib.parse.urlparse(url).path.lower()
    if lower.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as reader:
            return _read_bounded_stream(reader, max_bytes, "Gzip repository metadata")
    if lower.endswith(".bz2"):
        with bz2.BZ2File(io.BytesIO(data), mode="rb") as reader:
            return _read_bounded_stream(reader, max_bytes, "Bzip2 repository metadata")
    if lower.endswith(".xz"):
        with lzma.LZMAFile(io.BytesIO(data), mode="rb") as reader:
            return _read_bounded_stream(reader, max_bytes, "XZ repository metadata")
    if lower.endswith((".zst", ".zstd")):
        # Docker's current RPM metadata can use Zstandard frames without a
        # content-size field. ZstdDecompressor.decompress() requires that size
        # unless max_output_size is supplied, so use streaming decompression.
        if zstd_module is not None:
            dctx = zstd_module.ZstdDecompressor()
            with dctx.stream_reader(io.BytesIO(data)) as reader:
                return _read_bounded_stream(reader, max_bytes, "Zstandard repository metadata")
        if stdlib_zstd_module is not None:
            try:
                with stdlib_zstd_module.ZstdFile(io.BytesIO(data), mode="rb") as reader:
                    return _read_bounded_stream(reader, max_bytes, "Zstandard repository metadata")
            except Exception as exc:
                raise RuntimeError(f"stdlib Zstandard decompression failed: {exc}") from exc
        raise RuntimeError(
            "Repository metadata is Zstandard-compressed but Zstandard support is unavailable. "
            "Start with run_gui.bat or install the Python 'zstandard' package."
        )
    if len(data) > max_bytes:
        raise RuntimeError(
            f"Repository metadata is {len(data):,} bytes, above Feathered's {max_bytes:,}-byte expanded limit")
    return data

def _entry(el: ET.Element, kind: str) -> Requirement:
    return Requirement(
        name=el.attrib.get("name", "").strip(),
        flags=el.attrib.get("flags"),
        epoch=el.attrib.get("epoch"),
        version=el.attrib.get("ver") or el.attrib.get("version"),
        release=el.attrib.get("rel") or el.attrib.get("release"),
        kind=kind,
    )

def _entries(fmt: Optional[ET.Element], tag: str, kind: str) -> List[Requirement]:
    if fmt is None:
        return []
    parent = fmt.find(f"rpm:{tag}", RPM_NS)
    return [_entry(x, kind) for x in parent.findall("rpm:entry", RPM_NS)] if parent is not None else []

def parse_primary(xml: bytes, repo: RepoSpec, arches: Set[str], reporter: Reporter, *, normalized_hash_algorithm_fn, select_digest_from_map_fn, repo_trust_fn) -> List[Package]:
    packages: List[Package] = []
    count = 0
    for _, el in ET.iterparse(io.BytesIO(xml), events=("end",)):
        if el.tag != f"{{{RPM_NS['common']}}}package":
            continue
        count += 1
        raw_element = ET.tostring(el, encoding="unicode")
        if count % 3000 == 0:
            reporter.log(f"{repo.name}: parsed {count:,} package records")
        if el.attrib.get("type") != "rpm":
            el.clear(); continue
        name_el = el.find("common:name", RPM_NS)
        arch_el = el.find("common:arch", RPM_NS)
        version_el = el.find("common:version", RPM_NS)
        location_el = el.find("common:location", RPM_NS)
        checksum_el = el.find("common:checksum", RPM_NS)
        if any(x is None for x in (name_el, arch_el, version_el, location_el, checksum_el)):
            el.clear(); continue
        arch = (arch_el.text or "").strip()
        if arch not in arches:
            el.clear(); continue
        name = (name_el.text or "").strip()
        epoch = version_el.attrib.get("epoch", "0")
        version = version_el.attrib.get("ver", "")
        release = version_el.attrib.get("rel", "")
        fmt = el.find("common:format", RPM_NS)
        provides = _entries(fmt, "provides", "provides")
        requires = _entries(fmt, "requires", "requires")
        recommends = _entries(fmt, "recommends", "recommends")
        conflicts = _entries(fmt, "conflicts", "conflicts")
        obsoletes = _entries(fmt, "obsoletes", "obsoletes")
        files = [(x.text or "").strip() for x in fmt.findall("common:file", RPM_NS) if x.text] if fmt is not None else []
        source_rpm_el = fmt.find("rpm:sourcerpm", RPM_NS) if fmt is not None else None
        source_rpm = (source_rpm_el.text or "").strip() if source_rpm_el is not None else ""
        if not any(p.name == name for p in provides):
            provides.append(Requirement(name, "EQ", epoch, version, release, "provides"))
        size_el = el.find("common:size", RPM_NS)
        try:
            size = int(size_el.attrib.get("package", "0")) if size_el is not None else 0
        except ValueError:
            size = 0
        raw_checksum_type = checksum_el.attrib.get("type", "sha256")
        raw_checksum = (checksum_el.text or "").strip()
        digest_map = {normalized_hash_algorithm_fn(raw_checksum_type): raw_checksum} if raw_checksum else {}
        selected_digest = select_digest_from_map_fn(digest_map, repo.digest_preference)
        selected_type, selected_value = selected_digest if selected_digest else (raw_checksum_type, raw_checksum)
        package = Package(
            name=name, arch=arch, epoch=epoch, version=version, release=release,
            location=location_el.attrib.get("href", ""),
            checksum_type=selected_type,
            checksum=selected_value, repo=repo, digests=digest_map,
            provides=provides, requires=requires, recommends=recommends,
            conflicts=conflicts, obsoletes=obsoletes, files=files, size=size,
            source_rpm=source_rpm,
        )
        package.raw_metadata = raw_element
        package.verification = ArtifactVerification(
            index_digest_verified=repo_trust_fn(repo).metadata_digest_verified,
            package_digest_declared=bool(package.digests),
        )
        packages.append(package)
        el.clear()
    reporter.log(f"{repo.name}: {len(packages):,} usable packages for {', '.join(sorted(arches))}")
    return packages

__all__ = ["RPM_NS", "decompress_metadata", "get_repo_data", "parse_primary"]
