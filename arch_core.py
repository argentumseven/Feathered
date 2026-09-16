from __future__ import annotations

"""Arch Linux / ALPM backend for Feathered.

The backend deliberately consumes repository database metadata rather than
shelling out to pacman.  This keeps repository inspection and dependency
analysis usable on Windows while emitting a repository that native pacman can
consume on the disconnected target.
"""

import artifact_digests
import base64
import gzip
import hashlib
import hmac
import io
import json
import os
import posixpath
import re
import shutil
import tarfile
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from functools import cmp_to_key
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Sequence, Set, Tuple

if TYPE_CHECKING:
    from root_requests import RootInput

import core
MAX_ARCH_METADATA_MEMBERS = core._positive_env_int(
    "FEATHERED_MAX_ARCH_METADATA_MEMBERS", 500_000)
MAX_ARCH_RESOLUTION_STATES = core._positive_env_int(
    "FEATHERED_MAX_ARCH_RESOLUTION_STATES", 512)

import provenance
from core import (
    ArtifactVerification, BuildOptions, Cancelled, RepoSpec, Reporter,
    abandon_staging, commit_staging, load_baseline, make_executable, meta_str_list,
    open_staging, redact_url, repository_verification_strategy, sha256_file,
    split_against_baseline, url_join, write_bundle_archive, write_bundle_index,
)
from evidence_model import AUTH_UNKNOWN, REL_EXACT_ARTIFACT, REL_EXACT_MIRROR


@dataclass(frozen=True)
class ArchRelation:
    name: str
    operator: str = ""
    version: str = ""
    kind: str = "depends"


@dataclass
class ArchPackage:
    name: str
    arch: str
    version: str
    location: str
    checksum_type: str
    checksum: str
    repo: RepoSpec
    digests: Dict[str, str] = field(default_factory=dict)
    provides: List[ArchRelation] = field(default_factory=list)
    depends: List[ArchRelation] = field(default_factory=list)
    optdepends: List[ArchRelation] = field(default_factory=list)
    conflicts: List[ArchRelation] = field(default_factory=list)
    replaces: List[ArchRelation] = field(default_factory=list)
    size: int = 0
    installed_size: int = 0
    pgpsig: str = ""
    description: str = ""
    base: str = ""
    url: str = ""
    licenses: List[str] = field(default_factory=list)
    build_date: str = ""
    packager: str = ""
    raw_fields: Dict[str, List[str]] = field(default_factory=dict)
    verification: Optional[ArtifactVerification] = None

    # Captured records override this conservative default for foreign packages.
    managed: bool = field(default=True, compare=False, repr=False)

    @property
    def nevra(self) -> str:
        # Shared UI/provenance compatibility property. Arch has no RPM-style
        # release/epoch columns outside its full version string.
        return f"{self.name}-{self.version}-{self.arch}"

    @property
    def evr_text(self) -> str:
        return self.version

    @property
    def evr(self) -> Tuple[str, str, str]:
        return ("0", self.version, "")


@dataclass
class ArchTargetInventory:
    packages: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)
    unparsed: List[str] = field(default_factory=list)

    relationships_complete: bool = field(default=False, compare=False, repr=False)
    retained_packages: List[ArchPackage] = field(default_factory=list, compare=False, repr=False)


@dataclass
class ArchResolutionResult:
    selected: List[ArchPackage]
    unresolved: List[ArchRelation]
    roots: List[ArchPackage]
    skipped_installed: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    reasons: Dict[str, str] = field(default_factory=dict)
    installed_satisfied: List[str] = field(default_factory=list)
    unresolved_notes: Dict[str, str] = field(default_factory=dict)
    ignored_unresolved: List[str] = field(default_factory=list)
    provider_choices: List[Tuple[str, str, List[str]]] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return sum(int(p.size or 0) for p in self.selected)


# ---------------------------------------------------------------------------
# Pacman/libalpm version comparison
# ---------------------------------------------------------------------------

def _split_version(value: str) -> Tuple[str, str, Optional[str]]:
    text = str(value or "")
    if ":" in text:
        epoch, remainder = text.split(":", 1)
    else:
        epoch, remainder = "0", text
    # pkgrel is the final '-' component. A dependency may omit it; pacman's
    # vercmp intentionally compares pkgrel only when both operands contain it.
    if "-" in remainder:
        version, rel = remainder.rsplit("-", 1)
    else:
        version, rel = remainder, None
    return epoch or "0", version, rel


def _segments(value: str):
    """Yield libalpm-like alphanumeric segments, preserving segment type.

    Separators are ignored. Numeric segments compare numerically (leading zeroes
    ignored); alpha segments lexically. A trailing alpha segment is a prerelease
    marker and sorts before exhaustion, while a trailing numeric segment sorts
    after exhaustion. This is the behavior documented by vercmp(8).
    """
    i = 0
    value = str(value or "")
    while i < len(value):
        while i < len(value) and not value[i].isalnum():
            i += 1
        if i >= len(value):
            break
        numeric = value[i].isdigit()
        j = i + 1
        while j < len(value) and value[j].isalnum() and value[j].isdigit() == numeric:
            j += 1
        yield ("num" if numeric else "alpha", value[i:j])
        i = j


def _rpmvercmp(a: str, b: str) -> int:
    sa = list(_segments(a)); sb = list(_segments(b))
    i = 0
    while i < len(sa) and i < len(sb):
        ta, va = sa[i]; tb, vb = sb[i]
        if ta != tb:
            # Numeric segments sort after alphabetic segments.
            return 1 if ta == "num" else -1
        if ta == "num":
            aa = va.lstrip("0") or "0"; bb = vb.lstrip("0") or "0"
            if len(aa) != len(bb):
                return 1 if len(aa) > len(bb) else -1
            if aa != bb:
                return 1 if aa > bb else -1
        else:
            if va != vb:
                return 1 if va > vb else -1
        i += 1
    if len(sa) == len(sb):
        return 0
    # Pacman's documented prerelease/postrelease behavior:
    #   1.0rc < 1.0 < 1.0.a < 1.0.1
    remainder = sa[i:] if len(sa) > i else sb[i:]
    sign = 1 if len(sa) > i else -1
    first_type = remainder[0][0]
    if first_type == "alpha":
        # A directly-attached alphabetic suffix (rc/beta/pre) is prerelease;
        # one introduced after a separator is postrelease. Inspect the original
        # side around the common consumed prefix conservatively via a suffix
        # heuristic that matches libalpm's separator handling.
        longer = a if sign > 0 else b
        shorter = b if sign > 0 else a
        prefix = shorter.rstrip("._+-")
        suffix = longer[len(prefix):] if longer.startswith(prefix) else ""
        post = bool(suffix and suffix[0] in ". _+-")
        return sign if post else -sign
    return sign


def compare_versions(a: str, b: str) -> int:
    ae, av, ar = _split_version(a); be, bv, br = _split_version(b)
    cmp_epoch = _rpmvercmp(ae, be)
    if cmp_epoch:
        return cmp_epoch
    cmp_ver = _rpmvercmp(av, bv)
    if cmp_ver:
        return cmp_ver
    if ar is not None and br is not None:
        return _rpmvercmp(ar, br)
    return 0


def _satisfies_version(candidate: str, operator: str, wanted: str) -> bool:
    if not operator or not wanted:
        return True
    cmpv = compare_versions(candidate, wanted)
    return {
        "=": cmpv == 0, "==": cmpv == 0,
        ">": cmpv > 0, ">=": cmpv >= 0,
        "<": cmpv < 0, "<=": cmpv <= 0,
    }.get(operator, False)


_REL_RE = re.compile(r"^([^<>=\s:]+)\s*(>=|<=|==|=|>|<)?\s*(.*?)\s*$")


def parse_relation(text: str, kind: str = "depends") -> ArchRelation:
    value = str(text or "").strip()
    if kind == "optdepends" and ": " in value:
        value = value.split(": ", 1)[0].strip()
    m = _REL_RE.match(value)
    if not m:
        return ArchRelation(value, kind=kind)
    return ArchRelation(m.group(1), m.group(2) or "", m.group(3) or "", kind)


def format_requirement(req: ArchRelation) -> str:
    return f"{req.name}{req.operator}{req.version}" if req.operator and req.version else req.name


# ---------------------------------------------------------------------------
# Repository database parsing
# ---------------------------------------------------------------------------

def _parse_sections(text: str) -> Dict[str, List[str]]:
    fields: Dict[str, List[str]] = {}
    current = ""
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("%") and line.endswith("%") and len(line) > 2:
            current = line.strip("%")
            fields.setdefault(current, [])
        elif line == "":
            continue
        elif current:
            fields[current].append(line)
    return fields


def _zstd_decompress(data: bytes) -> bytes:
    if core.zstd is not None:
        try:
            with core.zstd.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
                out = bytearray()
                while True:
                    chunk = reader.read(1024 * 1024)
                    if not chunk:
                        break
                    out.extend(chunk)
                    if len(out) > core.MAX_METADATA_EXPANDED_BYTES:
                        raise RuntimeError("ALPM repository database expands beyond Feathered's metadata limit")
                return bytes(out)
        except Exception as exc:
            if isinstance(exc, RuntimeError):
                raise
            raise RuntimeError(f"Cannot decompress zstd ALPM repository database: {exc}") from exc
    if core.stdlib_zstd is not None:
        try:
            with core.stdlib_zstd.ZstdFile(io.BytesIO(data), mode="rb") as reader:
                out = bytearray()
                while True:
                    chunk = reader.read(1024 * 1024)
                    if not chunk:
                        break
                    out.extend(chunk)
                    if len(out) > core.MAX_METADATA_EXPANDED_BYTES:
                        raise RuntimeError("ALPM repository database expands beyond Feathered's metadata limit")
                return bytes(out)
        except Exception as exc:
            if isinstance(exc, RuntimeError):
                raise
            raise RuntimeError(f"Cannot decompress zstd ALPM repository database: {exc}") from exc
    raise RuntimeError(
        "This ALPM repository database is zstd-compressed, but no zstd decoder is available. "
        "Install the Python 'zstandard' package and retry.")


def _tar_bytes(data: bytes) -> bytes:
    # tarfile supports gzip/bzip2/xz but not zstd on the older Python releases
    # Feathered targets. Detect zstd explicitly and decode it with a hard limit.
    if data[:4] == b"\x28\xb5\x2f\xfd":
        return _zstd_decompress(data)
    return data


def _repository_db_url(repo: RepoSpec) -> str:
    suite = (repo.suite or repo.name).strip()
    if not suite:
        raise RuntimeError(f"{repo.name}: pacman repository name is empty")
    base = repo.normalized_url.rstrip("/") + "/"
    # A direct .db URL is accepted for operator-added repositories.
    if urllib.parse.urlsplit(base.rstrip("/")).path.lower().endswith((".db", ".db.tar.gz", ".db.tar.zst", ".db.tar.xz")):
        return base.rstrip("/")
    return url_join(base, f"{suite}.db", repo)


def _load_repository_once(repo: RepoSpec, arches: Set[str], reporter: Reporter) -> List[ArchPackage]:
    db_url = _repository_db_url(repo)
    reporter.log(f"Reading pacman repository database: {redact_url(db_url)}")
    # repo= carries client certificates/CA and credential-redirect policy for
    # operator-added pacman repositories, and records effective origins for
    # evidence distinctness -- previously only the RPM/APT loaders passed it.
    raw = core.fetch_bytes(db_url, reporter, repo=repo,
                           max_bytes=core.MAX_METADATA_DOWNLOAD_BYTES)
    payload = _tar_bytes(raw)
    packages: List[ArchPackage] = []
    expanded = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(payload), mode="r:*")
    except tarfile.TarError as exc:
        raise RuntimeError(f"{repo.name}: {posixpath.basename(urllib.parse.urlsplit(db_url).path)} is not a readable ALPM repository database: {exc}") from exc
    with tf:
        # Pre-pacman-5.0 repo-add (and some third-party generators) split each
        # package entry into sibling `desc` and `depends` files; modern DBs
        # merge everything into `desc`. Read both and merge per package
        # directory so split-format repositories resolve dependencies instead
        # of silently producing dependency-free packages.
        sections: Dict[str, Dict[str, List[str]]] = {}
        entry_names: Dict[str, str] = {}
        member_count = 0
        for member in tf:
            member_count += 1
            if member_count > MAX_ARCH_METADATA_MEMBERS:
                raise RuntimeError(
                    f"{repo.name}: ALPM database contains more than "
                    f"{MAX_ARCH_METADATA_MEMBERS:,} tar members")
            base = posixpath.basename(member.name)
            if not member.isfile() or base not in ("desc", "depends"):
                continue
            expanded += int(member.size or 0)
            if expanded > core.MAX_METADATA_EXPANDED_BYTES:
                raise RuntimeError(f"{repo.name}: ALPM database metadata exceeds Feathered's expanded-size limit")
            fh = tf.extractfile(member)
            if fh is None:
                continue
            key = posixpath.dirname(member.name)
            parsed = _parse_sections(fh.read().decode("utf-8", "replace"))
            merged = sections.setdefault(key, {})
            for section, values in parsed.items():
                merged.setdefault(section, []).extend(values)
            if base == "desc":
                entry_names[key] = member.name
        for key, fields in sections.items():
            member_name = entry_names.get(key, key)
            def one(field, default="", fields=fields):
                return (fields.get(field) or [default])[0]
            name = one("NAME").strip(); version = one("VERSION").strip(); arch = one("ARCH").strip()
            filename = one("FILENAME").strip(); digest = one("SHA256SUM").strip().lower()
            if not (name and version and arch and filename):
                reporter.warn(f"{repo.name}: ignoring malformed ALPM desc entry {member_name}")
                continue
            if arch not in arches and arch != "any":
                continue
            try:
                csize = int(one("CSIZE", "0") or 0)
            except ValueError:
                csize = 0
            try:
                isize = int(one("ISIZE", "0") or 0)
            except ValueError:
                isize = 0
            pkg = ArchPackage(
                name=name, arch=arch, version=version, location=filename,
                checksum_type="sha256" if digest else "", checksum=digest, repo=repo,
                digests={"sha256": digest} if digest else {},
                provides=[parse_relation(x, "provides") for x in fields.get("PROVIDES", [])],
                depends=[parse_relation(x, "depends") for x in fields.get("DEPENDS", [])],
                optdepends=[parse_relation(x, "optdepends") for x in fields.get("OPTDEPENDS", [])],
                conflicts=[parse_relation(x, "conflicts") for x in fields.get("CONFLICTS", [])],
                replaces=[parse_relation(x, "replaces") for x in fields.get("REPLACES", [])],
                size=csize, installed_size=isize, pgpsig=one("PGPSIG").strip(),
                description=one("DESC"), base=one("BASE") or name, url=one("URL"),
                licenses=list(fields.get("LICENSE", [])), build_date=one("BUILDDATE"),
                packager=one("PACKAGER"), raw_fields=fields,
                verification=ArtifactVerification(
                    index_digest_verified=False,
                    package_digest_declared=bool(digest),
                    evidence_status="not-configured"),
            )
            # A package always provides its own name/version even if the DB does
            # not repeat it in %PROVIDES%.
            if not any(p.name == name for p in pkg.provides):
                pkg.provides.append(ArchRelation(name, "=", version, "provides"))
            packages.append(pkg)
    # Pacman sync DBs are not themselves required to be signed. The package
    # checksum and optional embedded package PGP signature are the artifact facts
    # carried by the DB. Do not imply a Release/repomd-style signed root.
    repo.trust = core.RepoTrust(repo=repo.name, archive_signature_verified=False,
                                metadata_digest_verified=False)
    reporter.log(f"{repo.name}: loaded {len(packages):,} pacman package records")
    return packages


def _apply_evidence(primary: Sequence[ArchPackage], evidence: Sequence[ArchPackage], evidence_repo: RepoSpec,
                    relationship: str, authority: str, reporter: Reporter) -> None:
    index = {(p.name, p.version, p.arch): p for p in evidence}
    matched = missing = conflicts = 0
    for pkg in primary:
        record = pkg.verification or ArtifactVerification(); pkg.verification = record
        peer = index.get((pkg.name, pkg.version, pkg.arch)) or index.get((pkg.name, pkg.version, "any"))
        record.evidence_relationship = REL_EXACT_ARTIFACT if relationship in {REL_EXACT_MIRROR, REL_EXACT_ARTIFACT} else relationship
        record.evidence_authority_relationship = authority or AUTH_UNKNOWN
        record.evidence_source = redact_url(evidence_repo.normalized_url)
        if peer is None:
            record.evidence_status = "unavailable"; missing += 1; continue
        matched += 1
        record.evidence_location = peer.location
        record.evidence_metadata_match = True
        if peer.checksum:
            record.evidence_digest_type = peer.checksum_type or "sha256"
            record.evidence_digest = peer.checksum
            if pkg.checksum and not hmac.compare_digest(pkg.checksum.lower(), peer.checksum.lower()):
                # Defer to selected-artifact verification. Live mirrors can be
                # mid-sync; unrelated skew must not poison a whole repository.
                record.evidence_status = "metadata-conflict"
                conflicts += 1
            else:
                record.evidence_status = "metadata-match"
        else:
            record.evidence_status = "metadata-only"
    reporter.log(f"Source bond {evidence_repo.name}: {matched:,} exact package identities matched, "
                 f"{missing:,} missing, {conflicts:,} digest conflict(s) deferred to selected-artifact verification")


def load_repository(repo: RepoSpec, arches: Set[str], reporter: Reporter) -> List[ArchPackage]:
    packages = _load_repository_once(repo, arches, reporter)
    strategy = repository_verification_strategy(repo)
    if strategy in {"checksum-required", "checksum-available", "skip-provenance"}:
        return packages
    if strategy in {"evidence-fallback", "legacy-fallback"} and all(p.checksum for p in packages):
        for pkg in packages:
            if pkg.verification:
                pkg.verification.evidence_status = "not-needed"
        return packages
    if not repo.evidence_urls:
        for pkg in packages:
            if pkg.verification:
                pkg.verification.evidence_status = "unavailable"
        return packages
    last_error = ""
    for url in repo.evidence_urls:
        distinct, why = core.mirrors_are_distinct(repo.normalized_url, url)
        if not distinct:
            last_error = why
            reporter.warn(f"{repo.name}: evidence source {redact_url(url)} ignored ({why})")
            continue
        evidence_repo = core.evidence_repo_for_url(repo, url)
        try:
            evidence = _load_repository_once(evidence_repo, arches, reporter)
            _apply_evidence(packages, evidence, evidence_repo,
                            core.evidence_relationship(repo, url),
                            core.evidence_authority_relationship(repo, url), reporter)
            return packages
        except Exception as exc:
            last_error = str(exc)
            reporter.warn(f"{repo.name}: pacman evidence repository unavailable/inconclusive: {exc}")
    if last_error:
        for pkg in packages:
            if pkg.verification and pkg.verification.evidence_status == "not-configured":
                pkg.verification.evidence_status = "artifact-pending"
    return packages


def probe_repository(repo: RepoSpec, reporter: Reporter):
    try:
        pkgs = _load_repository_once(repo, {"x86_64", "any"}, reporter)
        arches = ", ".join(sorted({p.arch for p in pkgs})) or "none"
        signed = sum(1 for p in pkgs if p.pgpsig)
        return True, f"pacman repo={repo.suite or repo.name}; packages={len(pkgs):,}; arch={arches}; package signatures={signed:,}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

def _relation_matches_package(pkg: ArchPackage, req: ArchRelation) -> bool:
    if pkg.name == req.name and _satisfies_version(pkg.version, req.operator, req.version):
        return True
    for provided in pkg.provides:
        if provided.name != req.name:
            continue
        # Unversioned provides satisfy only an unversioned dependency. Pacman
        # cannot infer the package's own version for an unrelated virtual name.
        if not req.operator:
            return True
        if provided.version and _satisfies_version(provided.version, req.operator, req.version):
            return True
    return False


def _arch_rank(pkg: ArchPackage, preferred_arch: str) -> int:
    return 0 if pkg.arch == preferred_arch else 1 if pkg.arch == "any" else 9


def _candidate_sort(a: ArchPackage, b: ArchPackage, requested: str, preferred_arch: str) -> int:
    ka = (0 if a.name == requested else 1, int(a.repo.priority or 50), _arch_rank(a, preferred_arch))
    kb = (0 if b.name == requested else 1, int(b.repo.priority or 50), _arch_rank(b, preferred_arch))
    if ka != kb:
        return -1 if ka < kb else 1
    vc = compare_versions(a.version, b.version)
    if vc:
        return -vc  # newest first
    return -1 if (a.repo.name, a.name) < (b.repo.name, b.name) else 1 if (a.repo.name, a.name) > (b.repo.name, b.name) else 0


def build_provider_index(packages: Sequence[ArchPackage]) -> Dict[str, List[ArchPackage]]:
    index: Dict[str, List[ArchPackage]] = defaultdict(list)
    for pkg in packages:
        index[pkg.name].append(pkg)
        for provide in pkg.provides:
            index[provide.name].append(pkg)
    return index


def _inventory_satisfies(inventory: Optional[ArchTargetInventory], req: ArchRelation) -> bool:
    if inventory is None:
        return False
    version = inventory.packages.get(req.name)
    return version is not None and _satisfies_version(version, req.operator, req.version)


def _find_root(request: Tuple, packages: Sequence[ArchPackage], preferred_arch: str) -> Optional[ArchPackage]:
    name = str(request[0])
    exact_version = str(request[1] or "") if len(request) > 1 else ""
    role = str(request[2] or "") if len(request) > 2 else ""
    repo_name = str(request[3] or "") if len(request) > 3 else ""
    exact_arch = str(request[4] or "") if len(request) > 4 else ""
    repo_identity = str(request[6] or "") if len(request) > 6 else ""
    from transaction_model import root_source_eligible
    candidates = [p for p in packages if p.name == name and p.arch in {preferred_arch, "any"}
                  and root_source_eligible(p, request)]
    if exact_version:
        candidates = [p for p in candidates if compare_versions(p.version, exact_version) == 0]
    if role:
        candidates = [p for p in candidates if p.repo.role == role]
    if repo_identity:
        candidates = [p for p in candidates if p.repo.source_identity == repo_identity]
    elif repo_name:
        candidates = [p for p in candidates if p.repo.name == repo_name]
    if exact_arch:
        candidates = [p for p in candidates if p.arch == exact_arch]
    if not candidates:
        return None
    def compare(a: ArchPackage, b: ArchPackage) -> int:
        return _candidate_sort(a, b, name, preferred_arch)

    return sorted(candidates, key=cmp_to_key(compare))[0]


def resolve(root_requests: Sequence[RootInput], packages: Sequence[ArchPackage],
            preferred_arch: str, options: BuildOptions[ArchTargetInventory], reporter: Reporter) -> ArchResolutionResult:
    from transaction_model import resolve_transaction
    return resolve_transaction(_resolve_once, root_requests, packages, preferred_arch,
                               options, reporter, 'arch')


def _package_identity(pkg: ArchPackage) -> Tuple[str, str, str, str, str]:
    return (pkg.repo.source_identity, pkg.name, pkg.version, pkg.arch, pkg.location)


def _provider_choice_label(pkg: ArchPackage) -> str:
    return f"{pkg.nevra}@{pkg.repo.source_identity}"


def _conflict_messages(packages: Sequence[ArchPackage]) -> List[str]:
    rows: List[str] = []
    seen: Set[str] = set()
    for pkg in packages:
        for relation in pkg.conflicts:
            offender = next((other for other in packages
                             if other is not pkg and _relation_matches_package(other, relation)), None)
            if offender is None:
                continue
            text = f"{pkg.nevra} conflicts with {offender.nevra} ({format_requirement(relation)})"
            if text not in seen:
                seen.add(text)
                rows.append(text)
    return rows


def _resolve_once(root_requests: Sequence[Tuple], packages: Sequence[ArchPackage], preferred_arch: str,
            options: BuildOptions[ArchTargetInventory], reporter: Reporter) -> ArchResolutionResult:
    index = build_provider_index(packages)
    identity_cache = {id(pkg): _package_identity(pkg) for pkg in packages}

    def identity(pkg: ArchPackage) -> Tuple[str, str, str, str, str]:
        cached = identity_cache.get(id(pkg))
        return cached if cached is not None else _package_identity(pkg)

    roots: List[ArchPackage] = []
    unresolved: List[ArchRelation] = []
    unresolved_notes: Dict[str, str] = {}
    skipped: List[str] = []
    selected: Dict[str, ArchPackage] = {}
    reasons: Dict[str, str] = {}

    for request in root_requests:
        name = str(request[0])
        root = _find_root(request, packages, preferred_arch)
        if root is None:
            req = ArchRelation(name, "=", str(request[1] or "") if len(request) > 1 else "", "root")
            if name in options.optional_roots:
                skipped.append(format_requirement(req))
                continue
            unresolved.append(req)
            unresolved_notes[format_requirement(req)] = (
                "No matching package root in enabled pacman repositories")
            continue
        current = selected.get(root.name)
        if current is not None and identity(current) != identity(root):
            req = ArchRelation(root.name, "=", root.version, "root")
            unresolved.append(req)
            unresolved_notes[format_requirement(req)] = (
                f"Explicit roots select incompatible versions of {root.name}: "
                f"{current.nevra} and {root.nevra}")
            continue
        roots.append(root)
        selected[root.name] = root
        reasons[root.nevra] = "requested root"

    def requirements_for(pkg: ArchPackage) -> List[ArchRelation]:
        if not options.include_dependencies:
            return []
        reqs = list(pkg.depends)
        if options.include_recommends:
            reqs.extend(pkg.optdepends)
        return reqs

    def candidates_for(req: ArchRelation) -> List[ArchPackage]:
        matches: List[ArchPackage] = []
        seen: Set[Tuple[str, str, str, str, str]] = set()
        for pkg in index.get(req.name, []):
            if pkg.arch not in {preferred_arch, "any"} or not _relation_matches_package(pkg, req):
                continue
            pkg_identity = identity(pkg)
            if pkg_identity in seen:
                continue
            seen.add(pkg_identity)
            matches.append(pkg)
        matches.sort(key=cmp_to_key(
            lambda a, b: _candidate_sort(a, b, req.name, preferred_arch)))
        return matches

    def build_selected_indexes(chosen: Dict[str, ArchPackage]):
        providers: Dict[str, List[ArchPackage]] = defaultdict(list)
        conflicts: Dict[str, List[Tuple[ArchPackage, ArchRelation]]] = defaultdict(list)
        for pkg in chosen.values():
            names = {pkg.name, *(relation.name for relation in pkg.provides)}
            for name in names:
                providers[name].append(pkg)
            for relation in pkg.conflicts:
                conflicts[relation.name].append((pkg, relation))
        return providers, conflicts

    def add_selected_indexes(pkg: ArchPackage, providers, conflicts) -> None:
        names = {pkg.name, *(relation.name for relation in pkg.provides)}
        for name in names:
            providers[name].append(pkg)
        for relation in pkg.conflicts:
            conflicts[relation.name].append((pkg, relation))

    def blocker(candidate: ArchPackage, chosen: Dict[str, ArchPackage],
                providers, conflict_index) -> Optional[str]:
        current = chosen.get(candidate.name)
        if current is not None and identity(current) != identity(candidate):
            return f"{candidate.nevra} cannot replace already selected {current.nevra}"
        for relation in candidate.conflicts:
            for other in providers.get(relation.name, ()):
                if identity(other) != identity(candidate) and _relation_matches_package(other, relation):
                    return f"{candidate.nevra} conflicts with {other.nevra}"
        candidate_names = {candidate.name, *(relation.name for relation in candidate.provides)}
        for name in candidate_names:
            for other, relation in conflict_index.get(name, ()):
                if identity(other) != identity(candidate) and _relation_matches_package(candidate, relation):
                    return f"{candidate.nevra} conflicts with {other.nevra}"
        return None

    pending = [(root, req) for root in roots for req in requirements_for(root)]
    search_attempts = 0
    best_failure = None

    def remember_failure(chosen, why_req, note, why_reasons, satisfied, choices):
        nonlocal best_failure
        failure = (dict(chosen), why_req, note, dict(why_reasons),
                   set(satisfied), list(choices))
        if best_failure is None or len(chosen) > len(best_failure[0]):
            best_failure = failure

    def solve(chosen: Dict[str, ArchPackage], outstanding: List[Tuple[ArchPackage, ArchRelation]],
              why_reasons: Dict[str, str], satisfied: Set[str],
              choices: List[Tuple[str, str, List[str]]]):
        nonlocal search_attempts
        chosen = dict(chosen)
        outstanding = list(outstanding)
        why_reasons = dict(why_reasons)
        satisfied = set(satisfied)
        choices = list(choices)
        selected_index, conflict_index = build_selected_indexes(chosen)

        while True:
            reporter.check_cancel()
            remaining = []
            dead = False
            for position, (owner, req) in enumerate(outstanding):
                if any(_relation_matches_package(pkg, req)
                       for pkg in selected_index.get(req.name, ())):
                    continue
                if _inventory_satisfies(options.target_inventory, req):
                    satisfied.add(format_requirement(req))
                    continue
                ranked = candidates_for(req)
                viable = []
                blocked = []
                for candidate in ranked:
                    reason = blocker(candidate, chosen, selected_index, conflict_index)
                    if reason is None:
                        viable.append(candidate)
                    else:
                        blocked.append(reason)
                if not viable:
                    if ranked:
                        detail = "; ".join(dict.fromkeys(blocked))
                        note = (f"Required by {owner.nevra}; matching providers cannot coexist "
                                f"with the selected transaction: {detail}")
                    else:
                        note = (f"Required by {owner.nevra}; no matching provider in enabled "
                                "pacman repositories")
                    remember_failure(chosen, req, note, why_reasons, satisfied, choices)
                    dead = True
                    break
                remaining.append((len(viable), position, owner, req, viable, ranked))
            if dead:
                return None
            if not remaining:
                return chosen, why_reasons, satisfied, choices

            _, position, owner, req, viable, ranked = min(
                remaining, key=lambda row: (row[0], row[1]))
            next_outstanding = [item for idx, item in enumerate(outstanding) if idx != position]
            ranked_labels = [_provider_choice_label(pkg) for pkg in ranked]
            if len(viable) == 1:
                candidate = viable[0]
                if len(ranked_labels) > 1:
                    chosen_label = _provider_choice_label(candidate)
                    choices.append((req.name, chosen_label,
                                    [label for label in ranked_labels if label != chosen_label]))
                if candidate.name not in chosen:
                    chosen[candidate.name] = candidate
                    add_selected_indexes(candidate, selected_index, conflict_index)
                    why_reasons[candidate.nevra] = (
                        f"dependency of {owner.nevra}: {format_requirement(req)}")
                    next_outstanding.extend((candidate, child)
                                            for child in requirements_for(candidate))
                outstanding = next_outstanding
                continue

            labels = ranked_labels
            for candidate in viable:
                search_attempts += 1
                if search_attempts > MAX_ARCH_RESOLUTION_STATES:
                    raise RuntimeError(
                        "pacman dependency resolution exhausted its provider-search safety budget; "
                        "no complete transaction has been proven")
                branch_selected = dict(chosen)
                branch_reasons = dict(why_reasons)
                branch_pending = list(next_outstanding)
                branch_choices = list(choices)
                branch_selected[candidate.name] = candidate
                branch_reasons[candidate.nevra] = (
                    f"dependency of {owner.nevra}: {format_requirement(req)}")
                branch_pending.extend((candidate, child) for child in requirements_for(candidate))
                branch_choices.append((req.name, _provider_choice_label(candidate),
                                       [label for label in labels
                                        if label != _provider_choice_label(candidate)]))
                solved = solve(branch_selected, branch_pending, branch_reasons,
                               satisfied, branch_choices)
                if solved is not None:
                    return solved
            return None

    solved = solve(selected, pending, reasons, set(), [])
    provider_choices: List[Tuple[str, str, List[str]]] = []
    satisfied_by_target: List[str] = []
    if solved is not None:
        selected, reasons, satisfied, provider_choices = solved
        satisfied_by_target = sorted(satisfied)
    elif best_failure is not None:
        selected, req, note, reasons, satisfied, provider_choices = best_failure
        key = format_requirement(req)
        if key not in {format_requirement(item) for item in unresolved}:
            unresolved.append(req)
            unresolved_notes[key] = note
        satisfied_by_target = sorted(satisfied)

    selected_values = list(selected.values())
    final_index, _ = build_selected_indexes(selected)

    # Final closure validation stays independent of the search. It protects
    # callers that disable dependencies and catches future changes that admit a
    # branch without satisfying every selected package requirement.
    for pkg in selected_values:
        for req in requirements_for(pkg):
            if _inventory_satisfies(options.target_inventory, req):
                continue
            if not any(_relation_matches_package(candidate, req)
                       for candidate in final_index.get(req.name, ())):
                key = format_requirement(req)
                if key not in {format_requirement(item) for item in unresolved}:
                    unresolved.append(req)
                    unresolved_notes[key] = (
                        f"Closure validation: requirement of {pkg.nevra} is not satisfied "
                        "by the selected transaction")

    conflicts = _conflict_messages(selected_values)
    selected_values.sort(key=lambda p: (p.name, p.arch, p.version))
    reporter.log(f"pacman closure: {len(selected_values):,} package(s), {len(unresolved):,} unresolved, "
                 f"{sum(p.size for p in selected_values):,} compressed bytes")
    return ArchResolutionResult(
        selected=selected_values, unresolved=unresolved, roots=roots,
        skipped_installed=skipped, conflicts=conflicts, reasons=reasons,
        installed_satisfied=satisfied_by_target, unresolved_notes=unresolved_notes,
        provider_choices=provider_choices)

def package_versions(packages: Sequence[ArchPackage], name: str, role: Optional[str], arch: str) -> List[str]:
    rows = [p for p in packages if p.name == name and p.arch in {arch, "any"}
            and (not role or p.repo.role == role)]
    rows.sort(key=cmp_to_key(lambda a, b: -compare_versions(a.version, b.version)))
    return list(dict.fromkeys(p.version for p in rows))


# ---------------------------------------------------------------------------
# Target inventory
# ---------------------------------------------------------------------------

def parse_target_inventory(path: str | Path) -> ArchTargetInventory:
    source = Path(path).expanduser()
    text = source.read_text(encoding="utf-8", errors="replace")
    declared = core.declared_inventory_family(text)
    if declared and declared not in {"arch", "pacman", "alpm"}:
        raise RuntimeError(f"Target inventory is for package family {declared!r}, not Arch/pacman")
    inv = ArchTargetInventory()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("DETAIL|"):
            continue
        parts = line.split("|")
        if parts[0] == "META" and len(parts) >= 3:
            inv.metadata[parts[1]] = "|".join(parts[2:])
        elif parts[0] in {"PAC", "ARCH"} and len(parts) >= 3:
            inv.packages[parts[1]] = parts[2]
        elif parts[0] not in {"META"}:
            inv.unparsed.append(line)
    from inventory_relationships import attach
    return attach(inv, text, 'arch')


# ---------------------------------------------------------------------------
# Repository emission and bundle writing
# ---------------------------------------------------------------------------

def _desc_blob(pkg: ArchPackage, filename: str) -> bytes:
    fields = dict(pkg.raw_fields or {})
    def put(key: str, values):
        if values is None:
            return
        if isinstance(values, str):
            values = [values] if values != "" else []
        values = [str(x) for x in values if str(x) != ""]
        if values:
            fields[key] = values
    put("FILENAME", filename); put("NAME", pkg.name); put("BASE", pkg.base or pkg.name)
    put("VERSION", pkg.version); put("DESC", pkg.description); put("CSIZE", str(pkg.size or 0))
    put("ISIZE", str(pkg.installed_size or 0)); put("SHA256SUM", pkg.checksum)
    put("PGPSIG", pkg.pgpsig); put("URL", pkg.url); put("LICENSE", pkg.licenses); put("ARCH", pkg.arch)
    put("BUILDDATE", pkg.build_date); put("PACKAGER", pkg.packager)
    put("REPLACES", [format_requirement(x) for x in pkg.replaces])
    put("CONFLICTS", [format_requirement(x) for x in pkg.conflicts])
    # Do not emit the implicit self-provide unless it was present upstream.
    upstream_provides = [format_requirement(x) for x in pkg.provides if x.name != pkg.name]
    put("PROVIDES", upstream_provides)
    put("DEPENDS", [format_requirement(x) for x in pkg.depends])
    put("OPTDEPENDS", [format_requirement(x) for x in pkg.optdepends])
    preferred = ["FILENAME", "NAME", "BASE", "VERSION", "DESC", "GROUPS", "CSIZE", "ISIZE",
                 "SHA256SUM", "PGPSIG", "URL", "LICENSE", "ARCH", "BUILDDATE", "PACKAGER",
                 "REPLACES", "CONFLICTS", "PROVIDES", "DEPENDS", "OPTDEPENDS"]
    order = preferred + [k for k in fields if k not in preferred]
    chunks = []
    for key in order:
        values = fields.get(key) or []
        if not values:
            continue
        chunks.append(f"%{key}%\n" + "\n".join(values) + "\n")
    return ("\n".join(chunks) + "\n").encode("utf-8")


def emit_arch_repository(repo_dir: Path, packages: Sequence[ArchPackage], reporter: core.RepositoryWriterReporter,
                         preserve_package_locations: bool = False) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
        for pkg in sorted(packages, key=lambda p: (p.name, p.version, p.arch)):
            filename = (pkg.location.replace("\\", "/").lstrip("./") if preserve_package_locations
                        else posixpath.basename(urllib.parse.urlsplit(pkg.location).path))
            if "/" in filename:
                # ALPM %FILENAME% is a package filename, not an arbitrary nested
                # repository-relative path. Refuse a repair that pacman could not
                # later retrieve correctly from Server=.
                raise RuntimeError(
                    f"{pkg.nevra}: pacman repository payload is nested ({filename!r}). "
                    "Place package files in one repository directory before rebuilding metadata.")
            blob = _desc_blob(pkg, filename)
            info = tarfile.TarInfo(f"{pkg.name}-{pkg.version}/desc")
            info.size = len(blob); info.mode = 0o644; info.mtime = 0
            tf.addfile(info, io.BytesIO(blob))
    db = buffer.getvalue()
    archive = repo_dir / "feathered.db.tar.gz"
    archive.write_bytes(db)
    # A regular copy is ZIP/Windows-safe; pacman accepts the DB by content, not
    # by requiring the conventional symlink that repo-add creates on Unix.
    (repo_dir / "feathered.db").write_bytes(db)
    reporter.log(f"Wrote pacman repository metadata for {len(packages):,} package(s)")


def _copy_or_download(pkg: ArchPackage, dest: Path, options: BuildOptions, reporter: Reporter) -> None:
    # Reuse the shared confined acquisition + checksum/evidence verifier. It is
    # package-format agnostic as long as the object exposes repo/location/digest.
    core._copy_or_download(pkg, dest, options, reporter)


def _safe_payload_names(packages: Sequence[ArchPackage]) -> Dict[int, str]:
    # Object identity distinguishes equal package names/versions from different
    # repositories. Callers retain the original package objects through writing;
    # copying, streaming or releasing them would invalidate these id() keys.
    seen: Dict[str, str] = {}
    result: Dict[int, str] = {}
    for pkg in packages:
        name = posixpath.basename(urllib.parse.urlsplit(pkg.location).path)
        if not re.search(r"\.pkg\.tar\.(?:zst|xz|gz|bz2|lz4|lrz|lzo|Z)$", name, re.IGNORECASE):
            raise RuntimeError(f"{pkg.nevra}: repository location is not an Arch package filename: {name!r}")
        key = core._windows_payload_key(name)
        previous = seen.get(key)
        if previous and previous != pkg.nevra:
            raise RuntimeError(f"Bundle filename collision: {previous} and {pkg.nevra} both map to {name!r}")
        seen[key] = pkg.nevra; result[id(pkg)] = name
    return result


def write_bundle(result: ArchResolutionResult, output_dir: Path, options: BuildOptions, reporter: Reporter,
                 metadata: Dict[str, object]) -> Path:
    reporter.phase(0.0, core.SEAL_PHASE_START if options.sign_bundle_index else 1.0)
    final_dir = output_dir
    staging = open_staging(final_dir, reporter)
    staging.mkdir(parents=True, exist_ok=True)
    if not options.sign_bundle_index:
        core.invalidate_bundle_seal(staging, reporter)
    try:
        with artifact_digests.digest_scope():
            return _write_bundle_body(result, staging, final_dir, options, reporter, metadata)
    except BaseException:
        abandon_staging(staging, reporter)
        raise


def _write_bundle_body(result: ArchResolutionResult, output_dir: Path, final_dir: Path,
                       options: BuildOptions, reporter: Reporter, metadata: Dict[str, object]) -> Path:
    pkg_dir = output_dir / "packages"; pkg_dir.mkdir(exist_ok=True)
    metadata_dir = pkg_dir  # Payload-scoped records travel with this pacman set.
    from transaction_model import validate_retained_payloads, write_installation_contract, installation_roots
    validate_retained_payloads(metadata_dir, result.selected, 'arch', reporter, options)
    baseline = load_baseline(options.baseline_manifest, reporter)
    to_ship, already_present = split_against_baseline(result.selected, baseline, reporter)
    filename_map = _safe_payload_names(to_ship)
    # Additive publication retains unrelated pacman payloads already present
    # in the destination. Same-name files may be verified/overwritten below.
    from bundle_writer import acquire_payloads, write_records
    from package_family import ARCH
    acquire_payloads(
        to_ship, filename_map, pkg_dir, final_dir.parent, options, reporter, ARCH,
        verify=lambda pkg, dest: core.verify_package_artifact(pkg, dest, options, reporter),
        download=lambda pkg, dest: _copy_or_download(pkg, dest, options, reporter),
    )

    shipped_ids = {id(p) for p in to_ship}
    manifest = []
    for pkg in result.selected:
        filename = filename_map.get(id(pkg), posixpath.basename(urllib.parse.urlsplit(pkg.location).path))
        dest = pkg_dir / filename
        record = pkg.verification
        manifest.append({
            "package_id": pkg.nevra, "name": pkg.name, "arch": pkg.arch, "version": pkg.version,
            "filename": filename,
            "sha256": artifact_digests.payload_sha256(dest, sha256_file) if id(pkg) in shipped_ids and dest.exists() else "",
            "source_digest_type": pkg.checksum_type or "", "source_digest": pkg.checksum or "",
            "repo": pkg.repo.name, "repo_url": redact_url(pkg.repo.normalized_url), "suite": pkg.repo.suite,
            "source": redact_url(url_join(pkg.repo.normalized_url, pkg.location, pkg.repo)), "size": pkg.size,
            "reason": result.reasons.get(pkg.nevra, "dependency"),
            "shipped": id(pkg) in shipped_ids,
            "package_signature_published": bool(pkg.pgpsig),
            "evidence_status": getattr(record, "evidence_status", "not-configured"),
            "evidence_source": getattr(record, "evidence_source", ""),
            "evidence_digest_type": getattr(record, "evidence_digest_type", ""),
            "evidence_digest": getattr(record, "evidence_digest", ""),
            "evidence_relationship": getattr(record, "evidence_relationship", ""),
            "evidence_authority_relationship": getattr(record, "evidence_authority_relationship", AUTH_UNKNOWN),
        })
    if options.additive_publish:
        manifest = core.merge_additive_manifest_rows(metadata_dir / "manifest.json", manifest)
    payload_files = [p for p in pkg_dir.glob("*.pkg.tar.*") if not p.name.endswith(".sig")]
    payload = {
        "metadata": metadata,
        "summary": {"package_count": len(payload_files) if options.additive_publish else len(to_ship),
                    "total_size": (sum(p.stat().st_size for p in payload_files) if options.additive_publish
                                   else sum(int(getattr(p, "size", 0) or 0) for p in to_ship)),
                    "resolved_package_count": len(result.selected),
                    "resolved_total_size": result.total_size,
                    "baseline_omitted_count": len(already_present),
                    "unresolved_count": len(result.unresolved),
                    "ignored_unresolved_count": len(result.ignored_unresolved),
                    "conflict_count": len(result.conflicts),
                    "dependency_completeness": metadata.get("dependency_completeness", "analyzed")},
        "packages": manifest,
    }
    write_records(
        metadata_dir, pkg_dir, ARCH, payload, manifest,
        unresolved=(format_requirement(req) for req in result.unresolved),
        ignored_unresolved=result.ignored_unresolved,
        conflicts=result.conflicts, skipped_installed=result.skipped_installed,
        installed_satisfied=result.installed_satisfied, hash_file=sha256_file,
    )

    prov_entries = []
    for pkg in to_ship:
        filename = filename_map[id(pkg)]; dest = pkg_dir / filename; record = pkg.verification
        entry = provenance.PackageProvenance(
            package_id=pkg.nevra, filename=filename, sha256=artifact_digests.payload_sha256(dest, sha256_file),
            size=dest.stat().st_size, source_url=redact_url(url_join(pkg.repo.normalized_url, pkg.location, pkg.repo)),
            repository=pkg.repo.name, assurance=provenance.UNVERIFIED,
            digest_checked=bool(record and record.package_digest_checked),
            index_digest_verified=False, archive_signature_verified=False,
            evidence_status=getattr(record, "evidence_status", "not-configured"),
            evidence_source=getattr(record, "evidence_source", ""),
            evidence_digest_type=getattr(record, "evidence_digest_type", ""),
            evidence_digest=getattr(record, "evidence_digest", ""),
            evidence_digest_checked=bool(record and record.evidence_digest_checked),
            evidence_metadata_match=bool(record and record.evidence_metadata_match),
            evidence_artifact_checked=bool(record and record.evidence_artifact_checked),
            evidence_relationship=getattr(record, "evidence_relationship", "") if record else "",
            evidence_authority_relationship=getattr(record, "evidence_authority_relationship", AUTH_UNKNOWN) if record else AUTH_UNKNOWN,
        )
        entry.assurance = provenance.assurance_from(entry)
        if pkg.pgpsig:
            entry.notes.append("The upstream ALPM repository published a package OpenPGP signature; Feathered preserved it in the generated pacman database for target-side verification.")
        else:
            entry.notes.append("The upstream ALPM repository did not publish an embedded package OpenPGP signature for this record.")
        prov_entries.append(entry)

    if options.emit_repository:
        repo_packages = to_ship
        if options.additive_publish:
            from repository_tools import load_local_repository_packages
            _family, repo_packages = load_local_repository_packages(pkg_dir, "arch")
            reporter.log(f"Regenerating pacman repository metadata over {len(repo_packages)} total package(s) in the additive folder.")
        emit_arch_repository(pkg_dir, repo_packages, reporter)
    core._write_provenance(output_dir, metadata_dir, prov_entries, already_present, options, reporter, metadata)

    package_only = bool(metadata.get("package_only_acquisition")); mirror = bool(metadata.get("repository_mirror"))
    if package_only:
        (metadata_dir / "PACKAGE-ONLY-WARNING.txt").write_text(
            "PACKAGE-ONLY ACQUISITION - NOT A COMPLETE OFFLINE INSTALLATION BUNDLE\n\n"
            "Dependency closure was not derived. The packages/ directory contains only requested root artifacts.\n",
            encoding="utf-8")
    elif mirror:
        (metadata_dir / "MIRROR-BUNDLE.txt").write_text(
            "REPOSITORY MIRROR - NO PACKAGE-ROOT TRANSACTION\n\n"
            "This output mirrors the selected pacman repository population. Use packages/feathered.db as the local repository database.\n",
            encoding="utf-8")
    else:
        write_installation_contract(metadata_dir, result, 'arch', metadata, already_present)
        roots = installation_roots(result, 'arch')
        if roots:
            (metadata_dir / "REQUESTED-ROOTS.txt").write_text("\n".join(roots) + "\n", encoding="utf-8")
            if options.emit_repository:
                from installer import write_installer
                write_installer(output_dir, metadata_dir, result, options, 'arch', metadata)
            else:
                (output_dir / "INSTALL-OFFLINE-NOTE.txt").write_text(
                    "Enable local repository metadata to generate the offline installer.\n", encoding="utf-8")
    if options.emit_repository:
        (output_dir / "USE-AS-REPOSITORY.txt").write_text(
            "This bundle contains a pacman repository in packages/.\n\n"
            "A temporary pacman.conf can contain:\n\n"
            "  [feathered]\n"
            "  Server = file:///path/to/this/bundle/packages\n\n"
            "Server is a URL, not a path. If this bundle lives under a directory containing a\n"
            "space, '#' or '%', percent-encode those characters (a space becomes %20). The\n"
            "generated install-offline.sh does this for you.\n\n"
            "The generated install-offline.sh uses only this repository for synchronization.\n",
            encoding="utf-8")
    core.write_unified_mirror_records(output_dir, metadata_dir, options)
    if reporter.warnings:
        (metadata_dir / "trust-warnings.txt").write_text(
            "Conditions recorded while building this bundle. Review before installing.\n\n" +
            "\n".join(f"- {w}" for w in reporter.warnings) + "\n", encoding="utf-8")
    __import__("core")._write_workload_artifacts(output_dir, metadata_dir, metadata, result)
    if options.sign_bundle_index:
        reporter.phase(core.SEAL_PHASE_START, 1.0 - core.SEAL_PHASE_START)
        write_bundle_index(output_dir, reporter, {
            "tool": provenance._tool_identity(), "bundle_id": final_dir.name,
            "target": {k: str(v) for k, v in metadata.items() if k in {"distribution", "release", "arch", "workload"}},
            "trust": core.trust_summary(to_ship),
        }, options.signing_key)
    return commit_staging(output_dir, final_dir, reporter)
