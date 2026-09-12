from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import hmac
import io
import json
import lzma
import os
import posixpath
import re
import shutil
import shlex
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import unicodedata
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Dict, Generic, Iterable, List, Optional, Protocol, Sequence, Set, SupportsInt, SupportsIndex, Tuple, TypeVar, Union

if TYPE_CHECKING:
    from root_requests import RootInput

try:
    import compression.zstd as stdlib_zstd  # Python 3.14+
except (ImportError, ModuleNotFoundError):
    stdlib_zstd = None

try:
    import zstandard as zstd
except (ImportError, ModuleNotFoundError):
    zstd = None

RPM_NS = {
    "repo": "http://linux.duke.edu/metadata/repo",
    "common": "http://linux.duke.edu/metadata/common",
    "rpm": "http://linux.duke.edu/metadata/rpm",
}
import provenance
import repository_transport as _transport
from evidence_model import (
    REL_EXACT_ARTIFACT, REL_EXACT_MIRROR, REL_REBUILD_PEER,
    AUTH_UNKNOWN, classify_relationship, infer_vendor_id, vendor_display_name,
)

FEATHERED_VERSION = "1.2.12"  # Keep in step with the newest CHANGELOG.md version.

USER_AGENT = f"Feathered-Airgap-Sideloader/{FEATHERED_VERSION}"

# repository metadata is hostile input.
# Bound both transfer size and expanded size so a malformed mirror cannot turn a
# metadata fetch into an unbounded memory allocation. Environment overrides are
# available for unusually large legitimate repositories.
def _positive_env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


MAX_METADATA_DOWNLOAD_BYTES = _positive_env_int(
    "FEATHERED_MAX_METADATA_DOWNLOAD_BYTES", 256 * 1024 * 1024)
MAX_METADATA_EXPANDED_BYTES = _positive_env_int(
    "FEATHERED_MAX_METADATA_EXPANDED_BYTES", 768 * 1024 * 1024)
MAX_PACKAGE_DOWNLOAD_BYTES = _positive_env_int(
    "FEATHERED_MAX_PACKAGE_DOWNLOAD_BYTES", 32 * 1024 * 1024 * 1024)


def zstd_backend() -> Optional[str]:
    if zstd is not None:
        return "zstandard-stream"
    if stdlib_zstd is not None:
        return "stdlib"
    return None




# Vendor identity helpers are implemented in evidence_model.py and re-exported here
# for compatibility with existing backend/UI imports.


@dataclass(frozen=True)
class Requirement:
    name: str
    flags: Optional[str] = None
    epoch: Optional[str] = None
    version: Optional[str] = None
    release: Optional[str] = None
    kind: str = "requires"

    @property
    def evr(self) -> Optional[Tuple[str, str, str]]:
        if self.version is None:
            return None
        return (self.epoch or "0", self.version or "", self.release or "")


@dataclass
class RepoSpec:
    name: str
    url: str
    role: str = "dependency"
    priority: int = 50
    enabled: bool = True
    note: str = ""
    target_release: str = ""
    client_cert: str = ""
    client_key: str = ""
    ca_cert: str = ""
    # Optional escape hatch for credentialed repositories whose vendor
    # intentionally redirects to another HTTPS origin (for example a vendor
    # CDN that also accepts the same mTLS identity). Empty is the secure
    # default: credentialed requests may redirect only within the same origin.
    # Entries may be full URLs or normalized origins (https://host:443).
    redirect_allow_origins: List[str] = field(default_factory=list)
    optional: bool = False
    repo_format: str = "rpm"
    suite: str = ""
    components: str = ""
    # Optional numeric identity expected in authenticated APT Release metadata.
    expected_release_version: str = ""
    # package-signature credentials are
    # scoped by vendor.  This prevents a keyring selected for one vendor from
    # being applied to unrelated repositories participating in the same build.
    vendor_id: str = ""
    # Trust configuration. `keyring` points at an OpenPGP keyring (an exported
    # .gpg/.asc file) used to verify repository signatures. When it is empty,
    # signature verification is skipped and the repository is reported as
    # unsigned so the operator can see exactly what was trusted.
    keyring: str = ""
    # Escape hatch for repositories that publish incomplete metadata (an index
    # that is not listed in the signed/rooted checksum manifest). Off by
    # default: an unverifiable index must be an explicit operator decision.
    allow_unverified_index: bool = False

    # Maximum age, in days, that a signed APT Release may reach when it
    # declares no Valid-Until. Zero disables the check, which is the default
    # for two reasons: APT itself ships Acquire::Max-ValidTime at 0, and
    # building from a deliberately pinned archive (a vault repository, a
    # Debian snapshot, a frozen internal mirror) is a first-class air-gap
    # workflow that a default age limit would break. Set it per repository to
    # make replay of an undated mirror a hard failure.
    max_release_age_days: int = 0

    # Independent evidence sources may be complete repositories or artifact-only
    # mirrors. Feathered never places the evidence copy in the output bundle; when
    # evidence is required it retrieves the exact matching artifact transiently
    # and compares its checksum with the acquisition copy.
    evidence_urls: List[str] = field(default_factory=list)
    # Curated candidates supplied by the distribution profile. They are UI
    # suggestions only until the operator activates a bond.
    evidence_suggestions: List[object] = field(default_factory=list)
    # Explicit proof semantics for active evidence URLs. These are populated by
    # the evidence selector and keep runtime verification from re-inferring a
    # relationship from a hostname after the operator made a concrete choice.
    evidence_relationship_hints: Dict[str, str] = field(default_factory=dict)
    evidence_authority_hints: Dict[str, str] = field(default_factory=dict)
    # off | fallback | best-effort | required. `fallback` consults the evidence
    # mirror only when the acquisition source cannot supply the operator-selected
    # digest strength; `best-effort` corroborates whenever possible; `required`
    # requires the selected package to exist on a distinct evidence mirror.
    evidence_policy: str = "off"

    # package-content provenance policy.
    # 1.0.36 treats an explicit SHA value as a *minimum acceptable strength*, not
    # an exact algorithm. For example, sha256 accepts SHA-256/384/512 and uses
    # the strongest one actually published for the package; sha384 accepts
    # SHA-384/512. `auto` uses the strongest strong SHA published per source.
    digest_preference: str = "auto"
    # Legacy compatibility field retained for older profiles/tests. The 1.0.36
    # UI writes `verification_strategy` below and derives these older fields.
    digest_requirement: str = "preferred"
    # one non-overlapping verification
    # strategy replaces the old Required?/Evidence-policy pair in the UI.
    # Empty means infer the historical behavior from digest_requirement and
    # evidence_policy, preserving compatibility for older saved/configured repos.
    # checksum-required | checksum-available | evidence-fallback | full-corroboration | skip-provenance
    verification_strategy: str = ""

    def __post_init__(self) -> None:
        if not self.vendor_id:
            object.__setattr__(self, "vendor_id", infer_vendor_id(self.name, self.url))
        register_url_secrets(self.url)
        # evidence URLs can carry the same credentials as acquisition
        # URLs, so register them with the central log redactor as well.
        for evidence_url in self.evidence_urls:
            register_url_secrets(evidence_url)

    def __setattr__(self, name, value):
        # URLs are also assigned after construction (media selection, custom
        # repositories), so secrets are registered on every assignment.
        object.__setattr__(self, name, value)
        if name == "url":
            register_url_secrets(value)
        elif name == "evidence_urls" and value:
            # assignments happen after construction from the GUI.
            for evidence_url in value:
                register_url_secrets(evidence_url)

    flat_repo: bool = False

    @property
    def normalized_url(self) -> str:
        if not self.url:
            return ""
        text = str(self.url)
        try:
            parts = urllib.parse.urlsplit(text)
        except ValueError:
            return text.rstrip("/") + "/"
        if not parts.scheme:
            return text.rstrip("/") + "/"
        path = (parts.path or "/").rstrip("/") + "/"
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))

    @property
    def source_identity(self) -> str:
        """Stable opaque identity for the concrete repository slice.

        Display names are deliberately excluded: two configured rows that point
        at the same archive slice are the same source, while two rows with the
        same human-readable name but different URLs/suites/components are not.
        Exact-package requests carry this fingerprint so later resolution cannot
        silently substitute a different repository that happens to share a name.
        """
        payload: Dict[str, object] = {
            "format": (self.repo_format or "rpm").strip().lower(),
            "url": self.normalized_url,
            "suite": (self.suite or "").strip(),
            "components": sorted(x for x in (self.components or "").split() if x),
        }
        if self.flat_repo:
            payload["flat_repo"] = True
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return "repo-sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class RepoDataRef:
    data_type: str
    url: str
    checksum_type: str = ""
    checksum: str = ""
    open_checksum_type: str = ""
    open_checksum: str = ""


@dataclass
class Package:
    name: str
    arch: str
    epoch: str
    version: str
    release: str
    location: str
    checksum_type: str
    checksum: str
    repo: RepoSpec
    # all package digests published by the
    # repository record, not just the single digest selected for verification.
    # This lets the operator choose SHA strength after metadata is known.
    digests: Dict[str, str] = field(default_factory=dict)
    provides: List[Requirement] = field(default_factory=list)
    requires: List[Requirement] = field(default_factory=list)
    recommends: List[Requirement] = field(default_factory=list)
    conflicts: List[Requirement] = field(default_factory=list)
    obsoletes: List[Requirement] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    size: int = 0
    # Source-package lineage from RPM primary metadata when available. This is
    # useful for independent rebuild-peer corroboration where binary RPM bytes
    # are expected to differ even though the upstream source lineage agrees.
    source_rpm: str = ""
    # What was actually verified about this artifact, carried to provenance.
    verification: Optional["ArtifactVerification"] = None
    # The upstream <package> element verbatim. Re-emitting this produces a
    # repository whose metadata matches what the vendor published, rather than
    # one reconstructed from a lossy subset of fields.
    raw_metadata: str = ""
    # RPMTAG_MODULARITYLABEL is also populated by local repository rebuilds.
    modularity_label: str = field(default="", compare=False, repr=False)

    @property
    def nevra(self) -> str:
        evr = f"{self.version}-{self.release}"
        if self.epoch and self.epoch != "0":
            evr = f"{self.epoch}:{evr}"
        return f"{self.name}-{evr}.{self.arch}"

    @property
    def evr(self) -> Tuple[str, str, str]:
        return (self.epoch or "0", self.version or "", self.release or "")

    @property
    def evr_text(self) -> str:
        prefix = f"{self.epoch}:" if self.epoch and self.epoch != "0" else ""
        return f"{prefix}{self.version}-{self.release}"


@dataclass(frozen=True)
class ProviderMatch:
    package: Package
    provide: Requirement


@dataclass
class RepoTrust:
    """What was actually verified for one repository during this run.

    Recorded as facts, not inferred later from the presence of configuration.
    A keyring being set says an operator intended verification; it does not say
    a signature was checked, or that it passed.
    """
    repo: str = ""
    archive_signature_verified: bool = False
    signer: str = ""
    metadata_digest_verified: bool = False
    freshness_checked: bool = False
    notes: List[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.archive_signature_verified:
            return f"archive signature verified ({self.signer})" if self.signer \
                else "archive signature verified"
        return "archive signature not verified"


@dataclass
class ArtifactVerification:
    """What was proven about one artifact, carried from load to provenance."""
    index_digest_verified: bool = False      # its index was covered by rooted metadata
    package_digest_declared: bool = False    # the acquisition index published a digest for it
    package_digest_checked: bool = False     # that acquisition digest was checked against the bytes
    vendor_signature_verified: bool = False
    vendor_signer: str = ""
    vendor_key_id: str = ""

    # Independent evidence may come from a complete repository or from an
    # artifact-only endpoint. Repository metadata is useful additional evidence,
    # but the selected evidence strategy ultimately compares independently
    # retrieved package bytes under the operator-selected checksum policy.
    evidence_status: str = "not-configured"
    evidence_source: str = ""
    evidence_location: str = ""
    evidence_digest_type: str = ""
    evidence_digest: str = ""
    evidence_metadata_match: bool = False
    evidence_digest_checked: bool = False
    evidence_artifact_checked: bool = False
    evidence_artifact_digest_type: str = ""
    evidence_artifact_digest: str = ""
    evidence_artifact_size: int = 0
    evidence_archive_signature_verified: bool = False
    # exact-artifact | independent-peer. Exact-artifact evidence is expected to
    # reproduce identical bytes. Independent-peer evidence (for example
    # AlmaLinux vs Rocky Linux) corroborates package/source lineage instead.
    evidence_relationship: str = ""
    evidence_authority_relationship: str = AUTH_UNKNOWN
    evidence_peer_identity_match: bool = False
    evidence_source_lineage_match: bool = False
    evidence_peer_package_id: str = ""
    evidence_peer_source_rpm: str = ""
    notes: List[str] = field(default_factory=list)


@dataclass
class TargetInventory:
    nevras: Set[str] = field(default_factory=set)
    capabilities: Dict[str, List[Requirement]] = field(default_factory=lambda: defaultdict(list))
    # Preserve per-installed-package Provides as well as the global capability
    # index. RPM rich `with` dependencies require all operands to be provided
    # by the same package, which cannot be proven from a flattened index.
    package_capabilities: Dict[str, List[Requirement]] = field(default_factory=lambda: defaultdict(list))
    metadata: Dict[str, str] = field(default_factory=dict)
    # Lines the parser did not recognise, kept for diagnostics instead of being
    # silently treated as installed packages.
    unparsed: List[str] = field(default_factory=list)

    relationships_complete: bool = field(default=False, compare=False, repr=False)
    retained_packages: List[Package] = field(default_factory=list, compare=False, repr=False)


@dataclass
class ResolutionResult:
    selected: List[Package]
    unresolved: List[Requirement]
    roots: List[Package]
    skipped_installed: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    reasons: Dict[str, str] = field(default_factory=dict)
    installed_satisfied: List[str] = field(default_factory=list)
    unresolved_notes: Dict[str, str] = field(default_factory=dict)
    # operator waivers are retained as
    # provenance, not deleted from the resolver result.  The UI may permit a
    # build when every remaining unresolved requirement is explicitly waived.
    ignored_unresolved: List[str] = field(default_factory=list)
    # Capabilities where more than one provider could have been chosen, so an
    # unworkable choice can be retried with another.
    provider_choices: List[Tuple[str, str, List[str]]] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return sum(p.size for p in self.selected)


InventoryT = TypeVar("InventoryT")


@dataclass
class BuildOptions(Generic[InventoryT]):
    # Resolver entry points specialize the installed-state type by package
    # family. Shared acquisition/publication options retain the same runtime
    # dataclass and constructor; no inventory conversion is performed.
    include_dependencies: bool = True
    include_recommends: bool = False
    include_rootless: bool = False
    verify_checksums: bool = True
    retries: int = 3
    target_inventory: Optional[InventoryT] = None
    # Upper bound on constraint-driven resolution passes. Each pass re-runs the
    # closure with the version floors discovered by the previous pass.
    max_resolution_passes: int = 8
    # Legacy single-keyring fields retained for compatibility with older API
    # callers.  Feathered's GUI now supplies vendor-scoped maps below so a keyring
    # for one vendor can never be tried against another vendor's RPMs.
    vendor_keyring: str = ""
    require_vendor_signatures: bool = False
    vendor_keyrings: Dict[str, str] = field(default_factory=dict)
    require_vendor_signatures_by_vendor: Set[str] = field(default_factory=set)
    # GPG key id/uid used to sign the finished bundle manifest.
    signing_key: str = ""
    # Compute a canonical index from the finished files and sign it, so the
    # operator signature attests to the exact bundle rather than to an
    # independently editable checksum list.
    sign_bundle_index: bool = False
    # Path to a previous bundle's manifest.json. When set, only packages that
    # are new or changed relative to it are collected.
    baseline_manifest: str = ""
    # Root package names that may legitimately be absent from the configured
    # sources. A workload preset spans repositories that not every mirror
    # carries, so a missing optional tool must not fail the whole analysis.
    optional_roots: Set[str] = field(default_factory=set)
    # Generate real repository metadata beside the packages, so the bundle can
    # be served or mounted as a repository rather than installed file-by-file.
    emit_repository: bool = True
    # Set only by the unified repository-mirror layout. Plain serializable data
    # produced by mirror_unification, carried here so the merge record is
    # written *before* the bundle index is sealed. A file added after sealing
    # would be flagged as unexpected by verify-bundle.py on the target.
    unified_mirror_note: str = ""
    unified_mirror_records: Optional[Dict[str, object]] = None
    # Existing output directories are additive by policy: prior payloads and
    # operator-created files remain in place. When True, repository metadata is
    # regenerated over the complete staged payload population rather than only
    # the packages selected by this invocation.
    additive_publish: bool = False
    # when True, selected packages with no usable SHA-256/384/512 from
    # either the acquisition metadata or its evidence bond are rejected. When
    # False Feathered records the weaker state and powers through, but a digest
    # disagreement is never ignored.
    require_package_digests: bool = False
    workload_context: object = None


class DownloadPackage(Protocol):
    """Package identity and verification state shared by payload acquisition."""

    verification: Optional[ArtifactVerification]

    @property
    def name(self) -> str: ...
    @property
    def size(self) -> int: ...
    @property
    def checksum_type(self) -> str: ...
    @property
    def checksum(self) -> str: ...
    @property
    def digests(self) -> Dict[str, str]: ...

    @property
    def repo(self) -> RepoSpec: ...
    @property
    def location(self) -> str: ...
    @property
    def nevra(self) -> str: ...


class RepositoryWriterReporter(Protocol):
    def log(self, message: str, /) -> None: ...


class Cancelled(RuntimeError):
    pass


class Reporter:
    def __init__(self, log: Optional[Callable[[str], None]] = None,
                 progress: Optional[Callable[[str, float], None]] = None,
                 cancel_event: Optional[threading.Event] = None,
                 item: Optional[Callable[[str, str, dict], None]] = None):
        self._log = log or (lambda msg: None)
        self._progress = progress or (lambda label, value: None)
        self._item = item or (lambda identity, state, info: None)
        self.cancel_event = cancel_event
        # Phase window: progress values are scaled into [start, start+span).
        self._phase_start = 0.0
        self._phase_span = 1.0
        # Warnings are both logged and retained so the GUI can show a count and
        # the bundle manifest can record what was not verified.
        self.warnings: List[str] = []

    def log(self, msg: str) -> None:
        # Redacting at the sink means a future call site cannot reintroduce a
        # credential leak by forgetting to redact its own message.
        self._log(redact_text(msg))

    def warn(self, msg: str) -> None:
        """Record a condition the operator must see before trusting a bundle."""
        text = redact_text(str(msg))
        if text not in self.warnings:
            self.warnings.append(text)
        self._log("WARNING: " + text)

    def item(self, identity: str, state: str, **info) -> None:
        """Report the state of one artifact: pending, active, done, reused, failed."""
        self._item(identity, state, info)

    def phase(self, start: float, span: float) -> None:
        """Map subsequent progress reports onto a slice of the overall bar.

        A build has two byte-heavy phases -- transferring packages, then
        sealing. Reporting each as its own 0..1 made the bar complete and then
        restart, which on a multi-terabyte mirror looks like the build began
        again. Each phase now advances its own portion of one monotonic bar.
        """
        self._phase_start = max(0.0, min(1.0, start))
        self._phase_span = max(0.0, min(1.0 - self._phase_start, span))

    def progress(self, label: str, value: float) -> None:
        local = max(0.0, min(1.0, value))
        self._progress(label, self._phase_start + local * self._phase_span)

    def check_cancel(self) -> None:
        if self.cancel_event and self.cancel_event.is_set():
            raise Cancelled("Operation cancelled")


# Compatibility exports during the transport-boundary migration.  Network
# policy lives in repository_transport.py; core keeps these names so existing
# backend code and external tests do not need a flag-day rewrite.
_RepositoryRedirectHandler = _transport.RepositoryRedirectHandler
_effective_origin = _transport.effective_origin
_effective_hostname = _transport.effective_hostname
_sensitive_query_parts = _transport.sensitive_query_parts
_url_has_endpoint_credentials = _transport.url_has_endpoint_credentials
_repo_has_endpoint_credentials = _transport.repo_has_endpoint_credentials
_credential_redirect_allow_origins = _transport.credential_redirect_allow_origins
_record_effective_origin = _transport.record_effective_origin
_inherit_sensitive_query_credentials = _transport.inherit_sensitive_query_credentials


def _ssl_context(repo: Optional[RepoSpec] = None):
    return _transport.ssl_context(repo)


def _urlopen(url: str, timeout: int, repo: Optional[RepoSpec] = None):
    return _transport.open_url(url, timeout, repo, user_agent=USER_AGENT)


def fetch_bytes(url: str, reporter: Reporter, retries: int = 3, timeout: int = 45,
                repo: Optional[RepoSpec] = None,
                max_bytes: Optional[int] = MAX_METADATA_DOWNLOAD_BYTES) -> bytes:
    return _transport.fetch_bytes(
        url, reporter, retries=retries, timeout=timeout, repo=repo, max_bytes=max_bytes,
        # Keep _urlopen as the compatibility injection seam while the backends
        # migrate to an explicit RepositoryTransport object.
        open_url_fn=lambda target, seconds, source: _urlopen(target, seconds, source),
        redact_url_fn=redact_url,
    )


def fetch_text(url: str, reporter: Optional[Reporter] = None, retries: int = 3, timeout: int = 45) -> str:
    return fetch_bytes(url, reporter or Reporter(), retries=retries, timeout=timeout).decode("utf-8", "replace")


def url_join(base: str, href: str) -> str:
    return _transport.url_join(base, href)


def _repo_trust(repo: RepoSpec) -> RepoTrust:
    """The verification record for a repository, created on first use."""
    record = getattr(repo, "trust", None)
    if record is None or record.repo != repo.name:
        record = RepoTrust(repo=repo.name)
        setattr(repo, "trust", record)
    return record


def get_repo_data(repo: RepoSpec, reporter: Reporter, retries: int = 3) -> Dict[str, RepoDataRef]:
    if not repo.normalized_url:
        raise RuntimeError(f"{repo.name}: no repository URL/path configured")
    repomd_url = url_join(repo.normalized_url, "repodata/repomd.xml")
    raw = fetch_bytes(repomd_url, reporter, retries=retries, repo=repo)
    # repomd.xml is the trust root for an RPM repository: every other digest in
    # the repository is chained from it. Verify its detached signature when a
    # keyring is configured, unless the operator explicitly selected the
    # skip-upstream-provenance strategy.
    if repository_verification_strategy(repo) == "skip-provenance":
        reporter.warn(f"{repo.name}: upstream provenance checks are intentionally skipped by policy; "
                      "repomd.xml signature/keyring verification was not attempted.")
        _repo_trust(repo).notes.append("Upstream provenance checks intentionally skipped by operator policy.")
    elif repo.keyring:
        try:
            signature = fetch_bytes(repomd_url + ".asc", reporter, retries=1, repo=repo)
        except Exception as exc:
            raise RuntimeError(f"{repo.name}: a keyring is configured but repodata/repomd.xml.asc "
                               f"could not be retrieved: {exc}") from exc
        verify_openpgp(raw, signature, repo.keyring, f"{repo.name} repomd.xml", reporter)
        _repo_trust(repo).archive_signature_verified = True
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
            url=repo_relative_url(repo.normalized_url, loc.attrib["href"]),
            checksum_type=checksum.attrib.get("type", "") if checksum is not None else "",
            checksum=(checksum.text or "").strip() if checksum is not None else "",
            open_checksum_type=open_checksum.attrib.get("type", "") if open_checksum is not None else "",
            open_checksum=(open_checksum.text or "").strip() if open_checksum is not None else "",
        )
    return refs


# Repository metadata names its own digest algorithm, so an attacker or a
# stale mirror could nominate a broken one. Only collision-resistant digests
# are accepted; anything else is a hard failure rather than a silent downgrade.
STRONG_HASHES = {"sha256", "sha384", "sha512", "sha3_256", "sha3_512"}
_HASH_ALIASES = {"sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512"}
WEAK_HASHES = {"md5", "sha1", "sha"}


def normalize_hash_name(algorithm: str) -> str:
    algo = (algorithm or "sha256").strip().lower().replace("-", "_")
    return _HASH_ALIASES.get(algorithm.strip().lower(), algo)


def load_baseline(manifest_path: str, reporter: Reporter) -> Dict[str, str]:
    """Read a previous bundle manifest into {package_id: sha256-or-version}.

    Differential bundles exist because transfer capacity, not build time, is
    the binding constraint in most airgapped programs: a point upgrade should
    move tens of megabytes, not the whole closure.
    """
    if not manifest_path:
        return {}
    path = Path(manifest_path).expanduser()
    if not path.is_file():
        raise RuntimeError(f"Baseline manifest was not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Baseline manifest {path.name} is not valid JSON: {exc}") from exc
    baseline: Dict[str, str] = {}
    for entry in payload.get("packages", []):
        key = entry.get("package_id") or entry.get("nevra") or entry.get("name")
        if key:
            # Only the digest identifies content. Falling back to the version
            # here made a republished artifact with the same NEVRA but
            # different bytes look unchanged, so it was omitted from the delta.
            # prefer a strong repository/evidence digest because it can
            # be compared before downloading a differential payload. Weak source
            # digests are not allowed to make an omission decision.
            source = strong_package_digest(str(entry.get("source_digest_type") or ""),
                                           str(entry.get("source_digest") or ""))
            evidence = strong_package_digest(str(entry.get("evidence_digest_type") or ""),
                                             str(entry.get("evidence_digest") or ""))
            baseline[str(key)] = (source or evidence or ("sha256", str(entry.get("sha256") or "")))[1]
    reporter.log(f"Baseline loaded: {len(baseline)} package(s) already present at the target")
    return baseline


def split_against_baseline(selected, baseline: Dict[str, str], reporter: Reporter):
    """Partition a closure into (to_ship, already_present) using a baseline."""
    if not baseline:
        return list(selected), []
    ship: List = []
    skip: List = []
    unverifiable = 0
    for pkg in selected:
        identity = getattr(pkg, "nevra", None) or pkg.name
        recorded = (baseline.get(identity) or "").strip()
        if not recorded:
            # Absent from the baseline, or present without a digest (an older
            # manifest). Ship it rather than assume the bytes match: identity
            # alone does not establish that a republished artifact is unchanged.
            if identity in baseline:
                unverifiable += 1
            ship.append(pkg)
            continue
        primary = strong_package_digest(getattr(pkg, "checksum_type", ""),
                                        getattr(pkg, "checksum", ""))
        # preserve compatibility with legacy baseline
        # callers that carried a bare 64-hex checksum without its algorithm.
        # This inference is used only for pre-download differential comparison,
        # never for artifact verification where an explicit algorithm is
        # required.
        if primary is None and not getattr(pkg, "checksum_type", ""):
            bare = str(getattr(pkg, "checksum", "") or "").strip().lower()
            if len(bare) == 64 and all(ch in "0123456789abcdef" for ch in bare):
                primary = ("sha256", bare)
        record = getattr(pkg, "verification", None)
        evidence = strong_package_digest(getattr(record, "evidence_digest_type", ""),
                                         getattr(record, "evidence_digest", "")) if record else None
        current = (primary or evidence or ("", ""))[1]
        if current and hmac.compare_digest(recorded.lower(), current.lower()):
            skip.append(pkg)
        else:
            ship.append(pkg)
    if unverifiable:
        reporter.warn(f"{unverifiable} baseline entry/entries record no digest, so their contents "
                      "could not be compared; those packages are included rather than assumed "
                      "unchanged. Rebuild the baseline with this version of Feathered.")
    if skip:
        reporter.log(f"Differential build: {len(skip)} package(s) byte-identical to the baseline, "
                     f"{len(ship)} to transfer")
    return ship, skip


def _windows_payload_key(name: str) -> str:
    """Return the Win32-equivalent destination key for a bundle payload.

    Feathered is primarily built and staged on Windows.  NTFS/Win32 paths are
    normally case-insensitive and Win32 also ignores trailing spaces/dots, so
    checking raw Python strings can accept two logical payloads that address
    the same physical file.  Unicode NFC + casefold is deliberately stricter
    and platform-independent so Linux CI can regression-test Windows staging.
    """
    return unicodedata.normalize("NFC", str(name)).rstrip(" .").casefold()


def write_unified_mirror_records(output_dir: Path, metadata_dir: Path, options) -> None:
    """Write the unified-mirror merge record, if this build is a unified mirror.

    Called by every backend's write_bundle immediately before the seal step so
    both files are covered by bundle-index.json. Writing them afterwards would
    make a sealed unified mirror fail its own verifier.
    """
    note = getattr(options, "unified_mirror_note", "") or ""
    records = getattr(options, "unified_mirror_records", None)
    if not note and not records:
        return
    if note:
        (output_dir / "UNIFIED-MIRROR.txt").write_text(note, encoding="utf-8")
    if records is not None:
        (metadata_dir / "mirror-sources.json").write_text(
            json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def payload_filenames(packages, expected_suffix: str) -> Dict[int, str]:
    """Return Windows-safe, collision-free destination payload names."""
    seen: Dict[str, Tuple[str, str]] = {}
    result: Dict[int, str] = {}
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    for pkg in packages:
        name = posixpath.basename(urllib.parse.urlparse(getattr(pkg, "location", "")).path)
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
        key = _windows_payload_key(name)
        previous = seen.get(key)
        if previous and previous[1] != identity:
            raise RuntimeError(
                f"Bundle filename collision: {previous[1]} ({previous[0]}) and {identity} ({name}) "
                "map to the same Windows destination. Feathered refuses to overwrite either artifact.")
        seen[key] = (name, identity)
        result[id(pkg)] = name
    return result


def meta_str_list(metadata: Dict[str, object], key: str) -> List[str]:
    """Read a list-of-strings out of the loosely typed metadata dict."""
    value = metadata.get(key, [])
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value if str(x).strip()]
    return []


def meta_dict_list(metadata: Dict[str, object], key: str) -> List[Dict[str, object]]:
    value = metadata.get(key, [])
    return [x for x in value if isinstance(x, dict)] if isinstance(value, (list, tuple)) else []


def diagnose_missing_repository(repo_url: str, reporter: Reporter, retries: int = 1) -> str:
    """Explain *why* a repository has no metadata, by looking at what is there.

    A bare 404 on repodata/repomd.xml cannot distinguish "wrong path", "release
    not published yet" and "placeholder directory". Fetching the directory
    listing separates them: an empty or readme-only directory means the release
    exists on the mirror but carries no content, while a listing full of
    subdirectories usually means the repository root is one level down.
    """
    root = repo_url.rstrip("/") + "/"
    try:
        raw = fetch_bytes(root, reporter, retries=retries).decode("utf-8", "replace")
    except Exception as exc:
        return (f"The directory itself could not be listed either ({exc}). The path is most "
                "likely wrong, or the mirror does not serve this release.")

    hrefs = re.findall(r'href=[\'"]([^\'"]+)[\'"]', raw, re.IGNORECASE)
    entries = []
    for href in hrefs:
        name = href.strip("/").split("/")[-1]
        if not name or name.startswith(("?", "#")) or name in {"..", "."}:
            continue
        if name not in entries:
            entries.append(name)

    if not entries:
        return ("The directory exists but appears to be empty. This usually means the release "
                "has not been published to this mirror.")

    substantive = [e for e in entries if not e.lower().startswith(("readme", "index", "changelog"))]
    if not substantive:
        return (f"The directory exists but contains only {', '.join(entries)} - no repository "
                "content. This release is almost certainly not published yet, or has been "
                "retired and moved to a vault mirror. Try the major-version stream directory "
                "instead of the exact point release.")

    likely = [e for e in substantive
              if any(k in e.lower() for k in ("baseos", "appstream", "os", "release", "updates",
                                              "extras", "crb", "powertools", "main", "everything"))]
    listing = ", ".join(substantive[:12]) + (" …" if len(substantive) > 12 else "")
    if likely:
        return (f"No repodata/ here, but the directory contains: {listing}. The repository root is "
                f"probably one level down - try appending one of: {', '.join(likely[:5])}.")
    return (f"No repodata/ here. The directory contains: {listing}. Check that this is the "
            "repository root (the folder that directly contains repodata/).")


SENSITIVE_QUERY_KEYS = _transport.SENSITIVE_QUERY_KEYS


def repo_relative_url(base: str, location: str) -> str:
    """Resolve a package location against its repository, refusing to escape it.

    Package locations come from repository metadata, which is exactly the thing
    an attacker controls when a mirror is compromised. urljoin() happily honours
    an absolute URL, a protocol-relative one, or enough ../ segments to leave
    the repository -- so a hostile index could redirect a package fetch to
    another host, or to a file: path on the build machine. A location must be a
    path underneath the repository root, and anything else is refused.
    """
    text = (location or "").strip()
    if not text:
        raise RuntimeError("Repository metadata supplied an empty package location")
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme or parsed.netloc or text.startswith("//"):
        raise RuntimeError(
            f"Repository metadata supplies an absolute package location ({redact_url(text)}). "
            "Package locations must be relative to the repository; refusing to fetch from a "
            "different origin than the repository that advertised it.")
    # Normalize the repository *path* rather than appending '/' to the raw URL;
    # appending after '?token=...' corrupts query-authenticated repository URLs.
    base_parts = urllib.parse.urlsplit(base)
    root_path = (base_parts.path or "/").rstrip("/") + "/"
    root = urllib.parse.urlunsplit(
        (base_parts.scheme, base_parts.netloc, root_path, base_parts.query, base_parts.fragment))
    joined = urllib.parse.urljoin(root, text)
    # Compare on the normalised path so ../ traversal cannot climb out.
    root_parts = urllib.parse.urlsplit(root)
    joined_parts = urllib.parse.urlsplit(joined)
    # validate decoded path semantics too.
    # Reverse proxies and HTTP servers commonly decode %2e/%2f before routing;
    # checking only the encoded string would let %2e%2e escape the repository
    # even though literal ../ is refused. Decode repeatedly for validation only
    # (the original URL is still returned/fetched).
    decoded_root = root_parts.path
    decoded_joined = joined_parts.path
    for _ in range(3):
        next_root = urllib.parse.unquote(decoded_root)
        next_joined = urllib.parse.unquote(decoded_joined)
        if next_root == decoded_root and next_joined == decoded_joined:
            break
        decoded_root, decoded_joined = next_root, next_joined
    if "\\" in decoded_joined:
        raise RuntimeError(
            f"Repository metadata supplies a location with backslash path separators "
            f"({redact_url(text)}). Refusing ambiguous repository traversal semantics.")
    if (joined_parts.scheme, joined_parts.netloc) != (root_parts.scheme, root_parts.netloc) \
            or not posixpath.normpath(decoded_joined).startswith(
                posixpath.normpath(decoded_root).rstrip("/") + "/"):
        raise RuntimeError(
            f"Repository metadata supplies a package location that escapes the repository "
            f"({redact_url(text)}). Refusing to fetch outside {redact_url(root)}.")
    return _inherit_sensitive_query_credentials(base, joined)


# Secret values seen in configured repository URLs. Pattern matching alone is
# not enough: a malformed URL inside an exception ("nonnumeric port:
# 'hunter2@example.invalid'") carries the password with no scheme to anchor on.
# Registering literal values lets long credentials be scrubbed if an exception
# surfaces them outside URL syntax.  Keep the cache bounded and synchronized:
# RepoSpec objects are created from worker and UI paths, while logs are rendered
# concurrently on the Tk thread.  Very short values are only redacted in URL/
# key=value context; global substring replacement of e.g. ``ab`` corrupts
# unrelated package names and digests.
_KNOWN_SECRETS: Set[str] = set()
_KNOWN_SECRET_ORDER: deque[str] = deque()
_KNOWN_SECRETS_LOCK = threading.RLock()
_MIN_GLOBAL_SECRET_LENGTH = 7
_MAX_KNOWN_SECRETS = 4096


def _remember_secret(value: str) -> None:
    secret = str(value or "")
    if len(secret) < _MIN_GLOBAL_SECRET_LENGTH:
        return
    with _KNOWN_SECRETS_LOCK:
        if secret in _KNOWN_SECRETS:
            return
        _KNOWN_SECRETS.add(secret)
        _KNOWN_SECRET_ORDER.append(secret)
        while len(_KNOWN_SECRET_ORDER) > _MAX_KNOWN_SECRETS:
            _KNOWN_SECRETS.discard(_KNOWN_SECRET_ORDER.popleft())


def register_url_secrets(url: str) -> None:
    """Remember long URL credential values for context-free exception scrubbing."""
    text = str(url or "")
    if "://" not in text:
        return
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return
    if parsed.password:
        _remember_secret(parsed.password)
    for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS and value:
            _remember_secret(value)


def redact_text(text: str) -> str:
    """Redact credentials anywhere in free text.

    Exception messages quote URLs in shapes we do not control, so redacting
    only known URL-valued fields leaves holes. This scrubs userinfo and
    sensitive query values out of any URL-looking substring.
    """
    body = str(text)
    body = re.sub(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@",
                  lambda m: f"{m.group(1)}{m.group(2)}:REDACTED@", body)
    body = re.sub(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+)@",
                  lambda m: f"{m.group(1)}REDACTED@", body)
    body = re.sub(r"(?i)\b(" + "|".join(sorted(SENSITIVE_QUERY_KEYS)) + r")=([^&\s\"\']+)",
                  lambda m: f"{m.group(1)}=REDACTED", body)
    with _KNOWN_SECRETS_LOCK:
        secrets = tuple(_KNOWN_SECRETS)
    for secret in secrets:
        if secret in body:
            body = body.replace(secret, "REDACTED")
    return body


def redact_url(url: str) -> str:
    """Strip credentials from a URL before it is logged or written to a bundle.

    Repository URLs legitimately carry userinfo or token query parameters. A
    bundle crosses an air gap and is reviewed by people who should not receive
    the build station's credentials, and logs get pasted into tickets.
    """
    text = str(url or "")
    if "://" not in text:
        return text
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return text
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        name = userinfo.split(":", 1)[0]
        netloc = (f"{name}:REDACTED@{host}" if name and ":" in userinfo else f"REDACTED@{host}")
    query = parsed.query
    if query:
        # Preserve every non-sensitive field byte-for-byte.  parse_qsl followed
        # by manual concatenation used to decode %2B/%26 and '+' and then emit
        # those decoded delimiters/spaces raw, producing an audit URL that was
        # never contacted.  Decode only the key for sensitivity classification.
        fields = []
        # Named `raw_field` rather than `field`: the module-level dataclasses
        # `field` import is shadowed by the shorter name.
        for raw_field in query.split("&"):
            raw_key, separator, _raw_value = raw_field.partition("=")
            try:
                key = urllib.parse.unquote_plus(raw_key).lower()
            except (UnicodeDecodeError, ValueError):
                key = raw_key.lower()
            if key in SENSITIVE_QUERY_KEYS:
                fields.append(f"{raw_key}=REDACTED")
            else:
                fields.append(raw_field)
        query = "&".join(fields)
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))


def path_to_file_url(path) -> str:
    """Convert a filesystem path to a file: URL that survives round-tripping.

    Path.as_uri() is wrong for Windows UNC paths: it renders
    \\\\server\\share\\x as file://server/share/x, putting the server in the URL
    *host* field. Every consumer then parses it back with url2pathname(path),
    which sees only /share/x and silently drops the server -- so an SMB mirror
    resolves to a non-existent local directory and reports "not found".

    pathname2url encodes UNC as file:////server/share/x (empty host, path
    beginning //server), which url2pathname reverses correctly.
    """
    text = str(path)
    return "file:" + urllib.request.pathname2url(text)


def file_url_to_path(url: str) -> Path:
    """Inverse of path_to_file_url for local and UNC file: URLs."""
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc and parsed.netloc.lower() not in {"", "localhost"}:
        # Tolerate the legacy file://server/share form written by as_uri().
        return Path(urllib.request.url2pathname("//" + parsed.netloc + parsed.path))
    return Path(urllib.request.url2pathname(parsed.path))


def human_size(value: float) -> str:
    """Byte count for humans; shared so progress text reads the same everywhere."""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def merge_additive_manifest_rows(manifest_path: Path, current_rows: List[dict]) -> List[dict]:
    """Merge a prior bundle manifest with rows produced by this build.

    Current rows win on filename/package identity. A malformed previous manifest
    is ignored rather than blocking the new build; the old file remains present
    in staging until the new canonical manifest is successfully written.
    """
    try:
        prior = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        old_rows = prior.get("packages", []) if isinstance(prior, dict) else []
    except Exception:
        old_rows = []
    def key(row):
        return str(row.get("filename") or row.get("package_id") or row.get("nevra") or row.get("name") or "")
    merged = {key(row): dict(row) for row in old_rows if isinstance(row, dict) and key(row)}
    for row in current_rows:
        merged[key(row)] = row
    return list(merged.values())


# Root-level artifacts that assert a whole-bundle seal. An unsealed successor
# must never inherit them from a previously sealed additive bundle.
_BUNDLE_SEAL_PATHS = frozenset({
    "bundle-index.json",
    "bundle-index.json.asc",
    "verify-bundle.py",
    "verify-bundle.py.asc",
})


def _publication_backup_path(dest: Path) -> Path:
    return Path(dest).parent / f".{Path(dest).name}.feathered-previous"


def _recover_interrupted_publication(dest: Path, reporter: Reporter) -> None:
    """Recover/clean the reserved sibling left by an interrupted directory swap."""
    dest = Path(dest)
    backup = _publication_backup_path(dest)
    if not (backup.exists() or backup.is_symlink()):
        return
    if backup.is_symlink() or not backup.is_dir():
        raise RuntimeError(
            f"Reserved publication backup path is not a directory: {backup}. "
            "Move it aside manually before building.")
    if dest.exists() or dest.is_symlink():
        if dest.is_symlink() or not dest.is_dir():
            raise RuntimeError(f"Output destination exists but is not a directory: {dest}")
        # The new directory made it into place and only cleanup was interrupted.
        # This path is reserved exclusively for Feathered's transaction backup.
        try:
            shutil.rmtree(backup)
        except OSError as exc:
            raise RuntimeError(
                f"A prior publication completed, but its transaction backup could not be removed: {backup}: {exc}") from exc
        reporter.log(f"Cleaned prior publication backup: {backup}")
        return
    try:
        os.replace(backup, dest)
    except OSError as exc:
        raise RuntimeError(
            f"A prior publication was interrupted after moving the old bundle. "
            f"Automatic recovery from {backup} failed: {exc}") from exc
    reporter.warn(f"Recovered the previous published bundle after an interrupted final swap: {dest}")


def open_staging(dest: Path, reporter: Reporter) -> Path:
    """Begin a build beside its destination without mutating published data.

    When a destination already exists, staging receives a complete snapshot of
    it. Immutable package payloads are hard-linked where possible; every other
    file is copied so rewriting generated manifests/repository metadata cannot
    mutate the published folder through a shared inode. This lets a subsequent
    build behave as an addendum while still keeping incomplete work isolated.
    """
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    _recover_interrupted_publication(dest, reporter)
    staging = dest.parent / f".{dest.name}.feathered-building"
    if staging.exists() or staging.is_symlink():
        if staging.is_symlink() or not staging.is_dir():
            raise RuntimeError(
                f"Reserved staging path is not a directory: {staging}. Move it aside manually before building.")
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        return staging
    if dest.is_symlink() or not dest.is_dir():
        raise RuntimeError(f"Output destination exists but is not a directory: {dest}")

    def is_payload(relative: Path) -> bool:
        if len(relative.parts) != 2:
            return False
        directory, name = relative.parts
        lower = name.lower()
        if directory == "rpms":
            return lower.endswith(".rpm")
        if directory == "debs":
            return lower.endswith(".deb")
        if directory == "packages":
            return ".pkg.tar." in lower and not lower.endswith(".sig")
        return False

    linked = copied = 0
    for source in sorted(dest.rglob("*"), key=lambda x: str(x).lower()):
        relative = source.relative_to(dest)
        target = staging / relative
        if source.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.symlink_to(os.readlink(source), target_is_directory=source.is_dir())
            except OSError:
                # Windows privilege/policy can reject symlink creation. Copy the
                # resolved object instead; the published source remains untouched.
                if source.is_dir():
                    shutil.copytree(source, target, dirs_exist_ok=True)
                else:
                    shutil.copy2(source, target)
                    copied += 1
            continue
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not source.is_file():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if is_payload(relative):
            try:
                os.link(source, target)
                linked += 1
                continue
            except OSError:
                pass
        shutil.copy2(source, target)
        copied += 1
    if linked or copied:
        reporter.log(
            f"Prepared additive staging from the existing folder: {linked} package payload(s) reused "
            f"and {copied} other file(s) copied; published files remain untouched until final publication.")
    return staging


def invalidate_bundle_seal(staging: Path, reporter: Reporter) -> None:
    """Remove seal artifacts inherited from an older bundle before an unsealed build."""
    staging = Path(staging)
    removed = []
    for name in sorted(_BUNDLE_SEAL_PATHS):
        path = staging / name
        if path.is_symlink() or path.is_file():
            path.unlink()
            removed.append(name)
        elif path.exists():
            raise RuntimeError(
                f"Cannot invalidate stale bundle seal because {name} is a directory. "
                "Resolve the output-folder conflict manually.")
    if removed:
        reporter.warn(
            "Removed stale whole-bundle seal artifacts inherited from the previous bundle because "
            "this build is not being sealed: " + ", ".join(removed))


def _path_present(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _preflight_additive_snapshot(staging: Path, dest: Path) -> None:
    """Reject merge conflicts before the published directory is moved."""
    for source in sorted(staging.rglob("*"), key=lambda p: (len(p.relative_to(staging).parts), str(p).lower())):
        relative = source.relative_to(staging)
        target = dest / relative
        if not _path_present(target):
            continue
        if source.is_symlink() or target.is_symlink():
            if not (source.is_symlink() and target.is_symlink()
                    and os.readlink(source) == os.readlink(target)):
                raise RuntimeError(
                    f"Cannot publish {relative}: a symlink conflicts with the staged/output path. "
                    "Open the output folder and resolve it manually.")
            continue
        if source.is_dir() and not target.is_dir():
            raise RuntimeError(
                f"Cannot publish {relative}: a file already exists where a directory is required. "
                "Open the output folder and resolve it manually.")
        if source.is_file() and target.is_dir():
            raise RuntimeError(
                f"Cannot publish {relative}: a directory already exists where a file is required. "
                "Open the output folder and resolve it manually.")


def _preserve_destination_only_entries(staging: Path, dest: Path) -> int:
    """Complete staging with destination-only entries before the directory swap."""
    preserved = 0
    for source in sorted(dest.rglob("*"), key=lambda p: (len(p.relative_to(dest).parts), str(p).lower())):
        relative = source.relative_to(dest)
        relative_text = relative.as_posix()
        target = staging / relative
        if _path_present(target):
            continue
        # Missing seal files are deliberate tombstones produced by
        # invalidate_bundle_seal(); carrying them back would recreate a stale
        # signature beside changed bundle contents.
        if relative_text in _BUNDLE_SEAL_PATHS:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source), target_is_directory=source.is_dir())
        elif source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif source.is_file():
            # These entries appeared only in the published destination after
            # staging began (or were deliberately omitted from staging). Copy
            # rather than hard-link so the completed successor cannot be
            # mutated through the still-published inode before the swap.
            shutil.copy2(source, target)
            preserved += 1
    return preserved


def commit_staging(staging: Path, dest: Path, reporter: Reporter) -> Path:
    """Publish a completed additive snapshot with rollback-safe directory swapping.

    Staging begins as a snapshot of the prior destination. Before publication we
    preflight all type/symlink conflicts and restore any destination-only files
    that appeared or were intentionally omitted from staging, except invalidated
    whole-bundle seal artifacts. The old destination is then moved to a reserved
    sibling and the completed staging directory is moved into place. If the
    second move fails, the old directory is restored before the error escapes.
    """
    staging = Path(staging)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if staging.is_symlink() or not staging.is_dir():
        raise RuntimeError(f"Completed staging directory does not exist: {staging}")
    _recover_interrupted_publication(dest, reporter)
    if not dest.exists():
        try:
            os.replace(staging, dest)
        except OSError as exc:
            raise RuntimeError(f"Could not publish completed bundle to {dest}: {exc}") from exc
        reporter.log(f"Bundle published transactionally: {dest} (new destination)")
        return dest
    if dest.is_symlink() or not dest.is_dir():
        raise RuntimeError(f"Output destination exists but is not a directory: {dest}")

    _preflight_additive_snapshot(staging, dest)
    preserved = _preserve_destination_only_entries(staging, dest)
    # Re-run after preservation so a concurrently appeared type conflict cannot
    # slip into the final snapshot after the first check.
    _preflight_additive_snapshot(staging, dest)

    backup = _publication_backup_path(dest)
    if backup.exists() or backup.is_symlink():
        raise RuntimeError(
            f"Reserved publication backup path is unexpectedly occupied: {backup}. "
            "Move it aside manually before building.")

    try:
        os.replace(dest, backup)
    except OSError as exc:
        raise RuntimeError(
            f"Could not begin transactional publication; the previous bundle is untouched: {exc}") from exc

    try:
        os.replace(staging, dest)
    except BaseException as publish_exc:
        try:
            os.replace(backup, dest)
        except BaseException as rollback_exc:
            reporter.warn(
                f"CRITICAL: publication failed and automatic rollback also failed. The previous bundle is "
                f"retained at {backup}; restore it to {dest} before using this output. Rollback error: {rollback_exc}")
            raise RuntimeError(
                f"Bundle publication failed and the previous bundle could not be restored automatically; "
                f"it remains at {backup}") from publish_exc
        reporter.warn("Final publication failed; restored the previous bundle unchanged.")
        raise

    try:
        shutil.rmtree(backup)
    except OSError as exc:
        # The new bundle is already fully in place. Retaining the hidden prior
        # snapshot is a cleanup issue, not a reason to report a failed build.
        reporter.warn(
            f"Bundle published, but the previous transaction snapshot could not be removed ({backup}): {exc}. "
            "Feathered will clean it before the next build.")
    reporter.log(
        f"Bundle published transactionally: {dest}; preserved {preserved} destination-only file(s), "
        "with no per-file in-place mutation of the previously published bundle.")
    return dest


def abandon_staging(staging: Path, reporter: Reporter) -> None:
    """Discard an incomplete build so it cannot be mistaken for a bundle."""
    try:
        if staging and Path(staging).exists():
            shutil.rmtree(staging, ignore_errors=True)
            reporter.log("Discarded the incomplete build; the previous bundle is untouched.")
    except OSError as exc:
        reporter.warn(f"Could not remove the incomplete build directory: {exc}")


# Files that describe the bundle rather than belong to it, so they are not
# listed inside the index that describes them.
# Sealing re-reads every byte already written, so it is a substantial share of
# a build rather than a rounding error; giving it the last fifth of the bar
# keeps the whole build monotonic without making small bundles feel stalled.
SEAL_PHASE_START = 0.8

INDEX_FILENAME = "bundle-index.json"
INDEX_SIGNATURE = "bundle-index.json.asc"



def _verify_script() -> str:
    """Load the receiver-side verifier and fail closed if release packaging omitted it."""
    candidates = [Path(__file__).resolve().parent / "verify_bundle_template.py"]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.insert(0, Path(meipass) / "verify_bundle_template.py")
    last_error = None
    for template in candidates:
        try:
            body = template.read_text(encoding="utf-8")
        except OSError as exc:
            last_error = exc
            continue
        if body.strip():
            return body
    detail = f" ({last_error})" if last_error else ""
    raise RuntimeError(
        "Receiver verifier resource verify_bundle_template.py is missing or empty. "
        "Refusing to seal a bundle without verify-bundle.py" + detail)


def write_bundle_index(bundle_dir: Path, reporter: Reporter, metadata: Dict[str, object],
                       signing_key: str = "") -> Path:
    """Hash every finished file and record them in one canonical index.

    The hashes are computed from the bytes on disk at finalisation, not reused
    from download or repository verification, so the index attests to the
    bundle that actually exists rather than to what was intended. Signing this
    one object makes it the single root of trust: the receiver verifies the
    signature, then re-hashes the files and compares.
    """
    bundle_dir = Path(bundle_dir)
    # write the receiver verifier *before* indexing and
    # include it in the signed file set.  A verifier that is not sealed can be
    # replaced with a script that simply prints success.
    body = _verify_script()
    verifier = bundle_dir / "verify-bundle.py"
    verifier.write_text(body, encoding="utf-8", newline="\n")
    make_executable(verifier)
    # Sealing the verifier inside the index is not sufficient by itself: when
    # an operator key is configured, authenticate the bootstrap verifier too.
    if signing_key:
        verifier_signature = _sign_detached(verifier, signing_key, reporter)
        if verifier_signature is None:
            raise RuntimeError(
                "Bundle signing was requested but verify-bundle.py could not be signed. "
                "The bundle has not been published.")

    # Exclusions are root-relative, so a nested file that happens to share the
    # index's name is still sealed. Symlinks are never followed: an "exact
    # bundle" must not be able to hash something outside its own tree.
    excluded = {INDEX_FILENAME, INDEX_SIGNATURE}
    files = []
    for candidate in bundle_dir.rglob("*"):
        relative = candidate.relative_to(bundle_dir).as_posix()
        if relative in excluded:
            continue
        if candidate.is_symlink():
            raise RuntimeError(
                f"Refusing to seal a bundle containing a symlink ({relative}); its target may "
                "lie outside the bundle and would not be covered by the signature.")
        if candidate.is_file():
            files.append(candidate)
    files.sort(key=lambda p: p.relative_to(bundle_dir).as_posix())
    total = sum(p.stat().st_size for p in files) or 1
    done = 0
    entries = []
    for path in files:
        reporter.check_cancel()
        digest = hashlib.sha256()
        hashed = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
                digest.update(chunk)
                hashed += len(chunk)
                done += len(chunk)
                # Weighted by bytes so the bar is meaningful for a 40 GB mirror
                # and does not stutter through thousands of tiny files.
                reporter.progress(f"Sealing bundle ({human_size(done)} of {human_size(total)})",
                                  done / total)
        if path.stat().st_size != hashed:
            # The file changed while it was being read, so the digest describes
            # something that no longer exists on disk.
            raise RuntimeError(f"{path.name} changed while the bundle was being sealed; "
                               "rebuild rather than publishing an index that does not match.")
        entries.append({
            "path": path.relative_to(bundle_dir).as_posix(),
            "sha256": digest.hexdigest(),
            "size": str(hashed),
        })
    total_bytes = sum(int(e["size"]) for e in entries)
    index: Dict[str, object] = {
        "format": "feathered-bundle-index/1",
        "tool": metadata.get("tool", f"Feathered {FEATHERED_VERSION}"),
        "bundle_id": str(metadata.get("bundle_id") or bundle_dir.name),
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": metadata.get("target", {}),
        "trust": metadata.get("trust", {}),
        "openpgp_verifier": gpg_backend_version() or "unavailable",
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "files": entries,
    }
    # sort_keys and a fixed separator keep the bytes reproducible for signing
    # without needing a canonicalisation framework.
    payload = json.dumps(index, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    target = bundle_dir / INDEX_FILENAME
    target.write_bytes(payload)
    if signing_key:
        signature = _sign_detached(target, signing_key, reporter)
        if signature is None:
            raise RuntimeError(
                "Bundle signing was requested but no signature could be produced. The bundle has "
                "not been published; fix the signing key or disable signing and rebuild.")
    return target


def _record_digest_checked(pkg) -> None:
    """Mark that this artifact's own digest was compared against its bytes."""
    record = getattr(pkg, "verification", None)
    if record is None:
        record = ArtifactVerification()
        setattr(pkg, "verification", record)
    record.package_digest_checked = True


def trust_summary(packages) -> Dict[str, int]:
    """Aggregate the recorded verification state of the shipped artifacts."""
    counts: Dict[str, int] = {}
    for pkg in packages:
        record = getattr(pkg, "verification", None)
        signed = bool(getattr(getattr(pkg, "repo", None), "trust", None)
                      and pkg.repo.trust.archive_signature_verified)
        if record is None:
            key = "unverified"
        elif record.vendor_signature_verified:
            key = "vendor-signature"
        elif signed and record.index_digest_verified and record.package_digest_checked:
            # Every link checked: archive signature, index covered by it, and
            # this package's digest actually compared against its bytes.
            key = "archive-chain"
        elif (record.evidence_relationship == "independent-peer"
              and record.evidence_peer_identity_match and record.evidence_digest_checked):
            key = "independent-peer-corroboration"
        elif record.package_digest_checked and record.evidence_digest_checked:
            # both acquisition and evidence
            # strong-digest claims matched the same single downloaded payload.
            key = "corroborated-digest"
        elif record.evidence_metadata_match and record.evidence_digest_checked:
            # the one downloaded payload matched a strong digest
            # independently published by the bonded evidence mirror.
            key = "independent-digest"
        elif record.package_digest_checked:
            key = "digest-only"
        elif record.evidence_metadata_match:
            key = "metadata-corroborated"
        else:
            key = "unverified"
        counts[key] = counts.get(key, 0) + 1
    return counts


_trust_summary = trust_summary


def _sign_detached(path: Path, signing_key: str, reporter: Reporter) -> Optional[Path]:
    """Detached armoured signature over a file, or None when gpg is unavailable."""
    # this helper now signs both the canonical
    # bundle index and the receiver verifier, so diagnostics identify the file
    # rather than incorrectly calling every signature a bundle-index signature.
    if shutil.which("gpg") is None:
        reporter.warn(f"gpg is not installed, so {path.name} could not be signed.")
        return None
    signature = path.with_suffix(path.suffix + ".asc")
    proc = subprocess.run(["gpg", "--batch", "--yes", "--armor", "--local-user", signing_key,
                           "--detach-sign", "--output", str(signature), str(path)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        reporter.warn(f"Signing {path.name} failed: " + (detail[-1] if detail else "unknown error"))
        return None
    reporter.log(f"Signed {path.name}: {signature.name}")
    return signature


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


def make_executable(path: Path) -> None:
    """Best-effort +x on generated scripts. ZIP transfer can drop the mode bit,
    so the docs also give `bash install-offline.sh` as a fallback."""
    try:
        path.chmod(path.stat().st_mode | 0o111)
    except OSError:
        pass


def _hash_bytes(data: bytes, algorithm: str) -> str:
    algo = normalize_hash_name(algorithm)
    if algo in WEAK_HASHES:
        raise RuntimeError(
            f"Repository metadata requests the {algo} digest, which is not collision resistant. "
            "Refusing to verify with it; use a repository that publishes SHA-256 or stronger."
        )
    if algo not in STRONG_HASHES:
        raise RuntimeError(f"Unsupported metadata digest algorithm: {algorithm!r}")
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def bundled_gpg_dir() -> Optional[Path]:
    """Directory of the GnuPG verifier shipped beside the application, if any.

    Frozen production builds require this directory and authenticate every file
    in it against a verifier-integrity policy embedded inside the signed
    Feathered executable. Source checkouts may use a local gnupg/ directory or
    fall back to PATH for developer convenience.
    """
    try:
        roots = []
        if getattr(sys, "frozen", False):
            roots.append(Path(sys.executable).resolve().parent)
        roots.append(Path(__file__).resolve().parent)
        for root in roots:
            candidate = root / "gnupg"
            if candidate.is_dir():
                return candidate
    except OSError:
        pass
    return None


class VerifierIntegrityError(RuntimeError):
    """The bundled OpenPGP verifier is missing, unauthenticated, or tampered.

    This is deliberately a distinct type. Callers that downgrade an ordinary
    signature failure to a warning (an unsigned package, a missing keyring)
    must never apply that same downgrade to a compromised verifier: the first
    is a property of the artifact, the second means no verification result on
    this machine can be trusted at all.
    """


def _verifier_policy_path() -> Optional[Path]:
    """Locate the verifier policy embedded by the production build."""
    roots = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.append(Path(meipass))
    roots.append(Path(__file__).resolve().parent)
    for root in roots:
        candidate = root / "verifier-integrity.json"
        if candidate.is_file():
            return candidate
    return None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


_VERIFIER_CACHE_LOCK = threading.Lock()
# (directory -> fingerprint) of the last successful full hash verification.
# The fingerprint is the exact (relpath, size, mtime_ns) set observed at that
# moment, so any write to the directory invalidates it.
_VERIFIER_VERIFIED: dict[str, frozenset] = {}


def _verifier_fingerprint(files: "dict[str, Path]") -> frozenset:
    return frozenset(
        (rel, path.stat().st_size, path.stat().st_mtime_ns)
        for rel, path in files.items()
    )


def _enumerate_verifier_files(directory: Path) -> "dict[str, Path]":
    """List the verifier directory, rejecting symlinks and reparse points."""
    found: dict[str, Path] = {}
    try:
        # Python 3.13 glob does not recurse into symlinked directories by
        # default, so a junction cannot smuggle files past this walk.
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise VerifierIntegrityError(
                    f"Bundled OpenPGP verifier contains a symlink/reparse entry: {path.name}"
                )
            if path.is_file():
                found[path.relative_to(directory).as_posix()] = path
    except OSError as exc:
        raise VerifierIntegrityError(
            "Unable to enumerate bundled OpenPGP verifier files."
        ) from exc
    return found


def _verify_bundled_gpg_integrity(directory: Path) -> None:
    """Authenticate the bundled verifier against the signed executable policy.

    The policy is a PyInstaller data resource. In a frozen release it is inside
    Feathered.exe before Authenticode signing, so a sidecar attacker cannot
    replace both gpgv and its expected hashes. The directory is exact-set
    checked: missing, changed, added, or symlinked files are rejected.

    This runs on every gpg_backend() call, and gpg_backend() is called once per
    package during a vendor-signature pass, so a full re-hash of several
    megabytes of DLLs per package is not affordable. After one successful full
    verification the (relpath, size, mtime_ns) set is recorded; subsequent calls
    re-enumerate and re-stat, and only re-hash when that set has changed.  This
    fast path detects ordinary modification but assumes an attacker able to write
    the verifier directory cannot also restore the original size and nanosecond
    mtime metadata.  gpgv itself is still re-hashed before each execution.  This
    does not close the exec-time TOCTOU window, which the original per-call
    hashing did not close either.
    """
    policy_path = _verifier_policy_path()
    frozen = bool(getattr(sys, "frozen", False))
    if policy_path is None:
        if frozen:
            raise VerifierIntegrityError(
                "Bundled OpenPGP verifier integrity policy is missing from this release. "
                "Refusing to execute an unauthenticated verifier."
            )
        return
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        expected = policy["files"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise VerifierIntegrityError(
            "Bundled OpenPGP verifier integrity policy is invalid."
        ) from exc
    if not isinstance(expected, dict) or not expected:
        raise VerifierIntegrityError(
            "Bundled OpenPGP verifier integrity policy contains no files."
        )

    actual = _enumerate_verifier_files(directory)

    expected_names = set(expected)
    actual_names = set(actual)
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        detail = []
        if missing:
            detail.append("missing: " + ", ".join(missing))
        if extra:
            detail.append("unexpected: " + ", ".join(extra))
        raise VerifierIntegrityError(
            "Bundled OpenPGP verifier file set does not match the signed release policy"
            + (" (" + "; ".join(detail) + ")" if detail else "") + "."
        )

    key = str(directory.resolve())
    try:
        fingerprint = _verifier_fingerprint(actual)
    except OSError as exc:
        raise VerifierIntegrityError(
            "Unable to stat bundled OpenPGP verifier files."
        ) from exc

    with _VERIFIER_CACHE_LOCK:
        cached = _VERIFIER_VERIFIED.get(key) == fingerprint

    def check(rel: str, path: Path) -> None:
        wanted = str(expected[rel]).lower()
        if len(wanted) != 64 or any(c not in "0123456789abcdef" for c in wanted):
            raise VerifierIntegrityError(f"Invalid verifier SHA-256 policy entry for {rel}.")
        if _sha256_file(path).lower() != wanted:
            raise VerifierIntegrityError(
                f"Bundled OpenPGP verifier integrity check failed for {rel}. "
                "Refusing to execute it."
            )

    if cached:
        # The stat fingerprint is unchanged, so the DLLs are taken on trust from
        # the earlier full pass. The binary that is actually about to be
        # executed is still re-hashed every time: it is small, and it is the one
        # file where a same-size, mtime-restored swap would be worth an
        # attacker's effort.
        for rel, path in actual.items():
            if rel.rsplit("/", 1)[-1].lower() in ("gpgv.exe", "gpgv"):
                check(rel, path)
        return

    for rel, path in actual.items():
        check(rel, path)

    with _VERIFIER_CACHE_LOCK:
        _VERIFIER_VERIFIED[key] = fingerprint


def _reset_verifier_integrity_cache() -> None:
    """Drop memoized verifier state. Used by tests and after a policy change."""
    with _VERIFIER_CACHE_LOCK:
        _VERIFIER_VERIFIED.clear()


def gpg_backend_name(backend: Optional[str]) -> str:
    """Comparable tool name ("gpgv"/"gpg") for a backend path or bare name."""
    if not backend:
        return ""
    stem = Path(backend).name.lower()
    return stem[:-4] if stem.endswith(".exe") else stem


def gpg_backend() -> Optional[str]:
    """Return an authenticated OpenPGP verifier available to this process.

    Frozen releases are fail-closed: they must contain the bundled verifier and
    it must match the integrity policy embedded in the signed executable. PATH
    fallback is intentionally disabled for frozen production builds.
    """
    bundled = bundled_gpg_dir()
    frozen = bool(getattr(sys, "frozen", False))
    if bundled is not None:
        _verify_bundled_gpg_integrity(bundled)
        for candidate in ("gpgv.exe", "gpgv"):
            tool = bundled / candidate
            if tool.is_file():
                return str(tool)
        if frozen:
            raise VerifierIntegrityError(
                "Authenticated OpenPGP verifier directory contains no gpgv executable."
            )
        # A source checkout may keep an incomplete gnupg/ scratch directory.
        # Only a frozen release treats that as fatal; development continues to
        # fall through to PATH exactly as it did before 1.2.2.
    elif frozen:
        raise VerifierIntegrityError(
            "This Feathered release is missing its bundled OpenPGP verifier. "
            "Refusing to fall back to an unauthenticated PATH executable."
        )
    for candidate in ("gpgv", "gpg"):
        if shutil.which(candidate):
            return candidate
    return None


def gpg_backend_or_none() -> Optional[str]:
    """gpg_backend() for status/reporting callers that must not raise.

    Returns None both when no verifier exists and when the bundled one fails
    authentication. Anything on a verification path must call gpg_backend()
    directly so a VerifierIntegrityError propagates instead of being read as
    "GnuPG is not installed".
    """
    try:
        return gpg_backend()
    except VerifierIntegrityError:
        return None


def gpg_backend_version(backend: Optional[str] = None) -> str:
    """First --version line of the active verifier, for provenance records."""
    tool = backend or gpg_backend_or_none()
    if not tool:
        return ""
    try:
        proc = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    first = (proc.stdout or "").strip().splitlines()
    return first[0].strip() if proc.returncode == 0 and first else ""


def verify_openpgp(signed_payload: bytes, signature: Optional[bytes], keyring: str,
                   description: str, reporter: Reporter) -> None:
    """Verify an OpenPGP signature against an explicit keyring.

    Two modes:
      * detached  - `signature` holds a .asc/.gpg signature over `signed_payload`.
      * clearsign - `signature` is None and `signed_payload` is the whole
        clearsigned document (an APT InRelease file). These MUST be verified
        inline: the bytes actually signed are the dash-unescaped, canonicalised
        body, not the armoured file, so handing the file to a detached-mode
        verification always reports a bad signature.

    Fails closed: a configured keyring that cannot be checked is an error.
    """
    keyring_path = Path(keyring).expanduser()
    if not keyring_path.is_file():
        raise RuntimeError(f"{description}: configured keyring was not found: {keyring_path}")
    backend = gpg_backend()
    if backend is None:
        raise RuntimeError(
            f"{description}: a keyring is configured but neither gpgv nor gpg is installed. "
            "Install GnuPG (Gpg4win on Windows) or clear the keyring setting for this repository."
        )
    with tempfile.TemporaryDirectory(prefix="feathered-gpg-") as tmpdir:
        tmp = Path(tmpdir)
        keyring_arg = _prepare_keyring(keyring_path, tmp, backend)
        payload_file = tmp / "payload"
        payload_file.write_bytes(signed_payload)
        if signature is None:
            args = [str(payload_file)]
        else:
            sig_file = tmp / "payload.sig"
            sig_file.write_bytes(signature)
            args = [str(sig_file), str(payload_file)]
        if gpg_backend_name(backend) == "gpgv":
            cmd = [backend, "--keyring", str(keyring_arg), *args]
        else:
            cmd = [backend, "--batch", "--no-default-keyring", "--keyring", str(keyring_arg),
                   "--verify", *args]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            detail = [x for x in (proc.stderr or proc.stdout or "").strip().splitlines() if x.strip()]
            raise RuntimeError(f"{description}: OpenPGP signature verification FAILED. "
                               + (detail[-1] if detail else "no detail from the verifier"))
        signer = ""
        for line in (proc.stderr or "").splitlines():
            if "Good signature from" in line:
                signer = line.split("Good signature from", 1)[1].strip().strip('"')
                break
    reporter.log(f"{description}: OpenPGP signature verified"
                 + (f" ({signer})" if signer else f" against {keyring_path.name}"))


MAX_ARMORED_KEYRING_BYTES = 32 * 1024 * 1024


def _dearmor_public_keyring(data: bytes) -> bytes:
    """Decode one ASCII-armoured OpenPGP public-key block.

    ``gpgv`` accepts OpenPGP packet bytes as a keyring but does not dearmor
    exported ``.asc`` public keys itself.  Release builds deliberately ship the
    smaller verifier rather than the full key-management utility, so Feathered
    performs the armour transport decoding locally.  Armour headers and the
    optional CRC24 line are not part of the packet stream.

    The decoder is intentionally limited to PUBLIC KEY blocks: repository
    verification never needs private-key material and should not silently accept
    arbitrary armoured message types as a trust store.
    """
    begin = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = b"-----END PGP PUBLIC KEY BLOCK-----"
    lines = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == begin)
    except StopIteration as exc:
        raise RuntimeError("ASCII keyring is missing an OpenPGP public-key armour header") from exc

    body_started = False
    body = []
    armor_crc = None
    saw_end = False
    for raw in lines[start + 1:]:
        line = raw.strip()
        if not body_started:
            # RFC 4880 armour permits descriptive Header: Value lines followed
            # by a mandatory blank separator.  Some exporters emit no headers.
            if not line:
                body_started = True
                continue
            if b":" in line:
                continue
            body_started = True
        if line == end:
            saw_end = True
            break
        if not line:
            continue
        if line.startswith(b"="):
            if armor_crc is not None:
                raise RuntimeError("ASCII keyring contains multiple armour checksums")
            armor_crc = line[1:]
            continue
        body.append(line)

    if not saw_end:
        raise RuntimeError("ASCII keyring is missing its OpenPGP armour footer")
    if not body:
        raise RuntimeError("ASCII keyring contains no OpenPGP public-key data")
    try:
        decoded = base64.b64decode(b"".join(body), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("ASCII keyring contains invalid base64 armour data") from exc
    if not decoded:
        raise RuntimeError("ASCII keyring decoded to an empty OpenPGP keyring")
    if armor_crc is not None:
        try:
            expected_crc = base64.b64decode(armor_crc, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError("ASCII keyring contains an invalid armour checksum") from exc
        if len(expected_crc) != 3:
            raise RuntimeError("ASCII keyring contains an invalid armour checksum")
        crc = 0xB704CE
        for octet in decoded:
            crc ^= octet << 16
            for _ in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= 0x1864CFB
        actual_crc = (crc & 0xFFFFFF).to_bytes(3, "big")
        if not hmac.compare_digest(actual_crc, expected_crc):
            raise RuntimeError("ASCII keyring armour checksum does not match its contents")
    return decoded


def _prepare_keyring(keyring_path: Path, tmpdir: Path, backend: str) -> Path:
    """Return a verifier-compatible keyring, dearmouring ``.asc`` locally.

    Binary keyrings are passed through unchanged.  ASCII-armoured exported
    public keys are decoded without requiring ``gpg.exe`` so the Windows
    release's bundled ``gpgv`` is sufficient on a clean machine.
    """
    try:
        with keyring_path.open("rb") as handle:
            head = handle.read(64)
            if not head.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK"):
                return keyring_path
            handle.seek(0)
            data = handle.read(MAX_ARMORED_KEYRING_BYTES + 1)
    except OSError as exc:
        raise RuntimeError(f"Could not read configured keyring {keyring_path}: {exc}") from exc
    if len(data) > MAX_ARMORED_KEYRING_BYTES:
        raise RuntimeError(
            f"ASCII keyring {keyring_path.name} exceeds Feathered's "
            f"{MAX_ARMORED_KEYRING_BYTES:,}-byte safety limit")
    target = tmpdir / "keyring.gpg"
    target.write_bytes(_dearmor_public_keyring(data))
    return target



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
    if expected and total != expected:
        raise RuntimeError(
            f"{pkg.nevra}: downloaded size {total:,} does not match repository metadata "
            f"size {expected:,}")
    return total


def decompress_metadata(data: bytes, url: str,
                        max_bytes: int = MAX_METADATA_EXPANDED_BYTES) -> bytes:
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
        if zstd is not None:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(io.BytesIO(data)) as reader:
                return _read_bounded_stream(reader, max_bytes, "Zstandard repository metadata")
        if stdlib_zstd is not None:
            try:
                with stdlib_zstd.ZstdFile(io.BytesIO(data), mode="rb") as reader:
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


def parse_primary(xml: bytes, repo: RepoSpec, arches: Set[str], reporter: Reporter) -> List[Package]:
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
        digest_map = {normalized_hash_algorithm(raw_checksum_type): raw_checksum} if raw_checksum else {}
        selected_digest = select_digest_from_map(digest_map, repo.digest_preference)
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
            index_digest_verified=_repo_trust(repo).metadata_digest_verified,
            package_digest_declared=bool(package.digests),
        )
        packages.append(package)
        el.clear()
    reporter.log(f"{repo.name}: {len(packages):,} usable packages for {', '.join(sorted(arches))}")
    return packages


def _load_repository_once(repo: RepoSpec, arches: Set[str], reporter: Reporter, retries: int = 3) -> List[Package]:
    reporter.log(f"Loading repository: {repo.name}")
    refs = get_repo_data(repo, reporter, retries=retries)
    primary = refs.get("primary")
    if primary is None:
        raise RuntimeError(f"{repo.name}: repomd.xml contains no primary metadata")
    reporter.log(f"{repo.name}: primary -> {primary.url}")
    compressed = fetch_bytes(primary.url, reporter, retries=retries, repo=repo)
    skip_provenance = repository_verification_strategy(repo) == "skip-provenance"
    if skip_provenance:
        # this mode intentionally parses
        # repository metadata without treating repomd checksums as provenance
        # gates. The bundle still receives Feathered's own transfer hashes later.
        reporter.warn(f"{repo.name}: primary metadata checksum verification skipped by operator policy.")
    elif primary.checksum:
        actual = _hash_bytes(compressed, primary.checksum_type)
        if actual.lower() != primary.checksum.lower():
            raise RuntimeError(f"{repo.name}: primary metadata checksum mismatch")
        _repo_trust(repo).metadata_digest_verified = True
    elif repo.allow_unverified_index:
        reporter.warn(f"{repo.name}: repomd.xml publishes no digest for primary metadata; "
                      "accepted because 'allow unverified indexes' is enabled for this repository.")
    else:
        # Silently accepting an undigested index would break the chain that
        # every per-package checksum depends on.
        raise RuntimeError(
            f"{repo.name}: repomd.xml publishes no checksum for the primary metadata, so the "
            "package digests cannot be trusted. Use a complete mirror, or enable 'Allow unverified "
            "indexes' for this repository in Advanced… if you accept that risk."
        )
    xml = decompress_metadata(compressed, primary.url)
    if primary.open_checksum and not skip_provenance:
        actual_open = _hash_bytes(xml, primary.open_checksum_type)
        if actual_open.lower() != primary.open_checksum.lower():
            raise RuntimeError(f"{repo.name}: decompressed metadata checksum mismatch")
    from module_policy import load_supplemental
    load_supplemental(repo, refs, reporter, retries)
    return parse_primary(xml, repo, arches, reporter)


def load_repository(repo: RepoSpec, arches: Set[str], reporter: Reporter, retries: int = 3) -> List[Package]:
    """Load acquisition metadata and optional evidence metadata; exact artifact corroboration occurs later.

    evidence mirrors are never payload
    sources.  Feathered loads only their repository metadata, matches exact package
    identities, and stores any strong digest for verification of the one package
    copy later downloaded from the acquisition mirror.
    """
    packages = _load_repository_once(repo, arches, reporter, retries=retries)
    # 1.0.36 replaces the overlapping
    # Required?/evidence controls with one verification strategy. Evidence
    # mirrors are contacted only by strategies whose definition actually uses
    # independent metadata.
    strategy = repository_verification_strategy(repo)
    if strategy in {"checksum-required", "checksum-available", "skip-provenance"}:
        return packages
    if strategy in {"evidence-fallback", "legacy-fallback"} and all(package_has_selected_digest(pkg) for pkg in packages):
        for pkg in packages:
            _artifact_verification(pkg).evidence_status = "not-needed"
        reporter.log(f"{repo.name}: configured checksum strength is available from acquisition metadata; evidence fallback not needed")
        return packages
    if not repo.evidence_urls:
        if strategy in {"evidence-fallback", "full-corroboration", "legacy-evidence-required",
                        "legacy-fallback", "legacy-corroborate"}:
            for pkg in packages:
                _artifact_verification(pkg).evidence_status = "unavailable"
        return packages

    usable = False
    last_error = ""
    for evidence_url in repo.evidence_urls:
        distinct, reason = mirrors_are_distinct(repo.normalized_url, evidence_url)
        if not distinct:
            reporter.warn(f"{repo.name}: evidence source {redact_url(evidence_url)} ignored ({reason}); "
                          "a source bond requires a distinct mirror hostname")
            last_error = reason
            continue
        # an evidence mirror is an
        # independent transport endpoint. Never forward the acquisition
        # repository's mTLS client certificate/private key or custom TLS CA to
        # it implicitly. the evidence
        # path is deliberately independent of the acquisition archive keyring.
        # Do not inherit it: mirror evidence must still be collectable when GPG
        # is absent, disabled, unavailable, or configured only for acquisition.
        evidence_repo = evidence_repo_for_url(repo, evidence_url)
        relationship = evidence_relationship(repo, evidence_url)
        try:
            evidence_packages = _load_repository_once(evidence_repo, arches, reporter, retries=1)
            stats = apply_mirror_evidence(
                packages, evidence_packages, evidence_repo, reporter, relationship=relationship,
                authority=evidence_authority_relationship(repo, evidence_url))
            kind = "independent rebuild peer" if relationship == REL_REBUILD_PEER else "evidence mirror"
            reporter.log(
                f"Source bond {repo.name}: {kind} {redact_url(evidence_url)} matched "
                f"{stats['matched']:,} package identities ({stats['digest']:,} with strong digest, "
                f"{stats['metadata']:,} metadata-only; {stats['missing']:,} not yet present; "
                f"{stats.get('conflict', 0):,} metadata conflict(s) deferred to selected-artifact verification)")
            usable = True
            break
        except RuntimeError as exc:
            # Contradictory exact-package evidence is qualitatively different
            # from an unavailable/lagging mirror and is never bypassed.
            if (("Mirror bond" in str(exc) or "Peer evidence" in str(exc))
                    and "disagreement" in str(exc)):
                raise
            last_error = str(exc)
            reporter.warn(f"{repo.name}: evidence mirror {redact_url(evidence_url)} unavailable/inconclusive: {exc}")

    if not usable:
        # Missing repomd.xml does not make an evidence endpoint useless. A
        # distinct source may intentionally expose package artifacts without
        # repository metadata. Defer the decisive check until the exact selected
        # artifact is known, then fetch/hash that evidence copy transiently.
        for pkg in packages:
            record = _artifact_verification(pkg)
            if record.evidence_status in {"not-configured", "unavailable"}:
                record.evidence_status = "artifact-pending"
            if not record.evidence_source and repo.evidence_urls:
                record.evidence_source = redact_url(repo.evidence_urls[0])
        if repo.evidence_urls:
            reporter.warn(
                f"{repo.name}: evidence endpoint is not a recognizable RPM repository"
                + (f" ({last_error})" if last_error else "")
                + "; Feathered will try the exact package artifact during verification")
    return packages


def probe_repository(repo: RepoSpec, reporter: Optional[Reporter] = None, retries: int = 2) -> Tuple[bool, str]:
    rep = reporter or Reporter()
    if not repo.url.strip():
        return False, "No URL/path configured"
    try:
        refs = get_repo_data(repo, rep, retries=retries)
        primary = refs.get("primary")
        if primary is None:
            return False, "No primary metadata"
        return True, primary.url
    except Exception as exc:
        # A bare 404 does not say whether the path is wrong or the release is
        # simply not published; look at the directory to find out.
        detail = str(exc)
        if "404" in detail or "Not Found" in detail:
            detail += "\n\n" + diagnose_missing_repository(repo.url, rep)
        return False, detail


def _segments(value: str) -> List[Tuple[int, Union[int, str]]]:
    out: List[Tuple[int, Union[int, str]]] = []
    i = 0
    value = value or ""
    while i < len(value):
        c = value[i]
        if c == "~": out.append((-1, "~")); i += 1; continue
        if c == "^": out.append((0, "^")); i += 1; continue
        if not c.isalnum(): i += 1; continue
        j = i + 1
        if c.isdigit():
            while j < len(value) and value[j].isdigit(): j += 1
            out.append((2, int(value[i:j].lstrip("0") or "0")))
        else:
            while j < len(value) and value[j].isalpha(): j += 1
            out.append((1, value[i:j]))
        i = j
    return out


def rpmvercmp(a: str, b: str) -> int:
    sa, sb = _segments(a), _segments(b)
    for left, right in zip(sa, sb):
        if left == right: continue
        lt, lv = left; rt, rv = right
        if lt == -1 or rt == -1: return -1 if lt == -1 else 1
        if lt != rt: return 1 if lt > rt else -1
        # Segment kinds: 2 = numeric run (value is int), 1 = alphabetic run
        # (value is str), 0 = "^", -1 = "~". Matching kinds guarantee matching
        # value types, so each branch compares like with like -- comparing a
        # numeric run as text would rank 1.9 above 1.10.
        if lt == 2:
            ln, rn = int(lv), int(rv)
            if ln != rn: return -1 if ln < rn else 1
        else:
            ls, rs = str(lv), str(rv)
            if ls != rs: return -1 if ls < rs else 1
    if len(sa) == len(sb): return 0
    rest = sa[len(sb):] if len(sa) > len(sb) else sb[len(sa):]
    if rest and rest[0][0] == -1: return -1 if len(sa) > len(sb) else 1
    return 1 if len(sa) > len(sb) else -1


def compare_evr(left: Tuple[str, str, str], right: Tuple[str, str, str]) -> int:
    try: le = int(left[0] or "0")
    except ValueError: le = 0
    try: re_ = int(right[0] or "0")
    except ValueError: re_ = 0
    if le != re_: return 1 if le > re_ else -1
    c = rpmvercmp(left[1], right[1])
    return c if c else rpmvercmp(left[2], right[2])


_PYDIST_CAP_RE = re.compile(r"^(python(?:\d+(?:\.\d+)?)?dist)\((.+)\)$", re.IGNORECASE)


def _pep503_name(value: str) -> str:
    """Normalize a Python distribution name using the PEP 503 convention.

    RPM's Python dependency generator uses this namespace for python3dist(...)
    and pythonX.Ydist(...) virtual capabilities. RHEL 9 can contain both legacy
    dotted spellings and canonical spellings in Provides while generated
    Requires use the canonical form. Treat those spellings as the same
    capability during lookup without inventing a package-name mapping.
    """
    return re.sub(r"[-_.]+", "-", (value or "").strip()).lower()


def canonical_capability_name(name: str) -> str:
    raw = (name or "").strip()
    m = _PYDIST_CAP_RE.fullmatch(raw)
    if not m:
        return raw
    prefix, dist = m.groups()
    extra = ""
    if "[" in dist and dist.endswith("]"):
        base, raw_extra = dist[:-1].split("[", 1)
        extras = [x for x in raw_extra.split(",") if x.strip()]
        dist = _pep503_name(base)
        extra = "[" + ",".join(_pep503_name(x) for x in extras) + "]"
    else:
        dist = _pep503_name(dist)
    return f"{prefix.lower()}({dist}{extra})"


def capability_names_equal(left: str, right: str) -> bool:
    return canonical_capability_name(left) == canonical_capability_name(right)


def _index_keys(name: str) -> Tuple[str, ...]:
    raw = (name or "").strip()
    canonical = canonical_capability_name(raw)
    return (raw,) if canonical == raw else (raw, canonical)


def _provider_candidates(index: Dict[str, List[ProviderMatch]], req: Requirement) -> List[ProviderMatch]:
    """Return de-duplicated provider candidates using exact and canonical keys."""
    seen: Set[Tuple[int, str, str, Optional[Tuple[str, str, str]]]] = set()
    out: List[ProviderMatch] = []
    for key in _index_keys(req.name):
        for match in index.get(key, []):
            ident = (id(match.package), match.provide.name, match.provide.flags or "", match.provide.evr)
            if ident in seen:
                continue
            seen.add(ident)
            out.append(match)
    return out


def _requirement_note(req: Requirement, candidates: Sequence[ProviderMatch]) -> str:
    """Explain an unresolved capability without calling every case a missing repo."""
    shown: List[str] = []
    for match in candidates:
        if not capability_names_equal(match.provide.name, req.name):
            continue
        pev = match.provide.evr
        if pev is not None:
            ep = f"{pev[0]}:" if pev[0] and pev[0] != "0" else ""
            evr = f"{ep}{pev[1]}" + (f"-{pev[2]}" if pev[2] else "")
        else:
            evr = "unversioned"
        item = f"{match.package.nevra} provides {match.provide.name} {evr} [{match.package.repo.name}]"
        if item not in shown:
            shown.append(item)
        if len(shown) >= 3:
            break
    if shown:
        return "Providers exist, but none satisfy the requested version: " + "; ".join(shown)
    if _PYDIST_CAP_RE.fullmatch((req.name or "").strip()):
        canonical = canonical_capability_name(req.name)
        return (f"No enabled repository advertises Python virtual capability {canonical}. "
                "Python RPM dependencies are satisfied through RPM Provides (python3dist/pythonX.Ydist), "
                "not by guessing a python3-* package name. Check AppStream/CRB/EPEL or add the repository that owns the module.")
    if req.name == "python(abi)" or req.name.startswith("/usr/bin/python"):
        return ("No enabled repository provides the required Python interpreter/ABI capability. "
                "Check the target release/architecture and BaseOS/AppStream sources.")
    return "No matching provider in enabled repositories"


def should_ignore(req: Requirement) -> bool:
    return not req.name or req.name.startswith(("rpmlib(", "config(", "user(", "group("))


def evr_satisfies(provider: Requirement, req: Requirement, package: Optional[Package] = None) -> bool:
    if not req.flags or req.evr is None:
        return True
    pevr = provider.evr
    if pevr is None and package is not None and provider.name == package.name:
        pevr = package.evr
    if pevr is None:
        return False
    c = compare_evr(pevr, req.evr)
    flag = req.flags.upper()
    return {"EQ": c == 0, "=": c == 0, "GE": c >= 0, ">=": c >= 0,
            "GT": c > 0, ">": c > 0, "LE": c <= 0, "<=": c <= 0,
            "LT": c < 0, "<": c < 0}.get(flag, False)  # unknown operators fail closed.


def package_satisfies(pkg: Package, req: Requirement) -> bool:
    own = Requirement(pkg.name, "EQ", pkg.epoch, pkg.version, pkg.release, "provides")
    if capability_names_equal(own.name, req.name) and evr_satisfies(own, req, pkg):
        return True
    arch_cap = _rpm_arch_capability(pkg)
    if arch_cap is not None and capability_names_equal(arch_cap.name, req.name) and evr_satisfies(arch_cap, req, pkg):
        return True
    for provide in pkg.provides:
        if capability_names_equal(provide.name, req.name) and evr_satisfies(provide, req, pkg):
            return True
    return not req.flags and req.name in pkg.files


def inventory_satisfies(inv: Optional[TargetInventory], req: Requirement) -> bool:
    if inv is None:
        return False
    seen: Set[int] = set()
    for key in _index_keys(req.name):
        for p in inv.capabilities.get(key, []):
            if id(p) in seen:
                continue
            seen.add(id(p))
            if evr_satisfies(p, req):
                return True
    return False


def _provider_rank(match: ProviderMatch, preferred_arch: str, requested_name: str) -> Tuple[int, int, int]:
    pkg = match.package
    exact_name = 0 if pkg.name == requested_name else 1
    arch_rank = 0 if pkg.arch == preferred_arch else 1 if pkg.arch == "noarch" else 2
    return (pkg.repo.priority, exact_name, arch_rank)


def choose_provider(matches: Iterable[ProviderMatch], preferred_arch: str, requested_name: str) -> Optional[ProviderMatch]:
    matches = list(matches)
    if not matches:
        return None
    best_rank = min(_provider_rank(m, preferred_arch, requested_name) for m in matches)
    candidates = [m for m in matches if _provider_rank(m, preferred_arch, requested_name) == best_rank]
    best = candidates[0]
    for m in candidates[1:]:
        c = compare_evr(m.package.evr, best.package.evr)
        if c > 0 or (c == 0 and m.package.nevra > best.package.nevra):
            best = m
    return best


def _detect_default_python_abi(packages: Sequence[Package]) -> Optional[str]:
    """Detect the distro default Python ABI from python3/python3-libs Provides.

    Generic python3dist(...) refers to the default Python 3 stack. We only use
    this ABI to create lookup aliases when the repository metadata exposes one
    form (generic or X.Y-specific) but not the other.
    """
    candidates: List[Tuple[int, Tuple[str, str, str], str]] = []
    for pkg in packages:
        if pkg.name not in {"python3", "python3-libs"}:
            continue
        for provide in pkg.provides:
            if provide.name != "python(abi)" or not provide.version:
                continue
            if not re.fullmatch(r"\d+\.\d+", provide.version):
                continue
            candidates.append((pkg.repo.priority, pkg.evr, provide.version))
    if not candidates:
        return None
    best_priority = min(x[0] for x in candidates)
    same = [x for x in candidates if x[0] == best_priority]
    best = same[0]
    for item in same[1:]:
        if compare_evr(item[1], best[1]) > 0:
            best = item
    return best[2]


def _python_default_alias(name: str, default_abi: Optional[str]) -> Optional[str]:
    if not default_abi:
        return None
    canonical = canonical_capability_name(name)
    m = _PYDIST_CAP_RE.fullmatch(canonical)
    if not m:
        return None
    prefix, dist = m.groups()
    if prefix == "python3dist":
        return f"python{default_abi}dist({dist})"
    if prefix == f"python{default_abi}dist":
        return f"python3dist({dist})"
    return None


def build_provider_index(packages: Sequence[Package], reporter: Optional[Reporter] = None) -> Dict[str, List[ProviderMatch]]:
    out: Dict[str, List[ProviderMatch]] = defaultdict(list)
    default_python_abi = _detect_default_python_abi(packages)
    if reporter and default_python_abi:
        reporter.log(f"Detected default Python ABI {default_python_abi}; enabling safe python3dist/python{default_python_abi}dist lookup aliases")
    for i, pkg in enumerate(packages, 1):
        own = Requirement(pkg.name, "EQ", pkg.epoch, pkg.version, pkg.release, "provides")
        for key in _index_keys(pkg.name):
            out[key].append(ProviderMatch(pkg, own))
        arch_cap = _rpm_arch_capability(pkg)
        if arch_cap is not None:
            for key in _index_keys(arch_cap.name):
                out[key].append(ProviderMatch(pkg, arch_cap))
        for p in pkg.provides:
            if p.name:
                keys = list(_index_keys(p.name))
                alias = _python_default_alias(p.name, default_python_abi)
                if alias:
                    keys.extend(_index_keys(alias))
                for key in dict.fromkeys(keys):
                    out[key].append(ProviderMatch(pkg, p))
        for f in pkg.files:
            if f:
                out[f].append(ProviderMatch(pkg, Requirement(f, kind="provides")))
        if reporter and i % 12000 == 0:
            reporter.log(f"Indexed {i:,}/{len(packages):,} package records")
    return out


def _find_root(name: str, version: Optional[str], index: Dict[str, List[ProviderMatch]],
               preferred_arch: str, role: Optional[str] = None,
               repo_name: Optional[str] = None, exact_arch: Optional[str] = None,
               source_scope: Optional[str] = None, repo_identity: Optional[str] = None) -> Optional[ProviderMatch]:
    """Find a root package under explicit provenance constraints.

    ``source_scope="distribution"`` means any repository in the distribution/base
    tier. This is intentionally different from ``role="dependency"``: several
    top-level repositories can share that backend role, and supplemental repositories
    may share it too. Workload/vendor roots instead use ``role``. Exact-package
    browser selections may additionally pin repository name and architecture.
    """
    matches = _provider_candidates(index, Requirement(name))
    if source_scope == "distribution":
        matches = [m for m in matches
                   if getattr(m.package.repo, "source_tier", "base") == "base"]
    if role:
        # An explicitly requested workload/vendor role is a constraint, not a hint.
        matches = [m for m in matches if m.package.repo.role == role]
    if repo_identity:
        matches = [m for m in matches if m.package.repo.source_identity == repo_identity]
    elif repo_name:
        matches = [m for m in matches if m.package.repo.name == repo_name]
    if exact_arch:
        matches = [m for m in matches if m.package.arch == exact_arch]
    if version and version != "Latest":
        matches = [m for m in matches if m.package.evr_text == version or m.package.version == version]
    return choose_provider(matches, preferred_arch, name)


_RICH_IF_RE = re.compile(r"^\((.+?)\s+if\s+(.+?)\)$")


def _rich_outer_body(text: str) -> Optional[str]:
    """Return the body of one complete parenthesized rich dependency.

    Capability names such as python3.9dist(chardet) contain parentheses of
    their own, so rich operators must be detected only at the outer expression
    depth rather than with a plain string split.
    """
    text = (text or "").strip()
    if len(text) < 2 or text[0] != "(" or text[-1] != ")":
        return None
    depth = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return None
            if depth == 0 and i != len(text) - 1:
                return None
    return text[1:-1].strip() if depth == 0 else None


def _split_top_level_keyword(body: str, keyword: str) -> List[str]:
    """Split on a whitespace-delimited rich operator at depth zero."""
    needle = f" {keyword} "
    depth = 0
    start = 0
    parts: List[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth -= 1
            if depth < 0:
                return []
            i += 1
            continue
        if depth == 0 and body.startswith(needle, i):
            part = body[start:i].strip()
            if not part:
                return []
            parts.append(part)
            i += len(needle)
            start = i
            continue
        i += 1
    if depth != 0:
        return []
    if not parts:
        return []
    tail = body[start:].strip()
    if not tail:
        return []
    parts.append(tail)
    return parts


def _simple_requirement_from_text(text: str, kind: str = "requires") -> Optional[Requirement]:
    """Parse the simple leaf form used inside common RPM rich deps.

    Examples:
      container-selinux
      container-selinux >= 2:2.162.1
      glibc-gconv-extra(x86-64) = 2.34-275.el9_8

    This intentionally does not pretend to implement the complete RPM rich
    dependency grammar. Unsupported expressions remain fail-closed.
    """
    text = (text or "").strip()
    m = re.fullmatch(r"([^\s]+)(?:\s*(>=|<=|=|>|<)\s*([^\s]+))?", text)
    if not m:
        return None
    name, flags, evr_text = m.groups()
    if not evr_text:
        return Requirement(name=name, kind=kind)
    epoch, version, release = _parse_evr_text(evr_text)
    return Requirement(name=name, flags=flags, epoch=epoch, version=version, release=release, kind=kind)


def parse_simple_rich_if(req: Requirement) -> Optional[Tuple[Requirement, Requirement]]:
    """Return (consequence, condition) for `(A if B)` rich dependencies."""
    body = _rich_outer_body(req.name)
    if body is None:
        return None
    parts = _split_top_level_keyword(body, "if")
    if len(parts) != 2:
        return None
    consequence = _simple_requirement_from_text(parts[0], req.kind)
    condition = _simple_requirement_from_text(parts[1], "condition")
    if consequence is None or condition is None:
        return None
    return consequence, condition


def parse_simple_rich_or(req: Requirement) -> Optional[List[Requirement]]:
    """Parse the common RPM rich ``(A or B [or C])`` form.

    1.0.39 resolves simple top-level
    alternatives instead of reporting them as unsupported syntax.  Each branch
    must still be a simple leaf requirement; nested boolean expressions remain
    fail-closed so Feathered never guesses at semantics it did not parse.
    """
    body = _rich_outer_body(req.name)
    if body is None:
        return None
    parts = _split_top_level_keyword(body, "or")
    if len(parts) < 2:
        return None
    leaves = [_simple_requirement_from_text(part, req.kind) for part in parts]
    if any(leaf is None for leaf in leaves):
        return None
    return [leaf for leaf in leaves if leaf is not None]


def parse_simple_rich_with(req: Requirement) -> Optional[List[Requirement]]:
    """Parse a simple RPM rich `with` expression into leaf requirements.

    RPM defines `with` as requiring every operand to be fulfilled by the SAME
    package. This is frequently emitted by Python dependency generators to
    encode bounded ranges, for example:

      (python3.9dist(chardet) < 5 with python3.9dist(chardet) >= 3.0.4)

    We support one or more simple leaf operands and keep the same-package
    semantics during provider selection. Nested boolean operands intentionally
    remain fail-closed.
    """
    body = _rich_outer_body(req.name)
    if body is None:
        return None
    parts = _split_top_level_keyword(body, "with")
    if len(parts) < 2:
        return None
    leaves = [_simple_requirement_from_text(part, req.kind) for part in parts]
    if any(leaf is None for leaf in leaves):
        return None
    return [leaf for leaf in leaves if leaf is not None]


def _package_satisfies_all(index: Dict[str, List[ProviderMatch]], pkg: Package, reqs: Sequence[Requirement]) -> bool:
    return all(_indexed_package_satisfies(index, pkg, req) for req in reqs)


def _inventory_package_satisfies(inv: Optional[TargetInventory], capabilities: Sequence[Requirement], req: Requirement) -> bool:
    if inv is None:
        return False
    for provide in capabilities:
        if capability_names_equal(provide.name, req.name) and evr_satisfies(provide, req):
            return True
    return False


def inventory_satisfies_same_package(inv: Optional[TargetInventory], reqs: Sequence[Requirement]) -> bool:
    """Evaluate rich `with` against one installed package, not globally."""
    if inv is None:
        return False
    for capabilities in inv.package_capabilities.values():
        if all(_inventory_package_satisfies(inv, capabilities, req) for req in reqs):
            return True
    return False


def _same_package_provider_candidates(index: Dict[str, List[ProviderMatch]], reqs: Sequence[Requirement]) -> List[ProviderMatch]:
    """Return packages that satisfy every rich `with` operand themselves."""
    if not reqs:
        return []
    seen_pkg: Set[int] = set()
    out: List[ProviderMatch] = []
    for first in _provider_candidates(index, reqs[0]):
        pkg = first.package
        ident = id(pkg)
        if ident in seen_pkg:
            continue
        seen_pkg.add(ident)
        if not _package_satisfies_all(index, pkg, reqs):
            continue
        # Keep a provider match for ranking/provenance. The package itself has
        # already been verified against every operand above.
        out.append(first)
    return out


def _rich_with_note(index: Dict[str, List[ProviderMatch]], reqs: Sequence[Requirement]) -> str:
    details: List[str] = []
    for leaf in reqs:
        candidates = _provider_candidates(index, leaf)
        satisfying = [m for m in candidates if evr_satisfies(m.provide, leaf, m.package)]
        if satisfying:
            sample = satisfying[0].package.nevra
            details.append(f"{format_requirement(leaf)} has provider {sample}")
        elif candidates:
            details.append(f"{format_requirement(leaf)} has providers, but none satisfy its version bound")
        else:
            details.append(f"{format_requirement(leaf)} has no provider")
    suffix = "; ".join(details[:4])
    return ("RPM rich 'with' requires all operands to be satisfied by one RPM, but no single enabled package satisfies the full expression"
            + (f": {suffix}" if suffix else ""))


def _rpm_arch_capability(pkg: Package) -> Optional[Requirement]:
    # RPM commonly exposes architecture-qualified package capabilities such as
    # glibc-gconv-extra(x86-64). Primary metadata normally includes them, but
    # synthesize the canonical package capability as a defensive fallback.
    arch_names = {
        "x86_64": "x86-64",
        "aarch64": "aarch64",
        "ppc64le": "ppc-64",
        "s390x": "s390-64",
    }
    suffix = arch_names.get(pkg.arch)
    if not suffix:
        return None
    return Requirement(f"{pkg.name}({suffix})", "EQ", pkg.epoch, pkg.version, pkg.release, "provides")


def format_requirement(req: Requirement) -> str:
    if req.flags and req.evr:
        epoch, version, release = req.evr
        rel = f"-{release}" if release else ""
        ep = f"{epoch}:" if epoch and epoch != "0" else ""
        return f"{req.name} {req.flags} {ep}{version}{rel}"
    return req.name


def _indexed_package_satisfies(index: Dict[str, List[ProviderMatch]], pkg: Package, req: Requirement) -> bool:
    if package_satisfies(pkg, req):
        return True
    for match in _provider_candidates(index, req):
        if match.package is pkg and evr_satisfies(match.provide, req, pkg):
            return True
    return False


def _selected_or_pending_satisfies(packages: Iterable[Package], req: Requirement,
                                    index: Optional[Dict[str, List[ProviderMatch]]] = None) -> bool:
    if index is None:
        return any(package_satisfies(pkg, req) for pkg in packages)
    return any(_indexed_package_satisfies(index, pkg, req) for pkg in packages)


def _constraint_key(req: Requirement) -> Tuple[object, ...]:
    return (canonical_capability_name(req.name), req.flags, req.evr)


def _satisfies_constraints(index: Dict[str, List[ProviderMatch]], pkg: Package,
                           constraints: Sequence[Requirement]) -> bool:
    return all(_indexed_package_satisfies(index, pkg, c) for c in constraints)


def resolve(root_requests: Sequence[RootInput], packages: Sequence[Package],
            preferred_arch: str, options: BuildOptions[TargetInventory], reporter: Reporter) -> ResolutionResult:
    from transaction_model import resolve_transaction
    return resolve_transaction(_resolve_once, root_requests, packages, preferred_arch,
                               options, reporter, 'rpm')


def _resolve_once(root_requests: Sequence[Tuple], packages: Sequence[Package],
            preferred_arch: str, options: BuildOptions[TargetInventory], reporter: Reporter) -> ResolutionResult:
    """Resolve package roots and their dependency closure.

    Runs the closure repeatedly, accumulating *version floors*: constraints
    that a previously selected package failed to satisfy. A single greedy pass
    can pick package X-1.0 for an unversioned requirement and only later meet
    a `Requires: X >= 2.0`; rather than declaring that unresolvable, the next
    pass carries `X >= 2.0` forward and selects a candidate that satisfies both
    requirements. Resolution stops when a pass discovers no new constraints, or
    when a constraint set is genuinely unsatisfiable (reported as unresolved).
    """
    constraints: Dict[str, List[Requirement]] = defaultdict(list)
    # Providers proven unworkable for a capability, so another can be tried.
    rejected: Set[Tuple[str, str]] = set()
    seen_keys: Set[Tuple[object, ...]] = set()
    # The loop below always runs at least once, so `result` is bound before use.
    result: ResolutionResult = ResolutionResult(selected=[], unresolved=[], roots=[])
    for attempt in range(1, max(1, options.max_resolution_passes) + 1):
        reporter.check_cancel()
        result, discovered = _resolve_pass(root_requests, packages, preferred_arch, options,
                                           reporter, constraints, rejected)
        fresh = [(name, req) for name, req in discovered
                 if (name, _constraint_key(req)) not in seen_keys]
        if not fresh:
            if not result.unresolved:
                return result
            if not _reject_failed_provider(result, rejected, reporter):
                return result
            # Constraints are derived from the abandoned branch's selections,
            # so they are discarded with it and re-derived on the next pass.
            constraints.clear()
            seen_keys.clear()
            continue
        for name, req in fresh:
            seen_keys.add((name, _constraint_key(req)))
            constraints[name].append(req)
            reporter.log(f"Re-resolving with version floor {name} {format_requirement(req)} "
                         f"(pass {attempt + 1})")
    reporter.warn("Dependency resolution hit the pass limit; the reported closure may still "
                  "contain version conflicts. Review conflicts.txt before installing.")
    return result


def _reject_failed_provider(result, rejected: Set[Tuple[str, str]], reporter: Reporter) -> bool:
    """Blame a failed closure on the provider choice that introduced it."""
    for capability, chosen, others in reversed(getattr(result, "provider_choices", [])):
        if (capability, chosen) in rejected:
            continue
        remaining = [o for o in others if (capability, o) not in rejected]
        if not remaining:
            continue
        rejected.add((capability, chosen))
        reporter.log(f"Provider '{chosen}' for '{capability}' led to an unresolvable closure; "
                     f"trying {' or '.join(remaining)} instead")
        return True
    return False


def _resolve_pass(root_requests: Sequence[Tuple], packages: Sequence[Package],
                  preferred_arch: str, options: BuildOptions[TargetInventory], reporter: Reporter,
                  constraints: Dict[str, List[Requirement]],
                  rejected: Optional[Set[Tuple[str, str]]] = None
                  ) -> Tuple[ResolutionResult, List[Tuple[str, Requirement]]]:
    reporter.log("Building provider index...")
    index = build_provider_index(packages, reporter)
    # Constraints discovered during this pass, fed back into the next one.
    discovered: List[Tuple[str, Requirement]] = []
    rejected_set = rejected if rejected is not None else set()
    provider_choices: List[Tuple[str, str, List[str]]] = []

    def pick(matches, requested_name: str):
        """Choose a provider honouring version floors and past rejections."""
        matches = list(matches)
        filtered = [m for m in matches
                    if _satisfies_constraints(index, m.package, constraints.get(m.package.name, ()))]
        allowed = [m for m in filtered
                   if (requested_name, m.package.name) not in rejected_set]
        chosen = choose_provider(allowed or filtered or [], preferred_arch, requested_name)
        if chosen is not None:
            alternatives = sorted({m.package.name for m in filtered} - {chosen.package.name})
            if alternatives:
                provider_choices.append((requested_name, chosen.package.name, alternatives))
        return chosen
    roots: List[Package] = []
    root_names: Set[str] = set()
    # Declared before the root loop: missing roots are now recorded rather than
    # aborting, so the loop needs somewhere to record them.
    unresolved: List[Requirement] = []
    unresolved_notes: Dict[str, str] = {}
    skipped: Set[str] = set()
    roots_requested = bool(root_requests)
    for request in root_requests:
        if len(request) < 3:
            raise RuntimeError(f"Invalid root request: {request!r}")
        name, version, role = request[:3]
        repo_name = request[3] if len(request) >= 4 else None
        exact_arch = request[4] if len(request) >= 5 else None
        source_scope = request[5] if len(request) >= 6 else None
        repo_identity = request[6] if len(request) >= 7 else None
        match = _find_root(name, version, index, preferred_arch, role, repo_name, exact_arch, source_scope, repo_identity)
        if match and not _satisfies_constraints(index, match.package, constraints.get(match.package.name, ())):
            constrained_index = build_provider_index([
                p for p in packages if _satisfies_constraints(index, p, constraints.get(p.name, ()))], reporter)
            match = _find_root(name, version, constrained_index, preferred_arch, role, repo_name,
                               exact_arch, source_scope, repo_identity) or match
        if not match:
            # Report every missing root together rather than aborting on the
            # first. A preset lists tools that span several repositories, and
            # dying on one absent package hid the other 29 that were fine.
            detail = f"No provider found for '{name}'"
            if version:
                detail += f" version '{version}'"
            if repo_name:
                detail += f" in repository '{repo_name}'"
            if exact_arch:
                detail += f" for architecture '{exact_arch}'"
            if source_scope == "distribution":
                detail += " in the distribution repository set"
            if name in options.optional_roots:
                skipped.add(f"{name} (optional; not offered by the configured sources)")
                reporter.log(f"Skipping optional package '{name}': not present in any enabled source")
                continue
            requirement = Requirement(name, None, kind="root")
            unresolved.append(requirement)
            unresolved_notes[format_requirement(requirement)] = (
                detail + ". Enable a repository that carries it (EPEL and CRB/PowerTools hold "
                "many tools absent from BaseOS/AppStream), or remove it from the selection.")
            reporter.log("UNRESOLVED root: " + detail)
            continue
        roots.append(match.package)
        root_names.add(match.package.name)
        reporter.log(f"Root: {match.package.nevra} [{match.package.repo.name}]")

    if roots_requested and not roots:
        raise RuntimeError(
            "None of the selected packages were found in any enabled source. This usually means "
            "the sources are for a different release or architecture than the target, or that no "
            "source carrying operating-system packages is enabled.")
    if not options.include_dependencies:
        unique = {p.name: p for p in roots}
        return ResolutionResult(selected=sorted(unique.values(), key=lambda p: p.name), unresolved=unresolved, roots=roots,
                                unresolved_notes=unresolved_notes, skipped_installed=sorted(skipped),
                                reasons={p.nevra: "requested package" for p in unique.values()}), []

    selected_by_name: Dict[str, Package] = {}
    pending_by_name: Dict[str, Package] = {p.name: p for p in roots}
    queue = deque(roots)
    unresolved_keys: Set[Tuple[object, ...]] = set()
    reasons: Dict[str, str] = {p.nevra: "requested package" for p in roots}
    installed_satisfied: Set[str] = set()

    while queue:
        reporter.check_cancel()
        pkg = queue.popleft()
        pending_by_name.pop(pkg.name, None)
        existing = selected_by_name.get(pkg.name)
        if existing is not None:
            if existing.nevra != pkg.nevra:
                reporter.log(f"Keeping {existing.nevra}; ignoring alternate {pkg.nevra}")
            continue
        selected_by_name[pkg.name] = pkg

        reqs = list(pkg.requires)
        if options.include_recommends:
            reqs.extend(pkg.recommends)
        for req in reqs:
            if should_ignore(req):
                continue
            reason_override = None
            if req.name.startswith("("):
                rich_with = parse_simple_rich_with(req)
                if rich_with is not None:
                    all_current = list(selected_by_name.values()) + list(pending_by_name.values())
                    if any(_package_satisfies_all(index, current, rich_with) for current in all_current):
                        continue
                    if inventory_satisfies_same_package(options.target_inventory, rich_with):
                        installed_satisfied.add(format_requirement(req))
                        continue
                    same_pkg_candidates = _same_package_provider_candidates(index, rich_with)
                    provider = pick(same_pkg_candidates, canonical_capability_name(rich_with[0].name))
                    if provider is None:
                        key = (req.name, req.flags, req.evr, "rich-with")
                        if key not in unresolved_keys:
                            unresolved_keys.add(key); unresolved.append(req)
                            unresolved_notes[format_requirement(req)] = _rich_with_note(index, rich_with)
                            reporter.log(f"UNRESOLVED rich WITH {format_requirement(req)} required by {pkg.nevra}: {unresolved_notes[format_requirement(req)]}")
                        continue
                    chosen = provider.package
                    already = selected_by_name.get(chosen.name) or pending_by_name.get(chosen.name)
                    if already is not None:
                        if not _package_satisfies_all(index, already, rich_with):
                            for operand in rich_with:
                                discovered.append((chosen.name, operand))
                            key = (req.name, req.flags, req.evr, "rich-with-version-conflict")
                            if key not in unresolved_keys:
                                unresolved_keys.add(key); unresolved.append(req)
                                unresolved_notes[format_requirement(req)] = f"Selected package {already.nevra} does not satisfy every operand of this RPM rich 'with' expression"
                                reporter.log(f"UNRESOLVED rich WITH version constraint {format_requirement(req)}; selected {already.nevra}")
                        continue
                    pending_by_name[chosen.name] = chosen
                    queue.append(chosen)
                    reasons.setdefault(chosen.nevra, f"required by {pkg.name}: {format_requirement(req)}")
                    reporter.log(f"RICH WITH -> {chosen.nevra} satisfies all operands of {format_requirement(req)}")
                    continue

                rich_or = parse_simple_rich_or(req)
                if rich_or is not None:
                    all_current = list(selected_by_name.values()) + list(pending_by_name.values())
                    if any(_selected_or_pending_satisfies(all_current, branch, index)
                           for branch in rich_or):
                        continue
                    if any(inventory_satisfies(options.target_inventory, branch) for branch in rich_or):
                        installed_satisfied.add(format_requirement(req))
                        continue
                    branch_matches: List[ProviderMatch] = []
                    for branch in rich_or:
                        branch_matches.extend(
                            match for match in _provider_candidates(index, branch)
                            if evr_satisfies(match.provide, branch, match.package))
                    # De-duplicate identical packages that happen to satisfy more
                    # than one branch while preserving provider-ranking input.
                    seen_nevra = set()
                    candidates = []
                    for match in branch_matches:
                        if match.package.nevra not in seen_nevra:
                            seen_nevra.add(match.package.nevra)
                            candidates.append(match)
                    provider = pick(candidates, req.name)
                    if provider is None:
                        key = (req.name, req.flags, req.evr, "rich-or")
                        if key not in unresolved_keys:
                            unresolved_keys.add(key); unresolved.append(req)
                            branch_text = " or ".join(format_requirement(branch) for branch in rich_or)
                            unresolved_notes[format_requirement(req)] = (
                                f"No enabled package satisfies any branch of this RPM rich dependency: {branch_text}")
                            reporter.log(f"UNRESOLVED rich OR {format_requirement(req)} required by {pkg.nevra}")
                        continue
                    chosen = provider.package
                    already = selected_by_name.get(chosen.name) or pending_by_name.get(chosen.name)
                    if already is not None:
                        # The same package name may already have been selected at
                        # a version that does not satisfy the branch represented
                        # by this provider; let the ordinary version-floor pass
                        # discover a correction where possible.
                        matching_branch = next((branch for branch in rich_or
                                                if _indexed_package_satisfies(index, already, branch)), None)
                        if matching_branch is None:
                            branch = next((branch for branch in rich_or
                                           if _indexed_package_satisfies(index, chosen, branch)), rich_or[0])
                            discovered.append((chosen.name, branch))
                            if req not in unresolved:
                                unresolved.append(req)
                                unresolved_notes[format_requirement(req)] = "Selected provider does not satisfy this rich OR dependency"
                        continue
                    pending_by_name[chosen.name] = chosen
                    queue.append(chosen)
                    reasons.setdefault(chosen.nevra,
                                       f"required by {pkg.name}: {format_requirement(req)}")
                    reporter.log(f"RICH OR -> {chosen.nevra} satisfies {format_requirement(req)}")
                    continue

                parsed_rich = parse_simple_rich_if(req)
                if parsed_rich is None:
                    key = (req.name, req.flags, req.evr, "rich")
                    if key not in unresolved_keys:
                        unresolved_keys.add(key); unresolved.append(req)
                        unresolved_notes[format_requirement(req)] = "Unsupported/ambiguous RPM rich dependency expression"
                        reporter.log(f"UNRESOLVED unsupported rich dependency {format_requirement(req)}")
                    continue
                consequence, condition = parsed_rich
                all_current = list(selected_by_name.values()) + list(pending_by_name.values())
                condition_true = (_selected_or_pending_satisfies(all_current + list(getattr(options, "_transaction_candidates", [])), condition, index) or
                                  inventory_satisfies(options.target_inventory, condition))
                if options.target_inventory is not None and not condition_true:
                    # With a concrete target inventory, honor the `if` and do
                    # not collect the consequence when its condition is absent.
                    reporter.log(f"SKIP conditional dependency {format_requirement(consequence)}; target does not satisfy {format_requirement(condition)}")
                    continue
                # Without a target inventory we cannot know which standard OS
                # capabilities are already installed. For an offline COMPLETE
                # bundle, conservatively include the consequence so the bundle
                # works when the condition is present on the destination.
                req = consequence
                reason_override = f"conditional dependency of {pkg.name}: {format_requirement(consequence)} if {format_requirement(condition)}"
                reporter.log(f"RICH IF -> resolving {format_requirement(consequence)} (condition: {format_requirement(condition)})")
            all_current = list(selected_by_name.values()) + list(pending_by_name.values())
            if _selected_or_pending_satisfies(all_current, req, index):
                continue
            if inventory_satisfies(options.target_inventory, req):
                installed_satisfied.add(format_requirement(req))
                continue
            all_candidates = _provider_candidates(index, req)
            candidates = [m for m in all_candidates if evr_satisfies(m.provide, req, m.package)]
            provider = pick(candidates, canonical_capability_name(req.name))
            if provider is None:
                key = (canonical_capability_name(req.name), req.flags, req.evr, req.kind)
                if key not in unresolved_keys:
                    unresolved_keys.add(key); unresolved.append(req)
                    unresolved_notes[format_requirement(req)] = _requirement_note(req, all_candidates)
                    reporter.log(f"UNRESOLVED {format_requirement(req)} required by {pkg.nevra}: {unresolved_notes[format_requirement(req)]}")
                continue
            chosen = provider.package
            already = selected_by_name.get(chosen.name) or pending_by_name.get(chosen.name)
            if already is not None:
                if not _indexed_package_satisfies(index, already, req):
                    # Ask for another pass pinned to this constraint; if no
                    # candidate can satisfy every accumulated floor, the next
                    # pass reports it as unresolved and the build stays blocked.
                    discovered.append((chosen.name, req))
                    key = (req.name, req.flags, req.evr, "version-conflict")
                    if key not in unresolved_keys:
                        unresolved_keys.add(key); unresolved.append(req)
                        unresolved_notes[format_requirement(req)] = (
                            f"Selected package {already.nevra} does not satisfy this version constraint")
                        reporter.log(f"VERSION CONFLICT {format_requirement(req)}; selected {already.nevra}")
                continue
            pending_by_name[chosen.name] = chosen
            queue.append(chosen)
            reasons.setdefault(chosen.nevra, reason_override or f"required by {pkg.name}: {format_requirement(req)}")

    selected = sorted(selected_by_name.values(), key=lambda p: (p.repo.priority, p.name, p.nevra))

    conflicts: List[str] = []
    conflict_seen: Set[str] = set()
    for pkg in selected:
        for req in pkg.conflicts:
            if should_ignore(req):
                continue
            for other in selected:
                if other.name == pkg.name:
                    continue
                if package_satisfies(other, req):
                    text = f"{pkg.nevra} conflicts with {other.nevra} via {format_requirement(req)}"
                    if text not in conflict_seen:
                        conflict_seen.add(text); conflicts.append(text)
            if inventory_satisfies(options.target_inventory, req):
                text = f"{pkg.nevra} conflicts with an installed target capability: {format_requirement(req)}"
                if text not in conflict_seen:
                    conflict_seen.add(text); conflicts.append(text)

    # `skipped` was seeded above with optional roots that were not offered by
    # any source; keep those entries rather than starting a fresh list.
    # Target-aware mode uses capabilities during resolution. Exact package
    # matches are reported for visibility, but roots are never omitted.
    if options.target_inventory:
        for pkg in selected:
            if pkg.name not in root_names and pkg.nevra in options.target_inventory.nevras:
                skipped.add(pkg.nevra)
        if skipped:
            selected = [p for p in selected if p.nevra not in set(skipped)]

    outcome = ResolutionResult(
        selected=selected, unresolved=unresolved, roots=roots,
        skipped_installed=sorted(skipped), conflicts=conflicts,
        reasons=reasons, installed_satisfied=sorted(installed_satisfied),
        unresolved_notes=unresolved_notes,
    )
    outcome.provider_choices = provider_choices
    return outcome, discovered


def package_versions(packages: Sequence[Package], name: str, role: Optional[str], preferred_arch: str) -> List[str]:
    vals = [p for p in packages if p.name == name and (not role or p.repo.role == role)
            and p.arch in {preferred_arch, "noarch"}]
    from functools import cmp_to_key
    vals.sort(key=cmp_to_key(lambda a, b: -compare_evr(a.evr, b.evr)))
    seen: Set[str] = set(); out: List[str] = []
    for p in vals:
        if p.evr_text not in seen:
            seen.add(p.evr_text); out.append(p.evr_text)
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_file(path: Path, algorithm: str) -> str:
    algo = (algorithm or "sha256").lower()
    if algo == "sha": algo = "sha1"
    h = hashlib.new(algo)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# package-content verification is
# intentionally stricter than generic hashlib support.  Weak repository hashes
# can still be parsed for diagnostics, but they are not accepted as security
# evidence.
STRONG_PACKAGE_HASHES = {"sha256", "sha384", "sha512"}


def normalized_hash_algorithm(value: str) -> str:
    algo = (value or "").strip().lower().replace("-", "")
    aliases = {"sha2": "sha256", "sha256sum": "sha256", "sha384sum": "sha384",
               "sha512sum": "sha512", "sha": "sha1"}
    return aliases.get(algo, algo)


def strong_package_digest(checksum_type: str, checksum: str) -> Optional[Tuple[str, str]]:
    algo = normalized_hash_algorithm(checksum_type)
    value = (checksum or "").strip().lower()
    if algo in STRONG_PACKAGE_HASHES and value:
        return algo, value
    return None


# digest selection is a first-class
# provenance control. Keep all published SHA-2 values and choose according to
# repository policy rather than hard-coding SHA-256 or whichever field happened
# to be parsed first.
_DIGEST_STRENGTH_ORDER = ("sha512", "sha384", "sha256")

def normalized_digest_map(values: Optional[Dict[str, str]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for algo, value in (values or {}).items():
        norm = normalized_hash_algorithm(algo)
        text = str(value or "").strip().lower()
        if norm in STRONG_PACKAGE_HASHES and text:
            result[norm] = text
    return result

def select_digest_from_map(values: Optional[Dict[str, str]], preference: str = "auto")         -> Optional[Tuple[str, str]]:
    """Return the strongest published digest meeting the configured minimum.

    1.0.36 changes explicit SHA choices from
    exact-algorithm requests to minimum-strength policy. This is what makes a
    mixed repository set coherent: a SHA-256 minimum accepts a source publishing
    SHA-512 without forcing every source to expose the identical field.
    """
    digests = normalized_digest_map(values)
    pref = normalized_hash_algorithm(preference or "auto")
    accepted: Tuple[str, ...]
    if pref == "auto":
        accepted = _DIGEST_STRENGTH_ORDER
    elif pref == "sha256":
        accepted = ("sha512", "sha384", "sha256")
    elif pref == "sha384":
        accepted = ("sha512", "sha384")
    elif pref == "sha512":
        accepted = ("sha512",)
    else:
        return None
    for algo in accepted:
        if algo in digests:
            return algo, digests[algo]
    return None


def vendor_signature_settings(repo: RepoSpec, options: BuildOptions) -> Tuple[str, str, bool]:
    """Return ``(vendor_id, keyring_path, required)`` for one RPM source.

    once a vendor-scoped mapping is
    supplied there is deliberately no global-key fallback.  This makes the
    isolation rule explicit and independently testable.
    """
    vendor_id = getattr(repo, "vendor_id", "") or infer_vendor_id(repo.name, repo.url)
    keyring = options.vendor_keyrings.get(vendor_id, "")
    required = vendor_id in options.require_vendor_signatures_by_vendor
    if not options.vendor_keyrings:
        keyring = keyring or options.vendor_keyring
        required = required or options.require_vendor_signatures
    return vendor_id, keyring, required


def repository_verification_strategy(repo: RepoSpec) -> str:
    """Return the non-overlapping 1.0.36 verification strategy for a repository.

    Older RepoSpec instances may not have an explicit strategy. Infer their
    historical Required?/evidence combination so CLI callers and existing
    profiles remain compatible while the GUI uses the clearer strategy model.
    """
    explicit = (getattr(repo, "verification_strategy", "") or "").strip().lower()
    valid = {"checksum-required", "checksum-available", "evidence-fallback",
             "full-corroboration", "skip-provenance"}
    if explicit in valid:
        return explicit
    required = (getattr(repo, "digest_requirement", "preferred") or "preferred").strip().lower() == "required"
    evidence = (getattr(repo, "evidence_policy", "off") or "off").strip().lower()
    if required and evidence == "required":
        return "full-corroboration"
    if required:
        # 1.0.35 explicitly disabled evidence when Required? was Yes.
        return "checksum-required"
    if evidence == "fallback-required":
        return "evidence-fallback"
    if evidence == "required":
        return "legacy-evidence-required"
    if evidence == "fallback":
        return "legacy-fallback"
    if evidence == "best-effort":
        return "legacy-corroborate"
    return "checksum-available"

def package_digest_map(pkg) -> Dict[str, str]:
    digests = normalized_digest_map(getattr(pkg, "digests", None))
    legacy = strong_package_digest(getattr(pkg, "checksum_type", ""),
                                   getattr(pkg, "checksum", ""))
    if legacy:
        digests.setdefault(legacy[0], legacy[1])
    return digests

def selected_package_digest(pkg) -> Optional[Tuple[str, str]]:
    preference = getattr(getattr(pkg, "repo", None), "digest_preference", "auto")
    return select_digest_from_map(package_digest_map(pkg), preference)

def package_has_selected_digest(pkg) -> bool:
    return selected_package_digest(pkg) is not None


def mirrors_are_distinct(primary_url: str, evidence_url: str) -> Tuple[bool, str]:
    """Conservative endpoint-independence check for a source bond.

    Different hostnames are necessary, though not sufficient, evidence of an
    independent mirror operator.  Feathered records that limitation rather than
    claiming organizational independence it cannot prove from URLs alone.
    """
    a = urllib.parse.urlparse(primary_url)
    b = urllib.parse.urlparse(evidence_url)
    if not a.scheme or not b.scheme:
        return False, "both mirror URLs must be absolute"
    if a.scheme == "file" or b.scheme == "file":
        return False, "local file repositories are not independent network mirrors"
    if (a.hostname or "").lower() == (b.hostname or "").lower():
        return False, "same hostname"
    if primary_url.rstrip("/") == evidence_url.rstrip("/"):
        return False, "same repository endpoint"
    return True, "different hostnames"


def _artifact_verification(pkg) -> ArtifactVerification:
    record = getattr(pkg, "verification", None)
    if record is None:
        record = ArtifactVerification()
        setattr(pkg, "verification", record)
    return record


def evidence_relationship(primary_repo: RepoSpec, evidence_url: str) -> str:
    """Return the explicit evidence relationship selected for this endpoint.

    Profile/UI hints normally win. Impossible stale exact-mirror hints between
    distinct Enterprise Linux rebuild vendors are downgraded to semantic peers.
    Without a usable hint, Feathered falls back conservatively: known EL
    rebuild-family cross-vendor sources are semantic peers; arbitrary sources
    can prove only exact artifact equality.
    """
    hints = dict(getattr(primary_repo, "evidence_relationship_hints", {}) or {})
    hint = hints.get(str(evidence_url), "")
    return classify_relationship(primary_repo, evidence_url, hint=hint)


def evidence_authority_relationship(primary_repo: RepoSpec, evidence_url: str) -> str:
    return dict(getattr(primary_repo, "evidence_authority_hints", {}) or {}).get(
        str(evidence_url), AUTH_UNKNOWN)


def _rpm_source_lineage(source_rpm: str) -> Optional[Tuple[str, str, str]]:
    """Return conservative (source-name, version, release) lineage from SRPM name."""
    text = posixpath.basename(str(source_rpm or "").strip())
    if text.endswith(".src.rpm"):
        text = text[:-8]
    elif text.endswith(".nosrc.rpm"):
        text = text[:-10]
    else:
        return None
    parts = text.rsplit("-", 2)
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1], parts[2]


def independent_peer_packages_match(primary_pkg, evidence_pkg) -> Tuple[bool, str, bool]:
    """Compare semantic identity for independently rebuilt RPM packages.

    Returns (match, detail, source_lineage_match). Binary release strings and
    byte sizes are deliberately not required to match: rebuild distributions may
    legitimately produce different RPM payloads.
    """
    if evidence_pkg is None:
        return False, "peer does not publish the package", False
    fields = ("name", "arch", "epoch", "version")
    mismatches = [f for f in fields
                  if str(getattr(primary_pkg, f, "") or "") !=
                     str(getattr(evidence_pkg, f, "") or "")]
    if mismatches:
        return False, "peer differs in " + ", ".join(mismatches), False
    p_lineage = _rpm_source_lineage(getattr(primary_pkg, "source_rpm", ""))
    e_lineage = _rpm_source_lineage(getattr(evidence_pkg, "source_rpm", ""))
    if p_lineage and e_lineage:
        if p_lineage != e_lineage:
            return False, (f"source lineage differs: acquisition {p_lineage[0]}-{p_lineage[1]}-{p_lineage[2]} "
                           f"vs peer {e_lineage[0]}-{e_lineage[1]}-{e_lineage[2]}"), False
        return True, "package identity and source lineage agree", True
    # When source-RPM lineage is unavailable on either side, do not silently
    # weaken the comparison all the way to upstream version alone. Require the
    # binary package release to agree as a conservative fallback.
    if str(getattr(primary_pkg, "release", "") or "") != str(getattr(evidence_pkg, "release", "") or ""):
        return False, "source lineage is unavailable and package release differs", False
    return True, "package name/version/release/architecture agree; source lineage unavailable on one side", False


def find_independent_peer_package(primary_pkg, evidence_packages):
    """Find the best semantic peer without fuzzy package-name inference."""
    candidates = [p for p in evidence_packages
                  if getattr(p, "name", "") == getattr(primary_pkg, "name", "")
                  and getattr(p, "arch", "") == getattr(primary_pkg, "arch", "")
                  and str(getattr(p, "epoch", "") or "0") == str(getattr(primary_pkg, "epoch", "") or "0")
                  and getattr(p, "version", "") == getattr(primary_pkg, "version", "")]
    if not candidates:
        return None
    # Exact release is preferred when available, but not required for a rebuild peer.
    exact = [p for p in candidates if getattr(p, "release", "") == getattr(primary_pkg, "release", "")]
    return (exact or candidates)[0]


def evidence_repo_for_url(primary_repo: RepoSpec, evidence_url: str) -> RepoSpec:
    """Create a credential-isolated repository spec for an evidence endpoint."""
    evidence_repo = replace(
        primary_repo, name=f"{primary_repo.name} [evidence]", url=evidence_url, optional=True,
        client_cert="", client_key="", ca_cert="", keyring="",
        vendor_id=infer_vendor_id("", evidence_url),
        evidence_urls=[], evidence_suggestions=[], evidence_policy="off",
        verification_strategy="checksum-available")
    evidence_repo._evidence_distinct_from = primary_repo.normalized_url
    evidence_repo._evidence_distinct_effective_origins = set(
        getattr(primary_repo, "_effective_origins", set()) or set())
    evidence_repo._evidence_distinct_effective_hosts = set(
        getattr(primary_repo, "_effective_hosts", set()) or set())
    return evidence_repo


def evidence_artifact_candidates(evidence_url: str, package_location: str,
                                 evidence_location: str = "") -> List[str]:
    """Return deterministic exact-artifact URLs beneath an evidence endpoint.

    A direct package URL (.rpm/.deb/.pkg.tar.*) is accepted only when its basename matches the exact
    package basename. Otherwise Feathered preserves repository-relative layout; it
    never scrapes directories or guesses similar filenames.
    """
    base = (evidence_url or "").strip()
    if not base:
        return []
    primary_name = posixpath.basename(urllib.parse.urlsplit(package_location or "").path)
    evidence_name = posixpath.basename(urllib.parse.urlsplit(evidence_location or "").path)
    parsed = urllib.parse.urlsplit(base)
    direct_name = posixpath.basename(parsed.path)
    if direct_name.lower().endswith((".rpm", ".deb", ".pkg.tar.zst", ".pkg.tar.xz",
                                     ".pkg.tar.gz", ".pkg.tar.bz2", ".pkg.tar.lz4")):
        expected = evidence_name or primary_name
        return [base] if expected and direct_name == expected else []
    out: List[str] = []
    for location in (evidence_location, package_location):
        if not location:
            continue
        try:
            candidate = repo_relative_url(base, location)
        except RuntimeError:
            continue
        if candidate not in out:
            out.append(candidate)
    return out


def probe_evidence_artifact(url: str, repo: RepoSpec, reporter: Reporter) -> Tuple[bool, str]:
    """Check that an exact evidence artifact is readable without downloading it all."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme == "file":
            local = Path(urllib.request.url2pathname(parsed.path))
            if not local.is_file():
                return False, f"Artifact file does not exist: {local}"
            if local.stat().st_size <= 0:
                return False, f"Artifact file is empty: {local.name}"
            return True, f"Artifact file is readable ({local.stat().st_size:,} bytes)"
        with _urlopen(url, timeout=25, repo=repo) as response:
            sample = response.read(1)
            if not sample:
                return False, "Artifact endpoint returned an empty response"
            length = response.headers.get("Content-Length", "") if getattr(response, "headers", None) else ""
            detail = "Exact package artifact is readable"
            if str(length).isdigit():
                detail += f" ({int(length):,} bytes advertised)"
            return True, detail
    except Exception as exc:
        return False, redact_text(str(exc))


def _stream_hash_url(url: str, algorithms: Iterable[str], repo: RepoSpec,
                     reporter: Reporter,
                     max_bytes: int = MAX_PACKAGE_DOWNLOAD_BYTES) -> Tuple[Dict[str, str], int]:
    algos = list(dict.fromkeys(normalized_hash_algorithm(a) for a in algorithms if a))
    if not algos:
        raise RuntimeError("No checksum algorithm was selected for independent evidence")
    hashers = {algo: hashlib.new(algo) for algo in algos}
    total = 0
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme == "file":
        stream = Path(urllib.request.url2pathname(parsed.path)).open("rb")
    else:
        stream = _urlopen(url, timeout=90, repo=repo)
    try:
        if parsed.scheme != "file" and hasattr(stream, "headers"):
            declared = stream.headers.get("Content-Length")
            try:
                declared_size = int(declared) if declared is not None else None
            except (TypeError, ValueError):
                declared_size = None
            if declared_size is not None and declared_size > max_bytes:
                raise RuntimeError(
                    f"Artifact response is {declared_size:,} bytes, above Feathered's "
                    f"{max_bytes:,}-byte per-artifact limit")
        while True:
            reporter.check_cancel()
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError(
                    f"Artifact response exceeded Feathered's {max_bytes:,}-byte per-artifact limit")
            for hasher in hashers.values():
                hasher.update(chunk)
    finally:
        stream.close()
    return {algo: hasher.hexdigest().lower() for algo, hasher in hashers.items()}, total



def spot_compare_artifact_urls(acquisition_url: str, acquisition_repo: RepoSpec,
                               evidence_url: str, evidence_repo: RepoSpec,
                               checksum_policy: str, reporter: Reporter) -> Tuple[bool, str]:
    """Hash one acquisition/evidence artifact pair without persisting either copy.

    This is a configuration spot test used by the GUI. It proves that the selected
    evidence endpoint can independently serve the same exact bytes for one
    representative artifact. It is deliberately not a substitute for the build-time
    per-package corroboration performed by ``_verify_independent_evidence_payload``.
    """
    policy = normalized_hash_algorithm(checksum_policy or "auto")
    algorithm = "sha512" if policy == "auto" else policy
    if algorithm not in STRONG_PACKAGE_HASHES:
        return False, f"Unsupported evidence checksum policy: {checksum_policy or 'unset'}"
    try:
        acquisition_hashes, acquisition_size = _stream_hash_url(
            acquisition_url, [algorithm], acquisition_repo, reporter)
    except Exception as exc:
        return False, "Could not hash the acquisition artifact: " + redact_text(str(exc))
    try:
        evidence_hashes, evidence_size = _stream_hash_url(
            evidence_url, [algorithm], evidence_repo, reporter)
    except Exception as exc:
        return False, "Could not hash the evidence artifact: " + redact_text(str(exc))
    if acquisition_size != evidence_size:
        return False, (
            f"Artifact size mismatch: acquisition is {acquisition_size:,} bytes and evidence is "
            f"{evidence_size:,} bytes")
    acquisition_digest = acquisition_hashes[algorithm]
    evidence_digest = evidence_hashes[algorithm]
    if not hmac.compare_digest(acquisition_digest, evidence_digest):
        return False, f"Artifact checksum mismatch under {algorithm.upper()}"
    return True, (
        f"Spot check passed: acquisition and evidence artifacts match under {algorithm.upper()} "
        f"({acquisition_size:,} bytes)")

def spot_compare_peer_artifact_urls(primary_pkg, acquisition_url: str, acquisition_repo: RepoSpec,
                                    evidence_pkg, evidence_url: str, evidence_repo: RepoSpec,
                                    checksum_policy: str, reporter: Reporter) -> Tuple[bool, str]:
    """Spot-check an independent rebuild peer without requiring identical bytes.

    The two artifacts are independently hashed and, when their repositories
    publish usable strong digests, each artifact is checked against its own
    repository claim. The cross-source assertion is semantic identity/source
    lineage, not binary equality.
    """
    semantic_ok, semantic_detail, _lineage = independent_peer_packages_match(primary_pkg, evidence_pkg)
    if not semantic_ok:
        return False, "Independent peer disagreement: " + semantic_detail
    policy = normalized_hash_algorithm(checksum_policy or "auto")
    algorithm = "sha512" if policy == "auto" else policy
    if algorithm not in STRONG_PACKAGE_HASHES:
        return False, f"Unsupported evidence checksum policy: {checksum_policy or 'unset'}"
    primary_meta = selected_package_digest(primary_pkg)
    evidence_meta = selected_package_digest(evidence_pkg)
    algos = [algorithm]
    for item in (primary_meta, evidence_meta):
        if item and item[0] not in algos:
            algos.append(item[0])
    try:
        primary_hashes, primary_size = _stream_hash_url(acquisition_url, algos, acquisition_repo, reporter)
    except Exception as exc:
        return False, "Could not hash the acquisition artifact: " + redact_text(str(exc))
    try:
        evidence_hashes, evidence_size = _stream_hash_url(evidence_url, algos, evidence_repo, reporter)
    except Exception as exc:
        return False, "Could not hash the peer artifact: " + redact_text(str(exc))
    if primary_meta and not hmac.compare_digest(primary_hashes[primary_meta[0]], primary_meta[1].lower()):
        return False, f"Acquisition artifact does not match its published {primary_meta[0].upper()} checksum"
    if evidence_meta and not hmac.compare_digest(evidence_hashes[evidence_meta[0]], evidence_meta[1].lower()):
        return False, f"Peer artifact does not match its published {evidence_meta[0].upper()} checksum"
    binary_note = ("binary bytes also happen to match"
                   if primary_size == evidence_size and hmac.compare_digest(primary_hashes[algorithm], evidence_hashes[algorithm])
                   else "binary bytes differ, as permitted for an independent rebuild")
    own_checks = []
    if primary_meta:
        own_checks.append("acquisition digest verified")
    if evidence_meta:
        own_checks.append("peer digest verified")
    integrity = "; ".join(own_checks) if own_checks else "independent hashes calculated; no repository digest was available"
    return True, (f"Independent peer spot check passed: {semantic_detail}; {binary_note}. "
                  f"{integrity}. {algorithm.upper()} sizes: acquisition {primary_size:,} bytes, "
                  f"peer {evidence_size:,} bytes")


def _evidence_comparison_algorithm(pkg, primary: Optional[Tuple[str, str]]) -> str:
    if primary:
        return primary[0]
    preference = normalized_hash_algorithm(getattr(getattr(pkg, "repo", None), "digest_preference", "auto"))
    if preference in STRONG_PACKAGE_HASHES:
        return preference
    # Automatic evidence fallback must be deterministic even when acquisition
    # metadata publishes no usable checksum. Use the strongest supported SHA-2.
    return "sha512"


def _verify_independent_evidence_payload(pkg, acquisition_path: Path, primary,
                                         computed: Dict[str, str], reporter: Reporter) -> None:
    """Verify evidence according to the relationship to the acquisition source.

    Exact mirrors/artifact mirrors must reproduce identical bytes. Independent
    rebuild peers instead must publish a semantically corresponding package and
    the peer artifact must verify against the peer repository's own strong digest.
    """
    record = _artifact_verification(pkg)
    comparison_algo = _evidence_comparison_algorithm(pkg, primary)
    if comparison_algo not in computed:
        computed[comparison_algo] = hash_file(acquisition_path, comparison_algo).lower()
    acquisition_digest = computed[comparison_algo]
    acquisition_size = acquisition_path.stat().st_size
    strategy = repository_verification_strategy(pkg.repo)
    errors: List[str] = []

    for evidence_url in list(getattr(pkg.repo, "evidence_urls", []) or []):
        distinct, reason = mirrors_are_distinct(pkg.repo.normalized_url, evidence_url)
        if not distinct:
            errors.append(f"{redact_url(evidence_url)} ({reason})")
            continue
        relationship = evidence_relationship(pkg.repo, evidence_url)
        authority = evidence_authority_relationship(pkg.repo, evidence_url)
        evidence_repo = evidence_repo_for_url(pkg.repo, evidence_url)

        if relationship == REL_REBUILD_PEER:
            if strategy != "full-corroboration":
                errors.append(
                    f"{redact_url(evidence_url)} (independent rebuild peers cannot fill a missing "
                    "acquisition checksum; Enhanced requires an exact artifact mirror for that gap)")
                continue
            if not record.evidence_peer_identity_match or not record.evidence_location:
                errors.append(
                    f"{redact_url(evidence_url)} (peer metadata did not establish a matching package identity)")
                continue
            metadata_digest = strong_package_digest(record.evidence_digest_type, record.evidence_digest)
            if not metadata_digest:
                errors.append(
                    f"{redact_url(evidence_url)} (peer package publishes no strong checksum meeting the configured policy)")
                continue
            try:
                candidate = repo_relative_url(evidence_url, record.evidence_location)
            except Exception as exc:
                errors.append(f"{redact_url(evidence_url)} ({redact_text(str(exc))})")
                continue
            algorithms = [comparison_algo]
            if metadata_digest[0] not in algorithms:
                algorithms.append(metadata_digest[0])
            try:
                reporter.log(
                    f"EVIDENCE {getattr(pkg, 'nevra', getattr(pkg, 'name', 'package'))}: "
                    f"hashing independent rebuild peer artifact {redact_url(candidate)}")
                digests, size = _stream_hash_url(candidate, algorithms, evidence_repo, reporter)
            except Exception as exc:
                errors.append(f"{redact_url(candidate)} ({redact_text(str(exc))})")
                continue
            if not hmac.compare_digest(digests[metadata_digest[0]], metadata_digest[1].lower()):
                raise RuntimeError(
                    f"Independent peer evidence disagreement for {pkg.nevra}: the peer artifact "
                    f"does not match its published {metadata_digest[0].upper()} checksum")
            record.evidence_relationship = REL_REBUILD_PEER
            record.evidence_authority_relationship = authority
            record.evidence_digest_checked = True
            record.evidence_artifact_checked = True
            record.evidence_artifact_digest_type = comparison_algo
            record.evidence_artifact_digest = digests[comparison_algo]
            record.evidence_artifact_size = size
            record.evidence_status = "peer-corroborated"
            binary_same = (size == acquisition_size and
                           hmac.compare_digest(acquisition_digest, digests[comparison_algo]))
            record.notes.append(
                "Independent rebuild peer corroborated package identity"
                + (" and source lineage" if record.evidence_source_lineage_match else "")
                + "; peer artifact verified against its own repository digest; "
                + ("binary bytes also matched." if binary_same
                   else "binary bytes differed as permitted for a rebuild peer."))
            return

        metadata_digest = strong_package_digest(record.evidence_digest_type, record.evidence_digest)
        candidates = evidence_artifact_candidates(
            evidence_url, getattr(pkg, "location", ""), record.evidence_location)
        if not candidates:
            errors.append(f"{redact_url(evidence_url)} (no exact artifact path can be derived)")
            continue
        for candidate in candidates:
            algorithms = [comparison_algo]
            if metadata_digest and metadata_digest[0] not in algorithms:
                algorithms.append(metadata_digest[0])
            try:
                reporter.log(
                    f"EVIDENCE {getattr(pkg, 'nevra', getattr(pkg, 'name', 'package'))}: "
                    f"hashing independent artifact {redact_url(candidate)}")
                digests, size = _stream_hash_url(candidate, algorithms, evidence_repo, reporter)
            except Exception as exc:
                errors.append(f"{redact_url(candidate)} ({redact_text(str(exc))})")
                continue

            if size != acquisition_size:
                raise RuntimeError(
                    f"Independent evidence disagreement for {pkg.nevra}: acquisition artifact is "
                    f"{acquisition_size} bytes but {redact_url(candidate)} is {size} bytes")
            evidence_digest = digests[comparison_algo]
            if not hmac.compare_digest(acquisition_digest, evidence_digest):
                raise RuntimeError(
                    f"Independent evidence disagreement for {pkg.nevra}: acquisition and evidence "
                    f"artifacts have different {comparison_algo.upper()} checksums")
            if metadata_digest:
                actual_metadata_digest = digests[metadata_digest[0]]
                if not hmac.compare_digest(actual_metadata_digest, metadata_digest[1].lower()):
                    raise RuntimeError(
                        f"Independent evidence metadata disagreement for {pkg.nevra}: the evidence "
                        f"artifact does not match its published {metadata_digest[0].upper()} checksum")
                record.evidence_digest_checked = True

            record.evidence_relationship = relationship
            record.evidence_authority_relationship = authority
            record.evidence_source = redact_url(evidence_url)
            record.evidence_artifact_checked = True
            record.evidence_artifact_digest_type = comparison_algo
            record.evidence_artifact_digest = evidence_digest
            record.evidence_artifact_size = size
            record.evidence_status = ("digest-corroborated" if record.evidence_digest_checked
                                      else "artifact-corroborated")
            record.notes.append(
                f"Independent artifact matched acquisition bytes using {comparison_algo.upper()}.")
            return

    detail = "; ".join(errors[-3:])
    raise RuntimeError(
        f"{pkg.nevra}: no configured independent evidence source could satisfy the selected evidence policy"
        + (f" ({detail})" if detail else ""))

def apply_mirror_evidence(primary_packages, evidence_packages, evidence_repo: RepoSpec,
                          reporter: Reporter, relationship: str = REL_EXACT_ARTIFACT,
                          authority: str = AUTH_UNKNOWN) -> Dict[str, int]:
    """Attach evidence metadata without treating repository-wide skew as a build failure.

    Evidence repository metadata is a locator/index aid. Live mirrors are not atomic
    snapshots of one another, so an unrelated package that is missing or temporarily
    divergent must not abort metadata loading for the package transaction being built.
    Conflicts are recorded per package and decisive enforcement happens when the
    selected artifact is actually verified. That preserves strict byte equality for
    exact mirrors while avoiding false global failures during mirror synchronization.
    """
    stats = {"matched": 0, "digest": 0, "metadata": 0, "missing": 0,
             "peer": 0, "conflict": 0}
    if relationship == REL_REBUILD_PEER:
        for pkg in primary_packages:
            record = _artifact_verification(pkg)
            other = find_independent_peer_package(pkg, evidence_packages)
            if other is None:
                if record.evidence_status in {"not-configured", "unavailable"}:
                    record.evidence_status = "inconclusive"
                stats["missing"] += 1
                continue
            ok, detail, lineage_match = independent_peer_packages_match(pkg, other)
            record.evidence_relationship = REL_REBUILD_PEER
            record.evidence_authority_relationship = authority
            record.evidence_source = redact_url(evidence_repo.normalized_url)
            record.evidence_location = str(getattr(other, "location", "") or "")
            record.evidence_peer_package_id = getattr(other, "nevra", "")
            record.evidence_peer_source_rpm = str(getattr(other, "source_rpm", "") or "")
            evidence_digest = selected_package_digest(other)
            if evidence_digest:
                record.evidence_digest_type, record.evidence_digest = evidence_digest
            if not ok:
                record.evidence_status = "metadata-conflict"
                record.evidence_metadata_match = False
                record.notes.append("Independent rebuild-peer metadata conflict deferred to selected-package verification: " + detail + ".")
                stats["conflict"] += 1
                continue
            record.evidence_peer_identity_match = True
            record.evidence_source_lineage_match = lineage_match
            record.evidence_metadata_match = True
            evidence_trust: Optional[RepoTrust] = getattr(evidence_repo, "trust", None)
            record.evidence_archive_signature_verified = bool(
                evidence_trust and evidence_trust.archive_signature_verified)
            if evidence_digest:
                stats["digest"] += 1
            else:
                stats["metadata"] += 1
            record.evidence_status = "peer-metadata-corroborated"
            record.notes.append("Independent rebuild peer: " + detail + ".")
            stats["matched"] += 1
            stats["peer"] += 1
        return stats

    by_id = {getattr(p, "nevra", ""): p for p in evidence_packages}
    for pkg in primary_packages:
        record = _artifact_verification(pkg)
        other = by_id.get(getattr(pkg, "nevra", ""))
        if other is None:
            if record.evidence_status in {"not-configured", "unavailable"}:
                record.evidence_status = "inconclusive"
            stats["missing"] += 1
            continue

        record.evidence_relationship = relationship
        record.evidence_authority_relationship = authority
        record.evidence_source = redact_url(evidence_repo.normalized_url)
        record.evidence_location = str(getattr(other, "location", "") or "")
        evidence_trust = getattr(evidence_repo, "trust", None)
        record.evidence_archive_signature_verified = bool(
            evidence_trust and evidence_trust.archive_signature_verified)
        evidence_digest = selected_package_digest(other)
        if evidence_digest:
            record.evidence_digest_type, record.evidence_digest = evidence_digest

        conflicts = []
        psize = int(getattr(pkg, "size", 0) or 0)
        esize = int(getattr(other, "size", 0) or 0)
        if psize and esize and psize != esize:
            conflicts.append(f"size differs ({psize} vs {esize} bytes)")

        p_algo = normalized_hash_algorithm(getattr(pkg, "checksum_type", ""))
        e_algo = normalized_hash_algorithm(getattr(other, "checksum_type", ""))
        p_raw = str(getattr(pkg, "checksum", "") or "").strip().lower()
        e_raw = str(getattr(other, "checksum", "") or "").strip().lower()
        if p_algo and e_algo and p_algo == e_algo and p_raw and e_raw                 and not hmac.compare_digest(p_raw, e_raw):
            conflicts.append(f"published {p_algo.upper()} differs")

        p_strong = package_digest_map(pkg)
        e_strong = package_digest_map(other)
        for shared_algo in sorted(set(p_strong) & set(e_strong)):
            if not hmac.compare_digest(p_strong[shared_algo], e_strong[shared_algo]):
                conflicts.append(f"published {shared_algo.upper()} differs")
                break

        primary_digest = selected_package_digest(pkg)
        if primary_digest and evidence_digest and primary_digest[0] == evidence_digest[0]                 and not hmac.compare_digest(primary_digest[1], evidence_digest[1]):
            detail = f"selected {primary_digest[0].upper()} differs"
            if detail not in conflicts:
                conflicts.append(detail)

        if conflicts:
            record.evidence_status = "metadata-conflict"
            record.evidence_metadata_match = False
            record.notes.append(
                "Exact-mirror metadata conflict deferred to selected-package artifact verification: "
                + "; ".join(conflicts) + ".")
            stats["conflict"] += 1
            continue

        record.evidence_metadata_match = True
        stats["matched"] += 1
        if primary_digest and evidence_digest:
            record.evidence_status = "digest-corroborated"
            stats["digest"] += 1
        elif evidence_digest:
            record.evidence_status = "independent-digest"
            stats["digest"] += 1
        else:
            record.evidence_status = "metadata-corroborated"
            stats["metadata"] += 1
    return stats

def verify_package_artifact(pkg, path: Path, options: BuildOptions, reporter: Reporter) -> bool:
    """Verify one cached or freshly transferred package under its strategy.

    Enhanced and Maximum treat independent evidence as an independently
    retrieved exact package artifact, not merely a second metadata claim.
    Evidence-repository metadata remains useful extra provenance when present,
    but an artifact-only mirror can still corroborate bytes.
    """
    record = _artifact_verification(pkg)
    strategy = repository_verification_strategy(pkg.repo)
    primary = selected_package_digest(pkg)
    evidence = strong_package_digest(record.evidence_digest_type, record.evidence_digest)

    if strategy == "skip-provenance":
        record.notes.append("Upstream package provenance checks intentionally skipped by operator policy.")
        record.evidence_status = "skipped"
        return False

    if strategy == "full-corroboration" and not options.verify_checksums:
        raise RuntimeError(f"{pkg.nevra}: full corroboration requires acquisition checksum verification")

    checks: List[Tuple[str, str, str]] = []
    artifact_evidence_required = False

    if strategy == "checksum-required":
        if not options.verify_checksums:
            raise RuntimeError(f"{pkg.nevra}: checksum-required strategy cannot run with checksum verification disabled")
        if not primary:
            raise RuntimeError(
                f"{pkg.nevra}: acquisition metadata does not publish a checksum meeting "
                f"the configured minimum {getattr(pkg.repo, 'digest_preference', 'auto').upper()}")
        checks.append((primary[0], primary[1], "acquisition metadata"))

    elif strategy == "checksum-available":
        if options.verify_checksums and primary:
            checks.append((primary[0], primary[1], "acquisition metadata"))

    elif strategy == "evidence-fallback":
        if options.verify_checksums and primary:
            # Enhanced is a gap-filling policy. A qualifying acquisition digest
            # satisfies it directly; the independent endpoint is retained as an
            # explicitly configured fallback but is not needlessly downloaded.
            checks.append((primary[0], primary[1], "acquisition metadata"))
            record.evidence_status = "not-needed"
        else:
            if not list(getattr(pkg.repo, "evidence_urls", []) or []):
                raise RuntimeError(
                    f"{pkg.nevra}: Enhanced verification needs an independent evidence source "
                    "because acquisition metadata does not meet the selected checksum minimum")
            artifact_evidence_required = True

    elif strategy == "full-corroboration":
        if not primary:
            raise RuntimeError(
                f"{pkg.nevra}: full corroboration requires acquisition metadata to publish a "
                "checksum meeting the selected minimum")
        if not list(getattr(pkg.repo, "evidence_urls", []) or []):
            raise RuntimeError(
                f"{pkg.nevra}: full corroboration requires at least one configured independent evidence source")
        checks.append((primary[0], primary[1], "acquisition metadata"))
        artifact_evidence_required = True

    elif strategy in {"legacy-fallback", "legacy-corroborate", "legacy-evidence-required"}:
        # Backwards compatibility for RepoSpec instances created before 1.0.36.
        if strategy == "legacy-evidence-required" and not record.evidence_metadata_match:
            raise RuntimeError(f"{pkg.nevra}: required evidence source does not publish this exact package identity")
        if options.verify_checksums and primary:
            checks.append((primary[0], primary[1], "acquisition metadata"))
        if evidence:
            if strategy != "legacy-fallback" or not primary:
                checks.append((evidence[0], evidence[1], "evidence mirror metadata"))
        if strategy == "legacy-evidence-required" and not evidence:
            raise RuntimeError(f"{pkg.nevra}: required evidence source publishes no usable strong digest")

    else:
        raise RuntimeError(f"{pkg.nevra}: unknown verification strategy '{strategy}'")

    computed: Dict[str, str] = {}
    for algo, expected, source in checks:
        if algo not in computed:
            computed[algo] = hash_file(path, algo).lower()
        actual = computed[algo]
        if not hmac.compare_digest(actual, expected.lower()):
            raise RuntimeError(
                f"{pkg.nevra}: {algo.upper()} mismatch against {source}: expected {expected}, got {actual}")
        if source == "acquisition metadata":
            record.package_digest_checked = True
        else:
            record.evidence_digest_checked = True

    if artifact_evidence_required:
        _verify_independent_evidence_payload(pkg, path, primary, computed, reporter)
        return True

    if not checks:
        published = package_digest_map(pkg)
        if options.require_package_digests:
            raise RuntimeError(
                f"{pkg.nevra}: no usable SHA-256/SHA-384/SHA-512 package digest meets the configured policy")
        if published:
            reporter.warn(
                f"{pkg.nevra}: no published checksum meets the configured minimum; "
                "continuing with degraded package provenance")
        else:
            reporter.warn(
                f"{pkg.nevra}: acquisition metadata publishes no strong package checksum; "
                "continuing with degraded package provenance")
        record.notes.append("No qualifying strong package digest was checked; artifact accepted by checksum-available strategy.")
        return False

    return True

def _copy_or_download(pkg: DownloadPackage, dest: Path, options: BuildOptions, reporter: Reporter) -> None:
    # Confined join: a hostile index cannot redirect this off-origin.
    src = repo_relative_url(pkg.repo.normalized_url, pkg.location)
    tmp = dest.with_suffix(dest.suffix + ".partial")
    for attempt in range(1, options.retries + 1):
        reporter.check_cancel()
        try:
            if tmp.exists(): tmp.unlink()
            parsed = urllib.parse.urlparse(src)
            if parsed.scheme == "file":
                local = Path(urllib.request.url2pathname(parsed.path))
                reporter.log(f"COPY {local} -> {dest.name}")
                limit, expected = package_download_limit(pkg)
                actual = local.stat().st_size
                if actual > limit:
                    raise RuntimeError(
                        f"{pkg.nevra}: local package is {actual:,} bytes, above the allowed "
                        f"{limit:,}-byte package limit")
                if expected and actual != expected:
                    raise RuntimeError(
                        f"{pkg.nevra}: local package size {actual:,} does not match repository "
                        f"metadata size {expected:,}")
                shutil.copy2(local, tmp)
            else:
                reporter.log(f"DOWNLOAD {redact_url(src)}")
                with _urlopen(src, timeout=90, repo=pkg.repo) as response, tmp.open("wb") as f:
                    declared = response.headers.get("Content-Length") if hasattr(response, "headers") else None
                    copy_package_stream_bounded(response, f, pkg, reporter, declared)
            # use the shared strong-digest/evidence
            # verifier, eliminating RPM's previous missing/MD5 fail-open path.
            verify_package_artifact(pkg, tmp, options, reporter)
            tmp.replace(dest)
            return
        except Exception as exc:
            if tmp.exists(): tmp.unlink()
            # An operator cancel raised mid-download must surface as Cancelled,
            # not be retried or reported as a per-package failure on the final
            # attempt.  Re-checking re-raises Cancelled if the event is set.
            reporter.check_cancel()
            # Certificate validation failures are deterministic; fail fast with
            # the concrete remedy instead of burning retries.
            cert_advice = _transport.certificate_failure_advice(exc, src)
            if cert_advice:
                raise RuntimeError(f"Failed {pkg.nevra}: {cert_advice}") from exc
            if attempt == options.retries:
                raise RuntimeError(f"Failed {pkg.nevra}: {exc}") from exc
            reporter.log(redact_text(f"Healing download failure for {pkg.nevra}: {exc}; "
                                     f"retry {attempt + 1}/{options.retries}"))
            time.sleep(min(2 ** (attempt - 1), 5))



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
        # 1.0.39 local repository
        # rebuilds construct Package objects directly from RPM headers.  When
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

        def emit_entries(tag, requirements):
            if not requirements:
                return
            parent = ET.SubElement(fmt, f"{{{rpm_ns}}}{tag}")
            for requirement in requirements:
                attrs = {"name": requirement.name}
                if requirement.flags:
                    attrs["flags"] = requirement.flags
                if requirement.version is not None:
                    attrs.update({"epoch": requirement.epoch or "0",
                                  "ver": requirement.version or "",
                                  "rel": requirement.release or ""})
                ET.SubElement(parent, f"{{{rpm_ns}}}entry", attrs)

        emit_entries("provides", pkg.provides)
        emit_entries("requires", pkg.requires)
        emit_entries("recommends", pkg.recommends)
        emit_entries("conflicts", pkg.conflicts)
        emit_entries("obsoletes", pkg.obsoletes)
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


def write_vendor_key_manifest(metadata_dir: Path, entries) -> None:
    """Record which vendor keys the target must already trust.

    The installer refuses to import a key out of the bundle it is verifying, so
    the operator needs to know which keys to establish through their own
    channel. Signer text comes from the connected-side verification, which is
    the only place the identity behind the key id was actually observed.
    """
    rows: Dict[str, Tuple[str, str]] = {}
    for entry in entries or ():
        if entry.assurance != provenance.VERIFIED_VENDOR or not entry.signing_key_id:
            continue
        rows.setdefault(entry.signing_key_id, (entry.signer, entry.repository))
    if not rows:
        return
    lines = ["Vendor signing keys required on the target", "",
             "install-offline.sh enables gpgcheck and will refuse to run until these keys",
             "are present in the target rpm keyring. Import them from the target",
             "distribution's own material (for example /etc/pki/rpm-gpg) or another",
             "trusted channel. Do not import a key carried by this bundle: it could only",
             "vouch for the bundle that carried it.", ""]
    for key_id, (signer, repo) in sorted(rows.items()):
        short = "".join(c for c in key_id if c in "0123456789abcdefABCDEF")[-8:].lower()
        lines.append(f"  key {key_id}  (rpm: gpg-pubkey-{short})")
        lines.append(f"    signer:     {signer or 'not reported by the verifier'}")
        lines.append(f"    repository: {repo}")
    (Path(metadata_dir) / "VENDOR-SIGNING-KEYS.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


def _write_provenance(bundle_dir: Path, metadata_dir: Path, entries, already_present, options: BuildOptions,
                      reporter: Reporter, metadata: Dict[str, object]) -> None:
    """Emit payload-scoped provenance beside the package artifacts.

    ``bundle_dir`` keeps the stable bundle identity while ``metadata_dir`` is the
    package-family directory (rpms/, debs/, or packages/) that owns these records.
    """
    record = provenance.build_provenance(
        bundle_id=bundle_dir.name,
        target={k: str(v) for k, v in metadata.items()
                if k in {"distribution", "release", "codename", "arch", "package_family",
                         "dependency_mode", "workload", "acquisition_intent",
                         "acquisition_capability", "analysis_type", "publication_type",
                         "verification_scope", "dependency_completeness"}},
        repositories=meta_dict_list(metadata, "repositories"),
        entries=entries,
        warnings=list(reporter.warnings),
    )
    if options.additive_publish and (metadata_dir / "provenance.json").is_file():
        record = provenance.merge_previous_provenance(record, metadata_dir / "provenance.json")
    if already_present:
        record.warnings.append(
            f"Differential bundle: {len(already_present)} package(s) were omitted because the "
            "baseline manifest reports them already present on the target. This bundle is not "
            "self-contained.")
        (metadata_dir / "baseline-omitted.txt").write_text(
            "\n".join(sorted(getattr(p, "nevra", p.name) for p in already_present)) + "\n",
            encoding="utf-8")
    (metadata_dir / "provenance.json").write_text(record.to_json(), encoding="utf-8")
    _write_assurance_legend(metadata_dir, record)
    counts = ", ".join(f"{v} {k}" for k, v in sorted(record.summary().items()))
    reporter.log(f"Provenance recorded: {counts or 'no packages'}")
    if options.signing_key:
        provenance.sign_bundle(metadata_dir / "manifest.json", options.signing_key, reporter)
        provenance.sign_bundle(metadata_dir / "provenance.json", options.signing_key, reporter)

def _write_assurance_legend(metadata_dir: Path, record) -> None:
    """Emit ASSURANCE.txt beside the bundle.

    provenance.json already carries the legend, but the person who has to act on
    it is on the far side of an air gap, often reading files on a console with
    no JSON tooling and no access to Feathered's documentation. The mode names
    are short enough to invite a strength ordering they do not carry -- most
    importantly, "independent-peer-corroboration" reads as stronger than
    "digest-only" and is weaker than a signature or a byte match. Spell it out
    where they will actually see it.
    """
    counts = dict(record.summary())
    for mode, value in record.mode_summary().items():
        counts.setdefault(mode, value)
    rows = provenance.assurance_legend(list(counts))
    if not rows:
        return
    lines = [
        "FEATHERED BUNDLE ASSURANCE LEGEND",
        "",
        "What Feathered proved about the artifacts in this bundle, strongest first.",
        "Counts are the number of packages recording that mode; one package can",
        "record several, because provenance is multi-axis rather than a single tier.",
        "",
        "Read 'DOES NOT PROVE' before relying on any row. A stronger-sounding name",
        "does not mean a stronger guarantee; the rank below is the ordering.",
        "",
    ]
    for row in rows:
        count = counts.get(row["mode"], 0)
        lines.append(f"[rank {row['rank']:3d}] {row['label']}  ({row['mode']})")
        lines.append(f"    packages       : {count}")
        lines.append(f"    authority      : {row['authority']}")
        lines.append(f"    proves         : {row['proves']}")
        lines.append(f"    does not prove : {row['does_not_prove']}")
        lines.append("")
    lines.append("Full per-package detail is in provenance.json.")
    (metadata_dir / "ASSURANCE.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_bundle_archive(bundle_dir: Path, reporter: Optional[Reporter] = None) -> Path:
    """Create a portable ZIP containing the complete generated bundle directory."""
    bundle_dir = bundle_dir.resolve()
    if not bundle_dir.is_dir():
        raise RuntimeError(f"Bundle directory does not exist: {bundle_dir}")
    archive = bundle_dir.with_suffix(".zip")
    rep = reporter or Reporter()
    rep.log(f"PACK {archive.name}")
    made = shutil.make_archive(
        str(bundle_dir), "zip",
        root_dir=str(bundle_dir.parent),
        base_dir=bundle_dir.name,
    )
    return Path(made)


def write_bundle(result: ResolutionResult, output_dir: Path, options: BuildOptions, reporter: Reporter,
                 metadata: Dict[str, object]) -> Path:
    # Build beside the destination and publish only on success, so a failed or
    # interrupted run cannot leave something that looks like a finished bundle.
    # Transfer occupies the first part of the bar when sealing will follow it.
    reporter.phase(0.0, SEAL_PHASE_START if options.sign_bundle_index else 1.0)
    final_dir = output_dir
    output_dir = open_staging(final_dir, reporter)
    output_dir.mkdir(parents=True, exist_ok=True)
    if not options.sign_bundle_index:
        invalidate_bundle_seal(output_dir, reporter)
    try:
        return _write_bundle_body(result, output_dir, final_dir, options, reporter, metadata)
    except BaseException:
        # Anything short of success leaves the previous bundle untouched and
        # removes the half-built one, so nothing can be mistaken for finished.
        abandon_staging(output_dir, reporter)
        raise


def _write_bundle_body(result, output_dir: Path, final_dir: Path, options: BuildOptions,
                       reporter: Reporter, metadata: Dict[str, object]) -> Path:
    rpm_dir = output_dir / "rpms"
    rpm_dir.mkdir(exist_ok=True)
    metadata_dir = rpm_dir  # Payload-scoped records travel with this RPM set.
    from transaction_model import validate_retained_payloads, write_installation_contract, installation_roots
    validate_retained_payloads(metadata_dir, result.selected, 'rpm', reporter, options)

    # Keep rebuilt bundles deterministic. If the same output folder was used
    # for an earlier analysis/build with a different closure, remove RPMs that
    # are no longer part of the current result before writing checksums/ZIPs.
    # Differential bundles: drop anything the baseline says the target already has.
    baseline = load_baseline(options.baseline_manifest, reporter)
    to_ship, already_present = split_against_baseline(result.selected, baseline, reporter)
    # detect payload basename collisions before transfer
    # instead of allowing the later package to overwrite the earlier one.
    filename_map = payload_filenames(to_ship, ".rpm")

    # Existing payloads in staging are retained as an addendum. Same-name
    # artifacts may still be verified and overwritten below, but unrelated
    # packages are never pruned from a previously populated output folder.

    total = max(1, len(to_ship))
    for i, pkg in enumerate(to_ship, 1):
        reporter.check_cancel()
        filename = filename_map[id(pkg)]
        dest = rpm_dir / filename
        import artifact_cache
        artifact_cache.restore(pkg, dest, final_dir.parent, options, reporter)
        if dest.exists() and dest.stat().st_size > 0:
            # Re-hashing a cached file costs far less than fetching it again --
            # SHA-256 runs around 1 GB/s, an order of magnitude faster than any
            # realistic mirror -- so an interrupted transfer resumes rather than
            # starting over, and a corrupt file is detected instead of trusted.
            reporter.item(pkg.nevra, "verifying", size=dest.stat().st_size)
            valid = True
            try:
                # cached RPMs are no longer a weaker verification
                # path than fresh downloads.
                verify_package_artifact(pkg, dest, options, reporter)
            except RuntimeError:
                valid = False
            if valid:
                reporter.log(f"REUSE {dest.name} (already present, verification policy satisfied)")
                reporter.item(pkg.nevra, "reused", size=dest.stat().st_size)
                reporter.progress(f"RPM {i}/{total}", i / total)
                continue
            reporter.log(f"Cached file failed verification, re-fetching: {dest.name}")
            reporter.item(pkg.nevra, "stale", size=dest.stat().st_size)
            dest.unlink()
        reporter.item(pkg.nevra, "active", size=pkg.size)
        try:
            _copy_or_download(pkg, dest, options, reporter)
            artifact_cache.remember(pkg, dest, final_dir.parent, reporter)
        except Cancelled:
            reporter.item(pkg.nevra, "pending")
            raise
        except Exception as exc:
            reporter.item(pkg.nevra, "failed", detail=str(exc))
            raise
        reporter.item(pkg.nevra, "done",
                      size=dest.stat().st_size if dest.exists() else pkg.size)
        reporter.progress(f"RPM {i}/{total}", i / total)

    manifest = []
    shipped_ids = {id(p) for p in to_ship}
    for p in result.selected:
        # record the actual shipped SHA-256 plus the upstream source
        # digest used for pre-download differential comparison.
        filename = filename_map.get(id(p), posixpath.basename(urllib.parse.urlparse(p.location).path))
        dest = rpm_dir / filename
        record = getattr(p, "verification", None)
        manifest.append({
            "nevra": p.nevra, "package_id": p.nevra, "name": p.name, "arch": p.arch,
            "version": p.version, "release": p.release, "source_rpm": getattr(p, "source_rpm", ""), "filename": filename,
            "sha256": sha256_file(dest) if id(p) in shipped_ids and dest.exists() else "",
            "source_digest_type": p.checksum_type or "", "source_digest": p.checksum or "",
            "repo": p.repo.name, "repo_url": redact_url(p.repo.normalized_url),
            "source": redact_url(url_join(p.repo.normalized_url, p.location)), "size": p.size,
            "reason": result.reasons.get(p.nevra, "dependency"),
            "shipped": id(p) in shipped_ids,
            "evidence_status": getattr(record, "evidence_status", "not-configured"),
            "evidence_source": getattr(record, "evidence_source", ""),
            "evidence_digest_type": getattr(record, "evidence_digest_type", ""),
            "evidence_digest": getattr(record, "evidence_digest", ""),
            "evidence_relationship": getattr(record, "evidence_relationship", ""),
            "evidence_authority_relationship": getattr(record, "evidence_authority_relationship", AUTH_UNKNOWN),
            "evidence_peer_identity_match": bool(getattr(record, "evidence_peer_identity_match", False)),
            "evidence_source_lineage_match": bool(getattr(record, "evidence_source_lineage_match", False)),
            "evidence_peer_package_id": getattr(record, "evidence_peer_package_id", ""),
            "evidence_peer_source_rpm": getattr(record, "evidence_peer_source_rpm", ""),
        })
    if options.additive_publish:
        manifest = merge_additive_manifest_rows(metadata_dir / "manifest.json", manifest)
    payload_files = list(rpm_dir.glob("*.rpm"))
    payload = {
        "metadata": metadata,
        "summary": {
            # Bundle-local values describe bytes actually present in rpms/.
            "package_count": len(payload_files) if options.additive_publish else len(to_ship),
            "total_size": (sum(p.stat().st_size for p in payload_files) if options.additive_publish
                           else sum(int(getattr(p, "size", 0) or 0) for p in to_ship)),
            "resolved_package_count": len(result.selected),
            "resolved_total_size": result.total_size,
            "baseline_omitted_count": len(already_present),
            "unresolved_count": len(result.unresolved),
            "ignored_unresolved_count": len(getattr(result, "ignored_unresolved", []) or []),
            "conflict_count": len(result.conflicts),
            "dependency_completeness": metadata.get("dependency_completeness", "analyzed"),
        },
        "packages": manifest,
    }
    (metadata_dir / "manifest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (metadata_dir / "manifest.txt").write_text(
        "\n".join(f"{x['nevra']}\t{x['repo']}\t{x['reason']}\t{x['source']}" for x in manifest) + "\n", encoding="utf-8")
    (metadata_dir / "unresolved.txt").write_text(
        "\n".join(format_requirement(r) for r in result.unresolved) + ("\n" if result.unresolved else ""), encoding="utf-8")
    if getattr(result, "ignored_unresolved", None):
        (metadata_dir / "ignored-unresolved.txt").write_text(
            "\n".join(result.ignored_unresolved) + "\n", encoding="utf-8")
    (metadata_dir / "conflicts.txt").write_text("\n".join(result.conflicts) + ("\n" if result.conflicts else ""), encoding="utf-8")
    if result.skipped_installed:
        (metadata_dir / "skipped-installed.txt").write_text("\n".join(result.skipped_installed) + "\n", encoding="utf-8")
    if result.installed_satisfied:
        (metadata_dir / "satisfied-by-target.txt").write_text("\n".join(result.installed_satisfied) + "\n", encoding="utf-8")
    with (metadata_dir / "SHA256SUMS.txt").open("w", encoding="utf-8") as f:
        for rpm in sorted(rpm_dir.glob("*.rpm")):
            f.write(f"{sha256_file(rpm)}  {rpm.name}\n")


    # ---- Provenance -------------------------------------------------------
    # Record, per artifact, exactly what was proven about it. RPMs carry their
    # own vendor signature, so this is the strongest assurance Feathered can
    # report; when a vendor keyring is configured it is enforced here.
    prov_entries = []
    for pkg in to_ship:
        filename = filename_map[id(pkg)]
        dest = rpm_dir / filename
        entry = provenance.PackageProvenance(
            package_id=pkg.nevra, filename=filename,
            sha256=sha256_file(dest) if dest.exists() else "",
            size=dest.stat().st_size if dest.exists() else 0,
            source_url=redact_url(url_join(pkg.repo.normalized_url, pkg.location)),
            repository=pkg.repo.name,
            # Recorded verification, not inferred from configuration: a
            # keyring being set says an operator intended verification, not
            # that a signature was checked or that it passed.
            index_digest_verified=bool(getattr(pkg, "verification", None)
                                       and pkg.verification.index_digest_verified),
            archive_signature_verified=bool(
                getattr(pkg.repo, "trust", None)
                and pkg.repo.trust.archive_signature_verified),
            # source-bond facts are recorded separately from the
            # acquisition archive's trust chain.
            evidence_status=getattr(getattr(pkg, "verification", None), "evidence_status", "not-configured"),
            evidence_source=getattr(getattr(pkg, "verification", None), "evidence_source", ""),
            evidence_digest_type=getattr(getattr(pkg, "verification", None), "evidence_digest_type", ""),
            evidence_digest=getattr(getattr(pkg, "verification", None), "evidence_digest", ""),
            evidence_digest_checked=bool(getattr(pkg, "verification", None)
                                         and pkg.verification.evidence_digest_checked),
            evidence_metadata_match=bool(getattr(pkg, "verification", None)
                                         and pkg.verification.evidence_metadata_match),
            evidence_artifact_checked=bool(getattr(pkg, "verification", None)
                                           and pkg.verification.evidence_artifact_checked),
            evidence_artifact_digest_type=getattr(getattr(pkg, "verification", None), "evidence_artifact_digest_type", ""),
            evidence_artifact_digest=getattr(getattr(pkg, "verification", None), "evidence_artifact_digest", ""),
            evidence_artifact_size=int(getattr(getattr(pkg, "verification", None), "evidence_artifact_size", 0) or 0),
            evidence_archive_signature_verified=bool(getattr(pkg, "verification", None)
                                                      and pkg.verification.evidence_archive_signature_verified),
            evidence_relationship=getattr(getattr(pkg, "verification", None), "evidence_relationship", ""),
            evidence_authority_relationship=getattr(getattr(pkg, "verification", None), "evidence_authority_relationship", AUTH_UNKNOWN),
            evidence_peer_identity_match=bool(getattr(pkg, "verification", None)
                                              and pkg.verification.evidence_peer_identity_match),
            evidence_source_lineage_match=bool(getattr(pkg, "verification", None)
                                               and pkg.verification.evidence_source_lineage_match),
            evidence_peer_package_id=getattr(getattr(pkg, "verification", None), "evidence_peer_package_id", ""),
            evidence_peer_source_rpm=getattr(getattr(pkg, "verification", None), "evidence_peer_source_rpm", ""),
        )
        if repository_verification_strategy(pkg.repo) == "skip-provenance":
            entry.notes.append("Upstream vendor-signature verification intentionally skipped by operator policy.")
            entry.digest_checked = False
            entry.assurance = provenance.assurance_from(entry)
        else:
            vendor_id, scoped_keyring, scoped_required = vendor_signature_settings(pkg.repo, options)
            if scoped_keyring and dest.exists():
                try:
                    detail = provenance.verify_rpm_package(dest, scoped_keyring, reporter)
                    entry.assurance = provenance.VERIFIED_VENDOR
                    entry.signature_algorithm = detail.get("algorithm", "")
                    entry.signer = detail.get("signer", "")
                    entry.signing_key_id = detail.get("key_id", "")
                except VerifierIntegrityError:
                    # Never downgrade a compromised verifier to a package note.
                    # "This package is unsigned" and "this machine cannot be
                    # trusted to tell you whether it is signed" are not the
                    # same finding, and only the first one is waivable.
                    raise
                except RuntimeError as exc:
                    if scoped_required:
                        raise RuntimeError(
                            f"Vendor signature check failed for {vendor_display_name(vendor_id)} "
                            f"and signatures are required: {exc}") from exc
                    entry.notes.append(str(exc))
                    entry.assurance = provenance.assurance_from(entry)
                    reporter.warn(f"{filename}: {exc}")
            elif scoped_required:
                raise RuntimeError(
                    f"Vendor signatures are required for {vendor_display_name(vendor_id)}, "
                    "but no vendor package keyring is configured for that vendor.")
            else:
                if dest.exists():
                    entry.notes.append(provenance.rpm_signature_summary(dest))
                entry.digest_checked = bool(getattr(pkg, "verification", None)
                                            and pkg.verification.package_digest_checked)
                entry.assurance = provenance.assurance_from(entry)
        prov_entries.append(entry)
    if options.emit_repository:
        repo_packages = to_ship
        preserve_locations = False
        if options.additive_publish:
            from repository_tools import load_local_repository_packages
            _family, repo_packages = load_local_repository_packages(output_dir, "rpm")
            preserve_locations = True
            reporter.log(f"Regenerating RPM repository metadata over {len(repo_packages)} total package(s) in the additive folder.")
        emit_rpm_repository(output_dir, repo_packages, reporter,
                            preserve_package_locations=preserve_locations, supplemental_packages=result.selected)
    _write_provenance(output_dir, metadata_dir, prov_entries, already_present, options, reporter, metadata)

    package_only = bool(metadata.get("package_only_acquisition"))
    repository_mirror = bool(metadata.get("repository_mirror"))
    if package_only:
        warning = str(metadata.get("package_only_warning") or
                      "Dependencies were not derived for this package-only acquisition.")
        (metadata_dir / "PACKAGE-ONLY-WARNING.txt").write_text(
            "PACKAGE-ONLY ACQUISITION - NOT A COMPLETE OFFLINE INSTALLATION BUNDLE\n\n"
            + warning +
            "\n\nThe rpms/ directory contains only the requested workload root artifacts. "
            "Configure the target distribution/base repositories and rebuild before treating "
            "this package set as install-complete.\n",
            encoding="utf-8")
    elif repository_mirror:
        (metadata_dir / "MIRROR-BUNDLE.txt").write_text(
            "REPOSITORY MIRROR - NO PACKAGE-ROOT TRANSACTION\n\n"
            "This output mirrors the selected repository population. Feathered did not derive a "
            "root-package dependency closure and intentionally did not generate install-offline.sh.\n\n"
            "Use USE-AS-REPOSITORY.txt to expose the generated local repository metadata to DNF/YUM. "
            "Package installation decisions remain the target package manager's responsibility.\n",
            encoding="utf-8")
    else:
        write_installation_contract(metadata_dir, result, 'rpm', metadata, already_present)
        roots = installation_roots(result, 'rpm')
        if roots:
            (metadata_dir / "REQUESTED-ROOTS.txt").write_text("\n".join(roots) + "\n", encoding="utf-8")
            if options.emit_repository:
                from installer import write_installer
                write_vendor_key_manifest(metadata_dir, prov_entries)
                write_installer(output_dir, metadata_dir, result, options, 'rpm', metadata,
                                provenance_entries=prov_entries)
            else:
                (output_dir / "INSTALL-OFFLINE-NOTE.txt").write_text(
                    "Enable local repository metadata to generate the offline installer.\n", encoding="utf-8")
    write_unified_mirror_records(output_dir, metadata_dir, options)
    if reporter.warnings:
        (metadata_dir / "trust-warnings.txt").write_text(
            "Conditions recorded while building this bundle. Review before installing.\n\n"
            + "\n".join(f"- {w}" for w in reporter.warnings) + "\n", encoding="utf-8")
    # Seal and publish. The index is computed from the finished files on disk,
    # so the operator signature attests to the bundle that actually exists.
    _write_workload_artifacts(output_dir, metadata_dir, metadata, result)
    if options.sign_bundle_index:
        # Sealing owns the last slice of the same bar the transfer advanced.
        reporter.phase(SEAL_PHASE_START, 1.0 - SEAL_PHASE_START)
        write_bundle_index(output_dir, reporter, {
            "tool": provenance._tool_identity(),
            # The published name, not the temporary staging directory.
            "bundle_id": final_dir.name,
            "target": {k: str(v) for k, v in metadata.items()
                       if k in {"distribution", "release", "arch", "workload"}},
            "trust": _trust_summary(to_ship),
        }, options.signing_key)
    return commit_staging(output_dir, final_dir, reporter)


def _parse_evr_text(text: str) -> Tuple[str, str, str]:
    text = (text or "").strip()
    if not text or text == "(none)":
        return ("0", "", "")
    epoch = "0"
    if ":" in text:
        maybe_epoch, rest = text.split(":", 1)
        if maybe_epoch.isdigit():
            epoch, text = maybe_epoch, rest
    if "-" in text:
        version, release = text.rsplit("-", 1)
    else:
        version, release = text, ""
    return epoch, version, release


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


def _write_workload_artifacts(output_dir, metadata_dir, metadata, result):
    data = metadata.get('kubernetes')
    if not data:
        return
    assurance = metadata_dir / 'ASSURANCE.txt'
    previous = assurance.read_text(encoding='utf-8') if assurance.exists() else ''
    lines = ['KUBERNETES WORKLOAD OBSERVATIONS', 'PROVES: ' + data['proves'],
             'DOES NOT PROVE: ' + data['does_not_prove'],
             'API server versions assumed: ' + str(data['apiserver_assumed']),
             'Advisories acknowledged: ' + str(data['advisories_acknowledged'])]
    lines += [f"{f['severity']}: {f['package']} {f['version']}: {f['message']}" for f in data['findings'] + data['platform_advisories']]
    assurance.write_text(previous + '\n' + '\n'.join(lines) + '\n', encoding='utf-8')
    if data.get('image_draft_context'):
        from kubernetes_workflow import WorkloadContext, write_image_draft
        write_image_draft(output_dir, WorkloadContext(**data['image_draft_context']), result)
