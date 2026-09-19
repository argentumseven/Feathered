"""Core package, verification, inventory, and resolution data contracts.

This module is deliberately independent of the legacy ``core`` implementation.
``core`` re-exports these classes during the migration so existing imports remain
valid while new code can depend on the smaller domain boundary directly.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, Generic, List, Optional, Set, Tuple, TypeVar

from evidence_model import AUTH_UNKNOWN

if TYPE_CHECKING:
    from repository_config import RepoSpec


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
    # Package names participating in direct transaction conflicts.  Resolver
    # backtracking uses this internal attribution to reject only a provider
    # branch that actually caused a conflict rather than discarding unrelated
    # choices.  It is not part of bundle provenance.
    conflict_participants: List[str] = field(default_factory=list, compare=False, repr=False)

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

__all__ = [
    "ArtifactVerification",
    "BuildOptions",
    "Package",
    "ProviderMatch",
    "RepoDataRef",
    "RepoTrust",
    "Requirement",
    "ResolutionResult",
    "TargetInventory",
]
