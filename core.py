from __future__ import annotations

"""Compatibility façade for Feathered's RPM-domain implementation.

The implementation has been decomposed into Tk-free modules.  ``core`` keeps
historical import names and the small number of runtime injection seams relied
on by package-family backends, integrations, and regression tests.
"""

import hashlib
import hmac
import os
import posixpath
import re
import shutil
import sys
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Dict, IO, Iterable, List, Optional, Protocol, Sequence, Set, Tuple, TypeVar, Union

import artifact_verification as _artifact_verification_engine
import bundle_sealing as _bundle_sealing
import bundle_support as _bundle_support
import file_hashing
import metadata_digests as _metadata_digests
import openpgp_verifier as _openpgp
import package_acquisition as _package_acquisition
import repository_loader as _repository_loader
import repository_transport as _transport
import rpm_bundle as _rpm_bundle
import rpm_capabilities
import rpm_metadata as _rpm_metadata
import rpm_repository_writer as _rpm_repository_writer
import rpm_resolution as _rpm_resolution
import rpm_target_inventory as _rpm_target_inventory

from core_models import (
    ArtifactVerification,
    BuildOptions,
    Package,
    ProviderMatch,
    RepoDataRef,
    RepoTrust,
    Requirement,
    ResolutionResult,
    TargetInventory,
)
from credential_redaction import (
    SENSITIVE_QUERY_KEYS,
    _KNOWN_SECRET_ORDER,
    _KNOWN_SECRETS,
    _KNOWN_SECRETS_LOCK,
    _MAX_KNOWN_SECRETS,
    _MIN_GLOBAL_SECRET_LENGTH,
    _remember_secret,
    active_sensitive_query_keys as _active_sensitive_query_keys,
    redact_text,
    redact_url,
    register_url_secrets,
)
from evidence_model import (
    AUTH_UNKNOWN,
    REL_EXACT_ARTIFACT,
    REL_EXACT_MIRROR,
    REL_REBUILD_PEER,
    classify_relationship,
    infer_vendor_id,
    vendor_display_name,
)
from execution_reporter import Cancelled, CancellationProbe, Reporter
from package_contracts import PackageArtifact
from package_transfer import copy_package_stream_bounded, package_download_limit
from publication_staging import (
    _publication_backup_path,
    abandon_staging,
    commit_staging,
    invalidate_bundle_seal,
    open_staging,
)
from repository_config import RepoSpec
from root_requests import RootInput
from repository_paths import (
    file_url_to_path,
    human_size,
    path_to_file_url,
    repo_relative_url,
)
from runtime_limits import (
    MAX_METADATA_DOWNLOAD_BYTES,
    MAX_METADATA_EXPANDED_BYTES,
    MAX_PACKAGE_DOWNLOAD_BYTES,
    positive_env_int as _positive_env_int,
)

try:
    import compression.zstd as stdlib_zstd  # Python 3.14+
except (ImportError, ModuleNotFoundError):
    stdlib_zstd = None

try:
    import zstandard as zstd
except (ImportError, ModuleNotFoundError):
    zstd = None


FEATHERED_VERSION = "1.3.0"
USER_AGENT = f"Feathered-Airgap-Sideloader/{FEATHERED_VERSION}"
RPM_NS = _rpm_metadata.RPM_NS


class DownloadPackage(PackageArtifact, Protocol):
    """Compatibility name for the shared package-artifact protocol."""


class RepositoryWriterReporter(Protocol):
    def log(self, message: str, /) -> None: ...


BaselinePackageT = TypeVar("BaselinePackageT", bound=_bundle_support.BaselinePackage)


# ---------------------------------------------------------------------------
# Compression and transport compatibility façade
# ---------------------------------------------------------------------------


def zstd_backend() -> Optional[str]:
    if zstd is not None:
        return "zstandard-stream"
    if stdlib_zstd is not None:
        return "stdlib"
    return None


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


def fetch_bytes(
    url: str,
    reporter: Reporter,
    retries: int = 3,
    timeout: int = 45,
    repo: Optional[RepoSpec] = None,
    max_bytes: Optional[int] = MAX_METADATA_DOWNLOAD_BYTES,
) -> bytes:
    return _transport.fetch_bytes(
        url,
        reporter,
        retries=retries,
        timeout=timeout,
        repo=repo,
        max_bytes=max_bytes,
        open_url_fn=lambda target, seconds, source: _urlopen(target, seconds, source),
        redact_url_fn=redact_url,
    )


def fetch_text(
    url: str,
    reporter: Optional[Reporter] = None,
    retries: int = 3,
    timeout: int = 45,
) -> str:
    return fetch_bytes(
        url,
        reporter or Reporter(),
        retries=retries,
        timeout=timeout,
    ).decode("utf-8", "replace")


def url_join(base: str, href: str, repo: Optional[RepoSpec] = None) -> str:
    return _transport.url_join(base, href, repo)


# ---------------------------------------------------------------------------
# Repository metadata digest policy
# ---------------------------------------------------------------------------

STRONG_HASHES = _metadata_digests.STRONG_HASHES
_HASH_ALIASES = _metadata_digests._HASH_ALIASES
WEAK_HASHES = _metadata_digests.WEAK_HASHES
normalize_hash_name = _metadata_digests.normalize_hash_name
_hash_bytes = _metadata_digests.hash_bytes
_hash_stream = _metadata_digests.hash_stream


# ---------------------------------------------------------------------------
# OpenPGP verifier façade.  Wrappers deliberately resolve core names at call
# time so historical monkeypatch/injection seams keep working.
# ---------------------------------------------------------------------------

VerifierIntegrityError = _openpgp.VerifierIntegrityError
MAX_ARMORED_KEYRING_BYTES = _openpgp.MAX_ARMORED_KEYRING_BYTES
bundled_gpg_dir = _openpgp.bundled_gpg_dir
_verifier_policy_path = _openpgp.verifier_policy_path
def _sha256_file(path: Path) -> str:
    return file_hashing.stream_digest(path, hashlib.sha256())

_verifier_fingerprint = _openpgp.verifier_fingerprint
_enumerate_verifier_files = _openpgp.enumerate_verifier_files
_reset_verifier_integrity_cache = _openpgp.reset_verifier_integrity_cache
gpg_backend_name = _openpgp.gpg_backend_name
_windows_path_to_msys = _openpgp.windows_path_to_msys
_gpg_backend_uses_msys_paths = _openpgp.gpg_backend_uses_msys_paths
_dearmor_public_keyring = _openpgp.dearmor_public_keyring
_prepare_keyring = _openpgp.prepare_keyring


def _verify_bundled_gpg_integrity(directory: Path) -> None:
    return _openpgp.verify_bundled_gpg_integrity(
        directory,
        policy_path_fn=_verifier_policy_path,
        sha256_file_fn=_sha256_file,
    )


def _gpg_path_arg(path: Union[Path, str], backend: str) -> str:
    return _openpgp.gpg_path_arg(
        path,
        backend,
        uses_msys_fn=_gpg_backend_uses_msys_paths,
    )


def gpg_backend() -> Optional[str]:
    return _openpgp.gpg_backend(
        bundled_dir_fn=bundled_gpg_dir,
        verify_integrity_fn=_verify_bundled_gpg_integrity,
    )


def gpg_backend_or_none() -> Optional[str]:
    return _openpgp.gpg_backend_or_none(backend_fn=gpg_backend)


def gpg_backend_version(backend: Optional[str] = None) -> str:
    return _openpgp.gpg_backend_version(
        backend,
        backend_or_none_fn=gpg_backend_or_none,
    )


def verify_openpgp(
    signed_payload: bytes,
    signature: Optional[bytes],
    keyring: str,
    description: str,
    reporter: Reporter,
) -> None:
    return _openpgp.verify_openpgp(
        signed_payload,
        signature,
        keyring,
        description,
        reporter,
        backend_fn=gpg_backend,
        prepare_keyring_fn=_prepare_keyring,
        backend_name_fn=gpg_backend_name,
        path_arg_fn=_gpg_path_arg,
    )


# ---------------------------------------------------------------------------
# RPM metadata parsing and repository loading
# ---------------------------------------------------------------------------


def _repo_trust(repo: RepoSpec) -> RepoTrust:
    return _repository_loader.repo_trust(repo)


def decompress_metadata(
    data: bytes,
    url: str,
    max_bytes: int = MAX_METADATA_EXPANDED_BYTES,
) -> bytes:
    return _rpm_metadata.decompress_metadata(
        data,
        url,
        max_bytes,
        zstd_module=zstd,
        stdlib_zstd_module=stdlib_zstd,
    )


def decompress_metadata_stream(
    data: bytes,
    url: str,
    max_bytes: int = MAX_METADATA_EXPANDED_BYTES,
) -> IO[bytes]:
    return _rpm_metadata.decompress_metadata_stream(
        data,
        url,
        max_bytes,
        zstd_module=zstd,
        stdlib_zstd_module=stdlib_zstd,
    )


def parse_primary(
    xml: Union[bytes, IO[bytes]],
    repo: RepoSpec,
    arches: Set[str],
    reporter: Reporter,
) -> List[Package]:
    return _rpm_metadata.parse_primary(
        xml,
        repo,
        arches,
        reporter,
        normalized_hash_algorithm_fn=normalized_hash_algorithm,
        select_digest_from_map_fn=select_digest_from_map,
        repo_trust_fn=_repo_trust,
    )


def _repository_loader_services() -> _repository_loader.RepositoryLoaderServices:
    return _repository_loader.RepositoryLoaderServices(
        url_join=url_join,
        fetch_bytes=fetch_bytes,
        verification_strategy=repository_verification_strategy,
        verify_openpgp=verify_openpgp,
        repo_trust=_repo_trust,
        repo_relative_url=repo_relative_url,
        hash_bytes=_hash_bytes,
        hash_stream=_hash_stream,
        decompress_metadata=decompress_metadata,
        decompress_metadata_stream=decompress_metadata_stream,
        parse_primary=parse_primary,
        package_has_selected_digest=package_has_selected_digest,
        artifact_verification=_artifact_verification,
        mirrors_are_distinct=mirrors_are_distinct,
        redact_url=redact_url,
        evidence_repo_for_url=evidence_repo_for_url,
        evidence_relationship=evidence_relationship,
        evidence_authority_relationship=evidence_authority_relationship,
        apply_mirror_evidence=apply_mirror_evidence,
    )


def get_repo_data(
    repo: RepoSpec,
    reporter: Reporter,
    retries: int = 3,
) -> Dict[str, RepoDataRef]:
    return _repository_loader.get_repo_data(
        repo,
        reporter,
        _repository_loader_services(),
        retries=retries,
    )


def diagnose_missing_repository(
    repo_url: str,
    reporter: Reporter,
    retries: int = 1,
) -> str:
    return _repository_loader.diagnose_missing_repository(
        repo_url,
        reporter,
        _repository_loader_services(),
        retries=retries,
    )


def _load_repository_once(
    repo: RepoSpec,
    arches: Set[str],
    reporter: Reporter,
    retries: int = 3,
) -> List[Package]:
    return _repository_loader.load_repository_once(
        repo,
        arches,
        reporter,
        _repository_loader_services(),
        retries=retries,
    )


def load_repository(
    repo: RepoSpec,
    arches: Set[str],
    reporter: Reporter,
    retries: int = 3,
) -> List[Package]:
    return _repository_loader.load_repository(
        repo,
        arches,
        reporter,
        _repository_loader_services(),
        retries=retries,
        load_once_fn=_load_repository_once,
    )


def probe_repository(
    repo: RepoSpec,
    reporter: Optional[Reporter] = None,
    retries: int = 2,
) -> Tuple[bool, str]:
    return _repository_loader.probe_repository(
        repo,
        reporter,
        _repository_loader_services(),
        retries=retries,
    )


# ---------------------------------------------------------------------------
# Bundle-neutral support and final sealing
# ---------------------------------------------------------------------------

def load_baseline(manifest_path: str, reporter: Reporter) -> Dict[str, str]:
    return _bundle_support.load_baseline(
        manifest_path, reporter, digest_fn=strong_package_digest)


def split_against_baseline(
    selected: Iterable[BaselinePackageT],
    baseline: Dict[str, str],
    reporter: Reporter,
) -> Tuple[List[BaselinePackageT], List[BaselinePackageT]]:
    return _bundle_support.split_against_baseline(
        selected, baseline, reporter,
        digest_fn=strong_package_digest, compare_fn=hmac.compare_digest)


def _windows_payload_key(name: str) -> str:
    return _bundle_support.windows_payload_key(
        name, normalize_fn=unicodedata.normalize)


def payload_filenames(packages: Iterable[object], expected_suffix: str) -> Dict[int, str]:
    return _bundle_support.payload_filenames(
        packages, expected_suffix,
        location_name_fn=lambda location: posixpath.basename(urllib.parse.urlparse(location).path),
        key_fn=_windows_payload_key)


write_unified_mirror_records = _bundle_support.write_unified_mirror_records
meta_str_list = _bundle_support.meta_str_list
meta_dict_list = _bundle_support.meta_dict_list
merge_additive_manifest_rows = _bundle_support.merge_additive_manifest_rows
_record_digest_checked = _bundle_support.record_digest_checked
trust_summary = _bundle_support.trust_summary
_trust_summary = trust_summary

SEAL_PHASE_START = _bundle_sealing.SEAL_PHASE_START
INDEX_FILENAME = _bundle_sealing.INDEX_FILENAME
INDEX_SIGNATURE = _bundle_sealing.INDEX_SIGNATURE
def _verify_script() -> str:
    return _bundle_sealing.verify_script(Path(__file__))


_sign_detached = _bundle_sealing.sign_detached
make_executable = _bundle_sealing.make_executable


def write_bundle_index(
    bundle_dir: Path,
    reporter: Reporter,
    metadata: Dict[str, object],
    signing_key: str = "",
) -> Path:
    return _bundle_sealing.write_bundle_index(
        bundle_dir,
        reporter,
        metadata,
        signing_key,
        verify_script_fn=_verify_script,
        make_executable_fn=make_executable,
        sign_detached_fn=_sign_detached,
        gpg_version_fn=gpg_backend_version,
        default_tool=f"Feathered {FEATHERED_VERSION}",
    )


# ---------------------------------------------------------------------------
# File hashing
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    return file_hashing.stream_digest(path, hashlib.sha256())


def hash_file(path: Path, algorithm: str) -> str:
    algo = (algorithm or "sha256").lower()
    if algo == "sha":
        algo = "sha1"
    return file_hashing.stream_digest(path, hashlib.new(algo))


# ---------------------------------------------------------------------------
# RPM resolver compatibility façade
# ---------------------------------------------------------------------------

_segments = _rpm_resolution._segments
rpmvercmp = _rpm_resolution.rpmvercmp
compare_evr = _rpm_resolution.compare_evr
_provider_candidates = _rpm_resolution._provider_candidates
_requirement_note = _rpm_resolution._requirement_note
should_ignore = _rpm_resolution.should_ignore
evr_satisfies = _rpm_resolution.evr_satisfies
package_satisfies = _rpm_resolution.package_satisfies
inventory_satisfies = _rpm_resolution.inventory_satisfies
_provider_rank = _rpm_resolution._provider_rank
choose_provider = _rpm_resolution.choose_provider
_detect_default_python_abi = _rpm_resolution._detect_default_python_abi
_python_default_alias = _rpm_resolution._python_default_alias
build_provider_index = _rpm_resolution.build_provider_index
_find_root = _rpm_resolution._find_root
_rich_outer_body = _rpm_resolution._rich_outer_body
_split_top_level_keyword = _rpm_resolution._split_top_level_keyword
_simple_requirement_from_text = _rpm_resolution._simple_requirement_from_text
parse_simple_rich_if = _rpm_resolution.parse_simple_rich_if
parse_simple_rich_or = _rpm_resolution.parse_simple_rich_or
parse_simple_rich_with = _rpm_resolution.parse_simple_rich_with
_package_satisfies_all = _rpm_resolution._package_satisfies_all
_inventory_package_satisfies = _rpm_resolution._inventory_package_satisfies
inventory_satisfies_same_package = _rpm_resolution.inventory_satisfies_same_package
_same_package_provider_candidates = _rpm_resolution._same_package_provider_candidates
_rich_with_note = _rpm_resolution._rich_with_note
_rpm_arch_capability = _rpm_resolution._rpm_arch_capability
format_requirement = _rpm_resolution.format_requirement
_indexed_package_satisfies = _rpm_resolution._indexed_package_satisfies
_selected_or_pending_satisfies = _rpm_resolution._selected_or_pending_satisfies
_constraint_key = _rpm_resolution._constraint_key
_satisfies_constraints = _rpm_resolution._satisfies_constraints
_reject_failed_provider = _rpm_resolution._reject_failed_provider
package_versions = _rpm_resolution.package_versions
_parse_evr_text = _rpm_resolution._parse_evr_text

_PYDIST_CAP_RE = rpm_capabilities.PYDIST_CAP_RE


def _pep503_name(value: str) -> str:
    return rpm_capabilities.pep503_name(
        value,
        substitute=lambda pattern, replacement, text: re.sub(
            pattern,
            replacement,
            text,
        ),
    )


def canonical_capability_name(name: str) -> str:
    return rpm_capabilities.canonical_capability_name(
        name,
        pattern=_PYDIST_CAP_RE,
        normalize=lambda value: _pep503_name(value),
    )


def capability_names_equal(left: str, right: str) -> bool:
    return canonical_capability_name(left) == canonical_capability_name(right)


def _index_keys(name: str) -> Tuple[str, ...]:
    raw = (name or "").strip()
    canonical = canonical_capability_name(raw)
    return (raw,) if canonical == raw else (raw, canonical)


def _resolve_pass(
    root_requests,
    packages,
    preferred_arch,
    options,
    reporter,
    constraints,
    rejected=None,
):
    return _rpm_resolution._resolve_pass(
        root_requests,
        packages,
        preferred_arch,
        options,
        reporter,
        constraints,
        rejected,
        build_provider_index_fn=build_provider_index,
    )


def _resolve_once(root_requests, packages, preferred_arch, options, reporter):
    return _rpm_resolution._resolve_once(
        root_requests,
        packages,
        preferred_arch,
        options,
        reporter,
        build_provider_index_fn=build_provider_index,
    )


def resolve(
    root_requests: Sequence[RootInput],
    packages: Sequence[Package],
    preferred_arch: str,
    options: BuildOptions[TargetInventory],
    reporter: Reporter,
) -> ResolutionResult:
    from transaction_model import resolve_transaction

    return resolve_transaction(
        _resolve_once,
        root_requests,
        packages,
        preferred_arch,
        options,
        reporter,
        "rpm",
    )


# ---------------------------------------------------------------------------
# Artifact/evidence verification façade
# ---------------------------------------------------------------------------

STRONG_PACKAGE_HASHES = _artifact_verification_engine.STRONG_PACKAGE_HASHES
_DIGEST_STRENGTH_ORDER = _artifact_verification_engine._DIGEST_STRENGTH_ORDER
normalized_hash_algorithm = _artifact_verification_engine.normalized_hash_algorithm
strong_package_digest = _artifact_verification_engine.strong_package_digest
normalized_digest_map = _artifact_verification_engine.normalized_digest_map
select_digest_from_map = _artifact_verification_engine.select_digest_from_map
vendor_signature_settings = _artifact_verification_engine.vendor_signature_settings
repository_verification_strategy = _artifact_verification_engine.repository_verification_strategy
package_digest_map = _artifact_verification_engine.package_digest_map
selected_package_digest = _artifact_verification_engine.selected_package_digest
package_has_selected_digest = _artifact_verification_engine.package_has_selected_digest
mirrors_are_distinct = _artifact_verification_engine.mirrors_are_distinct
_artifact_verification = _artifact_verification_engine._artifact_verification
evidence_relationship = _artifact_verification_engine.evidence_relationship
evidence_authority_relationship = _artifact_verification_engine.evidence_authority_relationship
_rpm_source_lineage = _artifact_verification_engine._rpm_source_lineage
independent_peer_packages_match = _artifact_verification_engine.independent_peer_packages_match
find_independent_peer_package = _artifact_verification_engine.find_independent_peer_package
evidence_repo_for_url = _artifact_verification_engine.evidence_repo_for_url
evidence_artifact_candidates = _artifact_verification_engine.evidence_artifact_candidates
_evidence_comparison_algorithm = _artifact_verification_engine._evidence_comparison_algorithm
apply_mirror_evidence = _artifact_verification_engine.apply_mirror_evidence


def probe_evidence_artifact(
    url: str,
    repo: RepoSpec,
    reporter: Reporter,
) -> Tuple[bool, str]:
    return _artifact_verification_engine.probe_evidence_artifact(
        url,
        repo,
        reporter,
        open_url_fn=_urlopen,
    )


def _stream_hash_url(
    url: str,
    algorithms: Iterable[str],
    repo: RepoSpec,
    reporter: Reporter,
    max_bytes: int = MAX_PACKAGE_DOWNLOAD_BYTES,
) -> Tuple[Dict[str, str], int]:
    return _artifact_verification_engine._stream_hash_url(
        url,
        algorithms,
        repo,
        reporter,
        max_bytes,
        open_url_fn=_urlopen,
    )


def spot_compare_artifact_urls(
    acquisition_url: str,
    acquisition_repo: RepoSpec,
    evidence_url: str,
    evidence_repo: RepoSpec,
    checksum_policy: str,
    reporter: Reporter,
) -> Tuple[bool, str]:
    return _artifact_verification_engine.spot_compare_artifact_urls(
        acquisition_url,
        acquisition_repo,
        evidence_url,
        evidence_repo,
        checksum_policy,
        reporter,
        open_url_fn=_urlopen,
    )


def spot_compare_peer_artifact_urls(
    primary_pkg: Package,
    acquisition_url: str,
    acquisition_repo: RepoSpec,
    evidence_pkg: Package,
    evidence_url: str,
    evidence_repo: RepoSpec,
    checksum_policy: str,
    reporter: Reporter,
) -> Tuple[bool, str]:
    return _artifact_verification_engine.spot_compare_peer_artifact_urls(
        primary_pkg,
        acquisition_url,
        acquisition_repo,
        evidence_pkg,
        evidence_url,
        evidence_repo,
        checksum_policy,
        reporter,
        open_url_fn=_urlopen,
    )


def _verify_independent_evidence_payload(
    pkg: PackageArtifact,
    acquisition_path: Path,
    primary: Optional[Tuple[str, str]],
    computed: Dict[str, str],
    reporter: Reporter,
) -> None:
    return _artifact_verification_engine._verify_independent_evidence_payload(
        pkg,
        acquisition_path,
        primary,
        computed,
        reporter,
        open_url_fn=_urlopen,
        hash_file_fn=hash_file,
        mirrors_are_distinct_fn=mirrors_are_distinct,
        evidence_relationship_fn=evidence_relationship,
        evidence_authority_relationship_fn=evidence_authority_relationship,
    )


def verify_package_artifact(
    pkg: PackageArtifact,
    path: Path,
    options: BuildOptions,
    reporter: Reporter,
) -> bool:
    try:
        return _artifact_verification_engine.verify_package_artifact(
            pkg,
            path,
            options,
            reporter,
            hash_file_fn=hash_file,
            verify_independent_fn=_verify_independent_evidence_payload,
        )
    except VerifierIntegrityError:
        raise


# ---------------------------------------------------------------------------
# Payload acquisition
# ---------------------------------------------------------------------------


def _copy_or_download(
    pkg: DownloadPackage,
    dest: Path,
    options: BuildOptions,
    reporter: Reporter,
    *,
    opener=None,
    verifier=None,
) -> None:
    return _package_acquisition.copy_or_download(
        pkg,
        dest,
        options,
        reporter,
        _package_acquisition.AcquisitionServices(
            open_url=_urlopen if opener is None else opener,
            verify_artifact=verify_package_artifact if verifier is None else verifier,
        ),
    )


# ---------------------------------------------------------------------------
# RPM publication façade
# ---------------------------------------------------------------------------

emit_rpm_repository = _rpm_repository_writer.emit_rpm_repository
declared_inventory_family = _rpm_target_inventory.declared_inventory_family
parse_target_inventory = _rpm_target_inventory.parse_target_inventory
write_vendor_key_manifest = _rpm_bundle.write_vendor_key_manifest
_write_provenance = _rpm_bundle._write_provenance
_write_assurance_legend = _rpm_bundle._write_assurance_legend
write_bundle_archive = _rpm_bundle.write_bundle_archive
_write_workload_artifacts = _rpm_bundle._write_workload_artifacts


def _rpm_bundle_services() -> _rpm_bundle.BundleServices:
    return _rpm_bundle.BundleServices(
        load_baseline=load_baseline,
        split_against_baseline=split_against_baseline,
        payload_filenames=payload_filenames,
        verify_package_artifact=verify_package_artifact,
        copy_or_download=_copy_or_download,
        sha256_file=sha256_file,
        repository_verification_strategy=repository_verification_strategy,
        vendor_signature_settings=vendor_signature_settings,
        emit_rpm_repository=emit_rpm_repository,
        write_unified_mirror_records=write_unified_mirror_records,
        write_bundle_index=write_bundle_index,
        trust_summary=_trust_summary,
        format_requirement=format_requirement,
        merge_additive_manifest_rows=merge_additive_manifest_rows,
        redact_url=redact_url,
        url_join=url_join,
        verifier_integrity_error=VerifierIntegrityError,
    )


def write_bundle(
    result: ResolutionResult,
    output_dir: Path,
    options: BuildOptions,
    reporter: Reporter,
    metadata: Dict[str, object],
) -> Path:
    return _rpm_bundle.write_bundle(
        result,
        output_dir,
        options,
        reporter,
        metadata,
        _rpm_bundle_services(),
    )


def _write_bundle_body(
    result: ResolutionResult,
    output_dir: Path,
    final_dir: Path,
    options: BuildOptions,
    reporter: Reporter,
    metadata: Dict[str, object],
) -> Path:
    return _rpm_bundle._write_bundle_body(
        result,
        output_dir,
        final_dir,
        options,
        reporter,
        metadata,
        _rpm_bundle_services(),
    )
