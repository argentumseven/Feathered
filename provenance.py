"""Package-level provenance: proving where each artifact actually came from.

Repository metadata verification (see core/apt_core) proves that an index was
published by whoever holds the archive key, and that a downloaded file matches
the digest that index advertised. That is a chain rooted at the *archive*.

This module adds the link rooted at the *vendor*: the signature the packager
applied to the artifact itself, which survives mirroring, re-hosting and
re-indexing. For an airgapped transfer that distinction matters, because the
archive you fetched from is frequently not the party you actually trust.

The two package formats differ in an important way, and Feathered reports the
difference honestly rather than papering over it:

  RPM  - packages carry their own OpenPGP signature over the immutable header,
         and the header carries the payload digest. This is verifiable offline
         against a vendor keyring, independent of any repository.

  DEB  - individual .deb files are almost never signed (debsigs is rare and
         effectively unused by Debian and Ubuntu). Provenance instead derives
         from the signed Release file: Release signature -> Packages index
         digest -> .deb digest. Feathered records that chain explicitly so a
         bundle consumer can see that the artifact's authority is the archive key,
         not a per-package vendor signature.
"""
from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Tuple, TypedDict

if TYPE_CHECKING:  # avoids a core <-> provenance import cycle at runtime
    from core import Reporter


# RPM header magic and the signature-header tags Feathered cares about.
_HEADER_MAGIC = b"\x8e\xad\xe8"
_RPM_LEAD_SIZE = 96
RPMSIGTAG_DSA = 267        # DSA/EdDSA signature over the immutable header
RPMSIGTAG_RSA = 268        # RSA signature over the immutable header
RPMSIGTAG_SHA1 = 269
RPMSIGTAG_SHA256 = 273
RPMSIGTAG_PGP = 1002       # Signature over header + payload (legacy V3)
RPMSIGTAG_MD5 = 1004

# Immutable-header tags carrying the payload digest, which is what extends the
# header signature to cover the actual file contents.
RPMTAG_PAYLOADDIGEST = 5092
RPMTAG_PAYLOADDIGESTALGO = 5093
_DIGEST_ALGOS = {1: "md5", 2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512"}

# Verification outcomes. Each describes a distinct evidence axis.
VERIFIED_VENDOR = "vendor-signature"     # artifact itself is signed by a trusted key
VERIFIED_ARCHIVE = "archive-chain"       # signed index vouches for the digest
VERIFIED_DIGEST = "digest-only"          # digest matched, but nothing signed it
# assurance states for metadata-only
# source bonds. They are intentionally distinct from a vendor/archive signature.
VERIFIED_CORROBORATED = "corroborated-digest"  # acquisition + evidence strong digests both matched one payload
VERIFIED_EVIDENCE = "independent-digest" # evidence mirror alone supplied a strong digest that matched
VERIFIED_METADATA = "metadata-corroborated"  # exact identity corroborated, no strong digest available
VERIFIED_BYTE_CORROBORATED = "independent-byte-match"  # independently retrieved artifact bytes matched
VERIFIED_PEER_CORROBORATED = "independent-peer-corroboration"  # independently rebuilt package/source lineage corroborated
# provenance is multi-axis.  ``assurance``
# remains as a backward-compatible headline, while these mode names can coexist
# for one artifact.  In particular, mirror evidence is never erased merely
# because an archive keyring also authenticated the acquisition repository.
PROVENANCE_ACQUISITION_DIGEST = "acquisition-digest"
PROVENANCE_EVIDENCE_NONE = "none"
UNVERIFIED = "unverified"


@dataclass(frozen=True)
class AssuranceSemantics:
    """What one provenance mode actually entitles a reader to conclude.

    The mode names are short because they appear in tables. Short names invite
    readers to infer a strength ordering that the names alone do not carry --
    "independent-peer-corroboration" sounds stronger than "digest-only" and is
    not. Every mode therefore ships with an explicit statement of what it
    proves, what it does not prove, and where it sits in the ordering.

    ``rank`` exists so the ordering is data rather than the order constants
    happen to be declared in. It is a compatibility/display sort key, not a
    security ordering. Policies must evaluate evidence predicates and keys.
    """

    mode: str
    label: str
    authority: str          # vendor | archive | acquisition | corroboration | none
    rank: int
    proves: str
    does_not_prove: str


ASSURANCE_SEMANTICS: Dict[str, AssuranceSemantics] = {
    VERIFIED_VENDOR: AssuranceSemantics(
        VERIFIED_VENDOR, "Vendor signature", "vendor", 100,
        "The artifact's own bytes carry an OpenPGP signature that verified against the "
        "vendor keyring configured for this repository.",
        "That the configured keyring is the right one. This is only as strong as the key "
        "the operator supplied and the channel they obtained it over."),
    VERIFIED_ARCHIVE: AssuranceSemantics(
        VERIFIED_ARCHIVE, "Archive chain", "archive", 90,
        "The repository index was signed by the configured archive keyring, that index "
        "covers this file's digest, and the digest matched the downloaded bytes.",
        "That the vendor signed this specific artifact. Whoever controls the archive "
        "signing key can vouch for any bytes they choose to publish."),
    VERIFIED_BYTE_CORROBORATED: AssuranceSemantics(
        VERIFIED_BYTE_CORROBORATED, "Independent byte match", "corroboration", 60,
        "An independently retrieved copy of this artifact, fetched from a different "
        "endpoint, was byte-identical to the one acquired.",
        "Independence of authority. A mirror of the same archive redistributes the same "
        "publisher's bytes; it is a second copy, not a second opinion. This is only a "
        "genuine cross-check when the endpoint is operated by a different party."),
    VERIFIED_CORROBORATED: AssuranceSemantics(
        VERIFIED_CORROBORATED, "Corroborated digest", "corroboration", 55,
        "The acquisition metadata and a bonded evidence endpoint each published a strong "
        "digest, and both matched the single payload that was downloaded.",
        "Two independent claims, unless the two endpoints have separate publishers. If "
        "both derive from one upstream, this is one claim counted twice."),
    VERIFIED_EVIDENCE: AssuranceSemantics(
        VERIFIED_EVIDENCE, "Independent digest", "corroboration", 50,
        "A bonded evidence endpoint published a strong digest that matched the downloaded "
        "payload, where the acquisition repository itself supplied none.",
        "That anything signed either the artifact or the digest. This is an unsigned "
        "claim from a second location."),
    VERIFIED_PEER_CORROBORATED: AssuranceSemantics(
        VERIFIED_PEER_CORROBORATED, "Independent peer lineage", "corroboration", 40,
        "A package of the same identity and source lineage exists in an independently "
        "operated rebuild of the same upstream source (for example Rocky or AlmaLinux "
        "against Red Hat).",
        "Anything about these bytes. Independent rebuilds produce different binaries by "
        "construction, so no byte comparison is possible or implied. This corroborates "
        "that the package identity and its source lineage are real. It is never a "
        "substitute for a signature or a byte match, and it ranks below both."),
    VERIFIED_DIGEST: AssuranceSemantics(
        VERIFIED_DIGEST, "Digest only", "acquisition", 30,
        "The digest published by the acquisition repository matched the bytes that were "
        "downloaded, so the transfer was not corrupted.",
        "That the digest is authentic. Nothing signed the metadata, so a party able to "
        "alter the payload could alter the published digest with it."),
    PROVENANCE_ACQUISITION_DIGEST: AssuranceSemantics(
        PROVENANCE_ACQUISITION_DIGEST, "Acquisition digest", "acquisition", 30,
        "The acquisition repository's digest for this artifact was checked against the "
        "downloaded bytes.",
        "Authenticity of that digest on its own. Read this axis together with whether an "
        "archive or vendor signature also applies."),
    VERIFIED_METADATA: AssuranceSemantics(
        VERIFIED_METADATA, "Metadata corroborated", "corroboration", 20,
        "An independent endpoint lists the same package identity (name, version, size).",
        "Anything about content. No strong digest was available from either side, so the "
        "bytes themselves are uncorroborated."),
    UNVERIFIED: AssuranceSemantics(
        UNVERIFIED, "Unverified", "none", 0,
        "Nothing. The artifact was downloaded and recorded.",
        "Any property of the bytes. Treat this as untrusted input."),
}


def explain_assurance(mode: str) -> AssuranceSemantics:
    """Return the semantics for one mode, or an explicit unknown placeholder."""
    known = ASSURANCE_SEMANTICS.get(mode)
    if known is not None:
        return known
    return AssuranceSemantics(
        mode, mode or "unknown", "none", 0,
        "Unknown provenance mode; this Feathered build has no definition for it.",
        "Anything. Do not infer strength from the name.")


def assurance_legend(modes=None) -> List[Dict[str, object]]:
    """Legend rows for the modes present in a bundle, strongest first.

    Emitted into provenance.json so the artifact is self-describing. Whoever
    reads it is on the far side of an air gap with no access to this source,
    the GUI, or the documentation; a bare mode name is not enough for them to
    judge what was actually proven.
    """
    selected = (list(ASSURANCE_SEMANTICS) if modes is None
                else list(dict.fromkeys(modes)))
    rows = [explain_assurance(mode) for mode in selected]
    rows.sort(key=lambda item: (-item.rank, item.mode))
    return [
        {
            "mode": row.mode,
            "label": row.label,
            "authority": row.authority,
            "rank": row.rank,
            "proves": row.proves,
            "does_not_prove": row.does_not_prove,
        }
        for row in rows
    ]


@dataclass
class PackageProvenance:
    """What Feathered can actually prove about one artifact."""
    package_id: str
    filename: str
    sha256: str
    size: int
    source_url: str
    repository: str
    # How the artifact's authenticity was established.
    assurance: str = UNVERIFIED
    # Vendor signature detail, when the format supports it.
    signature_algorithm: str = ""
    signing_key_id: str = ""
    signer: str = ""
    # Archive-chain detail: what vouched for the digest.
    index_digest_verified: bool = False
    archive_signature_verified: bool = False
    # The artifact's own digest was checked against its bytes on disk.
    digest_checked: bool = False
    # Independent mirror evidence is recorded separately so archive
    # authentication remains distinct from cross-source corroboration.
    evidence_status: str = "not-configured"
    evidence_source: str = ""
    evidence_digest_type: str = ""
    evidence_digest: str = ""
    evidence_digest_checked: bool = False
    evidence_metadata_match: bool = False
    evidence_artifact_checked: bool = False
    evidence_artifact_digest_type: str = ""
    evidence_artifact_digest: str = ""
    evidence_artifact_size: int = 0
    evidence_archive_signature_verified: bool = False
    evidence_relationship: str = ""
    evidence_authority_relationship: str = "authority-unknown"
    evidence_peer_identity_match: bool = False
    evidence_source_lineage_match: bool = False
    evidence_peer_package_id: str = ""
    evidence_peer_source_rpm: str = ""
    # retain every independently established
    # provenance mode instead of collapsing archive authentication, payload
    # hashing and mirror evidence into one mutually-exclusive label.
    provenance_modes: List[str] = field(default_factory=list)
    archive_provenance: str = "none"
    evidence_provenance: str = "none"
    content_provenance: str = "none"
    vendor_provenance: str = "none"
    notes: List[str] = field(default_factory=list)


@dataclass
class BundleProvenance:
    """Chain of custody for a whole bundle, written as provenance.json."""
    bundle_id: str
    created: str
    tool: str
    target: Dict[str, str] = field(default_factory=dict)
    repositories: List[Dict[str, object]] = field(default_factory=list)
    packages: List[PackageProvenance] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, int]:
        """Backward-compatible headline-assurance counts."""
        counts: Dict[str, int] = {}
        for pkg in self.packages:
            counts[pkg.assurance] = counts.get(pkg.assurance, 0) + 1
        return counts

    def mode_summary(self) -> Dict[str, int]:
        """Count every independent provenance mode, not only the headline one.

        this is intentionally orthogonal to
        keyring/archive authentication.  One package may simultaneously count as
        ``archive-chain`` and ``corroborated-digest``.
        """
        counts: Dict[str, int] = {}
        for pkg in self.packages:
            modes = pkg.provenance_modes or provenance_modes_from(pkg)
            for mode in modes:
                counts[mode] = counts.get(mode, 0) + 1
        return counts

    def to_json(self) -> str:
        # Populate the axis/mode fields before serialising so bundle consumers
        # do not have to reconstruct them from a single ``assurance`` label.
        for pkg in self.packages:
            apply_provenance_modes(pkg)
        payload = asdict(self)
        payload["summary"] = self.summary()
        payload["mode_summary"] = self.mode_summary()
        # The reader of this file is on the far side of an air gap with no
        # access to Feathered, its documentation, or the operator who built the
        # bundle. Mode names alone invite a strength ordering they do not carry,
        # so ship the definitions with the evidence.
        present = list(self.summary()) + list(self.mode_summary())
        payload["assurance_legend"] = assurance_legend(present)
        return json.dumps(payload, indent=2, sort_keys=False)




def merge_previous_provenance(record: "BundleProvenance", path: Path) -> "BundleProvenance":
    """Merge prior package provenance into a new additive bundle record.

    Current entries win for the same filename/package id. The function is
    deliberately tolerant of older schema revisions by filtering each stored
    package object to fields known by the current PackageProvenance dataclass.
    """
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return record
    known = set(PackageProvenance.__dataclass_fields__)
    old_entries = []
    for raw in payload.get("packages", []) if isinstance(payload, dict) else []:
        if not isinstance(raw, dict):
            continue
        try:
            old_entries.append(PackageProvenance(**{k: v for k, v in raw.items() if k in known}))
        except Exception:
            continue
    def key(item):
        return item.filename or item.package_id
    current = {key(item): item for item in record.packages if key(item)}
    merged = {key(item): item for item in old_entries if key(item)}
    merged.update(current)
    record.packages = list(merged.values())
    prior_repos = payload.get("repositories", []) if isinstance(payload, dict) else []
    seen = {json.dumps(r, sort_keys=True, default=str) for r in record.repositories}
    for repo in prior_repos:
        marker = json.dumps(repo, sort_keys=True, default=str)
        if marker not in seen:
            record.repositories.append(repo)
            seen.add(marker)
    record.warnings.append("Additive publication: prior package provenance was preserved and merged with this build.")
    return record


# ---------------------------------------------------------------------------
# RPM header parsing
# ---------------------------------------------------------------------------

def _read_header(buf: bytes, offset: int) -> Tuple[List[Tuple[int, int, int, int]], int, int]:
    """Parse one RPM header structure at `offset`.

    Returns (index entries, data-store offset, end offset). Each index entry is
    (tag, type, data offset relative to the store, count).
    """
    if buf[offset:offset + 3] != _HEADER_MAGIC:
        raise ValueError(f"not an RPM header at offset {offset}")
    nindex, hsize = struct.unpack(">II", buf[offset + 8:offset + 16])
    if nindex > 100_000 or hsize > 64 * 1024 * 1024:
        # Guard against a malformed or hostile file steering a huge allocation.
        raise ValueError("RPM header index is implausibly large")
    base = offset + 16
    entries = []
    for i in range(nindex):
        entries.append(struct.unpack(">IIiI", buf[base + i * 16: base + i * 16 + 16]))
    store = base + nindex * 16
    return entries, store, store + hsize


# RPM header data types (rpmtag.h). Only the ones Feathered reads are listed.
_TYPE_STRING = 6
_TYPE_BIN = 7
_TYPE_STRING_ARRAY = 8
_TYPE_I18NSTRING = 9


def _entry_bytes(buf: bytes, store: int, entry: Tuple[int, int, int, int]) -> bytes:
    """Return the first value of a header entry as raw bytes.

    STRING, STRING_ARRAY and I18NSTRING are all NUL-terminated in the data
    store and `count` is the number of *strings*, not bytes -- reading
    `count * 4` bytes truncates them, which silently produced a 4-character
    payload digest and a verification failure on a perfectly good package.
    """
    _tag, typ, off, count = entry
    start = store + off
    if typ in (_TYPE_STRING, _TYPE_STRING_ARRAY, _TYPE_I18NSTRING):
        return buf[start:].split(b"\0", 1)[0]
    if typ == _TYPE_BIN:
        return buf[start:start + count]
    return buf[start:start + count * 4]


class RpmSignatureInfo(TypedDict):
    """Precise shape of read_rpm_signature's result.

    Typed rather than Dict[str, object] so the payload/header byte fields
    cannot be silently passed somewhere expecting a string.
    """
    header_blob: bytes
    header_signature: bytes
    legacy_signature: bytes
    legacy_signed_offset: int
    algorithm: str
    payload_offset: int
    payload_size: int
    payload_digest: str
    payload_digest_algo: str


def _read_header_at(path: Path, offset: int) -> Tuple[bytes, List[Tuple[int, int, int, int]], int, int]:
    """Read exactly one bounded RPM header rather than the complete package.

    vendor-signature inspection used to
    call Path.read_bytes(), doubling memory pressure for multi-gigabyte RPMs.
    RPM headers are independently sized, so parse only the header bytes here
    and leave payload verification to a streaming file hash below.
    """
    with path.open("rb") as f:
        f.seek(offset)
        prefix = f.read(16)
        if len(prefix) != 16 or prefix[:3] != _HEADER_MAGIC:
            raise ValueError(f"not an RPM header at offset {offset}")
        nindex, hsize = struct.unpack(">II", prefix[8:16])
        if nindex > 100_000 or hsize > 64 * 1024 * 1024:
            raise ValueError("RPM header index is implausibly large")
        total = 16 + nindex * 16 + hsize
        rest = f.read(total - 16)
        if len(rest) != total - 16:
            raise ValueError("truncated RPM header")
    blob = prefix + rest
    entries, store, end = _read_header(blob, 0)
    return blob, entries, store, offset + end


def _hash_file_region(path: Path, offset: int, algorithm: str) -> str:
    try:
        h = hashlib.new(algorithm)
    except ValueError as exc:
        raise RuntimeError(f"{path.name}: unsupported payload digest algorithm {algorithm!r}") from exc
    with path.open("rb") as f:
        f.seek(offset)
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_file_region(path: Path, offset: int, destination: Path) -> None:
    with path.open("rb") as src, destination.open("wb") as dst:
        src.seek(offset)
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            dst.write(chunk)


def read_rpm_signature(path: Path) -> RpmSignatureInfo:
    """Extract the header signature and the exact bytes it covers.

    An RPM is: 96-byte lead, signature header, (8-byte aligned) immutable
    header, payload. The vendor signature in RPMSIGTAG_RSA/DSA is a detached
    OpenPGP signature over the immutable header blob verbatim -- which in turn
    contains the payload digest, so verifying it authenticates the whole file
    when combined with the payload check.
    """
    with path.open("rb") as f:
        lead = f.read(_RPM_LEAD_SIZE)
    if len(lead) != _RPM_LEAD_SIZE or lead[:4] != b"\xed\xab\xee\xdb":
        raise ValueError("not an RPM file (bad lead magic)")
    sig_blob, sig_entries, sig_store, sig_end = _read_header_at(path, _RPM_LEAD_SIZE)
    # The immutable header begins at the next 8-byte boundary.
    main_offset = sig_end + (-sig_end % 8)
    main_blob, main_entries, main_store, main_end = _read_header_at(path, main_offset)
    payload_digest = ""
    payload_algo = "sha256"
    for entry in main_entries:
        if entry[0] == RPMTAG_PAYLOADDIGEST:
            payload_digest = _entry_bytes(main_blob, main_store, entry).decode("ascii", "replace")
        elif entry[0] == RPMTAG_PAYLOADDIGESTALGO:
            code = struct.unpack(">I", main_blob[main_store + entry[2]: main_store + entry[2] + 4])[0]
            payload_algo = _DIGEST_ALGOS.get(code, "sha256")

    signature = b""
    algorithm = ""
    for entry in sig_entries:
        tag = entry[0]
        if tag in (RPMSIGTAG_DSA, RPMSIGTAG_RSA):
            signature = _entry_bytes(sig_blob, sig_store, entry)
            algorithm = "DSA/EdDSA" if tag == RPMSIGTAG_DSA else "RSA"
            break
    legacy = b""
    if not signature:
        for entry in sig_entries:
            if entry[0] == RPMSIGTAG_PGP:
                legacy = _entry_bytes(sig_blob, sig_store, entry)
                algorithm = "OpenPGP (V3, header+payload)"
                break
    file_size = path.stat().st_size
    if main_end > file_size:
        raise ValueError("truncated RPM payload")
    return RpmSignatureInfo(**{
        "header_blob": main_blob,
        "header_signature": signature,
        "legacy_signature": legacy,
        "legacy_signed_offset": main_offset,
        "algorithm": algorithm,
        "payload_offset": main_end,
        "payload_size": file_size - main_end,
        "payload_digest": payload_digest,
        "payload_digest_algo": payload_algo,
    })


def verify_rpm_package(path: Path, keyring: str, reporter: Reporter) -> Dict[str, str]:
    """Verify an RPM's vendor signature against a keyring.

    Raises RuntimeError when a signature is present but does not verify, or
    when the package is unsigned. Returns signer detail on success.
    """
    from core import gpg_backend, gpg_backend_name as core_gpg_backend_name, _prepare_keyring

    info = read_rpm_signature(path)
    signature = info["header_signature"] or info["legacy_signature"]
    if not signature:
        raise RuntimeError(f"{path.name} carries no OpenPGP signature")
    backend = gpg_backend()
    if backend is None:
        raise RuntimeError("no OpenPGP verifier (gpgv/gpg) is available on this machine")
    keyring_path = Path(keyring).expanduser()
    if not keyring_path.is_file():
        raise RuntimeError(f"vendor keyring was not found: {keyring_path}")

    with tempfile.TemporaryDirectory(prefix="feathered-rpmsig-") as td:
        tmp = Path(td)
        keyring_arg = _prepare_keyring(keyring_path, tmp, backend)
        blob = tmp / "header"
        sig = tmp / "header.sig"
        if info["header_signature"]:
            blob.write_bytes(info["header_blob"])
        else:
            # Legacy V3 signatures cover immutable header + payload. Stream the
            # region to the verifier temp file rather than holding it in RAM.
            _copy_file_region(path, info["legacy_signed_offset"], blob)
        sig.write_bytes(signature)
        if core_gpg_backend_name(backend) == "gpgv":
            cmd = [backend, "--keyring", str(keyring_arg), str(sig), str(blob)]
        else:
            cmd = [backend, "--batch", "--no-default-keyring", "--keyring", str(keyring_arg),
                   "--verify", str(sig), str(blob)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        stderr = proc.stderr or ""
        if proc.returncode != 0:
            detail = [x for x in stderr.strip().splitlines() if x.strip()]
            raise RuntimeError(f"{path.name}: vendor signature verification FAILED. "
                               + (detail[-1] if detail else "no detail from the verifier"))
    # The header signature authenticates the header, and the header carries the
    # payload digest. Checking that digest is what extends the vendor's
    # attestation to the file contents; without it a payload could be swapped
    # under a valid signature.
    if info["header_signature"]:
        declared = info["payload_digest"] or ""
        if not declared:
            raise RuntimeError(f"{path.name}: header signature is valid but the header carries no "
                               "payload digest, so the archive contents are not covered by it")
        algo = info["payload_digest_algo"] or "sha256"
        actual = _hash_file_region(path, info["payload_offset"], algo)
        if actual.lower() != declared.lower():
            raise RuntimeError(f"{path.name}: payload does not match the digest in the signed header "
                               "(the archive contents have been altered)")

    signer = ""
    key_id = ""
    for line in stderr.splitlines():
        if "Good signature from" in line:
            signer = line.split("Good signature from", 1)[1].strip().strip('"')
        if " key " in line and not key_id:
            key_id = line.rsplit(" ", 1)[-1].strip()
    return {"algorithm": info["algorithm"], "signer": signer, "key_id": key_id,
            "payload_digest": info["payload_digest"] or ""}


def rpm_signature_summary(path: Path) -> str:
    """Describe an RPM's signature without verifying it (for display)."""
    try:
        info = read_rpm_signature(path)
    except Exception as exc:
        return f"unreadable ({exc})"
    if info["header_signature"]:
        return f"signed ({info['algorithm']}, header)"
    if info["legacy_signature"]:
        return f"signed ({info['algorithm']})"
    return "unsigned"


# ---------------------------------------------------------------------------
# Bundle-level provenance assembly
# ---------------------------------------------------------------------------

def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _tool_identity() -> str:
    """Exactly which build produced a bundle.

    Incident response needs to answer "which code made this?", so the record
    carries the interpreter and the zstandard version alongside Feathered's own,
    and is derived from one constant rather than a literal that drifts.
    """
    import platform
    from core import FEATHERED_VERSION
    parts = [f"Feathered {FEATHERED_VERSION}", f"python {platform.python_version()}"]
    try:
        import zstandard
        parts.append(f"zstandard {zstandard.__version__}")
    except Exception:
        parts.append("zstandard unavailable")
    if getattr(sys, "frozen", False):
        parts.append("frozen")
    return "; ".join(parts)


def provenance_modes_from(entry: "PackageProvenance") -> List[str]:
    """Return all provenance claims independently supported by recorded facts.

    GPG/keyring provenance and source-bond
    provenance are separate axes.  This function deliberately does not choose
    one over the other.
    """
    modes: List[str] = []
    if entry.signing_key_id or entry.signer:
        modes.append(VERIFIED_VENDOR)
    if entry.archive_signature_verified and entry.index_digest_verified and entry.digest_checked:
        modes.append(VERIFIED_ARCHIVE)
    if entry.digest_checked:
        modes.append(PROVENANCE_ACQUISITION_DIGEST)
    if (entry.evidence_relationship == "independent-peer"
            and entry.evidence_peer_identity_match and entry.evidence_digest_checked):
        modes.append(VERIFIED_PEER_CORROBORATED)
    elif entry.evidence_artifact_checked:
        modes.append(VERIFIED_BYTE_CORROBORATED)
    if entry.evidence_relationship != "independent-peer":
        if entry.evidence_metadata_match and entry.evidence_digest_checked:
            if entry.digest_checked:
                modes.append(VERIFIED_CORROBORATED)
            else:
                modes.append(VERIFIED_EVIDENCE)
        elif entry.evidence_metadata_match:
            modes.append(VERIFIED_METADATA)
    if not modes:
        modes.append(UNVERIFIED)
    # Preserve order while eliminating accidental duplicates.
    return list(dict.fromkeys(modes))


def apply_provenance_modes(entry: "PackageProvenance") -> List[str]:
    """Populate explicit provenance axes and return the complete mode list."""
    modes = provenance_modes_from(entry)
    entry.provenance_modes = modes
    entry.vendor_provenance = VERIFIED_VENDOR if VERIFIED_VENDOR in modes else "none"
    entry.archive_provenance = VERIFIED_ARCHIVE if VERIFIED_ARCHIVE in modes else "none"
    entry.content_provenance = (PROVENANCE_ACQUISITION_DIGEST
                                if PROVENANCE_ACQUISITION_DIGEST in modes else "none")
    if VERIFIED_CORROBORATED in modes:
        entry.evidence_provenance = VERIFIED_CORROBORATED
    elif VERIFIED_PEER_CORROBORATED in modes:
        entry.evidence_provenance = VERIFIED_PEER_CORROBORATED
    elif VERIFIED_BYTE_CORROBORATED in modes:
        entry.evidence_provenance = VERIFIED_BYTE_CORROBORATED
    elif VERIFIED_EVIDENCE in modes:
        entry.evidence_provenance = VERIFIED_EVIDENCE
    elif VERIFIED_METADATA in modes:
        entry.evidence_provenance = VERIFIED_METADATA
    else:
        entry.evidence_provenance = "none"
    return modes


def assurance_from(entry: "PackageProvenance") -> str:
    """Return a backward-compatible headline while preserving all modes.

    callers that need provenance semantics
    should inspect ``provenance_modes`` / the explicit axis fields.  The headline
    exists for older UI/report consumers only and must not be treated as the sole
    provenance record.
    """
    modes = apply_provenance_modes(entry)
    if VERIFIED_VENDOR in modes:
        return VERIFIED_VENDOR
    if VERIFIED_ARCHIVE in modes:
        return VERIFIED_ARCHIVE
    if VERIFIED_CORROBORATED in modes:
        return VERIFIED_CORROBORATED
    if VERIFIED_PEER_CORROBORATED in modes:
        return VERIFIED_PEER_CORROBORATED
    if VERIFIED_BYTE_CORROBORATED in modes:
        return VERIFIED_BYTE_CORROBORATED
    if VERIFIED_EVIDENCE in modes:
        return VERIFIED_EVIDENCE
    if PROVENANCE_ACQUISITION_DIGEST in modes:
        return VERIFIED_DIGEST
    if VERIFIED_METADATA in modes:
        return VERIFIED_METADATA
    return UNVERIFIED


def build_provenance(bundle_id: str, target: Dict[str, str], repositories: Sequence[Dict[str, object]],
                     entries: Sequence[PackageProvenance], warnings: Sequence[str]) -> BundleProvenance:
    return BundleProvenance(
        bundle_id=bundle_id,
        created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        tool=_tool_identity(),
        target=dict(target),
        repositories=list(repositories),
        packages=list(entries),
        warnings=list(warnings),
    )


def sign_bundle(manifest_path: Path, signing_key: str, reporter: Reporter) -> Optional[Path]:
    """Produce a detached OpenPGP signature over the bundle manifest.

    This is the operator's own attestation: it lets the receiving side confirm
    the media came from the expected build station, which digests alone cannot
    do because anyone who can substitute the media can regenerate them.
    """
    from shutil import which

    backend = "gpg"
    if which(backend) is None:
        reporter.warn("Bundle signing was requested but gpg is not installed; the bundle is unsigned.")
        return None
    signature = manifest_path.with_suffix(manifest_path.suffix + ".asc")
    proc = subprocess.run([backend, "--batch", "--yes", "--armor", "--local-user", signing_key,
                           "--detach-sign", "--output", str(signature), str(manifest_path)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        raise RuntimeError("Bundle signing failed: " + (detail[-1] if detail else "unknown error"))
    reporter.log(f"Bundle manifest signed: {signature.name}")
    return signature


def verify_manifest_signature(manifest_path: Path, signature_path: Path, keyring: str,
                              reporter: Reporter) -> None:
    """Counterpart to sign_bundle, used by the receiving side."""
    from core import verify_openpgp
    verify_openpgp(manifest_path.read_bytes(), signature_path.read_bytes(), keyring,
                   f"bundle manifest {manifest_path.name}", reporter)
