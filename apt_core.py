from __future__ import annotations

import artifact_digests
import bz2
import gzip
import hashlib
import io
import json
import lzma
import posixpath
import re
import shutil
import shlex
import time
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from functools import cmp_to_key
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Sequence, Set, Tuple

if TYPE_CHECKING:
    from root_requests import RootInput

import core
import repository_transport as _transport
from core import (RepositoryWriterReporter, ArtifactVerification, BuildOptions, Cancelled, RepoSpec, RepoTrust, Reporter, _urlopen, fetch_bytes, hash_file,
                  load_baseline, meta_dict_list, redact_text,
                  redact_url,
                  repo_relative_url, open_staging, commit_staging, abandon_staging,
                  write_bundle_index, trust_summary, _record_digest_checked,
                  SEAL_PHASE_START,
                  meta_str_list, sha256_file,
                  split_against_baseline, url_join, verify_openpgp,
                  apply_mirror_evidence, mirrors_are_distinct, evidence_relationship, evidence_authority_relationship, verify_package_artifact,
                  evidence_repo_for_url, _artifact_verification, payload_filenames, select_digest_from_map,
                  write_unified_mirror_records as core_write_unified_mirror_records,
                  package_has_selected_digest, repository_verification_strategy,
                  decompress_metadata)

import provenance

from core import FEATHERED_VERSION

USER_AGENT = f"Feathered-Airgap-Sideloader/{FEATHERED_VERSION}"  # one release identity.


@dataclass(frozen=True)
class DebAtom:
    name: str
    op: Optional[str] = None
    version: Optional[str] = None
    qualifier: str = ""


@dataclass(frozen=True)
class DebRequirement:
    alternatives: Tuple[DebAtom, ...]
    kind: str = "depends"
    raw: str = ""

    @property
    def name(self) -> str:
        return self.raw or " | ".join(format_atom(a) for a in self.alternatives)


@dataclass
class DebPackage:
    name: str
    arch: str
    version: str
    location: str
    checksum_type: str
    checksum: str
    repo: RepoSpec
    # retain every strong package digest
    # published in the Packages stanza so the operator can select SHA strength.
    digests: Dict[str, str] = field(default_factory=dict)
    provides: List[DebAtom] = field(default_factory=list)
    depends: List[DebRequirement] = field(default_factory=list)
    pre_depends: List[DebRequirement] = field(default_factory=list)
    recommends: List[DebRequirement] = field(default_factory=list)
    conflicts: List[DebRequirement] = field(default_factory=list)
    breaks: List[DebRequirement] = field(default_factory=list)
    size: int = 0
    multi_arch: str = ""
    # The upstream Packages stanza fields verbatim, so a republished repository
    # carries exactly what the archive published rather than a lossy subset.
    raw_fields: Dict[str, str] = field(default_factory=dict)
    # What was actually verified about this artifact, carried to provenance.
    verification: Optional[ArtifactVerification] = None

    @property
    def nevra(self) -> str:
        # Kept as a compatibility property for the shared GUI. For DEB targets
        # this is a package identity, not an RPM NEVRA.
        return f"{self.name}_{self.version}_{self.arch}"

    @property
    def evr_text(self) -> str:
        return self.version

    @property
    def evr(self) -> Tuple[str, str, str]:
        # Only for compatibility with old callers; Debian sorting uses
        # compare_deb_versions() instead of RPM EVR comparison.
        return ("0", self.version, "")


@dataclass
class AptTargetInventory:
    packages: Dict[Tuple[str, str], str] = field(default_factory=dict)
    provides: Dict[str, List[Tuple[str, str, Optional[str]]]] = field(default_factory=lambda: defaultdict(list))
    metadata: Dict[str, str] = field(default_factory=dict)
    multi_arch: Dict[Tuple[str, str], str] = field(default_factory=dict)

    relationships_complete: bool = field(default=False, compare=False, repr=False)
    retained_packages: List[DebPackage] = field(default_factory=list, compare=False, repr=False)


@dataclass
class DebResolutionResult:
    selected: List[DebPackage]
    unresolved: List[DebRequirement]
    roots: List[DebPackage]
    skipped_installed: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    reasons: Dict[str, str] = field(default_factory=dict)
    installed_satisfied: List[str] = field(default_factory=list)
    unresolved_notes: Dict[str, str] = field(default_factory=dict)
    # operator waivers are retained as
    # provenance, not deleted from the resolver result.  The UI may permit a
    # build when every remaining unresolved requirement is explicitly waived.
    ignored_unresolved: List[str] = field(default_factory=list)
    # Requirements where more than one alternative could have been taken, used
    # to retry a different branch when the chosen one fails to resolve.
    alternative_choices: List[Tuple[str, str, List[str]]] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return sum(p.size for p in self.selected)


def _declared_family(text: str) -> str:
    """Read META|package_family from an inventory file, if present."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if parts[0] == "META" and len(parts) >= 3 and parts[1] == "package_family":
            return parts[2].strip().lower()
    return ""


def _make_executable(path: Path) -> None:
    """Best-effort +x. ZIP transfer may drop the bit, so scripts also document
    `bash install-offline.sh` as a fallback."""
    try:
        mode = path.stat().st_mode
        path.chmod(mode | 0o111)
    except OSError:
        pass


def _order_char(ch: str) -> int:
    if ch == "~":
        return -1
    if ch == "":
        return 0
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _compare_part(a: str, b: str) -> int:
    ia = ib = 0
    while ia < len(a) or ib < len(b):
        # Compare non-digit runs using dpkg ordering.
        while (ia < len(a) and not a[ia].isdigit()) or (ib < len(b) and not b[ib].isdigit()):
            ca = a[ia] if ia < len(a) and not a[ia].isdigit() else ""
            cb = b[ib] if ib < len(b) and not b[ib].isdigit() else ""
            oa, ob = _order_char(ca), _order_char(cb)
            if oa != ob:
                return -1 if oa < ob else 1
            if ca:
                ia += 1
            if cb:
                ib += 1
        # Compare digit runs numerically without integer conversion.
        za = ia
        while za < len(a) and a[za] == "0":
            za += 1
        zb = ib
        while zb < len(b) and b[zb] == "0":
            zb += 1
        ea = za
        while ea < len(a) and a[ea].isdigit():
            ea += 1
        eb = zb
        while eb < len(b) and b[eb].isdigit():
            eb += 1
        lena, lenb = ea - za, eb - zb
        if lena != lenb:
            return -1 if lena < lenb else 1
        if lena:
            sa, sb = a[za:ea], b[zb:eb]
            if sa != sb:
                return -1 if sa < sb else 1
        # Advance over the complete original digit runs, including zeroes.
        while ia < len(a) and a[ia].isdigit():
            ia += 1
        while ib < len(b) and b[ib].isdigit():
            ib += 1
    return 0


def _split_deb_version(v: str) -> Tuple[int, str, str]:
    epoch = 0
    rest = v or ""
    if ":" in rest:
        ep, maybe = rest.split(":", 1)
        if ep.isdigit():
            epoch, rest = int(ep), maybe
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, "0"
    return epoch, upstream, revision


def compare_deb_versions(a: str, b: str) -> int:
    ea, ua, ra = _split_deb_version(a)
    eb, ub, rb = _split_deb_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _compare_part(ua, ub)
    return c if c else _compare_part(ra, rb)


def format_atom(atom: DebAtom) -> str:
    name = atom.name + (":" + atom.qualifier if atom.qualifier else "")
    if atom.op and atom.version:
        return f"{name} ({atom.op} {atom.version})"
    return name


def format_requirement(req: DebRequirement) -> str:
    return req.raw or " | ".join(format_atom(a) for a in req.alternatives)


def _split_top(text: str, separator: str) -> List[str]:
    out: List[str] = []
    start = 0
    par = br = 0
    for i, ch in enumerate(text):
        if ch == "(": par += 1
        elif ch == ")" and par: par -= 1
        elif ch == "[": br += 1
        elif ch == "]" and br: br -= 1
        elif ch == separator and par == 0 and br == 0:
            out.append(text[start:i].strip()); start = i + 1
    out.append(text[start:].strip())
    return [x for x in out if x]


def _normalize_dep_name(name: str) -> str:
    name = name.strip()
    # APT multiarch qualifiers do not change the virtual/package capability
    # name for our single-target-architecture resolver.
    if name.endswith(":any") or name.endswith(":native"):
        name = name.rsplit(":", 1)[0]
    return name


def _parse_atom(text: str) -> Optional[DebAtom]:
    # Architecture/profile restrictions are relevant to source control files;
    # strip them conservatively when encountered in binary Packages metadata.
    text = re.sub(r"\s*\[[^\]]*\]", "", text)
    text = re.sub(r"\s*<[^>]*>", "", text).strip()
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9+.-]*(?::(?:any|native))?)\s*(?:\((<<|<=|=|>=|>>)\s*([^\)]+)\))?$", text)
    if not m:
        return None
    name = m.group(1)
    qualifier = name.rsplit(":", 1)[1] if ":" in name else ""
    return DebAtom(_normalize_dep_name(name), m.group(2), (m.group(3) or "").strip() or None, qualifier)


def parse_dependency_field(text: str, kind: str) -> List[DebRequirement]:
    result: List[DebRequirement] = []
    for group in _split_top(text or "", ","):
        atoms: List[DebAtom] = []
        valid = True
        for alt in _split_top(group, "|"):
            atom = _parse_atom(alt)
            if atom is None:
                valid = False
                break
            atoms.append(atom)
        if valid and atoms:
            result.append(DebRequirement(tuple(atoms), kind, group.strip()))
        elif group.strip():
            # Fail closed: retain an impossible synthetic requirement so the
            # UI reports unsupported dependency syntax rather than dropping it.
            result.append(DebRequirement(tuple(), kind, group.strip()))
    return result


def parse_provides(text: str) -> List[DebAtom]:
    out: List[DebAtom] = []
    for item in _split_top(text or "", ","):
        atom = _parse_atom(item)
        if atom:
            out.append(atom)
    return out


MAX_DEB822_LINE_CHARS = 8 * 1024 * 1024
MAX_DEB822_FIELD_CHARS = 64 * 1024 * 1024


def _parse_deb822(text: str, max_line_chars: int = MAX_DEB822_LINE_CHARS,
                  max_field_chars: int = MAX_DEB822_FIELD_CHARS) -> List[Dict[str, str]]:
    """Parse Deb822 records without duplicating the entire input into a line list.

    Packages/Release files are repository
    input. Iterating StringIO avoids splitlines()'s second full-size allocation,
    and explicit line/field ceilings stop a single pathological record from
    dominating memory even inside the overall metadata-size limit.
    """
    records: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    last = None
    for raw in io.StringIO(text):
        raw = raw.rstrip("\r\n")
        if len(raw) > max_line_chars:
            raise RuntimeError(
                f"Deb822 metadata contains a line longer than Feathered's {max_line_chars:,}-character limit")
        if not raw.strip():
            if current:
                records.append(current); current = {}; last = None
            continue
        if raw[:1].isspace() and last:
            combined = current[last] + "\n" + raw[1:]
            if len(combined) > max_field_chars:
                raise RuntimeError(
                    f"Deb822 field {last!r} exceeds Feathered's {max_field_chars:,}-character limit")
            current[last] = combined
            continue
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        value = value.lstrip()
        if len(value) > max_field_chars:
            raise RuntimeError(
                f"Deb822 field {key!r} exceeds Feathered's {max_field_chars:,}-character limit")
        current[key] = value; last = key
    if current:
        records.append(current)
    return records


def _release_payload(raw: bytes) -> str:
    """Return the signed body of an InRelease file (or a plain Release file).

    Note this only strips the OpenPGP armour; it does not verify anything.
    Signature checking is done separately by verify_release_signature().
    """
    text = raw.decode("utf-8", "replace")
    if "-----BEGIN PGP SIGNED MESSAGE-----" not in text:
        return text
    payload: List[str] = []
    in_body = False
    for line in text.splitlines():
        # Armour headers are separated from the body by a blank line, which on
        # a CRLF-encoded mirror arrives as "\r" rather than "".
        if not in_body:
            if line.strip() == "":
                in_body = True
            continue
        if line.startswith("-----BEGIN PGP SIGNATURE-----"):
            break
        if line.startswith("- "):
            line = line[2:]
        payload.append(line)
    return "\n".join(payload)


def _is_clearsigned(raw: bytes) -> bool:
    """True for an inline-signed (clearsigned) document such as InRelease."""
    return (b"-----BEGIN PGP SIGNED MESSAGE-----" in raw
            and b"-----BEGIN PGP SIGNATURE-----" in raw)


def _release_checksums(fields: Dict[str, str]) -> Dict[str, Tuple[str, str, int]]:
    """Return the strongest supported Release digest for each metadata path."""
    out: Dict[str, Tuple[str, str, int]] = {}
    for field_name, algorithm in (("SHA512", "sha512"), ("SHA384", "sha384"), ("SHA256", "sha256")):
        for line in fields.get(field_name, "").splitlines():
            parts = line.split()
            if len(parts) < 3 or parts[2] in out:
                continue
            try:
                size = int(parts[1])
            except ValueError:
                continue
            digest = parts[0].lower()
            try:
                expected_len = hashlib.new(algorithm).digest_size * 2
            except ValueError:
                continue
            if len(digest) != expected_len or re.fullmatch(r"[0-9a-f]+", digest) is None:
                continue
            out[parts[2]] = (algorithm, digest, size)
    return out


def _decompress(data: bytes, path: str) -> bytes:
    # Use the shared bounded metadata decompressor.
    return decompress_metadata(data, path)


def target_arch(arches) -> str:
    """Resolve the single binary architecture an APT index should be read for.

    Callers pass the shared RPM-style arch set (e.g. {"amd64", "noarch"}).
    Iterating a set returns members in hash order, so pick deterministically
    rather than depending on whichever element happened to come out first.
    """
    if isinstance(arches, str):
        return arches
    real = sorted(a for a in arches if a not in {"all", "noarch", "any"})
    if not real:
        return "amd64"
    if len(real) > 1:
        # Not fatal, but the caller has a bug worth surfacing rather than
        # silently building for whichever architecture sorted first.
        raise RuntimeError(
            "APT repositories are read for exactly one binary architecture, but several were "
            f"requested: {', '.join(real)}"
        )
    return real[0]


# Retained under the old private name for any external caller.
_target_arch = target_arch


def _parse_release_date(value: str) -> Optional[datetime]:
    """Parse an RFC 2822/1123 date as published in Release metadata."""
    text = (value or "").strip()
    if not text:
        return None
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def check_release_freshness(repo: RepoSpec, fields: Dict[str, str], reporter: Reporter,
                            now: Optional[datetime] = None) -> None:
    """Reject expired Release metadata and enforce an optional maximum age."""
    now = now or datetime.now(timezone.utc)
    valid_until = _parse_release_date(fields.get("Valid-Until", ""))
    release_date = _parse_release_date(fields.get("Date", ""))

    if valid_until is not None:
        if now > valid_until:
            age = now - valid_until
            raise RuntimeError(
                f"{repo.name}: Release metadata expired {age.days} day(s) ago (Valid-Until: "
                f"{valid_until:%Y-%m-%d %H:%M %Z}). The mirror is stale or is replaying old metadata; "
                "refresh the mirror rather than building from it."
            )
        reporter.log(f"{repo.name}: Release valid until {valid_until:%Y-%m-%d %H:%M %Z}")
        return

    max_age_days = int(getattr(repo, "max_release_age_days", 0) or 0)

    if max_age_days <= 0:
        reporter.warn(
            f"{repo.name}: Release metadata declares no Valid-Until, so the publisher states no "
            "lifetime and replay of an old index cannot be detected from the metadata alone. "
            "Set this repository's maximum Release age to make that a hard failure."
        )
        return

    if release_date is None:
        raise RuntimeError(
            f"{repo.name}: Release declares neither a usable Valid-Until nor a usable Date, so its "
            f"freshness cannot be established at all while a {max_age_days}-day maximum age is "
            "configured. Refresh the mirror, or clear the maximum age to accept undated metadata."
        )

    # A Date in the future is not a staleness problem but it does mean the
    # signed metadata disagrees with this builder's clock, so an age computed
    # from it proves nothing. Allow a small skew before treating it as a fault.
    if release_date - now > timedelta(minutes=10):
        raise RuntimeError(
            f"{repo.name}: Release Date is in the future ({release_date:%Y-%m-%d %H:%M %Z}). "
            "The mirror's signed metadata and this builder's clock disagree; correct one of them "
            "rather than building from metadata whose age cannot be computed."
        )

    age = now - release_date
    if age > timedelta(days=max_age_days):
        raise RuntimeError(
            f"{repo.name}: Release declares no Valid-Until and its signed Date is {age.days} day(s) "
            f"old, exceeding the configured {max_age_days}-day maximum "
            f"(Date: {release_date:%Y-%m-%d %H:%M %Z})."
        )

    reporter.log(
        f"{repo.name}: Release declares no Valid-Until; signed Date age {max(age.days, 0)} day(s) "
        f"is within the configured {max_age_days}-day maximum.")


def check_release_suite(repo: RepoSpec, fields: Dict[str, str], reporter: Reporter) -> None:
    """Confirm the Release we fetched is the suite we actually asked for."""
    if repo.flat_repo:
        return
    requested = repo.suite.strip()
    declared = {(fields.get("Codename") or "").strip(), (fields.get("Suite") or "").strip()}
    declared.discard("")
    if not declared:
        reporter.warn(f"{repo.name}: Release metadata declares neither Suite nor Codename.")
        return
    # pockets are distinct trust targets.
    # `noble-updates` must not be accepted merely because the returned metadata
    # says Codename: noble; otherwise a redirect can silently substitute base,
    # security, updates or backports. Base-suite requests may still match their
    # exact codename.
    if "-" in requested:
        valid = requested in declared
    else:
        valid = requested in declared or any(value.split("-", 1)[0] == requested for value in declared)
    if not valid:
        raise RuntimeError(
            f"{repo.name}: requested suite '{requested}' but the archive returned metadata for "
            f"{'/'.join(sorted(declared))}. Check the archive root and suite; a redirecting or "
            "misconfigured mirror can serve the wrong release/pocket."
        )



def check_release_target_identity(repo: RepoSpec, fields: Dict[str, str], reporter: Reporter) -> None:
    """Bind a discovered APT suite back to the operator's numeric target.

    Suite/Codename checks prove that the archive returned the suite Feathered
    requested.  They do not prove a runtime-discovered mapping such as
    ``26.04 -> noble`` was correct.  Profiles that have an independent numeric
    identity therefore set ``expected_release_version`` on their base repository;
    after signature verification, require the signed Release ``Version`` field to
    identify the same release series.
    """
    expected = (getattr(repo, "expected_release_version", "") or "").strip()
    if not expected:
        return
    declared_raw = (fields.get("Version") or "").strip()
    match = re.search(r"(?<!\d)(\d+(?:\.\d+)+)(?!\d)", declared_raw)
    if not match:
        raise RuntimeError(
            f"{repo.name}: expected signed release identity {expected!r}, but Release metadata "
            "declares no usable Version field. Refusing to trust a runtime-discovered suite mapping."
        )
    declared = match.group(1)
    if declared != expected:
        raise RuntimeError(
            f"{repo.name}: target release identity is {expected!r}, but authenticated Release metadata "
            f"identifies {declared!r}. The discovered version/codename mapping may be stale or wrong; "
            "refresh release discovery rather than cross-grading to another valid suite."
        )
    reporter.log(f"{repo.name}: authenticated release identity {declared}")

def _repo_trust(repo: RepoSpec) -> RepoTrust:
    """The verification record for a repository, created on first use."""
    record = getattr(repo, "trust", None)
    if record is None or record.repo != repo.name:
        record = RepoTrust(repo=repo.name)
        setattr(repo, "trust", record)
    return record


def verify_release_signature(repo: RepoSpec, leaf: str, raw: bytes, reporter: Reporter) -> None:
    """Verify InRelease/Release signatures when a keyring is configured."""
    trust = _repo_trust(repo)
    if repository_verification_strategy(repo) == "skip-provenance":
        # explicit upstream-provenance opt-out.
        reporter.warn(f"{repo.name}: APT Release signature/keyring verification intentionally skipped by policy.")
        trust.notes.append("Upstream provenance checks intentionally skipped by operator policy.")
        return
    if not repo.keyring:
        reporter.warn(f"{repo.name}: APT Release metadata is NOT signature-verified "
                      "(no keyring configured). Index and .deb digests chain from unauthenticated metadata.")
        return
    if _is_clearsigned(raw):
        # An InRelease file is signed inline; hand the whole document to the
        # verifier rather than treating it as a detached signature.
        verify_openpgp(raw, None, repo.keyring, f"{repo.name} InRelease", reporter)
        # Only set once the check has actually run and passed.
        trust.archive_signature_verified = True
        return
    # A detached Release.gpg alongside a plain Release file.
    try:
        signature = fetch_bytes(url_join(repo.normalized_url, leaf + ".gpg", repo), reporter, retries=1, repo=repo)
    except Exception as exc:
        raise RuntimeError(f"{repo.name}: a keyring is configured but no signature was found "
                           f"(neither a clearsigned InRelease nor {leaf}.gpg): {exc}") from exc
    verify_openpgp(raw, signature, repo.keyring, f"{repo.name} Release", reporter)
    trust.archive_signature_verified = True


def _published_apt_suites(repo: RepoSpec, reporter: Reporter) -> List[str]:
    """Return suite directories advertised below an APT repository's dists/ root."""
    if repo.flat_repo:
        return []
    dists_url = url_join(repo.normalized_url, "dists/", repo)
    try:
        raw = fetch_bytes(dists_url, reporter, retries=1, repo=repo).decode("utf-8", "replace")
    except Exception:
        return []
    suites: List[str] = []
    for href in re.findall(r'href=[\'"]([^\'"]+)[\'"]', raw, re.IGNORECASE):
        parsed = urllib.parse.urlsplit(href)
        path = urllib.parse.unquote(parsed.path).strip()
        if not path.endswith("/"):
            continue
        leaf = path.rstrip("/").rsplit("/", 1)[-1]
        if not leaf or leaf in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", leaf):
            continue
        if leaf not in suites:
            suites.append(leaf)
    return sorted(suites)


def _missing_apt_suite_message(repo: RepoSpec, reporter: Reporter, errors: Sequence[str]) -> Optional[str]:
    """Explain a missing APT suite when the repository advertises other suites."""
    suite = repo.suite.strip()
    if repo.flat_repo or not suite or not any("404" in e or "Not Found" in e for e in errors):
        return None
    suites = _published_apt_suites(repo, reporter)
    if not suites or suite in suites:
        return None
    checked = redact_url(url_join(repo.normalized_url, "dists/", repo))
    message = (
        f"{repo.name}: APT suite '{suite}' is not published by this repository. "
        f"Checked {checked}. Published suites: {', '.join(suites)}."
    )
    host = (urllib.parse.urlsplit(repo.normalized_url).hostname or "").lower()
    path = urllib.parse.urlsplit(repo.normalized_url).path.rstrip("/").lower()
    if host == "download.docker.com" and path.endswith("/linux/ubuntu"):
        message += (
            f" Docker CE does not currently publish an Ubuntu '{suite}' repository. "
            "Feathered will not substitute packages from a different Ubuntu release."
        )
    return message


def _fetch_release(repo: RepoSpec, reporter: Reporter) -> Tuple[Dict[str, str], Dict[str, Tuple[str, str, int]]]:
    suite = repo.suite.strip()
    if not suite and not repo.flat_repo:
        raise RuntimeError(f"{repo.name}: APT suite/codename is not configured")
    base = repo.normalized_url
    errors = []
    prefix = "" if repo.flat_repo else f"dists/{suite}/"
    for leaf in (prefix + "InRelease", prefix + "Release"):
        try:
            # InRelease is optional. If it is unavailable, try Release/Release.gpg promptly.
            probe_retries = 1 if leaf.endswith("InRelease") else 3
            raw = fetch_bytes(url_join(base, leaf, repo), reporter, retries=probe_retries, repo=repo)
        except Exception as exc:
            errors.append(f"{leaf}: {exc}")
            if leaf.endswith("InRelease"):
                missing_suite = _missing_apt_suite_message(repo, reporter, errors)
                if missing_suite:
                    raise RuntimeError(missing_suite)
            continue
        # Once the file is in hand, a parse/verify failure is fatal rather than
        # a reason to silently fall back to the unsigned sibling.
        recs = _parse_deb822(_release_payload(raw))
        if not recs:
            raise RuntimeError(f"{repo.name}: {leaf} contained no Release metadata")
        fields = recs[0]
        verify_release_signature(repo, leaf, raw, reporter)
        check_release_suite(repo, fields, reporter)
        check_release_target_identity(repo, fields, reporter)
        if repository_verification_strategy(repo) != "skip-provenance":
            check_release_freshness(repo, fields, reporter)
        else:
            reporter.warn(f"{repo.name}: Release freshness/Valid-Until enforcement skipped by operator policy.")
        return fields, _release_checksums(fields)
    missing_suite = _missing_apt_suite_message(repo, reporter, errors)
    if missing_suite:
        raise RuntimeError(missing_suite)
    raise RuntimeError(f"{repo.name}: could not read APT {'flat root' if repo.flat_repo else 'suite'} Release/InRelease metadata: {'; '.join(errors)}")


def _component_bindings(configured: List[str], advertised: Set[str], repo_name: str,
                        reporter: Reporter) -> List[Tuple[str, str]]:
    """Bind configured components to the labels published by Release metadata."""
    if not advertised:
        return [(component, component) for component in configured]

    bindings: List[Tuple[str, str]] = []
    unavailable: List[str] = []
    for component in configured:
        if component in advertised:
            bindings.append((component, component))
            continue
        suffix_matches = sorted(a for a in advertised if a.endswith("/" + component))
        if len(suffix_matches) == 1:
            semantic = suffix_matches[0]
            reporter.log(
                f"{repo_name}: archive advertises component '{component}' as '{semantic}'; "
                "retaining the configured component for index-path discovery")
            bindings.append((component, semantic))
        elif len(suffix_matches) > 1:
            raise RuntimeError(
                f"{repo_name}: configured APT component '{component}' is ambiguous; archive publishes "
                f"multiple suffix matches ({' '.join(suffix_matches)}). Configure the exact component name.")
        else:
            unavailable.append(component)

    if unavailable:
        reporter.warn(
            f"{repo_name}: configured APT component(s) not published by this archive and therefore "
            f"excluded: {' '.join(unavailable)}")
    if not bindings:
        raise RuntimeError(
            f"{repo_name}: none of the configured APT components ({' '.join(configured)}) are published "
            f"by this archive ({' '.join(sorted(advertised))}); refusing to widen the configured source scope.")
    return bindings


def _component_index_candidates(component: str, semantic: str, arch: str) -> List[str]:
    """Return bounded Packages index candidates for one configured component."""
    prefixes: List[str] = []
    for value in (component, semantic):
        value = (value or "").strip("/")
        if value and value not in prefixes:
            prefixes.append(value)

    # Legacy Debian security sources may store labels such as ``updates/main``
    # even though the signed index path is rooted at ``main/``.
    for value in (component, semantic):
        value = (value or "").strip("/")
        if "/" in value:
            leaf = value.rsplit("/", 1)[-1]
            if leaf and leaf not in prefixes:
                prefixes.append(leaf)

    out: List[str] = []
    for prefix in prefixes:
        base = f"{prefix}/binary-{arch}/Packages"
        out.extend(base + ext for ext in (".xz", ".gz", ".zst", ".bz2", ""))
    return out


def _index_url(repo: RepoSpec, path: str) -> str:
    return url_join(repo.normalized_url, path if repo.flat_repo else f"dists/{repo.suite}/{path}", repo)


def _fetch_index_bytes(repo: RepoSpec, fields: Dict[str, str], index_path: str,
                       algorithm: str, expected: str, reporter: Reporter) -> bytes:
    """Prefer the Release-pinned index during archive publication/mirror sync.

    A missing by-hash object may fall back to the canonical filename; callers
    still enforce the exact Release size and digest for either representation.
    """
    try:
        expected_len = hashlib.new(algorithm).digest_size * 2
    except ValueError:
        expected_len = 0
    if (fields.get("Acquire-By-Hash", "").strip().lower() == "yes"
            and len(expected) == expected_len
            and re.fullmatch(r"[0-9a-fA-F]+", expected)):
        leaf = posixpath.join(posixpath.dirname(index_path), "by-hash", algorithm.upper(), expected.lower())
        try:
            return fetch_bytes(_index_url(repo, leaf),
                               reporter, retries=1, repo=repo)
        except Cancelled:
            raise
        except Exception as exc:
            reporter.check_cancel()
            reporter.log(redact_text(f"{repo.name}: pinned index unavailable; trying canonical index ({exc})"))
    return fetch_bytes(_index_url(repo, index_path), reporter, repo=repo)


def empty_repository_explanation(repo: RepoSpec) -> str:
    """Explain a successfully parsed APT repository that contains no packages."""
    suite = str(getattr(repo, "suite", "") or "").strip().lower()
    name = str(getattr(repo, "name", "") or "").strip().lower()
    if name.startswith("ubuntu ") and suite.endswith("-updates"):
        return (
            "the Packages indexes are valid but empty because Ubuntu has not published "
            "any packages to this -updates pocket for the selected target yet. This is a "
            "normal repository state, including during a development cycle before update "
            "publications begin."
        )
    if name.startswith("ubuntu ") and suite.endswith("-security"):
        return (
            "the Packages indexes are valid but empty because Ubuntu has not published "
            "any packages to this -security pocket for the selected target yet. This is a "
            "normal repository state, including before security publications begin for that "
            "target."
        )
    return (
        "the Packages indexes were read successfully, but the selected suite, components, "
        "and architecture currently publish no package records."
    )


def _load_repository_once(repo: RepoSpec, arches: Set[str], reporter: Reporter) -> List[DebPackage]:
    fields, checksums = _fetch_release(repo, reporter)
    arch = target_arch(arches)
    configured_components = [x for x in (repo.components or "main").split() if x]
    advertised = set(fields.get("Components", "").split())
    bindings = [("", "")] if repo.flat_repo else _component_bindings(configured_components, advertised, repo.name, reporter)

    published_arches = set((fields.get("Architectures") or "").split())
    if published_arches and arch not in published_arches:
        raise RuntimeError(
            f"{repo.name}: suite '{repo.suite}' does not publish architecture '{arch}'. "
            f"Published architectures: {' '.join(sorted(published_arches))}.")

    if repo.flat_repo and not published_arches:
        reporter.warn(f"{repo.name}: flat Release has no Architectures field; target architecture is not confirmed by Release. Package records are still checked.")
    packages: List[DebPackage] = []
    loaded_indices = 0
    unverified_indexes: List[str] = []
    skipped_components: List[str] = []
    # Called for its side effect: _repo_trust lazily attaches the verification
    # record to the repository, and later stages read repo.trust directly.
    _repo_trust(repo)
    skip_provenance = repository_verification_strategy(repo) == "skip-provenance"
    index_verified = False
    for component, semantic_component in bindings:
        candidates = (["Packages" + ext for ext in (".xz", ".gz", ".zst", ".bz2", "")]
                      if repo.flat_repo else _component_index_candidates(component, semantic_component, arch))
        index_path = next((path for path in candidates if path in checksums), None)
        if index_path is None:
            # The index is not listed in the Release checksum manifest, so it
            # cannot be verified at all. Fail closed unless the operator opted
            # in per repository. Empty advertised components are skipped and the
            # aggregate check below decides whether the source is usable.
            if not repo.allow_unverified_index and not skip_provenance:
                reporter.log(
                    f"{repo.name}: no signed Packages index for component '{component}' "
                    f"(advertised as '{semantic_component}') on binary-{arch}; skipping that component.")
                skipped_components.append(component)
                continue
            probe_errors = []
            raw = None
            for candidate in candidates:
                try:
                    raw = fetch_bytes(_index_url(repo, candidate),
                                      reporter, repo=repo)
                    index_path = candidate
                    break
                except Exception as exc:
                    probe_errors.append(f"{candidate}: {exc}")
            if raw is None:
                detail = "; ".join(probe_errors) or "no candidate index paths responded"
                if repo.optional:
                    reporter.log(f"APT component unavailable in optional source {repo.name}: "
                                 f"{component}/{arch} ({detail})")
                    continue
                raise RuntimeError(f"{repo.name}: no Packages index for {component}/binary-{arch}: {detail}")
            index_verified = False
            unverified_indexes.append(f"{repo.suite}/{index_path}")
            if skip_provenance:
                reporter.warn(f"{repo.name}: using index {index_path} without Release checksum verification by operator policy.")
            else:
                reporter.warn(f"{repo.name}: using UNVERIFIED index {index_path} - it is absent from the "
                              "Release checksum manifest and its contents are not authenticated.")
        else:
            index_algorithm, expected, expected_size = checksums[index_path]
            raw = _fetch_index_bytes(repo, fields, index_path, index_algorithm, expected, reporter)
            if skip_provenance:
                index_verified = False
                unverified_indexes.append(f"{repo.suite}/{index_path}")
                reporter.warn(f"{repo.name}: Packages index checksum verification skipped by operator policy ({index_path}).")
            else:
                if len(raw) != expected_size:
                    raise RuntimeError(f"{repo.name}: metadata size mismatch for {index_path} "
                                       f"(expected {expected_size} bytes, got {len(raw)})")
                actual = hashlib.new(index_algorithm, raw).hexdigest()
                if actual.lower() != expected.lower():
                    raise RuntimeError(
                        f"{repo.name}: metadata {index_algorithm.upper()} mismatch for {index_path}")
                index_verified = True
        assert index_path is not None, "index path must be resolved before decompression"
        text = _decompress(raw, index_path).decode("utf-8", "replace")
        loaded_indices += 1
        for rec in _parse_deb822(text):
            name = rec.get("Package", "").strip()
            version = rec.get("Version", "").strip()
            parch = rec.get("Architecture", "").strip()
            location = rec.get("Filename", "").strip()
            if not (name and version and parch and location):
                continue
            if parch not in {arch, "all"}:
                continue
            digests = {
                algo: value
                for algo, value in (
                    ("sha256", rec.get("SHA256", "").strip()),
                    ("sha384", rec.get("SHA384", "").strip()),
                    ("sha512", rec.get("SHA512", "").strip()),
                )
                if value
            }
            selected_digest = select_digest_from_map(digests, repo.digest_preference)
            checksum_type, checksum = selected_digest if selected_digest else ("", "")
            try:
                size = int(rec.get("Size", "0") or 0)
            except ValueError:
                size = 0
            packages.append(DebPackage(
                name=name, arch=parch, version=version, location=location,
                checksum_type=checksum_type, checksum=checksum, repo=repo, digests=digests,
                provides=parse_provides(rec.get("Provides", "")),
                depends=parse_dependency_field(rec.get("Depends", ""), "depends"),
                pre_depends=parse_dependency_field(rec.get("Pre-Depends", ""), "pre-depends"),
                recommends=parse_dependency_field(rec.get("Recommends", ""), "recommends"),
                conflicts=parse_dependency_field(rec.get("Conflicts", ""), "conflicts"),
                breaks=parse_dependency_field(rec.get("Breaks", ""), "breaks"),
                size=size, multi_arch=rec.get("Multi-Arch", "").strip(),
                raw_fields=dict(rec),
            ))
            packages[-1].verification = ArtifactVerification(
                index_digest_verified=index_verified,
                package_digest_declared=bool(packages[-1].digests),
            )
    if loaded_indices == 0:
        published = sorted(advertised)
        detail = (f"{repo.name}: no usable APT Packages indexes were found for "
                  f"suite '{repo.suite}' architecture '{arch}'.")
        if skipped_components:
            detail += (f" Configured components {', '.join(skipped_components)} have no signed "
                       f"binary-{arch} Packages index.")
        if published:
            detail += f" Archive Components: {', '.join(published)}."
        else:
            detail += " The Release file advertises no components at all."
        raise RuntimeError(detail)
    undigested = [p.name for p in packages if not p.checksum]
    if undigested:
        reporter.warn(f"{repo.name}: {len(undigested)} package record(s) publish no SHA-256/SHA-512 digest; "
                      "downloads for those packages cannot be content-verified.")
    if unverified_indexes:
        reporter.warn(f"{repo.name}: {len(unverified_indexes)} index file(s) were accepted without verification.")
    reporter.log(
        f"Loaded {len(packages):,} DEB records from {repo.name} "
        f"({repo.suite}: {' '.join(configured_components)})")
    if not packages:
        reporter.log(f"{repo.name}: {empty_repository_explanation(repo)}")
    return packages


def load_repository(repo: RepoSpec, arches: Set[str], reporter: Reporter) -> List[DebPackage]:
    """Load one APT source and any metadata-only evidence peers."""
    packages = _load_repository_once(repo, arches, reporter)
    # Query evidence peers only for strategies that use them.
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
            # Defer exact-package failure to selected-artifact verification where
            # optional/mirror-lag package records cannot fail an entire index load.
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
        # do not leak acquisition mTLS
        # credentials or its transport-specific CA configuration to a distinct
        # evidence endpoint. do not inherit
        # the acquisition archive keyring either. Source-bond evidence is an
        # independent provenance axis and must not be gated by GPG/keyring state.
        evidence_repo = evidence_repo_for_url(repo, evidence_url)
        relationship = evidence_relationship(repo, evidence_url)
        try:
            evidence_packages = _load_repository_once(evidence_repo, arches, reporter)
            stats = apply_mirror_evidence(
                packages, evidence_packages, evidence_repo, reporter, relationship=relationship,
                authority=evidence_authority_relationship(repo, evidence_url))
            reporter.log(
                f"Source bond {repo.name}: evidence mirror {redact_url(evidence_url)} matched "
                f"{stats['matched']:,} package identities ({stats['digest']:,} with strong digest, "
                f"{stats['metadata']:,} metadata-only; {stats['missing']:,} not yet present; "
                f"{stats.get('conflict', 0):,} metadata conflict(s) deferred to selected-artifact verification)")
            usable = True
            break
        except RuntimeError as exc:
            if "Mirror bond" in str(exc) and "disagreement" in str(exc):
                raise
            last_error = str(exc)
            reporter.warn(f"{repo.name}: evidence mirror {redact_url(evidence_url)} unavailable/inconclusive: {exc}")

    if not usable:
        # An evidence endpoint may be artifact-only and therefore publish no
        # APT Release/Packages metadata. The exact selected .deb is checked
        # later by independent byte hashing; absence of metadata is a warning,
        # not an immediate rejection.
        for pkg in packages:
            record = _artifact_verification(pkg)
            if record.evidence_status in {"not-configured", "unavailable"}:
                record.evidence_status = "artifact-pending"
            if not record.evidence_source and repo.evidence_urls:
                record.evidence_source = redact_url(repo.evidence_urls[0])
        if repo.evidence_urls:
            reporter.warn(
                f"{repo.name}: evidence endpoint is not a recognizable APT repository"
                + (f" ({last_error})" if last_error else "")
                + "; Feathered will try the exact package artifact during verification")
    return packages


def probe_repository(repo: RepoSpec, reporter: Reporter):
    try:
        fields, checksums = _fetch_release(repo, reporter)
        archs = fields.get("Architectures", "")
        comps = fields.get("Components", "")
        return True, f"APT suite={fields.get('Codename') or fields.get('Suite') or repo.suite}; arch={archs}; components={comps}; {len(checksums)} indexed files"
    except Exception as exc:
        return False, str(exc)


def _version_satisfies(actual: str, op: Optional[str], wanted: Optional[str]) -> bool:
    if not op or wanted is None:
        return True
    c = compare_deb_versions(actual, wanted)
    return {"<<": c < 0, "<=": c <= 0, "=": c == 0, ">=": c >= 0, ">>": c > 0}.get(op, False)


def _pkg_satisfies_atom(pkg: DebPackage, atom: DebAtom) -> bool:
    if atom.qualifier == "any" and pkg.multi_arch != "allowed":
        return False
    if pkg.name == atom.name and _version_satisfies(pkg.version, atom.op, atom.version):
        return True
    for prov in pkg.provides:
        if prov.name != atom.name:
            continue
        if not atom.op:
            return True
        # Versioned dependency can only be satisfied by a versioned Provide.
        if prov.version and _version_satisfies(prov.version, atom.op, atom.version):
            return True
    return False


def _ordered_packages(candidates: Iterable[DebPackage], preferred_arch: str) -> List[DebPackage]:
    """APT candidate order shared by root selection and provider backtracking."""
    vals = list(candidates)
    def cmp(a: DebPackage, b: DebPackage):
        if a.repo.priority != b.repo.priority:
            return -1 if a.repo.priority < b.repo.priority else 1
        aa = 0 if a.arch == preferred_arch else 1 if a.arch == "all" else 2
        ba = 0 if b.arch == preferred_arch else 1 if b.arch == "all" else 2
        if aa != ba: return -1 if aa < ba else 1
        c = compare_deb_versions(a.version, b.version)
        if c: return -c
        return -1 if a.repo.name < b.repo.name else (1 if a.repo.name > b.repo.name else 0)
    vals.sort(key=cmp_to_key(cmp))
    return vals


def _best_package(candidates: Iterable[DebPackage], preferred_arch: str) -> Optional[DebPackage]:
    vals = _ordered_packages(candidates, preferred_arch)
    return vals[0] if vals else None


def build_provider_index(packages: Sequence[DebPackage]) -> Dict[str, List[DebPackage]]:
    idx: Dict[str, List[DebPackage]] = defaultdict(list)
    for pkg in packages:
        idx[pkg.name].append(pkg)
        for p in pkg.provides:
            idx[p.name].append(pkg)
    return idx


def _find_root(request: Tuple, packages: Sequence[DebPackage], preferred_arch: str) -> Optional[DebPackage]:
    name, version, role = request[:3]
    repo_name = request[3] if len(request) >= 4 else None
    exact_arch = request[4] if len(request) >= 5 else None
    source_scope = request[5] if len(request) >= 6 else None
    repo_identity = request[6] if len(request) >= 7 else None
    vals = []
    for p in packages:
        if p.name != name: continue
        if version and p.version != version: continue
        if source_scope == "distribution" and getattr(p.repo, "source_tier", "base") != "base": continue
        if role and p.repo.role != role: continue
        if repo_identity:
            if p.repo.source_identity != repo_identity: continue
        elif repo_name and p.repo.name != repo_name:
            continue
        if exact_arch and p.arch != exact_arch: continue
        if p.arch not in {preferred_arch, "all"}: continue
        vals.append(p)
    return _best_package(vals, preferred_arch)


def _inventory_atom_satisfied(inv: AptTargetInventory, atom: DebAtom, target_arch: str) -> Optional[str]:
    for arch in (target_arch, "all"):
        actual = inv.packages.get((atom.name, arch))
        if (actual and (atom.qualifier != "any" or inv.multi_arch.get((atom.name, arch)) == "allowed")
                and _version_satisfies(actual, atom.op, atom.version)):
            return f"{atom.name}={actual}:{arch}"
    for owner, _owner_version, provided_version in inv.provides.get(atom.name, []):
        owner_name, owner_arch = owner.split("=", 1)[0], owner.rsplit(":", 1)[-1]
        if owner_arch not in {target_arch, "all"}:
            continue
        if atom.qualifier == "any" and inv.multi_arch.get((owner_name, owner_arch)) != "allowed":
            continue
        if not atom.op or (provided_version and _version_satisfies(provided_version, atom.op, atom.version)):
            return owner

    return None


def _atom_key(atom: DebAtom) -> Tuple[object, ...]:
    return (atom.name, atom.op, atom.version, atom.qualifier)


def resolve(root_requests: Sequence[RootInput], packages: Sequence[DebPackage],
            preferred_arch: str, options: BuildOptions[AptTargetInventory], reporter: Reporter) -> DebResolutionResult:
    from transaction_model import resolve_transaction
    return resolve_transaction(_resolve_once, root_requests, packages, preferred_arch,
                               options, reporter, 'deb')


def _resolve_once(root_requests: Sequence[Tuple], packages: Sequence[DebPackage], preferred_arch: str,
            options: BuildOptions[AptTargetInventory], reporter: Reporter) -> DebResolutionResult:
    """Resolve DEB roots and their dependency closure.

    Like the RPM resolver, this runs repeated passes carrying forward *version
    floors*. A greedy single pass can select libfoo 2.0 for an unversioned
    `Depends: libfoo` and only afterwards encounter `Depends: libfoo (= 1.0)`;
    the next pass carries that constraint into candidate selection so a version
    satisfying both is chosen. Constraints that no candidate can satisfy are
    reported as unresolved, which blocks the build.
    """
    constraints: Dict[str, List[DebAtom]] = defaultdict(list)
    # Providers proven unworkable for a given requirement. Choosing the first
    # satisfiable alternative is only correct if its own closure resolves; when
    # it does not, the alternative must be rejected and the next one tried.
    # Without this the resolver reports failure for a request that has a
    # perfectly good solution behind the second alternative.
    rejected: Set[Tuple[str, str]] = set()
    seen: Set[Tuple[str, Tuple[object, ...]]] = set()
    # The loop below always runs at least once, so `result` is bound before use.
    result: DebResolutionResult = DebResolutionResult([], [], [], [], [], {}, [], {})
    for attempt in range(1, max(1, options.max_resolution_passes) + 1):
        reporter.check_cancel()
        result, discovered = _resolve_pass(root_requests, packages, preferred_arch, options,
                                           reporter, constraints, rejected)
        fresh = [(name, atom) for name, atom in discovered if (name, _atom_key(atom)) not in seen]
        if not fresh:
            if not result.unresolved:
                return result
            # Something could not be resolved. If it was pulled in by a choice
            # between alternatives, reject that choice and try the next one.
            retry = _reject_failed_alternative(result, rejected, reporter)
            if not retry:
                return result
            # Version floors are derived from the selections a branch made, so
            # they belong to that branch. Carrying them past a rejection let a
            # constraint discovered under the abandoned alternative forbid the
            # version the surviving alternative needs, turning a solvable
            # request into a failure. They are re-derived on the next pass.
            constraints.clear()
            seen.clear()
            continue
        for name, atom in fresh:
            seen.add((name, _atom_key(atom)))
            constraints[name].append(atom)
            reporter.log(f"Re-resolving with version floor {format_atom(atom)} (pass {attempt + 1})")
    reporter.warn("DEB dependency resolution hit the pass limit; review conflicts.txt before installing.")
    return result


def _reject_failed_alternative(result, rejected: Set[Tuple[str, str]], reporter: Reporter) -> bool:
    """Blame a failed closure on the alternative that introduced it.

    Walks from each unresolved requirement back through the chain that pulled
    it in, looking for a package chosen from a list of alternatives that still
    has an untried option. Returns True when a choice was rejected, meaning
    another pass is worth running.
    """
    for choice in reversed(result.alternative_choices):
        requirement_key, chosen, others = choice
        if (requirement_key, chosen) in rejected:
            continue
        remaining = [o for o in others if (requirement_key, o) not in rejected]
        if not remaining:
            continue
        rejected.add((requirement_key, chosen))
        reporter.log(f"Dependency choice '{chosen}' led to an unresolvable closure; "
                     f"trying {' or '.join(remaining)} instead")
        return True
    return False


def _resolve_pass(root_requests: Sequence[Tuple], packages: Sequence[DebPackage], preferred_arch: str,
                  options: BuildOptions[AptTargetInventory], reporter: Reporter,
                  constraints: Dict[str, List[DebAtom]],
                  rejected: Optional[Set[Tuple[str, str]]] = None
                  ) -> Tuple[DebResolutionResult, List[Tuple[str, DebAtom]]]:
    index = build_provider_index(packages)
    discovered: List[Tuple[str, DebAtom]] = []
    rejected = rejected if rejected is not None else set()
    alternative_choices: List[Tuple[str, str, List[str]]] = []

    def honours_constraints(pkg: DebPackage) -> bool:
        return all(_pkg_satisfies_atom(pkg, c) for c in constraints.get(pkg.name, ()))
    roots: List[DebPackage] = []
    # Declared ahead of the root loop, which now records misses instead of raising.
    unresolved: List[DebRequirement] = []
    unresolved_notes: Dict[str, str] = {}
    skipped: List[str] = []
    for request in root_requests:
        root = _find_root(request, packages, preferred_arch)
        if root is not None and not honours_constraints(root):
            better = _find_root(request, [p for p in packages if honours_constraints(p)], preferred_arch)
            root = better or root
        if not root:
            # Record every missing root rather than aborting on the first, so a
            # preset spanning several repositories reports all its gaps at once.
            name = request[0]
            version = request[1] if len(request) > 1 else None
            label = name + (f"={version}" if version else "")
            if name in options.optional_roots:
                skipped.append(f"{name} (optional; not offered by the configured sources)")
                reporter.log(f"Skipping optional package '{name}': not present in any enabled source")
                continue
            requirement = parse_dependency_field(name, "root")[0]
            unresolved.append(requirement)
            unresolved_notes[format_requirement(requirement)] = (
                f"No package named '{label}' exists in any enabled source. Enable a repository "
                "that carries it (universe on Ubuntu, or an additional component), or remove it "
                "from the selection.")
            reporter.log(f"UNRESOLVED root: no package named '{label}'")
            continue
        roots.append(root)

    selected_by_name: Dict[str, DebPackage] = {}
    reasons: Dict[str, str] = {}
    conflicts: List[str] = []
    installed_satisfied: List[str] = []
    q: deque = deque()
    for root in roots:
        selected_by_name[root.name] = root
        reasons[root.nevra] = "requested package"
        q.append(root)

    inv = options.target_inventory if isinstance(options.target_inventory, AptTargetInventory) else None

    while q:
        reporter.check_cancel()
        pkg = q.popleft()
        reqs = []
        if options.include_dependencies:
            reqs.extend(pkg.pre_depends)
            reqs.extend(pkg.depends)
            if options.include_recommends:
                reqs.extend(pkg.recommends)
        for req in reqs:
            if not req.alternatives:
                if req not in unresolved:
                    unresolved.append(req)
                    unresolved_notes[format_requirement(req)] = "Unsupported/ambiguous Debian dependency expression"
                continue
            # Already-selected package satisfies any alternative.
            if any(_pkg_satisfies_atom(s, atom) for s in selected_by_name.values() for atom in req.alternatives):
                continue
            if inv:
                sat = next((_inventory_atom_satisfied(inv, atom, preferred_arch) for atom in req.alternatives if _inventory_atom_satisfied(inv, atom, preferred_arch)), None)
                if sat:
                    installed_satisfied.append(f"{format_requirement(req)} <- {sat}")
                    continue
            provider = None
            # branch not only across `a | b`, but also
            # across multiple packages that provide the *same* virtual atom.
            # The old code collapsed each atom to one _best_package(), so a bad
            # virtual provider prevented a perfectly valid second provider from
            # ever being tried.
            requirement_key = format_requirement(req)
            viable = []
            seen_choices = set()
            for atom in req.alternatives:
                candidate_set = [cand for cand in index.get(atom.name, [])
                                 if cand.arch in {preferred_arch, "all"}
                                 and _pkg_satisfies_atom(cand, atom)
                                 and honours_constraints(cand)]
                for candidate in _ordered_packages(candidate_set, preferred_arch):
                    choice_key = f"{atom.name} -> {candidate.nevra}"
                    if choice_key in seen_choices:
                        continue
                    seen_choices.add(choice_key)
                    viable.append((atom, candidate, choice_key))
            allowed = [(a, c, key) for a, c, key in viable
                       if (requirement_key, key) not in rejected]
            if allowed:
                atom, provider, chosen_key = allowed[0]
                if len(viable) > 1:
                    alternative_choices.append(
                        (requirement_key, chosen_key,
                         [key for _a, _c, key in viable if key != chosen_key]))
            elif viable:
                atom, provider, _chosen_key = viable[0]
            else:
                provider = None
            if provider is None:
                if req not in unresolved:
                    unresolved.append(req)
                    names = sorted({a.name for a in req.alternatives})
                    if any(index.get(n) for n in names):
                        unresolved_notes[format_requirement(req)] = "Providers exist in enabled APT repositories, but none satisfy the requested version/architecture"
                    else:
                        unresolved_notes[format_requirement(req)] = "No matching provider in enabled APT repositories"
                continue
            existing = selected_by_name.get(provider.name)
            if existing is not None:
                if existing.version != provider.version or existing.arch != provider.arch:
                    # The already-selected build of this package does not
                    # satisfy the requirement we are currently processing.
                    # Carry the constraint into the next pass; if nothing can
                    # satisfy every accumulated constraint, record it as
                    # UNRESOLVED so the build gate blocks. Reporting this only
                    # as an advisory "conflict" allowed a bundle that the
                    # target package manager will reject to be labelled
                    # COMPLETE and shipped across the air gap.
                    for atom in req.alternatives:
                        if atom.name == provider.name:
                            discovered.append((provider.name, atom))
                    if req not in unresolved:
                        unresolved.append(req)
                        unresolved_notes[format_requirement(req)] = (
                            f"Selected {existing.nevra} does not satisfy this requirement, and no single "
                            f"version satisfies every dependant (also wanted: {provider.nevra})")
                    conflicts.append(
                        f"dependency would require {provider.nevra}, but {existing.nevra} is already selected")
                continue
            if inv and inv.packages.get((provider.name, provider.arch)) == provider.version:
                skipped.append(provider.nevra)
                installed_satisfied.append(f"{format_requirement(req)} <- installed {provider.nevra}")
                continue
            selected_by_name[provider.name] = provider
            reasons[provider.nevra] = f"required by {pkg.name}: {format_requirement(req)}"
            q.append(provider)

    # Surface direct package Conflicts/Breaks among the selected set.
    chosen = list(selected_by_name.values())
    for pkg in chosen:
        for req in pkg.conflicts + pkg.breaks:
            for other in chosen:
                if other is pkg: continue
                if any(_pkg_satisfies_atom(other, atom) for atom in req.alternatives):
                    conflicts.append(f"{pkg.nevra} declares {req.kind}: {format_requirement(req)}; selected {other.nevra}")

    # Stable display: roots first, then dependency reason/name.
    root_ids = {r.nevra for r in roots}
    selected = sorted(chosen, key=lambda p: (0 if p.nevra in root_ids else 1, p.name, p.arch, p.version))
    outcome = DebResolutionResult(selected, unresolved, roots, sorted(set(skipped)),
                                  sorted(set(conflicts)), reasons,
                                  sorted(set(installed_satisfied)), unresolved_notes)
    outcome.alternative_choices = alternative_choices
    return outcome, discovered


def package_versions(packages: Sequence[DebPackage], name: str, role: Optional[str], preferred_arch: str) -> List[str]:
    vals = [p for p in packages if p.name == name and (not role or p.repo.role == role) and p.arch in {preferred_arch, "all"}]
    vals.sort(key=cmp_to_key(lambda a, b: -compare_deb_versions(a.version, b.version)))
    out: List[str] = []
    seen = set()
    for p in vals:
        if p.version not in seen:
            seen.add(p.version); out.append(p.version)
    return out


def _copy_or_download(pkg: DebPackage, dest: Path, options: BuildOptions, reporter: Reporter) -> None:
    """Compatibility entry point retaining APT's transport and verifier hooks."""
    core._copy_or_download(pkg, dest, options, reporter,
                           opener=_urlopen, verifier=verify_package_artifact)


def write_bundle(result: DebResolutionResult, output_dir: Path, options: BuildOptions, reporter: Reporter,
                 metadata: Dict[str, object]) -> Path:
    # Build beside the destination and publish only on success, so a failed or
    # interrupted run cannot leave something that looks like a finished bundle.
    # Transfer occupies the first part of the bar when sealing will follow it.
    reporter.phase(0.0, SEAL_PHASE_START if options.sign_bundle_index else 1.0)
    final_dir = output_dir
    output_dir = open_staging(final_dir, reporter)
    output_dir.mkdir(parents=True, exist_ok=True)
    if not options.sign_bundle_index:
        core.invalidate_bundle_seal(output_dir, reporter)
    try:
        with artifact_digests.digest_scope():
            return _write_bundle_body(result, output_dir, final_dir, options, reporter, metadata)
    except BaseException:
        # Anything short of success leaves the previous bundle untouched and
        # removes the half-built one, so nothing can be mistaken for finished.
        abandon_staging(output_dir, reporter)
        raise


def _write_bundle_body(result: DebResolutionResult, output_dir: Path, final_dir: Path, options: BuildOptions,
                       reporter: Reporter, metadata: Dict[str, object]) -> Path:
    deb_dir = output_dir / "debs"
    deb_dir.mkdir(exist_ok=True)
    metadata_dir = deb_dir  # Payload-scoped records travel with this DEB set.
    from transaction_model import validate_retained_payloads, write_installation_contract, installation_roots
    validate_retained_payloads(metadata_dir, result.selected, 'deb', reporter, options)
    # Differential bundles: drop anything the baseline says the target already has.
    baseline = load_baseline(options.baseline_manifest, reporter)
    to_ship, already_present = split_against_baseline(result.selected, baseline, reporter)
    # preflight destination names before touching the
    # staging payload directory so two repositories cannot silently overwrite
    # each other when they publish the same basename.
    filename_map = payload_filenames(to_ship, ".deb")

    # Additive publication retains unrelated DEBs already present in the
    # destination. Same-name files may be verified/overwritten below, but old
    # package payloads are never pruned automatically.
    from bundle_writer import acquire_payloads, write_records
    from package_family import DEB
    acquire_payloads(
        to_ship, filename_map, deb_dir, final_dir.parent, options, reporter, DEB,
        verify=lambda pkg, dest: verify_package_artifact(pkg, dest, options, reporter),
        download=lambda pkg, dest: _copy_or_download(pkg, dest, options, reporter),
    )

    # manifests now bind the actual SHA-256 of shipped bytes and also
    # retain the upstream source digest so a later differential build can decide
    # unchanged content before downloading it again.
    shipped_ids = {id(p) for p in to_ship}
    manifest = []
    for p in result.selected:
        filename = filename_map.get(id(p), posixpath.basename(urllib.parse.urlparse(p.location).path))
        dest = deb_dir / filename
        record = getattr(p, "verification", None)
        manifest.append({
            "package_id": p.nevra, "name": p.name, "arch": p.arch, "version": p.version,
            "filename": filename,
            "sha256": artifact_digests.payload_sha256(dest, sha256_file) if id(p) in shipped_ids and dest.exists() else "",
            "source_digest_type": p.checksum_type or "", "source_digest": p.checksum or "",
            "repo": p.repo.name, "repo_url": redact_url(p.repo.normalized_url), "suite": p.repo.suite,
            "source": redact_url(url_join(p.repo.normalized_url, p.location, p.repo)), "size": p.size,
            "reason": result.reasons.get(p.nevra, "dependency"),
            "shipped": id(p) in shipped_ids,
            "evidence_status": getattr(record, "evidence_status", "not-configured"),
            "evidence_source": getattr(record, "evidence_source", ""),
            "evidence_digest_type": getattr(record, "evidence_digest_type", ""),
            "evidence_digest": getattr(record, "evidence_digest", ""),
            "evidence_relationship": getattr(record, "evidence_relationship", ""),
            "evidence_authority_relationship": getattr(record, "evidence_authority_relationship", core.AUTH_UNKNOWN),
        })
    if options.additive_publish:
        manifest = core.merge_additive_manifest_rows(metadata_dir / "manifest.json", manifest)
    payload_files = list(deb_dir.glob("*.deb"))
    payload = {
        "metadata": metadata,
        "summary": {"package_count": len(payload_files) if options.additive_publish else len(to_ship),
                    "total_size": (sum(p.stat().st_size for p in payload_files) if options.additive_publish
                                   else sum(int(getattr(p, "size", 0) or 0) for p in to_ship)),
                    "resolved_package_count": len(result.selected),
                    "resolved_total_size": result.total_size,
                    "baseline_omitted_count": len(already_present),
                    "unresolved_count": len(result.unresolved),
                    "ignored_unresolved_count": len(getattr(result, "ignored_unresolved", []) or []),
                    "conflict_count": len(result.conflicts),
                    "dependency_completeness": metadata.get("dependency_completeness", "analyzed")},
        "packages": manifest,
    }
    write_records(
        metadata_dir, deb_dir, DEB, payload, manifest,
        unresolved=(format_requirement(req) for req in result.unresolved),
        ignored_unresolved=result.ignored_unresolved,
        conflicts=result.conflicts, skipped_installed=result.skipped_installed,
        installed_satisfied=result.installed_satisfied, hash_file=sha256_file,
    )


    # ---- Provenance -------------------------------------------------------
    # Individual .deb files are effectively never signed, so a DEB artifact's
    # authority is the archive key, reached through: signed Release -> index
    # digest -> package digest. Record that chain rather than implying a
    # vendor signature that does not exist.
    prov_entries = []
    for pkg in to_ship:
        archive_trust = getattr(pkg.repo, "trust", None)
        filename = filename_map[id(pkg)]
        dest = deb_dir / filename
        record = getattr(pkg, "verification", None)
        # The recorded chain, not the configured intent.
        chain_intact = bool(
            record and record.index_digest_verified and record.package_digest_checked
            and archive_trust and archive_trust.archive_signature_verified)
        entry = provenance.PackageProvenance(
            package_id=pkg.nevra, filename=filename,
            sha256=artifact_digests.payload_sha256(dest, sha256_file) if dest.exists() else "",
            size=dest.stat().st_size if dest.exists() else 0,
            source_url=redact_url(url_join(pkg.repo.normalized_url, pkg.location, pkg.repo)),
            repository=pkg.repo.name,
            # Recorded verification, not inferred from configuration: a
            # keyring being set says an operator intended verification, not
            # that a signature was checked or that it passed.
            index_digest_verified=bool(getattr(pkg, "verification", None)
                                       and pkg.verification.index_digest_verified),
            archive_signature_verified=bool(
                archive_trust and archive_trust.archive_signature_verified),
            assurance=provenance.UNVERIFIED,
            digest_checked=bool(record and record.package_digest_checked),
            # preserve mirror-bond evidence independently from archive
            # signature state; the two claims are not interchangeable.
            evidence_status=getattr(record, "evidence_status", "not-configured"),
            evidence_source=getattr(record, "evidence_source", ""),
            evidence_digest_type=getattr(record, "evidence_digest_type", ""),
            evidence_digest=getattr(record, "evidence_digest", ""),
            evidence_digest_checked=bool(record and record.evidence_digest_checked),
            evidence_metadata_match=bool(record and record.evidence_metadata_match),
            evidence_artifact_checked=bool(record and record.evidence_artifact_checked),
            evidence_artifact_digest_type=getattr(record, "evidence_artifact_digest_type", "") if record else "",
            evidence_artifact_digest=getattr(record, "evidence_artifact_digest", "") if record else "",
            evidence_artifact_size=int(getattr(record, "evidence_artifact_size", 0) or 0) if record else 0,
            evidence_archive_signature_verified=bool(
                record and record.evidence_archive_signature_verified),
            evidence_relationship=getattr(record, "evidence_relationship", "") if record else "",
            evidence_authority_relationship=getattr(record, "evidence_authority_relationship", core.AUTH_UNKNOWN) if record else core.AUTH_UNKNOWN,
            evidence_peer_identity_match=bool(record and record.evidence_peer_identity_match),
            evidence_source_lineage_match=bool(record and record.evidence_source_lineage_match),
            evidence_peer_package_id=getattr(record, "evidence_peer_package_id", "") if record else "",
            evidence_peer_source_rpm=getattr(record, "evidence_peer_source_rpm", "") if record else "",
        )
        entry.assurance = provenance.assurance_from(entry)
        entry.notes.append("Debian packages are authenticated by the signed Release chain, "
                           "not by a per-file vendor signature.")
        if repository_verification_strategy(pkg.repo) == "skip-provenance":
            entry.notes.append("Upstream archive/signature provenance intentionally skipped by operator policy.")
        elif options.require_vendor_signatures and not chain_intact:
            raise RuntimeError(
                f"{filename}: signature-backed provenance was required, but this package's chain "
                "is incomplete (configure a keyring for its repository).")
        prov_entries.append(entry)
    if options.emit_repository:
        repo_packages = to_ship
        preserve_locations = False
        if options.additive_publish:
            from repository_tools import load_local_repository_packages
            _family, repo_packages = load_local_repository_packages(output_dir, "deb")
            preserve_locations = True
            reporter.log(f"Regenerating APT repository metadata over {len(repo_packages)} total package(s) in the additive folder.")
        emit_apt_repository(output_dir, repo_packages, reporter,
                            preserve_package_locations=preserve_locations)
    _write_provenance(output_dir, metadata_dir, prov_entries, already_present, options, reporter, metadata)

    package_only = bool(metadata.get("package_only_acquisition"))
    repository_mirror = bool(metadata.get("repository_mirror"))
    if package_only:
        warning = str(metadata.get("package_only_warning") or
                      "Dependencies were not derived for this package-only acquisition.")
        (metadata_dir / "PACKAGE-ONLY-WARNING.txt").write_text(
            "PACKAGE-ONLY ACQUISITION - NOT A COMPLETE OFFLINE INSTALLATION BUNDLE\n\n"
            + warning +
            "\n\nThe debs/ directory contains only the requested root artifacts. "
            "Enable appropriate dependency-provider repositories and rebuild before treating "
            "this package set as install-complete.\n",
            encoding="utf-8")
    elif repository_mirror:
        (metadata_dir / "MIRROR-BUNDLE.txt").write_text(
            "REPOSITORY MIRROR - NO PACKAGE-ROOT TRANSACTION\n\n"
            "This output mirrors the selected repository population. Feathered did not derive a "
            "root-package dependency closure and intentionally did not generate install-offline.sh.\n\n"
            "Use USE-AS-REPOSITORY.txt to expose the generated local repository metadata to APT. "
            "Package installation decisions remain the target package manager's responsibility.\n",
            encoding="utf-8")
    else:
        write_installation_contract(metadata_dir, result, 'deb', metadata, already_present)
        roots = installation_roots(result, 'deb')
        if roots:
            (metadata_dir / "REQUESTED-ROOTS.txt").write_text("\n".join(roots) + "\n", encoding="utf-8")
            if options.emit_repository:
                from installer import write_installer
                write_installer(output_dir, metadata_dir, result, options, 'deb', metadata)
            else:
                (output_dir / "INSTALL-OFFLINE-NOTE.txt").write_text(
                    "Enable local repository metadata to generate the offline installer.\n", encoding="utf-8")
    core_write_unified_mirror_records(output_dir, metadata_dir, options)
    if reporter.warnings:
        (metadata_dir / "trust-warnings.txt").write_text(
            "Conditions recorded while building this bundle. Review before installing.\n\n"
            + "\n".join(f"- {w}" for w in reporter.warnings) + "\n", encoding="utf-8")
    __import__("core")._write_workload_artifacts(output_dir, metadata_dir, metadata, result)
    if options.sign_bundle_index:
        # Sealing owns the last slice of the same bar the transfer advanced.
        reporter.phase(SEAL_PHASE_START, 1.0 - SEAL_PHASE_START)
        write_bundle_index(output_dir, reporter, {
            "tool": provenance._tool_identity(),
            # The published name, not the temporary staging directory.
            "bundle_id": final_dir.name,
            "target": {k: str(v) for k, v in metadata.items()
                       if k in {"distribution", "release", "arch", "workload"}},
            "trust": trust_summary(to_ship),
        }, options.signing_key)
    return commit_staging(output_dir, final_dir, reporter)



def _fold_field(key: str, value: str) -> str:
    """Render one Deb822 field, restoring continuation-line indentation.

    _parse_deb822 stores a folded field as newline-joined text with the leading
    space removed. Writing that back verbatim produces lines that apt reads as
    new (nameless) fields, so multi-line Description and folded dependency
    lists have to be re-indented. An empty continuation line is written as the
    " ." form Deb822 requires.
    """
    lines = str(value).split("\n")
    out = [f"{key}: {lines[0]}"]
    for line in lines[1:]:
        out.append(" " + line if line.strip() else " .")
    return "\n".join(out)


def emit_apt_repository(output_dir: Path, packages, reporter: RepositoryWriterReporter, preserve_package_locations: bool = False) -> None:
    """Write dists/ metadata so the bundle is itself a usable APT repository.

    The stanzas are the ones the upstream archive published, with only Filename
    rewritten to the bundle-relative path, so versions, dependencies and digests
    are exactly what the resolver saw. The result is unsigned: it is meant to be
    consumed locally via file:// or served internally, not to impersonate the
    archive it came from.
    """
    suite = "feathered"
    component = "main"
    arches = sorted({p.arch for p in packages if p.arch != "all"}) or ["amd64"]
    field_order = ["Package", "Source", "Version", "Architecture", "Essential", "Priority",
                   "Section", "Origin", "Maintainer", "Original-Maintainer", "Bugs",
                   "Installed-Size", "Provides", "Pre-Depends", "Depends", "Recommends",
                   "Suggests", "Conflicts", "Breaks", "Replaces", "Enhances", "Multi-Arch",
                   "Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512", "Homepage",
                   "Description", "Description-md5", "Task"]

    written = []
    for arch in arches:
        rows = [p for p in packages if p.arch in {arch, "all"}]
        stanzas = []
        for pkg in rows:
            fields = dict(pkg.raw_fields) if pkg.raw_fields else {
                "Package": pkg.name, "Version": pkg.version, "Architecture": pkg.arch,
                "Size": str(pkg.size), "SHA256": pkg.checksum,
            }
            fields["Filename"] = (pkg.location.replace("\\", "/").lstrip("./")
                                  if preserve_package_locations else
                                  "debs/" + posixpath.basename(urllib.parse.urlparse(pkg.location).path))
            ordered = [k for k in field_order if k in fields]
            ordered += [k for k in fields if k not in field_order]
            stanzas.append("\n".join(_fold_field(k, fields[k]) for k in ordered))
        body = ("\n\n".join(stanzas) + ("\n" if stanzas else "")).encode("utf-8")
        target = output_dir / f"dists/{suite}/{component}/binary-{arch}"
        target.mkdir(parents=True, exist_ok=True)
        (target / "Packages").write_bytes(body)
        (target / "Packages.gz").write_bytes(gzip.compress(body, mtime=0))
        written.append((f"{component}/binary-{arch}/Packages", body))
        written.append((f"{component}/binary-{arch}/Packages.gz",
                        (target / "Packages.gz").read_bytes()))
        # An empty Release per binary directory keeps apt quiet.
        (target / "Release").write_text(
            f"Archive: {suite}\nComponent: {component}\nArchitecture: {arch}\n", encoding="utf-8")

    stamp = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S UTC")
    lines = ["Origin: Feathered", "Label: Feathered offline bundle", f"Suite: {suite}",
             f"Codename: {suite}", f"Components: {component}",
             f"Architectures: {' '.join(arches)}", f"Date: {stamp}",
             "Description: Offline bundle generated by Feathered", "SHA256:"]
    for rel, blob in written:
        lines.append(f" {hashlib.sha256(blob).hexdigest()} {len(blob)} {rel}")
    (output_dir / f"dists/{suite}").mkdir(parents=True, exist_ok=True)
    (output_dir / f"dists/{suite}/Release").write_text("\n".join(lines) + "\n", encoding="utf-8")
    reporter.log(f"Wrote APT repository metadata for {len(packages)} package(s) "
                 f"({', '.join(arches)})")
    (output_dir / "USE-AS-REPOSITORY.txt").write_text(
        "This bundle also contains APT repository metadata.\n\n"
        "On the target, add it as a local source:\n\n"
        f"  echo 'deb [trusted=yes] file:/path/to/this/bundle {suite} {component}' \\\n"
        "    | sudo tee /etc/apt/sources.list.d/feathered.list\n"
        "  sudo apt-get update\n\n"
        "The metadata is unsigned, hence [trusted=yes]. Verify debs/SHA256SUMS.txt and any\n"
        "manifest signature before trusting the contents.\n", encoding="utf-8")


def _write_provenance(bundle_dir: Path, metadata_dir: Path, entries, already_present, options: BuildOptions,
                      reporter: Reporter, metadata: Dict[str, object]) -> None:
    """Compatibility entry point for the shared payload-scoped record writer."""
    core._write_provenance(bundle_dir, metadata_dir, entries, already_present,
                           options, reporter, metadata)


def write_bundle_archive(bundle_dir: Path, reporter: Optional[Reporter] = None) -> Path:
    bundle_dir = bundle_dir.resolve()
    archive = bundle_dir.with_suffix(".zip")
    (reporter or Reporter()).log(f"PACK {archive.name}")
    return Path(shutil.make_archive(str(bundle_dir), "zip", root_dir=str(bundle_dir.parent), base_dir=bundle_dir.name))


def parse_target_inventory(path: Path) -> AptTargetInventory:
    """Parse a dpkg target inventory produced by target_inventory.sh.

    The inventory declares the package family it came from. Checking it stops
    an RPM inventory from parsing into an empty DEB inventory, which used to
    turn target-aware mode into a silent no-op (over-collection) or, in the
    other direction, feed junk records into the RPM capability index.
    """
    inv = AptTargetInventory()
    text = path.read_text(encoding="utf-8", errors="replace")
    declared = _declared_family(text)
    if declared and declared != "deb":
        raise RuntimeError(
            f"{path.name} is a '{declared}' target inventory, but the selected target uses dpkg/APT. "
            "Re-run target_inventory.sh on the intended Debian/Ubuntu host."
        )
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"): continue
        if line.startswith("DETAIL|"):
            continue
        parts = line.split("|")
        if parts[0] == "META" and len(parts) >= 3:
            inv.metadata[parts[1]] = "|".join(parts[2:]); continue
        if parts[0] == "ERROR":
            raise RuntimeError(f"{path.name} records a collection failure on the target: "
                               + "|".join(parts[1:]))
        if parts[0] in {"PKG", "PROVIDE"}:
            raise RuntimeError(f"{path.name} contains RPM inventory records, but the selected target "
                               "uses dpkg/APT. Re-run target_inventory.sh on the intended host.")
        if parts[0] == "DEB" and len(parts) >= 4:
            _, name, version, arch = parts[:4]
            if name.endswith(":" + arch):
                name = name[:-(len(arch) + 1)]
            inv.packages[(name, arch)] = version
            if len(parts) >= 6:
                inv.multi_arch[(name, arch)] = parts[5]
            if len(parts) >= 5 and parts[4]:
                for item in parts[4].split(","):
                    atom = _parse_atom(item.strip())
                    if atom:
                        inv.provides[atom.name].append((f"{name}={version}:{arch}", version, atom.version))
    from inventory_relationships import attach
    return attach(inv, text, 'deb')
