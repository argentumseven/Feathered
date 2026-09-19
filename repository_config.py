"""Repository configuration model.

Keeping repository intent here prevents transport/logging side effects from forcing
all package-domain models to import the legacy ``core`` module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Dict, List
import urllib.parse

import credential_redaction as _redaction
from evidence_model import infer_vendor_id
import repository_transport as _transport


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

    # Minimum accepted package digest strength. ``auto`` uses the strongest
    # supported digest published by each source.
    digest_preference: str = "auto"
    # Compatibility field for older profiles and callers.
    digest_requirement: str = "preferred"
    # one non-overlapping verification
    # strategy replaces the old Required?/Evidence-policy pair in the UI.
    # Empty means infer the historical behavior from digest_requirement and
    # evidence_policy, preserving compatibility for older saved/configured repos.
    # checksum-required | checksum-available | evidence-fallback | full-corroboration | skip-provenance
    verification_strategy: str = ""

    # Vendor-specific query fields that carry credential material. Built-in
    # names such as token/access_token are always recognized; these lists let a
    # custom repository declare spellings such as license_token without relying
    # on a global hard-coded allowlist. These fields are appended to the
    # dataclass so the established positional RepoSpec constructor remains
    # compatible with older callers.
    sensitive_query_keys: List[str] = field(default_factory=list)
    # Only fields explicitly declared inheritable are copied from a repository
    # root URL to same-origin child metadata/package URLs. A declared inheritable
    # field is automatically treated as sensitive too.
    inheritable_query_credential_keys: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.vendor_id:
            object.__setattr__(self, "vendor_id", infer_vendor_id(self.name, self.url))
        _transport.register_sensitive_query_keys(self.sensitive_query_keys)
        _transport.register_sensitive_query_keys(self.inheritable_query_credential_keys)
        _redaction.register_url_secrets(self.url)
        # evidence URLs can carry the same credentials as acquisition
        # URLs, so register them with the central log redactor as well.
        for evidence_url in self.evidence_urls:
            _redaction.register_url_secrets(evidence_url)

    def __setattr__(self, name, value):
        # URLs are also assigned after construction (media selection, custom
        # repositories), so secrets are registered on every assignment.
        if name == "sensitive_query_keys":
            value = sorted(_transport.normalize_query_key_names(value))
        elif name == "inheritable_query_credential_keys":
            value = sorted(
                _transport.normalize_query_key_names(value)
                - _transport.NON_INHERITABLE_QUERY_CREDENTIAL_KEYS)
        object.__setattr__(self, name, value)
        if name == "url":
            _redaction.register_url_secrets(value)
        elif name in {"sensitive_query_keys", "inheritable_query_credential_keys"}:
            _transport.register_sensitive_query_keys(value)
            existing_url = getattr(self, "url", "")
            if existing_url:
                _redaction.register_url_secrets(existing_url)
        elif name == "evidence_urls" and value:
            # assignments happen after construction from the GUI.
            for evidence_url in value:
                _redaction.register_url_secrets(evidence_url)

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

__all__ = ["RepoSpec"]
