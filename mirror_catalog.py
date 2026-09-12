from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Iterable, List

from evidence_model import (
    AUTH_INDEPENDENT,
    AUTH_UNKNOWN,
    EvidenceCandidate,
    REL_EXACT_MIRROR,
)

CATALOG_SCHEMA = 1
CATALOG_DIRNAME = "mirror_catalogs"
AUTOMATIC_EVIDENCE_COUNTRY = "US"


def catalog_root() -> Path:
    """Return the user-editable sidecar mirror-catalog directory.

    Development runs use the source tree.  PyInstaller one-file releases use a
    directory beside Feathered.exe; build_exe.bat stages that directory so edits
    survive application restarts and executable upgrades can be reviewed/diffed.
    """
    override = os.environ.get("FEATHERED_MIRROR_CATALOG_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / CATALOG_DIRNAME
    return Path(__file__).resolve().parent / CATALOG_DIRNAME


def catalog_path(profile_key: str) -> Path:
    safe = re.sub(r"[^a-z0-9._-]+", "-", str(profile_key or "").lower()).strip("-")
    return catalog_root() / f"{safe or 'unknown'}.json"


def _blank_catalog(profile_key: str) -> Dict[str, Any]:
    return {
        "schema": CATALOG_SCHEMA,
        "distribution": profile_key,
        "source_url": "",
        "snapshot_date": "",
        "notes": "",
        "mirrors": [],
        "exact_overrides": [],
    }


def load_catalog(profile_key: str) -> Dict[str, Any]:
    path = catalog_path(profile_key)
    if not path.is_file():
        return _blank_catalog(profile_key)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _blank_catalog(profile_key)
    if not isinstance(data, dict):
        return _blank_catalog(profile_key)
    merged = _blank_catalog(profile_key)
    merged.update(data)
    if not isinstance(merged.get("mirrors"), list):
        merged["mirrors"] = []
    if not isinstance(merged.get("exact_overrides"), list):
        merged["exact_overrides"] = []
    return merged


def save_catalog(profile_key: str, data: Dict[str, Any]) -> Path:
    path = catalog_path(profile_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _blank_catalog(profile_key)
    payload.update(data or {})
    payload["schema"] = CATALOG_SCHEMA
    payload["distribution"] = profile_key
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def _norm(url: str) -> str:
    return str(url or "").strip().rstrip("/")


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def _join(root: str, suffix: str) -> str:
    root = _norm(root)
    suffix = str(suffix or "").lstrip("/")
    return root + ("/" + suffix if suffix else "") + "/"


def _rpm_suffix(profile_key: str, repo_url: str) -> str | None:
    url = _norm(repo_url)
    patterns = {
        "rocky": [r"/pub/rocky/(.+)$", r"/rocky-linux/(.+)$", r"/rockylinux/(.+)$"],
        "alma": [r"/almalinux/(.+)$"],
        "centos-stream": [r"/(\d+-stream/.+)$", r"/centos-stream/(\d+-stream/.+)$"],
        "fedora": [r"/pub/fedora/linux/(.+)$", r"/fedora/linux/(.+)$"],
        # EPEL is operated by Fedora infrastructure but is a distinct archive
        # rooted at /pub/epel rather than /pub/fedora/linux.  Keeping it as a
        # separate catalog key prevents Fedora OS mirror roots from being
        # misapplied to an EPEL repository and gives Maximum verification a
        # real exact-mirror choice for supplemental EPEL sources.
        "epel": [r"/pub/epel/(.+)$", r"/fedora-epel/(.+)$", r"/epel/(.+)$"],
    }.get(profile_key, [])
    for pattern in patterns:
        match = re.search(pattern, url, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _mirror_url_for_repo(profile_key: str, repo: Any, root: str, scopes: Iterable[str]) -> str | None:
    fmt = str(getattr(repo, "repo_format", "rpm") or "rpm").lower()
    root = _norm(root)
    if not root:
        return None
    scopes = {str(x).lower() for x in (scopes or ["archive"])}
    repo_url = _norm(getattr(repo, "normalized_url", "") or getattr(repo, "url", ""))

    if fmt == "rpm":
        if profile_key in {"rhel", "photon"}:
            return None
        if "vault" in repo_url.lower() and "vault" not in scopes:
            return None
        suffix = _rpm_suffix(profile_key, repo_url)
        return _join(root, suffix) if suffix else None

    if fmt == "apt":
        name = str(getattr(repo, "name", "")).lower()
        if profile_key == "debian" and "security" in name and "security" not in scopes:
            return None
        if profile_key == "ubuntu" and "ports" in repo_url and "ports" not in scopes:
            return None
        if profile_key == "devuan":
            # Devuan's published mirror_list.txt gives a BaseURL.  The package
            # repository itself lives below /merged (the same layout used by
            # deb.devuan.org), so convert the listed BaseURL into the exact APT
            # repository root rather than treating the bare host as a repo.
            return root.rstrip("/") + "/merged/"
        return root.rstrip("/") + "/"

    if fmt == "pacman":
        suite = (str(getattr(repo, "suite", "") or "").strip()
                 or str(getattr(repo, "name", "")).strip().split()[-1])
        arch = "x86_64"
        parts = repo_url.rstrip("/").split("/")
        if len(parts) >= 2 and parts[-2].lower() == "os":
            arch = parts[-1]
        return _join(root, f"{suite}/os/{arch}")

    return None


def candidates_for_repository(profile_key: str, repo: Any) -> List[EvidenceCandidate]:
    """Derive exact-mirror candidates solely from the local distro catalog.

    The catalog establishes that an endpoint is advertised as a mirror of the
    distribution.  It does *not* create a second signing authority: the archive
    signatures are still the distribution's.  `independent_operator` means only
    that the mirror copy/transport is operated separately from the acquisition
    endpoint, which is the independence relevant to byte-level corroboration.
    """
    if str(getattr(repo, "role", "")) != "dependency":
        return []
    catalog = load_catalog(profile_key)
    primary = _norm(getattr(repo, "normalized_url", "") or getattr(repo, "url", ""))
    primary_host = _host(primary)
    out: List[EvidenceCandidate] = []

    for item in catalog.get("mirrors", []):
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        # Feathered's automatic evidentiary-mirror threat boundary is the
        # United States. A locally edited catalog may retain historical or
        # operator-reference entries from elsewhere, but non-US and unknown
        # geography must never enter the automatic independent-evidence set.
        country = str(item.get("country", "")).strip().upper()
        if country != AUTOMATIC_EVIDENCE_COUNTRY:
            continue
        root = _norm(item.get("url", ""))
        candidate_url = _mirror_url_for_repo(profile_key, repo, root, item.get("scopes", ["archive"]))
        if not candidate_url or _host(candidate_url) == primary_host or _norm(candidate_url) == primary:
            continue
        authority = AUTH_INDEPENDENT if item.get("independent_operator", False) else AUTH_UNKNOWN
        label = str(item.get("label") or item.get("operator") or _host(candidate_url) or candidate_url)
        note = f"Derived from local distribution mirror catalog; geographic policy: {AUTOMATIC_EVIDENCE_COUNTRY}"
        if item.get("operator"):
            note += f"; operator: {item['operator']}"
        out.append(EvidenceCandidate(candidate_url, label, REL_EXACT_MIRROR, authority,
                                     "mirror-catalog", note + "."))

    repo_name = str(getattr(repo, "name", ""))
    suite = str(getattr(repo, "suite", "") or "")
    for item in catalog.get("exact_overrides", []):
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        if item.get("repo_name") and str(item.get("repo_name")) != repo_name:
            continue
        if item.get("suite") and str(item.get("suite")) != suite:
            continue
        url = _norm(item.get("url", ""))
        if not url or _host(url) == primary_host or url == primary:
            continue
        # Manual overrides remain operator-controlled and usable regardless
        # of geography, but Feathered will only *assert* independent mirror
        # authority when the operator has also marked the endpoint US-based.
        # This preserves the trusted-device workflow without silently weakening
        # the automatic US-only evidence policy.
        country = str(item.get("country", "")).strip().upper()
        authority = (AUTH_INDEPENDENT
                     if item.get("independent_operator", False)
                     and country == AUTOMATIC_EVIDENCE_COUNTRY
                     else AUTH_UNKNOWN)
        note = "User-persisted exact mirror override."
        if authority == AUTH_INDEPENDENT:
            note += f" Operator-marked independent and {AUTOMATIC_EVIDENCE_COUNTRY}-based."
        elif item.get("independent_operator", False):
            note += f" Independent authority not asserted because country is not {AUTOMATIC_EVIDENCE_COUNTRY}."
        out.append(EvidenceCandidate(
            url + "/", str(item.get("label") or _host(url) or url), REL_EXACT_MIRROR,
            authority, "mirror-catalog-user", note))

    seen = set()
    unique = []
    for candidate in out:
        key = _norm(candidate.url)
        if key and key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def add_exact_mirror_override(profile_key: str, repo: Any, url: str, label: str = "") -> Path:
    """Persist one operator-asserted exact mirror for this logical repo slice."""
    url = _norm(url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Mirror URL must be an absolute http:// or https:// URL")
    data = load_catalog(profile_key)
    rows = list(data.get("exact_overrides", []))
    repo_name = str(getattr(repo, "name", ""))
    suite = str(getattr(repo, "suite", "") or "")
    entry = {
        "label": label.strip() or f"User mirror - {_host(url)}",
        "url": url,
        "repo_name": repo_name,
        "suite": suite,
        "country": "",
        "independent_operator": False,
        "enabled": True,
        "note": ("Added from Feathered UI. Manual overrides remain operator-controlled. "
                 "To classify one as independent mirror evidence, set country=US and "
                 "independent_operator=true only when both facts are known."),
    }
    key = (repo_name, suite, url)
    replaced = False
    for index, existing in enumerate(rows):
        if not isinstance(existing, dict):
            continue
        existing_key = (str(existing.get("repo_name", "")), str(existing.get("suite", "")), _norm(existing.get("url", "")))
        if existing_key == key:
            rows[index] = entry
            replaced = True
            break
    if not replaced:
        rows.append(entry)
    data["exact_overrides"] = rows
    return save_catalog(profile_key, data)
