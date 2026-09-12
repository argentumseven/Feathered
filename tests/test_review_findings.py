"""Regression tests for four defects found in review.

1. workload-drift.yml spliced a workflow_dispatch input into a Bash program.
2. Generic "sig"/"signature" query parameters were inherited to child URLs
   despite being resource-bound, and overwrote a child's own signature.
3. check_release_freshness() passed when Release declared no Valid-Until.
4. INSTALLATION-CONTRACT.json implied a stronger baseline guarantee than the
   receiver can actually establish.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

import apt_core
import receiver_preflight
import transaction_model
from core import RepoSpec
from repository_transport import (INHERITABLE_QUERY_CREDENTIAL_KEYS,
                                  SENSITIVE_QUERY_KEYS, url_join)

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# 1. Actions shell injection
# --------------------------------------------------------------------------

def _drift_step():
    data = yaml.safe_load((ROOT / ".github/workflows/workload-drift.yml").read_text())
    return [s for s in data["jobs"]["matrix"]["steps"] if s.get("id") == "matrix"][0]


def test_dispatch_input_never_reaches_the_shell_as_syntax():
    step = _drift_step()
    assert "${{" not in step["run"], (
        "A GitHub expression interpolated into run: is evaluated before Bash sees it, "
        "so the input becomes program text.")


def test_dispatch_input_arrives_as_an_environment_variable():
    step = _drift_step()
    assert "FEATHERED_PROFILES" in step.get("env", {})
    assert '"$FEATHERED_PROFILES"' in step["run"], "must stay quoted at every use"


def test_profiles_are_passed_as_a_single_argv_element():
    """Unquoted array expansion would re-split the value on whitespace."""
    assert '"${args[@]}"' in _drift_step()["run"]


# --------------------------------------------------------------------------
# 2. Signed-URL inheritance
# --------------------------------------------------------------------------

def _query(url):
    return parse_qs(urlsplit(url).query)


@pytest.mark.parametrize("name", ["sig", "signature"])
def test_resource_bound_signatures_are_not_inherited(name):
    child = url_join(f"https://repo.example/root/?{name}=resource-signature", "Packages.gz")
    assert name not in _query(child)


@pytest.mark.parametrize("name", ["sig", "signature"])
def test_signatures_remain_sensitive_for_redaction(name):
    """Not inheritable is not the same as not a credential."""
    assert name in SENSITIVE_QUERY_KEYS
    assert name not in INHERITABLE_QUERY_CREDENTIAL_KEYS


def test_repository_token_is_still_inherited_same_origin():
    """The fix must not break legitimate repository-token behaviour."""
    child = url_join("https://repo.example/root/?token=repository-token", "Packages.gz")
    assert _query(child)["token"] == ["repository-token"]


def test_a_childs_own_signature_is_no_longer_overwritten():
    """Previously the base's sig displaced the child's, producing a signature
    that could not validate for the child resource."""
    child = url_join("https://repo.example/root/?token=t&sig=base-signature",
                     "Packages.gz?sig=child-specific")
    assert _query(child)["token"] == ["t"]
    assert _query(child)["sig"] == ["child-specific"]


def test_credentials_are_not_inherited_cross_origin():
    child = url_join("https://repo.example/root/?token=secret",
                     "https://cdn.example/Packages.gz")
    assert "token" not in _query(child)


def test_cloud_provider_signatures_stay_excluded():
    child = url_join("https://repo.example/root/?x-amz-signature=abc", "Packages.gz")
    assert _query(child) == {}


# --------------------------------------------------------------------------
# 3. APT Release freshness
# --------------------------------------------------------------------------

class _Reporter:
    def __init__(self):
        self.logs = []
        self.warnings = []

    def log(self, message): self.logs.append(message)
    def warn(self, message): self.warnings.append(message)


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)


def _stamp(when):
    return when.strftime("%a, %d %b %Y %H:%M:%S +0000")


def _repo(max_age=0):
    return RepoSpec(name="Example", url="https://repo.example/debian/",
                    repo_format="deb", suite="stable", max_release_age_days=max_age)


def test_valid_until_still_authoritative_when_present():
    reporter = _Reporter()
    apt_core.check_release_freshness(
        _repo(max_age=1), {"Valid-Until": _stamp(NOW + timedelta(days=5)),
                           "Date": _stamp(NOW - timedelta(days=400))}, reporter, now=NOW)
    assert reporter.warnings == []


def test_expired_valid_until_still_fails():
    with pytest.raises(RuntimeError, match="expired"):
        apt_core.check_release_freshness(
            _repo(), {"Valid-Until": _stamp(NOW - timedelta(days=3))}, _Reporter(), now=NOW)


def test_absent_valid_until_is_unenforced_by_default_but_reported():
    """Default matches APT's Acquire::Max-ValidTime of 0. Pinned archives are a
    legitimate air-gap source, so this must not become a hard failure without
    the operator asking for one -- but it must say what was not established."""
    reporter = _Reporter()
    apt_core.check_release_freshness(
        _repo(), {"Date": _stamp(NOW - timedelta(days=900))}, reporter, now=NOW)
    assert len(reporter.warnings) == 1
    assert "no Valid-Until" in reporter.warnings[0]


def test_recent_date_passes_under_a_configured_maximum():
    reporter = _Reporter()
    apt_core.check_release_freshness(
        _repo(max_age=14), {"Date": _stamp(NOW - timedelta(days=3))}, reporter, now=NOW)
    assert reporter.warnings == []
    assert "within the configured 14-day maximum" in reporter.logs[-1]


def test_stale_date_fails_under_a_configured_maximum():
    with pytest.raises(RuntimeError, match="exceeding the configured 14-day maximum"):
        apt_core.check_release_freshness(
            _repo(max_age=14), {"Date": _stamp(NOW - timedelta(days=40))}, _Reporter(), now=NOW)


def test_absent_date_fails_closed_under_a_configured_maximum():
    with pytest.raises(RuntimeError, match="neither a usable Valid-Until nor a usable Date"):
        apt_core.check_release_freshness(_repo(max_age=14), {}, _Reporter(), now=NOW)


def test_future_date_is_refused_rather_than_scored_as_fresh():
    with pytest.raises(RuntimeError, match="in the future"):
        apt_core.check_release_freshness(
            _repo(max_age=14), {"Date": _stamp(NOW + timedelta(days=2))}, _Reporter(), now=NOW)


def test_small_clock_skew_is_tolerated():
    reporter = _Reporter()
    apt_core.check_release_freshness(
        _repo(max_age=14), {"Date": _stamp(NOW + timedelta(minutes=3))}, reporter, now=NOW)
    assert reporter.warnings == []


# --------------------------------------------------------------------------
# 4. Baseline assurance
# --------------------------------------------------------------------------

class _Pkg:
    def __init__(self, name, evr, arch):
        self.name, self.evr_text, self.arch = name, evr, arch
        self.version = evr
        self.nevra = f"{name}-{evr}.{arch}"
        self.repo = type("R", (), {"source_identity": "src"})()


class _Result:
    def __init__(self, packages):
        self.roots = list(packages)
        self.selected = list(packages)
        self.target_inventory = None
        self.arch_full_upgrade = False


def _contract(tmp_path, omitted):
    transaction_model.write_installation_contract(
        tmp_path, _Result([_Pkg("app", "1.0-1", "amd64")]), "deb",
        {"distribution": "debian", "release": "12", "arch": "amd64"}, omitted=omitted)
    return json.loads((tmp_path / "INSTALLATION-CONTRACT.json").read_text())


def test_contract_is_schema_2(tmp_path):
    assert _contract(tmp_path, [])["schema"] == 2


def test_baseline_entries_name_their_assurance(tmp_path):
    contract = _contract(tmp_path, [_Pkg("libexample", "1.2.3-1", "amd64")])
    entry = contract["baseline_required"][0]
    assert entry["assurance"] == transaction_model.BASELINE_INSTALLED_IDENTITY


def test_no_baseline_entry_claims_integrity_it_cannot_prove(tmp_path):
    """An installed-file digest is not recoverable from dpkg state, so the
    contract must not carry a field implying one."""
    contract = _contract(tmp_path, [_Pkg("libexample", "1.2.3-1", "amd64")])
    entry = contract["baseline_required"][0]
    assert "sha256" not in entry and "digest" not in entry


@pytest.mark.parametrize("schema", [1, 2])
def test_receiver_accepts_both_schemas(schema):
    """The receiver travels out of band, so bundles and receivers roll
    independently and both versions must validate."""
    contract = {"schema": schema, "family": "deb", "target": {"arch": "amd64"},
                "baseline_required": [{"name": "libexample", "version": "1.2.3-1",
                                       "architecture": "amd64",
                                       "package_id": "libexample-1.2.3-1.amd64"}]}
    receiver_preflight.validate(
        contract, {("libexample", "amd64"): "1.2.3-1"}, machine="x86_64")


def test_receiver_rejects_an_unknown_schema():
    contract = {"schema": 99, "family": "deb", "target": {}, "baseline_required": []}
    assert contract["schema"] not in (1, 2)


def test_missing_baseline_error_describes_identity_not_integrity():
    contract = {"schema": 2, "family": "deb", "target": {"arch": "amd64"},
                "baseline_required": [{"name": "libexample", "version": "1.2.3-1",
                                       "architecture": "amd64",
                                       "package_id": "libexample-1.2.3-1.amd64",
                                       "assurance": "installed-identity"}]}
    with pytest.raises(RuntimeError, match="identity is not present exactly"):
        receiver_preflight.validate(contract, {}, machine="x86_64")
