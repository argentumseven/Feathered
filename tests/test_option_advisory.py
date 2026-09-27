"""Beta/EOL/incompatible option classification and the related bug fixes.

Pure tests: no Tk root and no network.
"""
from __future__ import annotations

from datetime import date
from types import SimpleNamespace

import pytest

from feathered_app.option_advisory import (
    OptionStatus, classify_kubernetes_minor, classify_package_version, classify_release,
    display_label, preferred_default, ubuntu_series_unreleased, version_text_is_prerelease,
)
from feathered_app.target_transition import TargetTransitionService

TODAY = date(2026, 9, 26)


@pytest.mark.parametrize("value", [
    "5:28.0.0~rc.1-1~ubuntu.24.04~noble", "2.0-0.1.rc1.el9", "1.36.0-beta.0",
    "1.37.0-alpha.2", "10.3 Beta", "sid", "testing", "rawhide", "ceres", "3.0~preview1",
])
def test_prerelease_markers_are_detected(value):
    assert version_text_is_prerelease(value)
    assert classify_package_version(value).status is OptionStatus.PRERELEASE


@pytest.mark.parametrize("value", [
    "Latest", "Follows repositories", "rolling", "5:28.0.4-1~debian.12~bookworm",
    "1.2-1+deb12u1", "devuan", "daedalus", "10-stream", "2.4.1-3.src", "24.04", "trixie",
    "1.2.3-1.el9_4", "preempt-rt",
])
def test_ordinary_versions_are_not_flagged(value):
    assert not version_text_is_prerelease(value)
    assert classify_package_version(value).stable


def test_ubuntu_development_series_is_flagged_offline_by_release_month():
    assert ubuntu_series_unreleased("26.10", TODAY)
    assert not ubuntu_series_unreleased("26.04", TODAY)
    assert not ubuntu_series_unreleased("24.04.3", TODAY)
    advice = classify_release("ubuntu", "26.10", today=TODAY)
    assert advice.status is OptionStatus.PRERELEASE and "not been released" in advice.reason
    assert classify_release("ubuntu", "26.04", today=TODAY).stable
    # The month heuristic is Ubuntu-specific; Fedora 45 is simply a number.
    assert classify_release("fedora", "45", today=TODAY).stable


def test_release_flag_matches_codename_or_version_form():
    codenames = {"26.10": "stonking", "26.04": "resolute", "26": "resolute"}
    for value in ("26.10", "stonking"):
        assert classify_release("ubuntu", value, prerelease={"stonking"},
                                codenames=codenames, today=date(2026, 10, 20)).status \
            is OptionStatus.PRERELEASE
    assert classify_release("ubuntu", "26.04", prerelease={"stonking"},
                            codenames=codenames, today=TODAY).stable
    assert classify_release("debian", "forky", prerelease={"forky"}).status is OptionStatus.PRERELEASE
    assert classify_release("debian", "trixie", prerelease={"forky"}).stable


def test_kubernetes_minor_lifecycle():
    rows = [SimpleNamespace(minor="1.37", end_of_life="2027-10-28"),
            SimpleNamespace(minor="1.34", end_of_life="2026-10-27"),
            SimpleNamespace(minor="1.28", end_of_life="2024-10-22")]
    assert classify_kubernetes_minor("1.38", rows, TODAY).status is OptionStatus.PRERELEASE
    assert classify_kubernetes_minor("1.37", rows, TODAY).stable
    assert classify_kubernetes_minor("1.34", rows, TODAY).stable
    assert classify_kubernetes_minor("1.28", rows, TODAY).status is OptionStatus.END_OF_LIFE
    assert classify_kubernetes_minor("1.38", (), TODAY).stable  # no data, no claim
    assert classify_kubernetes_minor("not-a-version", rows, TODAY).stable


def test_preferred_default_skips_beta_then_eol_then_incompatible():
    status = {"b": OptionStatus.PRERELEASE, "e": OptionStatus.END_OF_LIFE,
              "i": OptionStatus.INCOMPATIBLE, "s": OptionStatus.STABLE}
    classify = lambda v: SimpleNamespace(status=status[v[0]])  # noqa: E731
    assert preferred_default(["b1", "s1", "s2"], classify) == "s1"
    assert preferred_default(["b1", "e1"], classify) == "e1"
    assert preferred_default(["i1", "b1"], classify) == "b1"
    assert preferred_default(["i1"], classify) == "i1"
    assert preferred_default([], classify) == ""


def test_display_label_tags_only_non_stable_rows():
    assert display_label("26.04", classify_release("ubuntu", "26.04", today=TODAY)) == "26.04"
    assert display_label("26.10", classify_release("ubuntu", "26.10", today=TODAY)).endswith("\u00b7 beta")


def test_new_target_defaults_to_newest_stable_release_not_first_entry():
    service = TargetTransitionService()
    advice = lambda v: classify_release("ubuntu", v, today=TODAY)  # noqa: E731
    choice = service.select_profile(profile="ubuntu", known=["26.10", "26.04", "24.04"], current="",
                                    default=lambda values: preferred_default(values, advice))
    assert choice == "26.04"
    # An explicit operator choice of a beta is remembered, never overridden.
    service.select_profile(profile="debian", known=["trixie"], current="26.10")
    assert service.select_profile(profile="ubuntu", known=["26.10", "26.04"], current="trixie",
                                  default=lambda values: preferred_default(values, advice)) == "26.10"
    # Legacy callers without a default keep the historical first-entry behavior.
    assert TargetTransitionService().select_profile(
        profile="x", known=["b", "a"], current="") == "b"


def test_apt_discovery_reports_development_aliases_as_prerelease(monkeypatch):
    import core
    import profiles

    releases = {
        "resolute": ("26.04", "resolute"), "stonking": ("26.10", "stonking"),
        "noble": ("24.04", "noble"), "devel": ("26.10", "stonking"),
    }

    def fake_fetch(url, reporter, retries=1, timeout=45):
        if url.endswith("/dists/"):
            return b'<a href="noble/">noble</a><a href="resolute/">r</a><a href="stonking/">s</a><a href="devel/">d</a>'
        suite = url.rstrip("/").split("/")[-2]
        if suite not in releases:
            raise OSError("404")
        version, codename = releases[suite]
        return f"Version: {version}\nCodename: {codename}\n".encode()

    monkeypatch.setattr(core, "fetch_bytes", fake_fetch)
    marked = set()
    found = profiles.discover_apt_releases("https://archive.invalid/ubuntu", prerelease_out=marked)
    assert found["26.04"] == "resolute" and found["26.10"] == "stonking"
    assert marked == {"stonking", "26.10"}
    # Callers that do not ask for classification make no extra alias probes.
    assert profiles.discover_apt_releases("https://archive.invalid/ubuntu")["24.04"] == "noble"


def test_release_page_beta_rows_are_classified_without_hiding_ga_rows():
    from profiles import extract_prerelease_versions, extract_versions
    page = ("<tr><td>RHEL 10.3 Beta</td></tr><tr><td>RHEL 10.2</td><td>GA</td></tr>"
            "<tr><td>RHEL 9.8</td></tr><p>RHEL 9.8 Beta was announced earlier</p>")
    pattern = r"RHEL\s+(\d+\.\d+)"
    assert extract_versions(page, pattern, "text")[:2] == ["10.3", "10.2"]
    assert extract_prerelease_versions(page, pattern, "text") == {"10.3"}
    assert extract_prerelease_versions(page, pattern, "href") == set()


def test_release_cache_round_trips_prerelease_identities():
    from feathered_app.application.discovery import _validated_release_cache
    data = {"schema": 2, "profiles": {"ubuntu": {
        "releases": ["26.10", "26.04"], "verified": ["26.04"], "prerelease": ["26.10", "stonking"],
        "codenames": {"26.10": "stonking"}}}}
    clean = _validated_release_cache(data, now=1e9)
    assert clean["profiles"]["ubuntu"]["prerelease"] == ["26.10", "stonking"]
    # Older caches without the field remain valid.
    del data["profiles"]["ubuntu"]["prerelease"]
    assert _validated_release_cache(data, now=1e9)["profiles"]["ubuntu"]["prerelease"] == []
    with pytest.raises(ValueError):
        _validated_release_cache({"schema": 2, "profiles": {"ubuntu": {"prerelease": ["bad value!"]}}})


def test_cache_release_state_updates_profile_even_if_write_fails(tmp_path):
    from feathered_app.application.discovery import DiscoveryMixin
    from profiles import PROFILES

    class Host(DiscoveryMixin):
        def __init__(self): self.logs = []
        def _log(self, message): self.logs.append(message)
        def _read_release_cache(self): return {"schema": 2, "profiles": {}}
        def _write_release_cache(self, data): raise OSError("disk full")

    host = Host()
    host._cache_release_state("ubuntu", ["26.10", "26.04"], ["26.04"], "test", True,
                              prerelease=["26.10"])
    profile = PROFILES["ubuntu"]
    assert profile.discovered_versions == ["26.10", "26.04"]
    assert profile.prerelease_versions == ["26.10"]
    assert any("disk full" in line for line in host.logs)
    # prerelease=None preserves the known flags.
    host._cache_release_state("ubuntu", ["26.04"], [], "operator", False)
    assert profile.prerelease_versions == ["26.10"]


def test_version_scan_ignores_init_and_target_incompatible_sources():
    from feathered_app.application.discovery import DiscoveryMixin

    def repo(name, role="docker", url="https://x.invalid/"):
        return SimpleNamespace(name=name, role=role, url=url, enabled=True)
    docker_ce, custom = repo("Docker CE"), repo("Custom docker")

    class Host(DiscoveryMixin):
        repo_rows = [docker_ce, custom]
        def _repository_target_compatible(self, r): return True
        def _init_repository_conflict(self, r): return "systemd only" if r is docker_ce else ""

    workload = SimpleNamespace(version_package="docker-ce", label="Docker Engine",
                               repository_role_for=lambda _n: "docker")
    assert Host()._version_scan_repositories(workload) == ([custom], "docker")
    Host.repo_rows = [docker_ce]
    with pytest.raises(RuntimeError, match="systemd only"):
        Host()._version_scan_repositories(workload)


@pytest.mark.parametrize("name,expected", [
    ("lz4-1:1.10.0-2-x86_64.pkg.tar.zst", True),
    ("foo-2:3.0-1.1-x86_64.pkg.tar.zst", True),   # decimal pkgrel (was truncated)
    ("foo-3.0-1.1-x86_64.pkg.tar.zst", False),     # no epoch: ordinary name
    ("javascript:alert(1)", False),
])
def test_arch_epoch_filenames_including_decimal_pkgrel(name, expected):
    from repository_paths import arch_package_basename, is_arch_epoch_filename, repo_relative_url
    assert is_arch_epoch_filename(name) is expected
    if expected:
        assert arch_package_basename(name) == name
        assert repo_relative_url("https://m.invalid/core/os/x86_64/", name) == \
            "https://m.invalid/core/os/x86_64/" + name
