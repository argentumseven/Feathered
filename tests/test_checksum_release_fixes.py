"""Regressions for checksum inspection and responsive target selection."""
from __future__ import annotations

import copy
import hashlib
import lzma
import queue
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import apt_core
from checksum_inspection import inspect_checksums
from core import Cancelled, Reporter, RepoSpec
from feathered_app.application import discovery
from feathered_app.application.discovery import DiscoveryMixin
from feathered_app.application.operations import OperationsMixin
from feathered_app.application.provenance import ProvenanceMixin
from feathered_app.application.repositories import RepositoriesMixin
from profiles import PROFILES
from release_seed import RELEASE_SEEDS
from test_target_release_transition import target_host


@pytest.fixture
def ubuntu_archive(monkeypatch):
    packages = ("Package: demo\nVersion: 1\nArchitecture: amd64\n"
                "Filename: pool/main/d/demo/demo_1_amd64.deb\nSize: 4\n"
                f"SHA256: {hashlib.sha256(b'demo').hexdigest()}\n\n").encode()
    raw = lzma.compress(packages)
    digest = hashlib.sha256(raw).hexdigest()
    path = "main/binary-amd64/Packages.xz"
    root = "https://archive.example/ubuntu/dists/noble/"
    release = ("Origin: Ubuntu\nSuite: noble\nCodename: noble\nVersion: 24.04\n"
               "Architectures: amd64\nComponents: main\nAcquire-By-Hash: yes\n"
               f"SHA256:\n {digest} {len(raw)} {path}\n").encode()
    pinned = root + "main/binary-amd64/by-hash/SHA256/" + digest
    canonical = root + path
    objects = {root + "InRelease": release, pinned: raw, canonical: b"stale mirror"}
    calls = []

    def fetch(url, *_args, **_kwargs):
        calls.append(url)
        value = objects.get(url, FileNotFoundError(url))
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(apt_core, "fetch_bytes", fetch)
    repo = RepoSpec("Ubuntu", "https://archive.example/ubuntu", repo_format="apt",
                    suite="noble", components="main", verification_strategy="checksum-available")
    return SimpleNamespace(repo=repo, objects=objects, calls=calls, raw=raw,
                           pinned=pinned, canonical=canonical)


def test_ubuntu_inspection_uses_release_pinned_index_during_mirror_update(ubuntu_archive):
    a = ubuntu_archive
    result = inspect_checksums(a.repo, {"amd64"}, Reporter(), apt_core.load_repository)
    assert result.algorithms == ("sha256",) and result.package_count == 1
    assert a.pinned in a.calls and a.canonical not in a.calls


def test_missing_by_hash_falls_back_to_verified_canonical_index(ubuntu_archive):
    a = ubuntu_archive
    del a.objects[a.pinned]
    a.objects[a.canonical] = a.raw
    packages = apt_core._load_repository_once(a.repo, {"amd64"}, Reporter())
    assert [p.name for p in packages] == ["demo"]
    assert packages[0].verification.index_digest_verified
    assert a.calls[-2:] == [a.pinned, a.canonical]


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("damage", ["size", "sha256"])
def test_damaged_pinned_or_fallback_index_is_rejected(ubuntu_archive, fallback, damage):
    a = ubuntu_archive
    bad = b"short" if damage == "size" else bytes([a.raw[0] ^ 1]) + a.raw[1:]
    a.objects[a.pinned] = FileNotFoundError("not replicated") if fallback else bad
    a.objects[a.canonical] = bad if fallback else a.raw
    with pytest.raises(RuntimeError, match="metadata (size|SHA256) mismatch"):
        apt_core._load_repository_once(a.repo, {"amd64"}, Reporter())
    assert (a.canonical in a.calls) == fallback


def test_cancelled_pinned_fetch_does_not_fall_back(ubuntu_archive):
    a = ubuntu_archive
    a.objects[a.pinned] = Cancelled("cancelled")
    with pytest.raises(Cancelled):
        apt_core._load_repository_once(a.repo, {"amd64"}, Reporter())
    assert a.canonical not in a.calls


@pytest.mark.parametrize("fails", [False, True])
def test_checksum_worker_never_reads_widgets_or_mutates_repository(monkeypatch, fails):
    main_thread = threading.get_ident()
    repo = RepoSpec("Ubuntu", "https://example.test", repo_format="apt", suite="noble",
                    keyring="operator.gpg", evidence_urls=["https://peer.test"],
                    verification_strategy="enhanced", digest_preference="sha512")
    repo.trust = SimpleNamespace(notes=["original"])
    before = copy.deepcopy(repo.__dict__)

    def ui_only(value):
        assert threading.get_ident() == main_thread, "worker accessed UI state"
        return value

    def load(probe, arches, reporter):
        assert threading.get_ident() != main_thread
        assert arches == {"amd64"}
        assert probe.keyring == "" and probe.evidence_urls == []
        assert probe.verification_strategy == "checksum-available"
        assert probe.digest_preference == "auto"
        probe.trust.notes.append("probe only")
        if fails:
            raise RuntimeError("repository unavailable")
        return [SimpleNamespace(digests={"sha256": "a" * 64})]

    monkeypatch.setattr(apt_core, "load_repository", load)
    host = SimpleNamespace(arch_var=SimpleNamespace(get=lambda: ui_only("amd64")),
                           _is_arch=lambda: ui_only(False), _is_deb=lambda: ui_only(True),
                           events=queue.Queue(), _log=Mock())
    host._checksum_inspection_loader = lambda repo: RepositoriesMixin._checksum_inspection_loader(host, repo)
    finish = Mock()
    RepositoriesMixin._start_checksum_inspection(host, repo, finish)
    kind, callback, result, error = host.events.get(timeout=5)
    assert kind == "checksum_inspection_finished" and callback is finish
    finish.assert_not_called()
    assert result == ([] if fails else ["sha256"])
    assert error == ("repository unavailable" if fails else "")
    assert repo.__dict__ == before
    logs = "\n".join(str(call.args[0]) for call in host._log.call_args_list)
    assert ("checksum inspection failed" if fails else "checksum inspection read 1 package records") in logs


def test_coverage_counts_distinguish_exact_fields_from_minimum_strength():
    repo = RepoSpec("mixed", "https://example.test")
    packages = [SimpleNamespace(digests=digests) for digests in (
        {"sha256": "a" * 64}, {"sha512": "b" * 128}, {},
        {"sha256": "c" * 64, "sha384": "d" * 96})]
    coverage = inspect_checksums(repo, {"amd64"}, Reporter(), lambda *_: packages)
    assert coverage.algorithms == ("sha512", "sha384", "sha256")
    assert dict(coverage.counts) == {
        "total": 4, "auto": 3, "sha256": 3, "sha384": 2, "sha512": 1,
        "exact_sha256": 2, "exact_sha384": 1, "exact_sha512": 1}


@pytest.mark.parametrize("fails", [False, True])
@pytest.mark.parametrize("alive", [False, True])
def test_main_panel_inspection_queues_all_ui_work_and_releases_operation(monkeypatch, fails, alive):
    main_thread = threading.get_ident()

    def ui_only(*_args, **_kwargs):
        assert threading.get_ident() == main_thread, "worker accessed a widget"

    widget = SimpleNamespace(set=ui_only, configure=ui_only)
    repo = RepoSpec("Ubuntu", "https://example.test", repo_format="apt", suite="noble")

    def load(*_args):
        assert threading.get_ident() != main_thread
        if fails:
            raise RuntimeError("network unavailable")
        return [SimpleNamespace(digests={"sha256": "a" * 64})]

    monkeypatch.setattr(apt_core, "load_repository", load)
    host = SimpleNamespace(
        events=queue.Queue(), active_operation="checksum-inspection", _log=Mock(),
        arch_var=SimpleNamespace(get=lambda: (ui_only(), "amd64")[1]),
        _is_arch=lambda: (ui_only(), False)[1], _is_deb=lambda: (ui_only(), True)[1],
        _enabled_provenance_repos=lambda: [repo], _busy=lambda: False,
        _claim_operation=lambda *_args, **_kwargs: True,
        prov_detected_var=widget, prov_inspect_progress=widget,
        prov_inspect_status_var=widget, progress_var=widget,
        _operation_status=ui_only, _lock_operation_controls=ui_only, after=ui_only,
        winfo_exists=lambda: (ui_only(), alive)[1],
        _refresh_provenance_editor=ui_only, _release_operation=Mock(side_effect=ui_only))
    host._checksum_inspection_loader = lambda repo: RepositoriesMixin._checksum_inspection_loader(host, repo)
    host._provenance_repo_cache_key = lambda repo: ProvenanceMixin._provenance_repo_cache_key(host, repo)
    host._drain_events = lambda: OperationsMixin._drain_events(host)
    ProvenanceMixin._inspect_enabled_provenance_metadata(host)
    pending = []
    while not pending or pending[-1][0] != "checksum_inspection_finished":
        pending.append(host.events.get(timeout=5))
    host._release_operation.assert_not_called()
    for event in pending:
        host.events.put(event)
    host._drain_events()
    assert host._release_operation.call_count == 1
    assert host._release_operation.call_args.kwargs["outcome"] == ("failed" if fails else "idle")
    if alive:
        key = host._provenance_repo_cache_key(repo)
        if fails:
            assert host._provenance_inspection_errors == {key: "network unavailable"}
        else:
            assert host._provenance_detected_cache[key] == ["sha256"]
            assert host._provenance_digest_coverage_cache[key]["sha256"] == 1
    assert not any("UI event handler failed" in str(call) for call in host._log.call_args_list)


@pytest.fixture
def cold_profiles(monkeypatch):
    profiles = copy.deepcopy(PROFILES)
    for profile in profiles.values():
        profile.discovered_versions = []
        profile.verified_versions = []
        profile.release_codenames = {}
        profile.release_observed_at = 0.0
    monkeypatch.setattr(discovery, "PROFILES", profiles)
    return profiles


def test_cold_start_supplies_numbered_releases_and_matching_codenames(cold_profiles):
    host = SimpleNamespace(_read_release_cache=lambda: {"profiles": {}})
    DiscoveryMixin._load_cached_releases(host)
    for key in RELEASE_SEEDS:
        profile = cold_profiles[key]
        assert profile.known_versions()
        assert profile.release_observed_at == 0 and not profile.verified_versions
    ubuntu = cold_profiles["ubuntu"]
    assert ubuntu.codename("26.04") == "resolute"
    assert ubuntu.codename("24.04") == "noble"


def test_saved_release_observation_wins_over_bundled_seed(cold_profiles):
    host = SimpleNamespace(_read_release_cache=lambda: {"profiles": {"ubuntu": {
        "releases": ["24.04"], "verified": ["24.04"], "codenames": {"24.04": "noble"},
        "observed_at": 12345, "source": "saved observation"}}})
    DiscoveryMixin._load_cached_releases(host)
    ubuntu = cold_profiles["ubuntu"]
    assert ubuntu.known_versions() == ["24.04"]
    assert ubuntu.release_observed_at == 12345 and ubuntu.release_source == "saved observation"


def test_slow_previous_discovery_does_not_block_new_distribution(monkeypatch, cold_profiles):
    pending = []

    class DeferredThread:
        def __init__(self, target, daemon):
            self.target = target

        def start(self):
            pending.append(self.target)

    monkeypatch.setattr(discovery.threading, "Thread", DeferredThread)
    host = SimpleNamespace(_profile=lambda: cold_profiles["ubuntu"], _busy=lambda: False)
    DiscoveryMixin._auto_refresh_releases(host)
    DiscoveryMixin._auto_refresh_releases(host)
    host._profile = lambda: cold_profiles["debian"]
    DiscoveryMixin._auto_refresh_releases(host)
    assert len(pending) == 2
    DiscoveryMixin._finish_auto_release_refresh(host, "ubuntu")
    assert host._auto_release_refresh_profiles == {"debian"}
    assert host._auto_release_refresh_inflight
    DiscoveryMixin._finish_auto_release_refresh(host, "debian")
    assert not host._auto_release_refresh_inflight


def test_switching_back_restores_valid_selection_without_blank_intermediate_state():
    host = target_host("ubuntu", ["26.04", "24.04"])
    ubuntu = host._profile()
    debian = copy.deepcopy(PROFILES["debian"])
    debian.discovered_versions = ["trixie"]
    host._release_changed = Mock()
    host._profile_changed()
    host.release_var.set("24.04")
    observed = []
    original_set = host.release_var.set
    host.release_var.set = lambda value: (observed.append(value), original_set(value))
    host._profile = lambda: debian
    host._profile_changed()
    assert host.release_var.get() == "trixie"
    host._profile = lambda: ubuntu
    host._profile_changed()
    assert host.release_var.get() == "24.04"
    assert observed == ["trixie", "24.04"]
    assert host.after.call_args.args[0] == 0


def test_event_pump_ignores_previous_distribution_and_finishes_inspection_on_ui_thread():
    host = SimpleNamespace(events=queue.Queue(), active_operation=None,
                           _profile=lambda: SimpleNamespace(key="debian"),
                           _set_release_choices=Mock(), _log=Mock(), after=Mock())
    host._drain_events = lambda: OperationsMixin._drain_events(host)
    main_thread = threading.get_ident()
    finished = []

    def finish(result, error):
        assert threading.get_ident() == main_thread
        finished.append((result, error))

    host.events.put(("profile_versions", "ubuntu", ["24.04"]))
    host.events.put(("profile_versions", "debian", ["trixie"]))
    host.events.put(("checksum_inspection_finished", finish, ["sha256"], ""))
    host._drain_events()
    host._set_release_choices.assert_called_once_with(["trixie"])
    assert finished == [(["sha256"], "")]
    assert not host._log.called
