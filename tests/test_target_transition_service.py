"""Headless target transition contracts and the SourcesMixin boundary."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from feathered_app.application.sources import SourcesMixin
from feathered_app.target_transition import TargetTransitionService, WorkloadControls
from repository_config import RepoSpec


def make_repo(name: str, url: str, *, role: str = "dependency", tier: str = "base",
              managed: bool = False, enabled: bool = True, priority: int = 50) -> RepoSpec:
    repo = RepoSpec(name, url, role, priority, enabled)
    repo.source_tier = tier
    repo.workload_profile_managed = managed
    return repo


def test_new_service_imports_no_gui_or_application_mixins():
    path = Path(__file__).resolve().parents[1] / "feathered_app/target_transition.py"
    tree = ast.parse(path.read_text(encoding="utf8"))
    imported = [node.module or "" for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)]
    imported += [alias.name for node in ast.walk(tree)
                 if isinstance(node, ast.Import) for alias in node.names]
    assert not any(name.startswith(("tkinter", "app", "feathered_app.application",
                                    "feathered_app.ui")) for name in imported)


def test_profile_switch_remembers_only_releases_supported_by_destination():
    state = TargetTransitionService()
    assert state.select_profile(profile="rocky", known=["9.5", "9.4"], current="9.5") == "9.5"
    assert state.select_profile(profile="debian", known=["trixie"], current="9.4") == "trixie"
    assert state.remembered_releases == {"rocky": "9.4"}
    assert state.select_profile(profile="rocky", known=["9.5", "9.4"], current="trixie") == "9.4"


def test_empty_discovery_clears_release_instead_of_inheriting_old_target():
    state = TargetTransitionService(current_profile="rhel")
    assert state.select_profile(profile="ubuntu", known=[], current="9.5") == ""
    assert state.remembered_releases["rhel"] == "9.5"
    assert state.select_profile(profile="ubuntu", known=["24.04"], current="") == "24.04"


def test_invalid_saved_release_is_not_reintroduced_after_refresh():
    state = TargetTransitionService(remembered_releases={"debian": "bullseye"})
    assert state.select_profile(profile="debian", known=["trixie"], current="rocky") == "trixie"
    assert state.select_profile(profile="debian", known=["trixie"], current="trixie") == "trixie"


def test_independent_sessions_do_not_share_remembered_profiles():
    left = TargetTransitionService()
    right = TargetTransitionService()
    left.select_profile(profile="arch", known=["rolling"], current="rolling")
    left.select_profile(profile="debian", known=["trixie"], current="rolling")
    assert right.remembered_releases == {}
    assert right.current_profile is None


def test_switch_workloads_restores_versions_for_exact_target_and_workload():
    state = TargetTransitionService()
    docker = ("rhel", "9.5", "x86_64", "docker")
    nginx = ("rhel", "9.5", "x86_64", "nginx")
    selected = WorkloadControls("Latest", ("Latest",), "1.30")
    assert state.switch_workload(docker, current=selected, has_version_axis=True) == selected
    pinned = WorkloadControls("28.1", ("Latest", "28.1"), "1.30")
    assert state.switch_workload(docker, current=pinned, has_version_axis=True) is None
    assert state.switch_workload(nginx, current=pinned, has_version_axis=False) == WorkloadControls(
        "Follows repositories", (), "1.30")
    assert state.switch_workload(docker, current=WorkloadControls("Follows repositories", (), "1.31"),
                                 has_version_axis=True) == pinned


def test_changed_release_or_architecture_never_reuses_old_version_choice():
    state = TargetTransitionService()
    old = ("arch", "rolling", "x86_64", "docker")
    new_release = ("arch", "new-snapshot", "x86_64", "docker")
    new_arch = ("arch", "rolling", "aarch64", "docker")
    state.switch_workload(old, current=WorkloadControls("Latest", ("Latest",), "1.29"),
                          has_version_axis=True)
    current = WorkloadControls("28.1", ("Latest", "28.1"), "1.30")
    assert state.switch_workload(new_release, current=current, has_version_axis=True).version == "Latest"
    assert state.switch_workload(new_arch, current=current, has_version_axis=True).version == "Latest"
    assert state.switch_workload(old, current=current, has_version_axis=True) == current


def test_same_workload_context_does_not_erase_edited_controls():
    state = TargetTransitionService()
    target = ("arch", "rolling", "x86_64", "docker")
    state.switch_workload(target, current=WorkloadControls("Latest", ("Latest",), "1.30"),
                          has_version_axis=True)
    assert state.switch_workload(target, current=WorkloadControls("27.0", ("27.0",), "1.31"),
                                 has_version_axis=True) is None
    assert state.workload_versions == {}


def test_versionless_workload_does_not_restore_stale_version_axis():
    context = ("arch", "rolling", "x86_64", "nginx")
    state = TargetTransitionService(workload_versions={
        context: WorkloadControls("29.1", ("29.1",), "1.29")})
    assert state.switch_workload(context,
                                 current=WorkloadControls("Latest", ("Latest",), "1.30"),
                                 has_version_axis=False) == WorkloadControls(
                                     "Follows repositories", (), "1.29")


def test_missing_target_discards_only_base_and_managed_repository_rows():
    base = make_repo("core", "https://core.example", tier="base")
    managed = make_repo("docker", "https://docker.example", tier="workload", managed=True)
    manual_workload = make_repo("handmade", "https://manual.example", tier="workload")
    additional = make_repo("optional", "https://extra.example", tier="additional")
    rows = [base, managed, manual_workload, additional]
    tier = lambda item: item.source_tier
    assert TargetTransitionService.transaction_rows_for_target(
        rows, has_release=False, tier_of=tier) == [manual_workload, additional]
    assert TargetTransitionService.transaction_rows_for_target(
        rows, has_release=True, tier_of=tier) == [managed, manual_workload, additional]
    assert rows == [base, managed, manual_workload, additional]


def test_retarget_uses_role_and_priority_not_duplicate_display_names():
    managed = make_repo("Duplicate", "https://old.example", tier="workload",
                        role="docker", managed=True)
    manual = make_repo("Duplicate", "https://operator.example", tier="workload", role="docker")
    unavailable = make_repo("off", "https://off.example", tier="workload",
                            role="docker", priority=1, enabled=False)
    preferred = make_repo("Duplicate", "https://correct.example", tier="workload",
                          role="docker", priority=40)
    preferred.target_release = "rolling"
    preferred.evidence_suggestions = ["https://evidence.example"]
    TargetTransitionService.retarget_managed_workload_rows(
        [managed, manual], templates=[unavailable, preferred], tier_of=lambda r: r.source_tier)
    assert managed.url == "https://correct.example"
    assert managed.priority == 40
    assert managed.target_release == "rolling"
    assert managed.evidence_suggestions == ["https://evidence.example"]
    assert manual.url == "https://operator.example"
    assert manual.name == "Duplicate"
    preferred.evidence_suggestions.append("other")
    assert managed.evidence_suggestions == ["https://evidence.example"]


def test_absent_managed_role_is_disabled_without_disabling_manual_source():
    managed = make_repo("old", "https://old.example", tier="workload",
                        role="obsolete", managed=True)
    manual = make_repo("manual", "https://manual.example", tier="workload", role="obsolete")
    TargetTransitionService.retarget_managed_workload_rows(
        [managed, manual], templates=[], tier_of=lambda r: r.source_tier)
    assert managed.enabled is False
    assert managed.url == "https://old.example"  # displayed, but not active
    assert manual.enabled is True


def test_legacy_mixin_host_migrates_target_state_once():
    class Host(SourcesMixin):
        pass
    host = Host()
    context = ("rhel", "9.5", "x86_64", "docker")
    host.__dict__.update({
        "_release_selections": {"rhel": "9.5"},
        "_release_selection_profile": "rhel",
        "_content_version_states": {context: ("27.1", ("Latest", "27.1"), "1.30")},
        "_content_version_context": context,
        "_last_workload_key": "docker",
    })
    state = host._target_transition()
    assert state.remembered_releases == {"rhel": "9.5"}
    assert state.current_profile == "rhel"
    assert state.workload_versions[context] == WorkloadControls("27.1", ("Latest", "27.1"), "1.30")
    assert state.current_workload == context
    assert state.last_workload_key == "docker"
    assert host._target_transition() is state
    assert "_content_version_states" not in host.__dict__


def test_compatibility_host_keeps_gui_free_target_services_on_demand():
    class Host(SourcesMixin):
        pass
    host = Host()
    assert host.__dict__ == {}
    assert host._target_transition() is host._target_transition()
    assert list(host.__dict__) == ["_target_transition_service"]
