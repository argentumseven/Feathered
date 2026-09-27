"""Selection state is owned outside the GUI and remains legacy-compatible."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from feathered_app.repository_selection import MirrorSelectionService
from feathered_app.source_selection_state import (
    SourceSelectionMixin, SourceSelectionState, selection_value,
)
from repository_config import RepoSpec


def repo(name: str, url: str, *, enabled: bool = True) -> RepoSpec:
    return RepoSpec(name, url, "dependency", 50, enabled)


def test_selection_state_does_not_import_tk_or_app():
    source = (Path(__file__).resolve().parents[1] /
              "feathered_app/source_selection_state.py").read_text()
    modules = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
    assert not any(name.startswith(("tkinter", "app", "feathered_app.application",
                                    "feathered_app.ui")) for name in modules)


def test_partial_app_has_no_source_selection_side_effects():
    import app

    shell = object.__new__(app.App)
    assert shell.__dict__ == {}
    assert selection_value(shell, "selected_packages", ()) == ()
    with pytest.raises(AttributeError, match="selected_packages"):
        _ = object.__getattribute__(shell, "selected_packages")
    assert shell.__dict__ == {}
    selection = shell.source_selection
    assert isinstance(selection, SourceSelectionState)
    assert shell.source_selection is selection
    assert shell.selected_packages == []


def test_public_legacy_fields_are_owned_by_single_state_object():
    import app

    shell = object.__new__(app.App)
    roots = [object(), object()]
    shell.selected_packages = roots
    shell.mirror_repos = {"source-one"}
    shell._mirror_seen = {"source-one", "source-two"}
    shell._mirror_iid_to_source_identity = {"row-one": "source-one"}
    shell._mirror_iid_to_repo_index = {"row-one": 12}
    assert not any(name in shell.__dict__ for name in (
        "selected_packages", "mirror_repos", "_mirror_seen",
        "_mirror_iid_to_source_identity", "_mirror_iid_to_repo_index"))
    state = shell.source_selection
    assert state.selected_packages is roots
    assert state.mirror_repos is shell.mirror_repos
    assert state.mirror_seen is shell._mirror_seen
    assert state.mirror_iid_to_source_identity is shell._mirror_iid_to_source_identity
    assert state.mirror_iid_to_repo_index is shell._mirror_iid_to_repo_index
    shell.app_state.selection.mirror_repos.add("source-two")
    assert state.mirror_repos == {"source-one", "source-two"}
    shell.app_state.analysis.selected_packages = ["different-root"]
    assert state.selected_packages == ["different-root"]


def test_partially_constructed_host_migrates_legacy_dictionary_fields():
    class Shell(SourceSelectionMixin):
        pass

    shell = Shell()
    shell.__dict__["selected_packages"] = ["injected"]
    shell.__dict__["mirror_repos"] = {"selected"}
    assert selection_value(shell, "selected_packages") == ["injected"]
    assert shell.source_selection.mirror_repos == {"selected"}
    assert "mirror_repos" not in vars(shell)
    # Existing embedders writing __dict__ after creation are also supported.
    shell.__dict__["mirror_repos"] = {"overridden"}
    assert selection_value(shell, "mirror_repos", set()) == {"overridden"}
    assert shell.mirror_repos == {"overridden"}
    assert "mirror_repos" not in vars(shell)


def test_direct_selection_descriptor_read_migrates_multiple_injected_fields():
    """Regression: constructing state must not pop a legacy key twice."""
    class Shell(SourceSelectionMixin):
        pass

    host = Shell()
    host.__dict__["selected_packages"] = ["root"]
    host.__dict__["mirror_repos"] = {"source"}
    assert host.selected_packages == ["root"]
    assert host.mirror_repos == {"source"}
    assert "selected_packages" not in vars(host)
    assert "mirror_repos" not in vars(host)


def test_headless_host_without_state_keeps_existing_build_spec_contract():
    fake = SimpleNamespace(selected_packages=["root"], mirror_repos={"source"})
    assert selection_value(fake, "selected_packages", ()) == ["root"]
    assert selection_value(fake, "mirror_repos", ()) == {"source"}
    assert selection_value(SimpleNamespace(), "selected_packages", ()) == ()


def test_separate_selection_instances_do_not_share_sets_or_mappings():
    left, right = SourceSelectionState(), SourceSelectionState()
    left.selected_packages.append("pkg")
    left.mirror_repos.add("repo")
    left.mirror_iid_to_source_identity["row"] = "repo"
    assert right.selected_packages == []
    assert right.mirror_repos == set()
    assert right.mirror_iid_to_source_identity == {}


def test_refresh_preserves_explicit_deselection_when_names_collide():
    a, b = repo("Same name", "https://a.example/"), repo("Same name", "https://b.example/")
    state = SourceSelectionState()
    state.seed_mirror([a, b])
    previous = MirrorSelectionService.reconcile(
        [a, b], previous_selected=state.mirror_repos,
        previous_seen=state.mirror_seen, tier_of=lambda _r: "additional")
    state.commit_mirror_refresh(previous, ["row-0", "row-1"])
    assert state.mirror_iid_to_repo_index == {"row-0": 0, "row-1": 1}
    state.toggle_mirror_row("row-1")
    assert state.mirror_repos == {a.source_identity}
    refreshed = MirrorSelectionService.reconcile(
        [a, b], previous_selected=state.mirror_repos,
        previous_seen=state.mirror_seen, tier_of=lambda _r: "additional")
    state.commit_mirror_refresh(refreshed, ["new-a", "new-b"])
    assert state.source_for_row("new-b") == b.source_identity
    assert state.index_for_row("new-b") == 1
    assert state.mirror_repos == {a.source_identity}


def test_refresh_rejects_bad_row_mapping_without_partial_state_update():
    state = SourceSelectionState(mirror_repos={"old"}, mirror_seen={"old"},
                                 mirror_iid_to_source_identity={"old-row": "old"})
    a = repo("A", "https://a.example")
    b = repo("B", "https://b.example")
    snapshot = MirrorSelectionService.reconcile(
        [a, b], previous_selected=state.mirror_repos,
        previous_seen=state.mirror_seen, tier_of=lambda _r: "base")
    with pytest.raises(ValueError, match="uniquely"):
        state.commit_mirror_refresh(snapshot, ["duplicate", "duplicate"])
    assert state.mirror_repos == {"old"}
    assert state.mirror_seen == {"old"}
    assert state.mirror_iid_to_source_identity == {"old-row": "old"}
    with pytest.raises(ValueError):
        state.commit_mirror_refresh(snapshot, ["missing-row"])


def test_bulk_and_reset_actions_are_scoped_to_visible_mirror_rows():
    state = SourceSelectionState(
        selected_packages=["root"], mirror_repos={"hidden"},
        mirror_iid_to_source_identity={"a": "first", "b": "second"})
    state.bulk_mirror_rows(["a", "b"], "all")
    assert state.mirror_repos == {"first", "second"}
    state.bulk_mirror_rows(["a", "b"], "invert")
    assert state.mirror_repos == set()
    state.bulk_mirror_rows(["a", "b"], "invert")
    assert state.mirror_repos == {"first", "second"}
    state.remove_mirror_source("first", still_configured=True)
    assert "first" in state.mirror_repos
    state.remove_mirror_source("first", still_configured=False)
    assert "first" not in state.mirror_repos
    state.reset_mirror_for_target()
    assert state.mirror_repos == set()
    assert state.mirror_seen == set()
    assert state.mirror_iid_to_source_identity == {}
    assert state.selected_packages == ["root"]


def test_new_target_reseeding_ignores_unconfigured_sources_and_does_not_toggle_repository():
    incomplete = repo("Incomplete", "")
    disabled = repo("Disabled", "https://disabled.example/", enabled=False)
    enabled = repo("Enabled", "https://enabled.example/")
    state = SourceSelectionState(mirror_repos={"stale"}, mirror_seen={"stale"})
    state.seed_mirror([incomplete, disabled, enabled])
    assert state.mirror_repos == {enabled.source_identity}
    assert not disabled.enabled
    assert incomplete.enabled
    assert state.mirror_seen == set()


def test_capture_real_app_selection_from_new_state():
    import app
    from build_spec import capture

    shell = object.__new__(app.App)
    # Existing capture tests cover all other controls on lightweight hosts;
    # the state-backed field here is exercised by the application's descriptor.
    package = SimpleNamespace(
        name="curl", evr_text="8.0-1", arch="x86_64",
        repo=SimpleNamespace(name="base", role="dependency", source_identity="source-0"))
    shell.selected_packages = [package]
    shell.mirror_repos = {"source-0"}
    shell._mirror_layout = lambda: None
    shell._merge_policy = lambda: None
    assert selection_value(shell, "selected_packages") == [package]
    assert "selected_packages" not in shell.__dict__
    spec = capture(shell)
    assert len(spec.content.exact_packages) == 1
    assert spec.content.exact_packages[0].name == "curl"
    assert spec.mirror.selected_repositories == ("source-0",)
