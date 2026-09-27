"""Headless source-selection invariants and GUI adapter regression tests.

These run without Tk: the selection services have no application reference,
while existing application tests exercise rendering with real Tk and test doubles.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ast
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feathered_app.repository_selection import MirrorSelectionService, WorkloadRepositoryService
from feathered_app.repository_universe import RepositoryUniverse
from repository_config import RepoSpec


def repo(name: str, role: str = "dependency", *, url: str | None = None,
         tier: str = "additional", managed: bool = False, enabled: bool = True,
         priority: int = 50) -> RepoSpec:
    item = RepoSpec(name, url if url is not None else f"https://{name.lower().replace(' ', '-')}.example/repo/",
                    role, priority, enabled)
    item.source_tier = tier
    item.workload_profile_managed = managed
    return item


def tier(item: RepoSpec) -> str:
    return item.source_tier


@dataclass
class Template:
    name: str
    role: str
    priority: int = 50
    enabled: bool = True


def materialize(template: Template, target_tier: str) -> RepoSpec:
    return repo(template.name, template.role, tier=target_tier, priority=template.priority)


def templates(roles: list[str]):
    return [Template("Managed " + role, role) for role in roles]


def test_selection_services_do_not_depend_on_tk_or_the_application_shell():
    source = (ROOT / "feathered_app/repository_selection.py").read_text(encoding="utf-8")
    imports = [node for node in ast.walk(ast.parse(source))
               if isinstance(node, (ast.Import, ast.ImportFrom))]
    modules = [name.name for node in imports if isinstance(node, ast.Import) for name in node.names]
    modules += [node.module or "" for node in imports if isinstance(node, ast.ImportFrom)]
    assert not any(module.startswith(("tkinter", "app", "feathered_app.application"))
                   for module in modules)


def test_workload_sync_disables_only_irrelevant_managed_sources():
    unused = repo("Old", "old", tier="workload", managed=True)
    required = repo("Required", "new", tier="workload", managed=True)
    manual = repo("Manual", "old", tier="workload", managed=False)
    base = repo("Base", "dependency", tier="base")
    rows = [unused, required, manual, base]
    changes = WorkloadRepositoryService.synchronize(rows, required_roles={"new"}, tier_of=tier)
    assert changes == ("Old",)
    assert [r.enabled for r in rows] == [False, True, True, True]
    assert WorkloadRepositoryService.synchronize(rows, required_roles={"new"}, tier_of=tier) == ()


def test_exact_package_selection_is_scoped_to_concrete_source_identity():
    a = repo("Duplicate", "vendor", url="https://a.example", tier="workload", managed=True)
    b = repo("Duplicate", "vendor", url="https://b.example", tier="workload", managed=True)
    manual = repo("Manual", "other", enabled=False, tier="workload", managed=False)
    rows = [a, b, manual]
    assert a.source_identity != b.source_identity
    disabled = WorkloadRepositoryService.synchronize(
        rows, required_roles={"vendor"}, tier_of=tier,
        exact_source_ids={b.source_identity, manual.source_identity})
    assert disabled == ()  # workload mode alone logs disabled sources
    assert [r.enabled for r in rows] == [False, True, True]
    WorkloadRepositoryService.synchronize(rows, required_roles={"vendor"}, tier_of=tier,
                                          exact_source_ids=set())
    assert [r.enabled for r in rows] == [False, False, True]


def test_active_role_prefers_priority_then_name_then_url_and_requires_url():
    service = WorkloadRepositoryService()
    unavailable = repo("Lowest", "vendor", url="", priority=1)
    a = repo("Same", "vendor", url="https://z.example", priority=10)
    b = repo("Same", "vendor", url="https://a.example", priority=10)
    inactive = repo("Inactive", "vendor", enabled=False, priority=0)
    assert service.enabled_for_role([unavailable, a, b, inactive], "vendor") is b
    assert service.enabled_for_role([a], "unmatched") is None
    assert service.enabled_for_role([a], "") is None


def test_automatic_materialization_ignores_unconfigured_existing_source_and_is_idempotent():
    incomplete = repo("Operator source", "vendor", url="", tier="workload", managed=False)
    rows = [incomplete]
    service = WorkloadRepositoryService()
    changes = service.materialize_required(rows, ["vendor"], templates_for_role=templates,
                                           make_repository=materialize)
    assert changes == ("selected Managed vendor",)
    assert len(rows) == 2
    assert rows[1].enabled and rows[1].workload_profile_managed
    assert not incomplete.url
    assert service.materialize_required(rows, ["vendor"], templates_for_role=templates,
                                        make_repository=materialize) == ()
    assert len(rows) == 2


def test_automatic_materialization_enables_existing_usable_manual_source_without_replacing_url():
    manually_configured = repo("Manual", "vendor", url="https://internal.example/vendor", enabled=False)
    rows = [manually_configured]
    changes = WorkloadRepositoryService().materialize_required(
        rows, ["vendor"], templates_for_role=templates, make_repository=materialize)
    assert changes == ("enabled Manual",)
    assert rows == [manually_configured]
    assert manually_configured.url == "https://internal.example/vendor"
    assert not getattr(manually_configured, "workload_profile_managed", False)


def test_recommended_action_preserves_unconfigured_operator_source_for_editing():
    incomplete = repo("Manual", "vendor", url="", enabled=False)
    rows = [incomplete]
    changes = WorkloadRepositoryService().materialize_required(
        rows, ["vendor"], templates_for_role=templates,
        make_repository=materialize, recommended=True)
    assert changes == ("enabled Manual",)
    assert rows == [incomplete] and incomplete.enabled


def test_recommended_action_creates_managed_source_when_missing():
    rows: list[RepoSpec] = []
    service = WorkloadRepositoryService()
    assert service.materialize_required(rows, ["vendor"], templates_for_role=templates,
                                        make_repository=materialize, recommended=True) == ("added Managed vendor",)
    assert rows[0].source_tier == "workload" and rows[0].workload_profile_managed
    assert service.materialize_required(rows, ["vendor"], templates_for_role=templates,
                                        make_repository=materialize, recommended=True) == ()


def test_no_profile_template_does_not_invent_a_source():
    rows: list[RepoSpec] = []
    assert WorkloadRepositoryService().materialize_required(
        rows, ["unknown"], templates_for_role=lambda roles: [],
        make_repository=materialize) == ()
    assert rows == []


def test_mirror_reconcile_excludes_managed_sources_and_unconfigured_locations():
    base = repo("Base", tier="base", enabled=True)
    manual = repo("Manual", tier="workload", managed=False, enabled=False)
    auto = repo("Auto", tier="workload", managed=True, enabled=True)
    blank = repo("Blank", url="", tier="additional")
    state = MirrorSelectionService.reconcile(
        [base, manual, auto, blank], previous_selected=set(), previous_seen=set(), tier_of=tier)
    assert [(c.index, c.repository) for c in state.candidates] == [(0, base), (1, manual)]
    assert state.unconfigured == 1
    assert state.selected == frozenset({base.source_identity})
    assert state.seen == frozenset({base.source_identity, manual.source_identity})


def test_mirror_reconcile_preserves_explicit_disable_and_prunes_stale_sources():
    a = repo("A", enabled=True)
    b = repo("B", enabled=False)
    first = MirrorSelectionService.reconcile(
        [a, b], previous_selected=set(), previous_seen=set(), tier_of=tier)
    assert first.selected == {a.source_identity}
    # A was explicitly unchecked. Later refresh must not silently reselect it.
    second = MirrorSelectionService.reconcile(
        [a, b], previous_selected=set(), previous_seen=first.seen, tier_of=tier)
    assert not second.selected
    # After B is manually selected, removing B must purge its identity.
    third = MirrorSelectionService.reconcile(
        [a], previous_selected={b.source_identity}, previous_seen=second.seen, tier_of=tier)
    assert not third.selected and third.seen == {a.source_identity}
    assert MirrorSelectionService.reconcile(
        [a, b], previous_selected=set(), previous_seen=third.seen, tier_of=tier).selected == frozenset()


def test_mirror_duplicate_names_never_merge_distinct_sources():
    a = repo("Duplicate", url="https://a.example")
    b = repo("Duplicate", url="https://b.example")
    snapshot = MirrorSelectionService.reconcile(
        [a, b], previous_selected={a.source_identity},
        previous_seen={a.source_identity, b.source_identity}, tier_of=tier)
    assert len(snapshot.candidates) == 2
    assert snapshot.candidates[0].source_id != snapshot.candidates[1].source_id
    assert snapshot.selected == {a.source_identity}


@pytest.mark.parametrize("action,expected", [
    ("all", {"a", "b"}), ("none", set()), ("invert", {"b"}),
])
def test_mirror_bulk_applies_only_to_visible_sources(action, expected):
    service = MirrorSelectionService()
    assert service.bulk({"a", "hidden"}, {"a", "b"}, action) == expected


def test_mirror_toggle_mutates_only_explicit_selection():
    selections = {"a"}
    MirrorSelectionService.toggle(selections, "a")
    assert selections == set()
    MirrorSelectionService.toggle(selections, "b")
    assert selections == {"b"}


def test_source_universe_and_mirror_selection_reject_cross_workflow_leakage():
    universe = RepositoryUniverse()
    transaction = repo("Workload", "vendor", tier="workload", managed=True)
    mirror = repo("Mirror", tier="base")
    universe.set_rows([transaction], "transaction")
    universe.set_rows([mirror], "mirror")
    snapshot = MirrorSelectionService.reconcile(
        universe.rows("mirror"), previous_selected=set(), previous_seen=set(), tier_of=tier)
    assert snapshot.selected == {mirror.source_identity}
    WorkloadRepositoryService.synchronize(
        universe.rows("transaction"), required_roles=set(), tier_of=tier)
    assert not transaction.enabled
    assert universe.rows("mirror") == [mirror] and mirror.enabled
