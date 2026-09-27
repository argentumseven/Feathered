"""Repository status and pane routing contracts without a Tk interpreter."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from acquisition_model import AcquisitionIntent
from feathered_app.repository_status import RepositoryStatusService
from feathered_app.repository_workflow import RepositoryWorkflowService
from repository_config import RepoSpec


def repo(name: str, *, role: str = "dependency", priority: int = 50,
         url: str | None = None, enabled: bool = True,
         tier: str = "base") -> RepoSpec:
    r = RepoSpec(name, url if url is not None else f"https://{name.lower()}.example/repo/",
                 role, priority, enabled)
    r.source_tier = tier
    return r


def rows(items, **kwargs):
    return RepositoryStatusService.rows(items, **kwargs)


def test_source_status_and_routing_have_no_ui_or_app_imports():
    for module in ("repository_status", "repository_workflow"):
        path = Path(__file__).resolve().parents[1] / "feathered_app" / (module + ".py")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        imports += [alias.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                    for alias in n.names]
        assert not any(m.startswith(("tkinter", "app", "feathered_app.application",
                                     "feathered_app.ui")) for m in imports)


def test_mirror_status_distinguishes_same_named_repositories_and_redacts_credentials():
    first = repo("Same", url="https://user:SECRET@a.example/core?token=SECRET_TOKEN")
    second = repo("Same", url="https://b.example/core")
    result = rows([first, second], mode="mirror",
                  selected_mirror_ids={first.source_identity, second.source_identity})
    assert len(result) == 2
    assert len({item[0] for item in result}) == 2
    assert [item[1] for item in result] == ["Ready", "Ready"]
    assert "SECRET" not in result[0][3]
    assert "a.example/core" in result[0][3]


def test_mirror_status_allows_identical_origin_with_distinct_display_names():
    a = repo("Primary", url="https://example.test/core")
    b = repo("Alias", url="https://example.test/core")
    assert a.source_identity == b.source_identity
    result = rows([a, b], mode="mirror", selected_mirror_ids={a.source_identity})
    assert len(result) == 2 and len({entry[0] for entry in result}) == 2


def test_mirror_status_omits_unselected_and_unconfigured_entries():
    a = repo("A", enabled=False)
    b = repo("B", url="")
    c = repo("C")
    assert rows([a, b, c], mode="mirror",
                selected_mirror_ids={a.source_identity, b.source_identity}) == [
                    (f"mirror:0:{a.source_identity}", "Ready", "A", a.url, "ready")]
    assert rows([a, b, c], mode="mirror", selected_mirror_ids=set()) == []


def test_exact_status_matches_concrete_repository_identity_not_display_name():
    selected = repo("Duplicate", url="https://one.example/core", enabled=False)
    other = repo("Duplicate", url="https://two.example/core")
    packages = [SimpleNamespace(name="nginx", repo=selected)]
    status = rows([selected, other], mode="exact", exact_packages=packages)
    assert len(status) == 1
    assert status[0][1] == "Disabled"
    selected.enabled = True
    assert rows([selected, other], mode="exact", exact_packages=packages)[0][1] == "Ready"


def test_exact_status_preserves_one_row_per_root_from_same_source():
    source = repo("core")
    roots = [SimpleNamespace(name="nginx", repo=source),
             SimpleNamespace(name="curl", repo=source)]
    result = rows([source], mode="exact", exact_packages=roots)
    assert len(result) == 2
    assert result[0][0] != result[1][0]


def test_status_role_priority_and_disabled_state():
    first = repo("Alpha", role="vendor", priority=20)
    low = repo("Lowest", role="vendor", priority=1, enabled=False)
    status = rows([first, low], mode="workload", required_roles=["vendor"])
    assert status == [("role:vendor", "Ready", "Alpha", first.url, "ready")]
    first.enabled = False
    assert rows([first, low], mode="workload", required_roles=["vendor"])[0] == (
        "role:vendor", "Disabled", "Lowest", low.url, "disabled")


def test_vendor_repository_status_never_displays_authentication_secrets():
    vendor = repo("Vendor", role="vendor", url="https://user:SECRET@repo.example/path?token=SECRET_TOKEN")
    configured = rows([vendor], mode="workload", required_roles=["vendor"])
    proposed = rows([], mode="workload", required_roles=["vendor"],
                    templates_by_role={"vendor": [vendor]})
    assert "SECRET" not in configured[0][3]
    assert "SECRET" not in proposed[0][3]
    vendor.enabled = False
    assert "SECRET" not in rows([vendor], mode="workload", required_roles=["vendor"])[0][3]


def test_missing_role_prefers_enabled_template_then_priority():
    off = repo("Off", role="vendor", priority=1, enabled=False)
    on = repo("On", role="vendor", priority=9)
    status = rows([], mode="workload", required_roles=["vendor", "vendor", "missing"],
                  templates_by_role={"vendor": [off, on]})
    assert status == [
        ("role:vendor", "Available to add", "On", on.url, "available"),
        ("role:missing", "Source needed", "No profile source defined", "Configure manually", "missing")]


def test_distribution_sources_require_an_enabled_base_and_limit_summary_to_four():
    source_plan = [("nginx", "distribution", "")]
    base = [repo(f"B{i}", priority=i, tier="base") for i in range(6)]
    supplemental = repo("extra", priority=-1, tier="additional")
    classify = lambda item: item.source_tier
    status = rows(base + [supplemental], mode="workload", source_plan=source_plan,
                  tier_of=classify)
    assert status == [("distribution", "Ready", "B0, B1, B2, B3 + 2 more",
                       "All enabled distribution repositories are eligible", "ready")]
    for item in base:
        item.enabled = False
    assert rows(base + [supplemental], mode="workload", source_plan=source_plan,
                tier_of=classify)[0][1] == "Source needed"


def test_operator_defined_roots_accept_any_enabled_repository_and_empty_plan_is_empty():
    assert rows([], mode="workload") == []
    plan = [("nginx", "enabled", "")]
    assert rows([], mode="workload", source_plan=plan)[0][1] == "Source needed"
    only = repo("Additional", tier="additional")
    assert rows([only], mode="workload", source_plan=plan)[0][1] == "Ready"


def test_unrecognized_modes_and_missing_tier_classifier_fail_explicitly():
    with pytest.raises(ValueError, match="Unsupported"):
        rows([], mode="typo")
    with pytest.raises(ValueError, match="tier classifier"):
        rows([], mode="workload", source_plan=[("nginx", "distribution", "")])


def test_status_never_claims_incompatible_enabled_source_is_ready():
    wrong = repo("Wrong", role="vendor")
    issue = lambda row: "wrong architecture" if row is wrong else ""
    assert rows([wrong], mode="workload", required_roles=["vendor"],
                incompatibility=issue)[0] == (
                    "role:vendor", "Incompatible", "Wrong", "wrong architecture", "incompatible")
    status = rows([wrong], mode="workload", source_plan=[("nginx", "distribution", "")],
                  tier_of=lambda row: row.source_tier, incompatibility=issue)
    assert status[0][1] == "Incompatible"
    assert rows([wrong], mode="exact", exact_packages=[SimpleNamespace(repo=wrong)],
                incompatibility=issue)[0][1] == "Incompatible"
    assert rows([wrong], mode="workload", source_plan=[("nginx", "enabled", "")],
                incompatibility=issue)[0][1] == "Incompatible"
    assert rows([wrong], mode="workload", required_roles=["vendor"],
                workload_target_issue="Not offered for target")[0][1] == "Incompatible"
    # A profile's sole recommended template may itself be unusable for the
    # selected init; it must not be presented as an actionable source.
    assert rows([], mode="workload", required_roles=["vendor"],
                templates_by_role={"vendor": [wrong]},
                incompatibility=issue)[0][1] == "Incompatible"


@pytest.mark.parametrize("intent, contextual, expected", [
    (AcquisitionIntent.REPOSITORY_MIRROR, True, "mirror"),
    (AcquisitionIntent.PACKAGES, True, "packages"),
    (AcquisitionIntent.WORKLOAD, True, "contextual-packages"),
    (AcquisitionIntent.WORKLOAD, False, "workload"),
])
def test_repository_workflow_routes_on_explicit_inputs(intent, contextual, expected):
    assert RepositoryWorkflowService.mode(intent, contextual_packages=contextual) == expected


def test_repository_cache_key_tracks_full_target_and_omits_workload_in_mirror_mode():
    service = RepositoryWorkflowService()
    base = dict(mode="workload", workload="docker", profile="arch", release=" rolling ",
                architecture="x86_64", init_system="systemd")
    expected = "workload|docker|arch|rolling|x86_64|systemd"
    assert service.cache_key(**base) == expected
    for field, value in (("profile", "debian"), ("release", "noble"),
                         ("architecture", "aarch64"), ("init_system", "openrc"),
                         ("workload", "nginx")):
        assert service.cache_key(**dict(base, **{field: value})) != expected
    assert service.cache_key(**dict(base, mode="mirror", workload="different")) == \
           service.cache_key(**dict(base, mode="mirror"))
