"""Compatibility adapters collect explicit inputs without a running GUI."""
from __future__ import annotations

from types import SimpleNamespace

from acquisition_model import AcquisitionIntent
from feathered_app.application.sources import SourcesMixin
from feathered_app.ui.panes import PaneMixin
from repository_config import RepoSpec


class Var:
    def __init__(self, value: str):
        self.value = value

    def get(self) -> str:
        return self.value


def repo(name: str, url: str, role: str = "dependency") -> RepoSpec:
    item = RepoSpec(name, url, role)
    item.source_tier = "base"
    return item


def test_workload_adapter_captures_plan_roles_and_templates_explicitly():
    base = repo("core", "https://example.test/core")
    vendor = repo("docker", "https://example.test/docker", "docker")
    vendor.source_tier = "workload"
    calls = []
    host = SimpleNamespace(
        _mirror_mode=lambda: False, _single_mode=lambda: False,
        repo_rows=[base, vendor], _workload_required_repository_roles=lambda: ["docker"],
        _workload_root_source_plan=lambda: [("docker-ce", "workload", "docker"),
                                            ("nginx", "distribution", "")],
        _workload_repo_templates=lambda roles: calls.append(roles) or [],
        _repo_tier=lambda r: r.source_tier,
    )
    actual = SourcesMixin._workload_repo_state_rows(host)
    assert calls == [["docker"]]
    assert [line[:3] for line in actual] == [
        ("role:docker", "Ready", "docker"),
        ("distribution", "Ready", "core"),
    ]


def test_mirror_adapter_preserves_explicit_unchecked_sources():
    a = repo("same", "https://a.example/core")
    b = repo("same", "https://b.example/core")
    host = SimpleNamespace(
        _mirror_mode=lambda: True, _single_mode=lambda: False,
        repo_rows=[a, b], _mirror_repo_selected=lambda item: item is b,
    )
    result = SourcesMixin._workload_repo_state_rows(host)
    assert len(result) == 1 and result[0][2] == "same"
    assert "b.example" in result[0][3]


def test_exact_adapter_does_not_call_workload_methods():
    first = repo("same", "https://a.example/core")
    other = repo("same", "https://b.example/core")
    host = SimpleNamespace(
        _mirror_mode=lambda: False, _single_mode=lambda: True,
        repo_rows=[other], selected_packages=[SimpleNamespace(name="nginx", repo=first)],
    )
    result = SourcesMixin._workload_repo_state_rows(host)
    assert len(result) == 1 and result[0][1] == "Disabled"


def test_workflow_adapter_respects_contextual_workload_and_target_changes():
    profile = SimpleNamespace(key="arch")
    workload = SimpleNamespace(key="nginx", contextual_packages=False)
    host = SimpleNamespace(
        _acquisition_intent=lambda: AcquisitionIntent.WORKLOAD,
        _workload=lambda: workload, _profile=lambda: profile,
        _selected_init_system=lambda: "systemd",
        release_var=Var("rolling"), arch_var=Var("x86_64"),
    )
    host._repository_workflow_mode = lambda: PaneMixin._repository_workflow_mode(host)
    assert PaneMixin._repository_workflow_mode(host) == "workload"
    first = PaneMixin._repository_workflow_key_for_target(host)
    host.release_var.value = "rolling-snapshot"
    assert PaneMixin._repository_workflow_key_for_target(host) != first
    workload.contextual_packages = True
    assert PaneMixin._repository_workflow_mode(host) == "contextual-packages"
    host._acquisition_intent = lambda: AcquisitionIntent.REPOSITORY_MIRROR
    assert PaneMixin._repository_workflow_mode(host) == "mirror"
