from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest

from acquisition_model import (
    AcquisitionCapability,
    AcquisitionIntent,
    WORKLOAD_PACKAGE_ONLY_MODE,
    derive_acquisition_state,
)
from core import RepoSpec
from feathered_app.build_intent import BuildIntentMixin
from feathered_app.build_plan import BuildPlanMixin
from feathered_app.ui.kubernetes import KubernetesWorkloadMixin
from source_model import RootSourcePolicy, SourcePlan
from source_readiness import evaluate_source_readiness
from workloads import _builtins


def _display_available() -> bool:
    if sys.platform.startswith("win") or sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


requires_display = pytest.mark.skipif(
    not _display_available(),
    reason="no display; run the suite under xvfb-run as the release gate does",
)


@pytest.fixture
def application(tmp_path, monkeypatch):
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)
    import app

    window = app.App()
    try:
        yield window
    finally:
        window.destroy()


class Var:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


def repo(name, role, tier):
    item = RepoSpec(name, f"https://example.test/{name}/", role, enabled=True)
    item.source_tier = tier
    return item


def test_vendor_workload_uses_any_separate_enabled_repository_as_dependency_provider():
    plan = SourcePlan([RootSourcePolicy("docker-ce", "workload", "docker")])
    docker = repo("docker", "docker", "workload")
    supplemental = repo("internal-os-deps", "dependency", "additional")

    root_only = evaluate_source_readiness(plan, [docker])
    assert root_only.capability == "package-only"
    assert root_only.dependency_provider_repositories == ()

    with_provider = evaluate_source_readiness(plan, [docker, supplemental])
    assert with_provider.capability == "full-analysis"
    assert with_provider.dependency_provider_repositories == (supplemental,)


def test_explicit_package_only_remains_available_even_with_dependency_providers():
    plan = SourcePlan([RootSourcePolicy("docker-ce", "workload", "docker")])
    docker = repo("docker", "docker", "workload")
    base = repo("base", "dependency", "base")
    readiness = evaluate_source_readiness(plan, [docker, base])

    full = derive_acquisition_state(
        AcquisitionIntent.WORKLOAD,
        workload_readiness=readiness,
        workload_root_count=1,
    )
    root_only = derive_acquisition_state(
        AcquisitionIntent.WORKLOAD,
        workload_readiness=readiness,
        workload_root_count=1,
        workload_package_only_requested=True,
    )

    assert full.capability is AcquisitionCapability.FULL_TRANSACTION
    assert root_only.capability is AcquisitionCapability.PACKAGE_ONLY
    assert "selected" in root_only.reason.lower()


def test_vks_is_contextual_workload_not_generic_exact_package_mode():
    workloads = {item.key: item for item in _builtins()}
    vks = workloads["vks-node-additions"]
    custom = workloads["custom"]
    assert vks.custom and vks.contextual_packages
    assert custom.custom and not custom.contextual_packages

    host = BuildIntentMixin()
    host.workloads = workloads
    host.selection_mode_var = Var("Workload preset")
    host.workload_var = Var(vks.label)
    assert host._acquisition_intent() is AcquisitionIntent.WORKLOAD

    host.workload_var.set(custom.label)
    assert host._acquisition_intent() is AcquisitionIntent.PACKAGES


def test_vks_source_plan_is_derived_from_selected_os_additions():
    selected_repo = repo("ubuntu-main", "dependency", "base")
    package = SimpleNamespace(name="tcpdump", repo=selected_repo)
    vks = next(item for item in _builtins() if item.key == "vks-node-additions")

    host = SimpleNamespace(
        selected_packages=[package],
        _mirror_mode=lambda: False,
        _single_mode=lambda: False,
        _workload=lambda: vks,
    )
    plan = BuildPlanMixin._source_plan(host)

    assert len(plan.roots) == 1
    assert plan.roots[0].package == "tcpdump"
    assert plan.roots[0].source_kind == "enabled"


def test_vks_context_reset_discards_only_vks_owned_state():
    host = SimpleNamespace(
        pin_to_inventory_baseline_var=Var(True),
        advisories_acknowledged_var=Var(True),
        image_baker_name_var=Var("custom-image"),
        _k8s_advice_scope=("old",),
    )

    KubernetesWorkloadMixin._reset_vks_context(host)
    assert host.pin_to_inventory_baseline_var.get() is False
    assert host.advisories_acknowledged_var.get() is False
    assert host.image_baker_name_var.get() == "feathered-node-additions"
    assert "_k8s_advice_scope" not in host.__dict__

    host.pin_to_inventory_baseline_var.set(True)
    host.advisories_acknowledged_var.set(True)
    host.image_baker_name_var.set("keep-name")
    KubernetesWorkloadMixin._reset_vks_context(host, target_changed=True)
    assert host.pin_to_inventory_baseline_var.get() is False
    assert host.advisories_acknowledged_var.get() is False
    assert host.image_baker_name_var.get() == "keep-name"


def test_package_only_mode_label_is_explicit_not_an_implicit_capability_name():
    assert WORKLOAD_PACKAGE_ONLY_MODE == "Workload packages only"


@requires_display
def test_docker_offers_dependency_analysis_and_explicit_package_only(application):
    application.distro_var.set("Ubuntu")
    application.release_var.set("24.04")
    application.arch_var.set("x86_64")
    application._release_changed()
    application.workload_var.set("Docker Engine")
    application._workload_changed()
    application.update_idletasks()

    state = application._acquisition_state()
    assert state.capability is AcquisitionCapability.FULL_TRANSACTION
    assert WORKLOAD_PACKAGE_ONLY_MODE in application.mode_combo["values"]
    assert any(application._repo_tier(repo) == "base" and repo.enabled
               for repo in application.repo_rows)

    application.mode_var.set(WORKLOAD_PACKAGE_ONLY_MODE)
    application._mode_changed()
    assert application._acquisition_state().capability is AcquisitionCapability.PACKAGE_ONLY
    assert application.workload_var.get() == "Docker Engine"


@requires_display
def test_docker_falls_back_to_package_only_when_only_vendor_source_remains(application):
    application.distro_var.set("Ubuntu")
    application.release_var.set("24.04")
    application.arch_var.set("x86_64")
    application._release_changed()
    application.workload_var.set("Docker Engine")
    application._workload_changed()

    for repo in application.repo_rows:
        if repo.role != "docker":
            repo.enabled = False
    application.mode_var.set("Complete bundle (recommended)")

    state = application._acquisition_state()
    assert state.capability is AcquisitionCapability.PACKAGE_ONLY
    assert "no other enabled repository remains" in state.reason


@requires_display
def test_vks_context_reconfigures_and_resets_when_target_becomes_incompatible(application):
    application.distro_var.set("Ubuntu")
    application.release_var.set("24.04")
    application.arch_var.set("x86_64")
    application._release_changed()
    application.workload_var.set("VKS node OS package additions")
    application._workload_changed()
    application.update_idletasks()

    assert application._acquisition_intent() is AcquisitionIntent.WORKLOAD
    assert application._repository_workflow_mode() == "contextual-packages"
    assert WORKLOAD_PACKAGE_ONLY_MODE in application.mode_combo["values"]
    assert application.vks_repository_context_card is not None

    marker = object()
    application.selected_packages = [marker]
    application.pin_to_inventory_baseline_var.set(True)
    application.advisories_acknowledged_var.set(True)

    application.release_var.set("26.10")
    application._release_changed()
    application.update_idletasks()

    assert application.workload_var.get() != "VKS node OS package additions"
    assert application._repository_workflow_mode() == "workload"
    assert application.selected_packages == []
    assert application.pin_to_inventory_baseline_var.get() is False
    assert application.advisories_acknowledged_var.get() is False


@requires_display
def test_downstream_dependency_choice_does_not_exit_vks_context(application):
    application.distro_var.set("Ubuntu")
    application.release_var.set("24.04")
    application._release_changed()
    application.workload_var.set("VKS node OS package additions")
    application._workload_changed()

    application.mode_var.set(WORKLOAD_PACKAGE_ONLY_MODE)
    application._mode_changed()
    application.update_idletasks()

    assert application.workload_var.get() == "VKS node OS package additions"
    assert application._repository_workflow_mode() == "contextual-packages"


def test_vks_parameter_signature_includes_exact_version_and_source_identity():
    from feathered_app.application.selection import SelectionMixin

    vks = next(item for item in _builtins() if item.key == "vks-node-additions")
    repo_one = repo("base-one", "dependency", "base")
    repo_two = repo("base-two", "dependency", "base")
    package = SimpleNamespace(name="tcpdump", nevra="tcpdump-1.0.amd64", repo=repo_one)
    host = SimpleNamespace(
        selected_packages=[package],
        custom_var=Var(""),
        distro_var=Var("Ubuntu"),
        release_var=Var("24.04"),
        arch_var=Var("amd64"),
        mode_var=Var("Complete bundle (recommended)"),
        inventory_var=Var(""),
        selection_mode_var=Var("Workload preset"),
        mirror_repos=set(),
        _mirror_mode=lambda: False,
        _single_mode=lambda: False,
        _workload=lambda: vks,
        _source_plan=lambda: SourcePlan([RootSourcePolicy("tcpdump", "enabled")]),
        _active_source_method=lambda: "Distribution APT repositories",
        _signature=lambda: ("repos",),
    )

    first = SelectionMixin._parameter_signature(host)
    package.nevra = "tcpdump-1.1.amd64"
    second = SelectionMixin._parameter_signature(host)
    package.nevra = "tcpdump-1.0.amd64"
    package.repo = repo_two
    third = SelectionMixin._parameter_signature(host)

    assert first != second
    assert first != third


def test_rhel_entitlement_readiness_accepts_credentials_attached_to_cdn_rows():
    from feathered_app.build_preparation import BuildPreparationMixin

    cdn = repo("rhel-baseos", "dependency", "base")
    cdn.url = "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os/"
    cdn.client_cert = "entitlement.pem"
    cdn.client_key = "entitlement-key.pem"
    cdn.ca_cert = "redhat-uep.pem"
    host = SimpleNamespace(
        repo_rows=[cdn],
        rhsm_cert="",
        rhsm_key="",
        rhsm_ca="",
    )

    assert BuildPreparationMixin._entitlement_ready(host)
    assert BuildPreparationMixin._entitlement_credentials(host) == (
        "entitlement.pem", "entitlement-key.pem", "redhat-uep.pem")


def test_rhel_cdn_is_source_intent_even_before_entitlement_is_configured():
    import app as feather_app

    docker = repo("docker", "docker", "workload")
    docker.url = "https://download.docker.com/linux/rhel/9/x86_64/stable/"
    baseos = repo("rhel-baseos", "dependency", "base")
    baseos.url = "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os/"
    appstream = repo("rhel-appstream", "dependency", "base")
    appstream.url = "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/appstream/os/"
    plan = SourcePlan([RootSourcePolicy("docker-ce", "workload", "docker")])

    host = feather_app.App.__new__(feather_app.App)
    host.repo_rows = [docker, baseos, appstream]
    host.selection_mode_var = Var("Workload preset")
    host.source_method_var = Var("Red Hat CDN entitlement (official)")
    host.mode_var = Var("Complete bundle (recommended)")
    host.rhsm_cert = host.rhsm_key = host.rhsm_ca = ""
    host._profile = lambda: SimpleNamespace(key="rhel", package_family="rpm")
    host._source_plan = lambda: plan
    host._repo_tier = feather_app.App._repo_tier.__get__(host, feather_app.App)

    readiness_rows = feather_app.App._repositories_for_source_readiness(host, plan)
    state = feather_app.App._acquisition_state(host)

    assert readiness_rows == [docker, baseos, appstream]
    assert state.capability is AcquisitionCapability.FULL_TRANSACTION
    assert not feather_app.App._entitlement_ready(host)


def test_rhel_cdn_full_analysis_blocks_on_missing_entitlement_without_becoming_package_only():
    import app as feather_app

    docker = repo("docker", "docker", "workload")
    docker.url = "https://download.docker.com/linux/rhel/9/x86_64/stable/"
    baseos = repo("rhel-baseos", "dependency", "base")
    baseos.url = "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os/"

    host = feather_app.App.__new__(feather_app.App)
    host.repo_rows = [docker, baseos]
    host.selection_mode_var = Var("Workload preset")
    host.source_method_var = Var("Red Hat CDN entitlement (official)")
    host.mode_var = Var("Complete bundle (recommended)")
    host.rhsm_cert = host.rhsm_key = host.rhsm_ca = ""
    host._profile = lambda: SimpleNamespace(key="rhel", package_family="rpm")
    host._workload = lambda: SimpleNamespace(label="Docker Engine", contextual_packages=False)
    host._source_plan = lambda: SourcePlan([RootSourcePolicy("docker-ce", "workload", "docker")])
    host._workload_uses_distribution_sources = lambda: False
    host._workload_required_repository_roles = lambda: ["docker"]
    host._needs_dependency_repos = lambda: True
    host._repo_tier = feather_app.App._repo_tier.__get__(host, feather_app.App)
    host._single_mode = lambda: False
    host._mirror_mode = lambda: False

    assert feather_app.App._acquisition_state(host).capability is AcquisitionCapability.FULL_TRANSACTION
    with pytest.raises(RuntimeError, match="entitlement certificate"):
        feather_app.App._validate_source_plan(host)


def test_rhel_source_status_separates_selected_dependency_provider_from_missing_entitlement():
    import app as feather_app

    class Status:
        def __init__(self):
            self.kw = {}

        def configure(self, **kwargs):
            self.kw.update(kwargs)

    docker = repo("docker", "docker", "workload")
    docker.url = "https://download.docker.com/linux/rhel/9/x86_64/stable/"
    baseos = repo("rhel-baseos", "dependency", "base")
    baseos.url = "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os/"

    host = feather_app.App.__new__(feather_app.App)
    host.repo_rows = [docker, baseos]
    host.source_method_var = Var("Red Hat CDN entitlement (official)")
    host.source_status = Status()
    host.rhsm_cert = host.rhsm_key = host.rhsm_ca = ""
    host._profile = lambda: SimpleNamespace(key="rhel", package_family="rpm")
    host._repo_tier = feather_app.App._repo_tier.__get__(host, feather_app.App)
    host._participating_transaction_repositories = lambda: [docker, baseos]
    host._workload_uses_distribution_sources = lambda: False
    host._package_only_acquisition_mode = lambda: False
    host._local_media_pending = lambda: False

    feather_app.App._update_source_status(host)
    text = host.source_status.kw["text"].lower()
    assert "remain selected as dependency providers" in text
    assert "entitlement is not configured" in text
    assert "no other enabled repository remains" not in text
    assert "package-only" not in text
