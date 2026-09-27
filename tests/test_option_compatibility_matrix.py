"""Pure option-matrix and source-preflight regression checks; never use the network."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from acquisition_model import AcquisitionCapability
from build_spec import BuildSpec, ContentSpec, MirrorSpec, RepositoryRecord, SourceSpec, TargetSpec
from core import RepoSpec, Reporter
from feathered_app.build_api import prepare_build
from feathered_app.build_preparation import PreparationRejected
from feathered_app.build_services import BuildServices
from feathered_app.headless_host import HeadlessHost
from feathered_app.repository_status import RepositoryStatusService
from profiles import PROFILES
from workloads import load_workloads


def make_host(*, distro="devuan", workload="Web server - nginx", mode="Workload preset",
              repositories=(), selected=(), arch=None, init=None, release=None):
    profile = PROFILES[distro]
    release = release or (profile.fixed_releases[0] if profile.fixed_releases else "rolling")
    arch = arch or profile.arches[0]
    init = init if init is not None else (profile.init_systems[0] if profile.init_systems else "")
    repos = list(repositories)
    spec = BuildSpec(
        target=TargetSpec(distribution=profile.label, release=release, arch=arch, init_system=init),
        content=ContentSpec(selection_mode=mode, workload=workload),
        sources=SourceSpec(method="Custom repositories", repositories=tuple(RepositoryRecord.capture(r) for r in repos)),
        mirror=MirrorSpec(layout="separate", selected_repositories=tuple(r.source_identity for r in repos))
    )
    return HeadlessHost(spec, BuildServices(Reporter()), repos, selected_packages=selected)


def source(name, *, fmt="apt", role="dependency", tier="base", enabled=True, url=None, **fields):
    r = RepoSpec(name, url or "https://repo.example.invalid/" + name.lower(), role=role,
                 repo_format=fmt, enabled=enabled)
    r.source_tier = tier
    for name, value in fields.items():
        setattr(r, name, value)
    return r


def test_builtin_profile_workload_option_matrix_matches_catalog_without_metadata_io():
    catalog = load_workloads()
    tested = 0
    for profile in PROFILES.values():
        release = profile.fixed_releases[0] if profile.fixed_releases else "rolling"
        for workload in catalog.values():
            for init in profile.init_systems or [""]:
                host = make_host(distro=profile.key, workload=workload.label, release=release, init=init)
                problem = host._workload_target_conflict()
                allowed = workload.supports_target(profile.key, release)
                mapped = workload.custom or bool(workload.packages_for(profile.package_family))
                assert bool(problem) == (not allowed or not mapped), (
                    profile.key, release, init, workload.key, problem)
                if problem:
                    assert host._acquisition_state().capability is AcquisitionCapability.BLOCKED
                    with pytest.raises(RuntimeError, match="not offered|no package mapping"):
                        host._validate_source_plan()
                tested += 1
    assert tested >= 400


@pytest.mark.parametrize("distro,fmt,arch", [
    ("devuan", "apt", "arm64"), ("debian", "apt", "amd64"),
    ("rocky", "rpm", "aarch64"), ("arch", "pacman", "x86_64"),
    ("artix", "pacman", "x86_64"),
])
@pytest.mark.parametrize("exclusion", ["foreign-format", "foreign-profile", "foreign-release", "foreign-arch"])
def test_workload_base_source_matrix_rejects_ineligible_repositories_before_io(distro, fmt, arch, exclusion):
    p = PROFILES[distro]
    release = p.fixed_releases[0] if p.fixed_releases else "rolling"
    actual_arch = arch if arch in p.arches else p.arches[0]
    base = source("base", fmt=fmt)
    changes = {
        "foreign-format": {"repo_format": {"rpm": "apt", "apt": "pacman", "pacman": "rpm"}[fmt]},
        "foreign-profile": {"target_profile_key": "unrelated-profile"},
        "foreign-release": {"target_release": "other-release"},
        "foreign-arch": {"target_arch": "other-architecture"},
    }[exclusion]
    for key, value in changes.items():
        setattr(base, key, value)
    host = make_host(distro=distro, workload="Web server - nginx", repositories=[base],
                     release=release, arch=actual_arch)
    state = host._acquisition_state()
    assert state.capability is AcquisitionCapability.BLOCKED, (distro, exclusion)
    assert "different target" in state.reason, state.reason
    with pytest.raises(RuntimeError, match="distribution.*eligible"):
        host._validate_source_plan()
    assert host._package_coverage_repositories() == []


def test_ineligible_base_does_not_block_a_valid_same_scope_alternative():
    wrong = source("wrong", target_release="foreign")
    right = source("right")
    host = make_host(repositories=[wrong, right])
    assert host._acquisition_state().capability is AcquisitionCapability.FULL_TRANSACTION
    host._validate_source_plan()
    assert host._package_coverage_repositories() == [right]
    assert host._build_repository_scope() == [right]


def test_exact_selection_from_foreign_target_rejected_even_if_enabled():
    wrong = source("wrong", target_arch="another-architecture")
    host = make_host(mode="Choose packages", repositories=[wrong],
                     selected=[SimpleNamespace(name="nginx", repo=wrong)])
    assert host._acquisition_state().capability is AcquisitionCapability.BLOCKED
    assert "different target" in host._acquisition_state().reason
    with pytest.raises(RuntimeError, match="no longer eligible"):
        host._validate_source_plan()


def test_explicitly_unsupported_preset_replay_fails_before_network():
    base = source("base")
    host = make_host(workload="Cockpit web console", repositories=[base])
    assert "not offered" in host._acquisition_state().reason
    with pytest.raises(PreparationRejected, match="not offered"):
        prepare_build(host._build_snapshot, host._services)


def test_mirror_mixed_package_formats_block_before_loading_and_show_incompatible():
    apt = source("APT", fmt="apt")
    rpm = source("RPM", fmt="rpm")
    host = make_host(distro="debian", mode="Entire repository (mirror)", repositories=[apt, rpm])
    assert host._acquisition_state().capability is AcquisitionCapability.BLOCKED
    assert "different package format" in host._acquisition_state().reason
    with pytest.raises(RuntimeError, match="different package format"):
        host._validate_source_plan()
    status = RepositoryStatusService.rows([apt, rpm], mode="mirror",
        selected_mirror_ids={apt.source_identity, rpm.source_identity},
        mirror_incompatibility=lambda r: "wrong format" if r.repo_format != "apt" else "")
    assert [(item[1], item[4]) for item in status] == [
        ("Ready", "ready"), ("Incompatible", "incompatible")]


def test_mirror_of_foreign_distribution_with_matching_package_format_still_allowed():
    other = source("Another Debian-family target", fmt="apt", target_profile_key="other")
    host = make_host(distro="debian", mode="Entire repository (mirror)", repositories=[other])
    assert host._acquisition_state().capability is AcquisitionCapability.REPOSITORY_MIRROR
    host._validate_source_plan()


def test_status_shows_init_incompatible_role_and_valid_alternative():
    docker = source("Docker CE", fmt="apt", role="docker", tier="workload",
                    url="https://download.docker.com/linux/debian")
    safe = source("Custom docker", fmt="apt", role="docker", tier="workload")
    base = source("Devuan", fmt="apt")
    host = make_host(distro="devuan", workload="Docker Engine", repositories=[base, docker, safe])
    classify = lambda row: host._init_repository_conflict(row)
    status = RepositoryStatusService.rows([docker], mode="workload", required_roles=["docker"],
                                          incompatibility=classify)
    assert status[0][1] == "Incompatible"
    status = RepositoryStatusService.rows([docker, safe], mode="workload", required_roles=["docker"],
                                          incompatibility=classify)
    assert status[0][1] == "Ready" and status[0][2] == "Custom docker"
    assert host._acquisition_state().capability is AcquisitionCapability.FULL_TRANSACTION
