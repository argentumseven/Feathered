"""Guard against init-blocked vendor roots appearing ready until after metadata I/O."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from acquisition_model import AcquisitionCapability
from build_spec import RepositoryRecord
from core import RepoSpec, Reporter
from feathered_app.build_api import prepare_build
from feathered_app.build_preparation import PreparationRejected
from feathered_app.build_services import BuildServices
from feathered_app.headless_host import HeadlessHost
from feathered_app.source_scope import init_blocked_required_roles
from tests.test_cli_replay import spec_for

@pytest.fixture
def local_repository(tmp_path):
    """Path-only repository: preflight must not require dpkg or metadata I/O.

    The original shared fixture built real .deb files and skipped on Windows,
    removing coverage of this platform-independent policy code in release CI.
    """
    repository = tmp_path / "repository"
    repository.mkdir()
    return repository


def test_all_required_role_sources_must_be_init_compatible():
    excluded = SimpleNamespace(name="vendor", role="docker")
    independent = SimpleNamespace(name="internal", role="docker")
    other = SimpleNamespace(name="OS", role="dependency")
    reason = lambda repo: "systemd-only" if repo is excluded else ""
    assert init_blocked_required_roles(["docker"], [excluded, other], reason) == {
        "docker": ((excluded, "systemd-only"),)
    }
    assert not init_blocked_required_roles(["docker"], [excluded, independent], reason)
    assert not init_blocked_required_roles(["docker"], [other], reason)
    assert not init_blocked_required_roles([], [excluded], reason)


def devuan_docker_spec(local_repository, output, *, independent_vendor=False):
    spec = spec_for(local_repository, output, "devuan")
    base = spec.sources.repositories[0]
    docker = RepoSpec(
        "Docker CE Stable (Debian packages)",
        "https://download.docker.com/linux/debian/",
        "docker", repo_format="apt", suite="trixie", components="stable")
    docker.source_tier = "workload"
    docker.workload_profile_managed = True
    vendor_rows = [RepositoryRecord.capture(docker)]
    if independent_vendor:
        compatible = RepoSpec(
            "Operator-vetted upstream", "https://vendor.example.test/docker/",
            "docker", repo_format="apt", suite="excalibur", components="main")
        compatible.source_tier = "workload"
        vendor_rows.append(RepositoryRecord.capture(compatible))
    return replace(
        spec,
        target=replace(spec.target, release="excalibur", init_system="runit"),
        content=replace(spec.content, workload="Docker Engine"),
        sources=replace(spec.sources, repositories=(base, *vendor_rows)),
    )


def test_devuan_docker_is_blocked_before_metadata_fetch(local_repository, tmp_path):
    spec = devuan_docker_spec(local_repository, tmp_path / "out")
    # No network or package database is read when deriving this state.
    from build_spec import repositories_from
    host = HeadlessHost(spec, BuildServices(Reporter()), repositories_from(spec, RepoSpec))
    state = host._acquisition_state()
    assert state.capability is AcquisitionCapability.BLOCKED
    assert "docker" in state.reason
    assert "init system" in state.reason
    assert "docker.io" in state.reason
    with pytest.raises(PreparationRejected, match="all enabled, target-compatible sources.*role 'docker'"):
        prepare_build(spec, BuildServices(Reporter()))
    assert not (tmp_path / "out").exists()


def test_safe_same_role_alternative_preserves_workload_readiness(local_repository, tmp_path):
    spec = devuan_docker_spec(local_repository, tmp_path / "out", independent_vendor=True)
    from build_spec import repositories_from
    host = HeadlessHost(spec, BuildServices(Reporter()), repositories_from(spec, RepoSpec))
    assert host._acquisition_state().capability is AcquisitionCapability.FULL_TRANSACTION
    host._validate_source_plan()
    scoped = host._build_repository_scope()
    assert "Operator-vetted upstream" in [repo.name for repo in scoped]
    assert not any(repo.url.startswith("https://download.docker.com/") for repo in scoped)


def test_devuan_distribution_docker_custom_roots_have_no_vendor_role(local_repository, tmp_path):
    spec = devuan_docker_spec(local_repository, tmp_path / "out")
    spec = replace(spec, content=replace(
        spec.content, selection_mode="Choose packages", workload="Custom packages",
        custom_packages="docker.io"))
    from build_spec import repositories_from
    repositories = repositories_from(spec, RepoSpec)
    # The user has chosen docker.io from the Devuan index on Repositories.
    host = HeadlessHost(spec, BuildServices(Reporter()), repositories,
                        selected_packages=[SimpleNamespace(repo=repositories[0])])
    assert not host._source_plan().required_roles
    assert host._acquisition_state().capability is AcquisitionCapability.FULL_TRANSACTION
    assert all(repo.role != "docker" for repo in host._build_repository_scope())


def test_init_blocked_dependency_provider_does_not_imply_full_analysis(local_repository, tmp_path):
    spec = devuan_docker_spec(local_repository, tmp_path / "out", independent_vendor=True)
    base = replace(spec.sources.repositories[0],
                   url="https://download.docker.com/linux/debian/", name="Excluded dependency")
    spec = replace(spec, sources=replace(
        spec.sources, repositories=(base, *spec.sources.repositories[1:])))
    from build_spec import repositories_from
    host = HeadlessHost(spec, BuildServices(Reporter()), repositories_from(spec, RepoSpec))
    assert host._acquisition_state().capability is AcquisitionCapability.PACKAGE_ONLY


def test_exact_selection_from_init_blocked_source_is_not_ready(local_repository, tmp_path):
    spec = devuan_docker_spec(local_repository, tmp_path / "out")
    spec = replace(spec, content=replace(spec.content, selection_mode="Choose packages"))
    from build_spec import repositories_from
    rows = repositories_from(spec, RepoSpec)
    host = HeadlessHost(spec, BuildServices(Reporter()), rows,
                        selected_packages=[SimpleNamespace(repo=rows[1])])
    assert host._acquisition_state().capability is AcquisitionCapability.BLOCKED
