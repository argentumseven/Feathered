"""The live workload drift checker must not load irrelevant vendor repositories."""

from types import SimpleNamespace

import verify_workload_matrix as drift


def _source(name, role, enabled=True):
    return SimpleNamespace(
        name=name, role=role, enabled=enabled,
        url=f"https://example.invalid/{name}", priority=50,
        target_release="26.10", repo_format="apt",
        suite="test", components="main", optional=False,
        flat_repo=False, expected_release_version="",
    )


class _Workload:
    def __init__(self, *roles):
        self.roles = roles

    def required_repository_roles(self):
        return list(self.roles)

    def source_plan(self, family):
        from source_model import RootSourcePolicy, SourcePlan
        return SourcePlan([RootSourcePolicy(role, 'workload', role)
                           for role in self.roles])


def test_unrelated_workload_does_not_load_docker_repository():
    profile = SimpleNamespace(package_family="deb")
    base = _source("ubuntu", "dependency")
    docker = _source("docker", "docker")
    selected, errors = drift._templates_for_workload(
        profile, "26.10", "amd64", _Workload(), [docker, base],
        {"docker", "kubernetes"}, "1.35")
    assert errors == []
    assert selected == [base]


def test_docker_workload_still_loads_its_vendor_source():
    profile = SimpleNamespace(package_family="deb")
    base = _source("ubuntu", "dependency")
    docker = _source("docker", "docker")
    selected, errors = drift._templates_for_workload(
        profile, "26.10", "amd64", _Workload("docker"),
        [docker, base], {"docker", "kubernetes"}, "1.35")
    assert errors == []
    assert selected == [base, docker]


def test_kubernetes_workload_requires_explicit_minor():
    profile = SimpleNamespace(package_family="rpm")
    base = _source("base", "dependency")
    selected, errors = drift._templates_for_workload(
        profile, "9", "x86_64", _Workload("kubernetes"),
        [base], {"kubernetes"}, "")
    assert selected == [base]
    assert errors and "--kubernetes-minor" in errors[0]


def test_kubernetes_workload_uses_generated_vendor_repository():
    profile = SimpleNamespace(package_family="rpm")
    base = _source("base", "dependency")
    selected, errors = drift._templates_for_workload(
        profile, "9", "x86_64", _Workload("kubernetes"),
        [base], {"kubernetes"}, "1.35")
    assert errors == []
    assert selected[0] is base
    assert len(selected) == 2
    assert selected[1].role == "kubernetes"
    assert "v1.35/rpm" in selected[1].url


def test_missing_vendor_role_is_reported_not_ignored():
    profile = SimpleNamespace(package_family="deb")
    selected, errors = drift._templates_for_workload(
        profile, "24.04", "amd64", _Workload("vendor"),
        [_source("base", "dependency")], {"vendor"}, "1.35")
    assert len(selected) == 1
    assert errors and "vendor" in errors[0]
