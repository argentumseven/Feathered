"""Repository-scope behavior on the production preparation adapter."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from acquisition_model import AcquisitionCapability
from core import RepoSpec
from feathered_app.build_preparation import BuildPreparationMixin
from feathered_app.build_request import BuildRequestMixin
from feathered_app.source_scope import RepositoryTarget, TargetScope, target_compatible
from source_model import RootSourcePolicy, SourcePlan


class ScopeHost(BuildPreparationMixin, BuildRequestMixin):
    pass


def make_host(mode="workload", capability=AcquisitionCapability.FULL_TRANSACTION):
    host = ScopeHost()
    host.repo_rows = []
    host.selected_packages = []
    host.logs = []
    host._profile = lambda: SimpleNamespace(package_family="rpm", key="rocky")
    host._selected_arch = lambda: "x86_64"
    host.release_var = SimpleNamespace(get=lambda: "9")
    host._mirror_mode = lambda: mode == "mirror"
    host._single_mode = lambda: mode == "exact"
    host._mirror_repo_selected = lambda repo: bool(getattr(repo, "selected", False))
    host._repo_tier = lambda repo: repo.source_tier
    host._workload_required_repository_roles = lambda: ["vendor"]
    host._source_plan = lambda: SourcePlan([RootSourcePolicy("agent", "workload", "vendor")])
    host._acquisition_state = lambda: SimpleNamespace(capability=capability)
    host._init_repository_conflict = lambda repo: getattr(repo, "init_conflict", "")
    host._log = host.logs.append
    return host


def source(name, tier="additional", **fields):
    repo = RepoSpec(name, "https://example.test/" + name, role="vendor" if tier == "workload" else "dependency")
    repo.source_tier = tier
    for key, value in fields.items():
        setattr(repo, key, value)
    return repo


@pytest.mark.parametrize("fields", [
    {"repo_format": "apt"}, {"target_profile_key": "ubuntu"},
    {"target_release": "8"}, {"target_arch": "aarch64"},
])
def test_transaction_excludes_foreign_target_without_removing_source(fields):
    host = make_host()
    good, foreign = source("good"), source("foreign", **fields)
    host.repo_rows = [foreign, good]
    assert host._build_repository_scope() == [good]
    assert host.repo_rows == [foreign, good]


@pytest.mark.parametrize("mode,selected,expected", [
    ("workload", False, True), ("exact", False, False), ("exact", True, True),
])
def test_managed_workload_sources_participate_only_for_the_current_roots(mode, selected, expected):
    host = make_host(mode)
    vendor = source("vendor", "workload", workload_profile_managed=True)
    unrelated = source("other", "workload", workload_profile_managed=True, role="unused")
    host.repo_rows = [vendor, unrelated]
    if selected:
        host.selected_packages = [SimpleNamespace(repo=vendor)]
    assert host._repository_participates_in_current_intent(vendor) is expected
    assert not host._repository_participates_in_current_intent(unrelated)


@pytest.mark.parametrize("explicit", [False, True])
def test_package_only_uses_root_coverage_and_preserves_original_objects(explicit):
    host = make_host(capability=AcquisitionCapability.FULL_TRANSACTION if explicit else AcquisitionCapability.PACKAGE_ONLY)
    base, vendor, extra = source("base", "base"), source("vendor", "workload"), source("extra")
    host.repo_rows = [base, vendor, extra]
    scoped = host._build_repository_scope(package_only=explicit)
    assert len(scoped) == 1 and scoped[0] is vendor
    assert host.repo_rows == [base, vendor, extra]


def test_normal_transaction_keeps_all_eligible_dependency_sources_in_order():
    host = make_host()
    extra, vendor, base = source("extra"), source("vendor", "workload"), source("base", "base")
    host.repo_rows = [extra, vendor, base]
    assert host._build_repository_scope() == [extra, vendor, base]


def test_mirror_checkboxes_are_authoritative_even_for_disabled_or_foreign_sources():
    host = make_host("mirror", AcquisitionCapability.REPOSITORY_MIRROR)
    disabled = source("disabled", enabled=False, selected=True)
    foreign = source("foreign", repo_format="apt", selected=True, init_conflict="not a transaction provider")
    unticked = source("unticked")
    blank = source("blank", url=" ", selected=True)
    host.repo_rows = [disabled, foreign, unticked, blank]
    assert host._build_repository_scope() == [disabled, foreign]
    assert not disabled.enabled
    assert host._package_coverage_repositories() == [disabled, foreign]


def test_init_incompatible_transaction_repository_is_logged_and_excluded():
    host = make_host()
    forbidden, good = source("forbidden", init_conflict="systemd-only"), source("good")
    host.repo_rows = [forbidden, good]
    assert host._build_repository_scope() == [good]
    assert host.logs == ["Excluded from this init-locked target: forbidden - systemd-only"]


def test_disabled_repository_does_not_read_url_or_host_state():
    class Disabled:
        enabled = False

        @property
        def url(self):
            raise AssertionError("disabled source URL must not be read")

    assert not ScopeHost()._repository_participates_in_current_intent(Disabled())


def test_ordinary_source_does_not_need_exact_package_identity():
    class Ordinary:
        enabled = True
        url = "https://example.test/ordinary"
        source_tier = "additional"

        @property
        def source_identity(self):
            raise AssertionError("ordinary source identity is not needed for participation")

    host = make_host()
    host._repository_target_compatible = lambda repo: True
    assert host._repository_participates_in_current_intent(Ordinary())


def test_unknown_target_and_blank_release_keep_existing_compatibility_semantics():
    assert target_compatible(None, RepositoryTarget("apt", "ubuntu", "24.04", "amd64"))
    assert target_compatible(TargetScope("rpm", "rocky", "", ""), RepositoryTarget("rpm", "rocky", "9", "x86_64"))
