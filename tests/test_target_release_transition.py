"""Exercise target callbacks without constructing display-dependent widgets."""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feathered_app.application.sources import SourcesMixin
from feathered_app.repository_universe import RepositoryUniverseMixin
from feathered_app.ui.panes import PaneMixin
from profiles import PROFILES


class Variable:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class TargetHost(SourcesMixin, RepositoryUniverseMixin):
    pass


def target_host(key, releases):
    host = TargetHost()
    profile = copy.deepcopy(PROFILES[key])
    profile.discovered_versions = releases
    host._profile = lambda: profile
    host.release_var = Variable("9.8")
    host.release_combo = {}
    host.arch_var = Variable("x86_64")
    host.arch_combo = {}
    host.target_note = Mock()
    host.workload_combo = {}
    host.workload_var = Variable("Custom")
    host.source_method_var = Variable("Custom repositories")
    host.mirror_source_method_var = None
    host._workload_labels_for_profile = lambda: ["Custom"]
    host._default_workload_label = lambda: "Custom"
    host._workload_changed = Mock()
    host._sync_init_system_control = Mock()
    host._update_folder_preview = Mock()
    host._auto_refresh_releases = Mock()
    host.after = Mock()
    return host


@pytest.mark.parametrize("key", ["rhel", "rocky", "ubuntu", "debian", "devuan"])
def test_switch_to_uncached_distribution_clears_previous_release(key):
    host = target_host(key, [])
    host._release_changed = Mock()
    host._profile_changed()
    assert host.release_var.get() == ""
    assert host.release_combo["values"] == []
    host._release_changed.assert_called_once_with()


@pytest.mark.parametrize("key,releases", [
    ("ubuntu", ["24.04"]), ("debian", ["bookworm"]),
    ("arch", []), ("custom-rpm", []),
])
def test_switch_uses_only_new_profiles_known_releases(key, releases):
    host = target_host(key, releases)
    host._release_changed = Mock()
    host._profile_changed()
    assert host.release_var.get() == host._profile().known_versions()[0]
    assert host.release_var.get() != "9.8"


@pytest.mark.parametrize("mode", ["transaction", "mirror"])
def test_blank_target_clears_generated_sources_and_old_package_state(mode):
    host = target_host("ubuntu", [])
    host.release_var.set("")
    manual = SimpleNamespace(tier="additional", workload_profile_managed=False)
    host.transaction_repo_rows = [
        SimpleNamespace(tier="base", workload_profile_managed=False),
        SimpleNamespace(tier="workload", workload_profile_managed=True), manual,
    ]
    host.mirror_repo_rows = [SimpleNamespace(tier="base")]
    host.activate_repository_universe(mode)
    host.mirror_repos = {"previous-mirror"}
    host._mirror_seen = {"previous-mirror"}
    host.selected_packages = ["previous-selection"]
    host.single_catalog_packages = ["previous-catalog"]
    host.single_catalog_signature = "old-catalog"
    host.loaded_packages = ["previous-loaded-package"]
    host.loaded_signature = "previous-analysis"
    host.last_result = object()
    host._provenance_detected_cache = {"old-target": ["sha256"]}
    host._provenance_digest_coverage_cache = {"old-target": {"sha256": 10}}
    host._provenance_inspection_errors = {"old-target": "failed"}
    host._repo_tier = lambda repo: repo.tier
    for name in ("_update_release_hint", "_refresh_selected_packages",
                 "_sync_workload_repo_state", "_render_repository_workflow",
                 "_update_source_status", "_refresh_repo_tree_if_open"):
        setattr(host, name, Mock())
    host._set_transaction_source_ui = Mock()
    # Run real source generation, bypassing its widget synchronization wrapper.
    host._apply_source_method = host._apply_source_method_inner
    host.source_method_var.set("Distribution APT repositories")
    host._profile().repos_factory = Mock(side_effect=AssertionError("blank release must not generate URLs"))
    host._ensure_mirror_repository_seeded = lambda: setattr(
        host, "repo_rows", PaneMixin._mirror_source_rows_for_method(host, "Distribution APT repositories"))

    host._release_changed()

    assert host.release_var.get() == ""
    assert host.transaction_repo_rows == [manual]
    assert host.mirror_repo_rows == []
    assert not host.mirror_repos and not host._mirror_seen
    assert host._repository_universe_mode == mode
    assert host.selected_packages == host.single_catalog_packages == host.loaded_packages == []
    assert host.single_catalog_signature is host.loaded_signature is host.last_result is None
    assert host._provenance_detected_cache == host._provenance_digest_coverage_cache == host._provenance_inspection_errors == {}
    assert host._workload_repo_templates(["docker"]) == []
    host._profile().repos_factory.assert_not_called()


def test_release_discovery_populates_the_cleared_target():
    host = target_host("ubuntu", [])
    host._release_changed = Mock()
    host._profile_changed()
    host._set_release_choices(["24.04"])
    assert host.release_var.get() == "24.04"
    assert host.release_combo["values"] == ["24.04"]
    assert host._release_changed.call_count == 2
