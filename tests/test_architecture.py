"""Compatibility guardrails for Feathered's modular application shell."""
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feathered_app.state import ApplicationStateView

APP_PACKAGE = ROOT / "feathered_app"


def _python_files():
    return sorted(APP_PACKAGE.rglob("*.py"))


def test_component_modules_declare_dependencies_explicitly():
    offenders = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
                offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, "wildcard imports hide component dependencies: " + ", ".join(offenders)


def test_grouped_state_view_preserves_legacy_attribute_storage():
    class Shell:
        pass

    shell = Shell()
    shell.repo_rows = []
    shell.loaded_packages = []
    shell.transfer_done = 0
    shell.active_operation = None
    shell._activity_state = "idle"
    shell.app_state = ApplicationStateView(shell)

    shell.app_state.repositories.repo_rows = ["repo"]
    shell.app_state.analysis.loaded_packages = ["pkg"]
    shell.app_state.transfer.transfer_done = 4
    shell.app_state.operation.active_operation = "build"

    assert shell.__dict__["repo_rows"] == ["repo"]
    assert shell.__dict__["loaded_packages"] == ["pkg"]
    assert shell.__dict__["transfer_done"] == 4
    assert shell.__dict__["active_operation"] == "build"

    shell.__dict__["repo_rows"] = ["direct"]
    assert shell.app_state.repositories.repo_rows == ["direct"]
    del shell.repo_rows
    assert not hasattr(shell, "repo_rows")


def test_refactor_does_not_shadow_tk_state_api():
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"), filename="app.py")
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                        and target.value.id == "self" and target.attr == "state"):
                    offenders.append(node.lineno)
    assert not offenders, "App.state() is a tkinter window-manager API and must not be shadowed"


def test_legacy_state_fields_are_not_replaced_by_class_descriptors():
    """Instance storage stays instance storage, except where scoping demands it.

    ``repo_rows``/``transaction_repo_rows``/``mirror_repo_rows`` are deliberately
    excluded as of 1.2.6. They were three attributes aliasing one list whose
    isolation depended on every rebinding site remembering to update the matching
    mode slot by hand; they are now mode-scoped descriptors over a single
    RepositoryUniverse, which is the point of that change. Their replacement
    contract is pinned by test_repository_universe.py rather than left untested.
    """
    import app

    names = {
        "active_operation", "transfer_done", "single_browser_tree",
        "_activity_state", "worker", "loaded_packages", "last_output_path",
    }
    for name in names:
        assert not any(name in cls.__dict__ for cls in app.App.__mro__[:-1]), name

    scoped = {"repo_rows", "transaction_repo_rows", "mirror_repo_rows"}
    for name in scoped:
        assert any(name in cls.__dict__ for cls in app.App.__mro__[:-1]), name


def test_grouped_state_view_is_safe_on_partial_tk_app():
    import app

    shell = object.__new__(app.App)
    before = dict(shell.__dict__)
    try:
        shell.app_state.analysis.loaded_packages
    except AttributeError as exc:
        assert str(exc) == "loaded_packages"
    else:
        raise AssertionError("unset grouped state must raise AttributeError")
    assert shell.__dict__ == before

    shell.app_state.analysis.loaded_packages = ["pkg"]
    assert shell.__dict__["loaded_packages"] == ["pkg"]
    del shell.app_state.analysis.loaded_packages
    assert "loaded_packages" not in shell.__dict__

    # repo_rows is mode-scoped rather than a plain instance attribute, so it is
    # checked for the same partial-instance safety through its own storage.
    try:
        shell.app_state.repositories.repo_rows
    except AttributeError as exc:
        assert str(exc) == "repo_rows"
    else:
        raise AssertionError("unset repository universe must raise AttributeError")
    shell.app_state.repositories.repo_rows = ["repo"]
    assert shell.repository_universe.rows("transaction") == ["repo"]


def test_grouped_state_view_preserves_owner_setattr_hooks():
    from feathered_app.state import ApplicationStateView

    class Shell:
        def __init__(self):
            object.__setattr__(self, "writes", [])

        def __setattr__(self, name, value):
            self.writes.append((name, value))
            object.__setattr__(self, name, value)

    shell = Shell()
    ApplicationStateView(shell).transfer.transfer_done = 7
    assert shell.transfer_done == 7
    assert shell.writes == [("transfer_done", 7)]


def test_top_level_star_import_does_not_leak_state_implementation():
    import app

    assert "ApplicationStateView" not in {
        name for name in app.__dict__ if not name.startswith("_")
    }


def test_additive_app_state_name_remains_instance_overrideable():
    import app

    shell = object.__new__(app.App)
    shell.app_state = "embedder-owned"
    assert shell.app_state == "embedder-owned"
    assert shell.__dict__["app_state"] == "embedder-owned"
    del shell.app_state
    assert "app_state" not in shell.__dict__
    assert shell.app_state.__class__.__name__ == "ApplicationStateView"


def test_all_mixin_self_method_calls_resolve_on_composed_app():
    """Catch orphaned cross-mixin calls left behind by module extraction."""
    import app

    component_files = [
        *sorted((APP_PACKAGE / "application").glob("*.py")),
        APP_PACKAGE / "ui" / "layout.py",
        APP_PACKAGE / "ui" / "panes.py",
        APP_PACKAGE / "persistence" / "user_state.py",
    ]
    missing = []
    for path in component_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for cls in (node for node in tree.body if isinstance(node, ast.ClassDef) and node.name.endswith("Mixin")):
            for node in ast.walk(cls):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "self"):
                    continue
                if not hasattr(app.App, node.func.attr):
                    missing.append(
                        f"{path.relative_to(ROOT)}:{node.lineno}: self.{node.func.attr}()"
                    )
    assert not missing, "orphaned App/mixin calls: " + ", ".join(missing)


def test_media_layout_help_contract_is_defined():
    import app

    rpm = app.App.EXPECTED_RPM_LAYOUT
    apt = app.App.EXPECTED_APT_LAYOUT
    assert "repodata/repomd.xml" in rpm
    assert "BaseOS/repodata/repomd.xml" in rpm
    assert "AppStream/repodata/repomd.xml" in rpm
    assert "dists/<suite>/Release" in apt
    assert "binary-<arch>/Packages" in apt
    assert "pool/" in apt


def test_operation_unlock_reapplies_workload_version_semantics():
    from types import SimpleNamespace
    from feathered_app.application.operations import OperationsMixin
    from feathered_app.application.sources import SourcesMixin

    class Widget:
        def __init__(self, state):
            self.state = state

        def winfo_exists(self):
            return True

        def configure(self, **kwargs):
            if "state" in kwargs:
                self.state = kwargs["state"]

        def cget(self, name):
            assert name == "state"
            return self.state

    class Shell(OperationsMixin, SourcesMixin):
        def _workload(self):
            return SimpleNamespace(has_version_axis=False)

    shell = Shell()
    shell.version_scan_btn = Widget("disabled")
    shell.package_version_combo = Widget("readonly")
    # Simulate the global operation lock having saved the button as enabled.
    shell._operation_saved_states = {shell.version_scan_btn: "normal"}

    shell._unlock_operation_controls()

    # Raw restoration happens first, then the workload synchronizer must win.
    assert shell.version_scan_btn.state == "disabled"
    assert shell.package_version_combo.state == "disabled"


def test_component_modules_do_not_depend_on_an_injected_app_global():
    import app

    offenders = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(isinstance(node, ast.Name) and node.id == "App" for node in ast.walk(tree)):
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, "component refers to the composition root: " + ", ".join(offenders)
    assert all("App" not in module.__dict__ for module in app._COMPONENT_MODULES)


def test_review_dispatch_honors_the_host_state_override(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    import app
    from acquisition_model import AcquisitionIntent

    shell = object.__new__(app.App)
    package = SimpleNamespace(nevra="chosen-1.x86_64", repo=SimpleNamespace(name="Chosen repo"))
    shell.selected_packages = [package]
    state = SimpleNamespace(intent=AcquisitionIntent.PACKAGES)
    # A composed class override must not be bypassed through a cached global.
    class_state = Mock(return_value=state)
    monkeypatch.setattr(app.App, "_ui_acquisition_state", class_state)
    assert shell._review_contract_rows() == [
        ("chosen-1.x86_64", "requested", "Chosen repo", "explicit package selection")]
    class_state.assert_called_once_with()
    # Instance injection is also a real capability on the host.
    instance_state = Mock(return_value=state)
    shell._ui_acquisition_state = instance_state
    shell._review_contract_rows()
    instance_state.assert_called_once_with()
    assert class_state.call_count == 1


def test_pick_summary_uses_the_hosts_download_preview():
    from types import SimpleNamespace
    from unittest.mock import Mock

    import app

    shell = object.__new__(app.App)
    shell._pick_mode = lambda: True
    shell.last_result = SimpleNamespace(selected=[SimpleNamespace(nevra="chosen", size=42)])
    shell.picked = {"chosen"}
    shell.summary_var = Mock()
    shell._refresh_download_size_preview = Mock()
    shell._sync_review_action_states = Mock()
    shell._update_pick_summary()
    shell._refresh_download_size_preview.assert_called_once_with(shell.last_result)
    shell._sync_review_action_states.assert_called_once_with()


def test_facade_dependency_patching_still_reaches_component_consumers(monkeypatch):
    from types import SimpleNamespace

    import app
    from feathered_app.application.tools import ToolsMixin

    shell = SimpleNamespace(
        download_size_var=SimpleNamespace(set=lambda value: values.append(value)),
        _pick_mode=lambda: False, _mirror_mode=lambda: False,
    )
    values = []
    monkeypatch.setattr(app, "human_size", lambda size: f"patched-{size}")
    ToolsMixin._refresh_download_size_preview(
        shell, SimpleNamespace(selected=[SimpleNamespace(size=42)]))
    assert values == ["Planned package payload: patched-42 across 1 package(s)."]


def test_component_callbacks_execute_without_importing_app(tmp_path):
    import subprocess

    probe = """
import sys
sys.path.insert(0, sys.argv[1])
from acquisition_model import AcquisitionIntent
from feathered_app.application.sources import SourcesMixin
from feathered_app.application.selection import SelectionMixin

class Host(SourcesMixin, SelectionMixin):
    def _acquisition_intent(self):
        return AcquisitionIntent.REPOSITORY_MIRROR

    def repository_rows(self):
        return self.repo_rows

host = Host()
host.repo_rows = []
host.mirror_repos = set()
assert 'app' not in sys.modules
assert host._acquisition_state().intent is AcquisitionIntent.REPOSITORY_MIRROR
assert host._review_contract_rows() == []
assert 'app' not in sys.modules
print('Component callbacks executed without the App composition root')
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", probe, str(ROOT)],
        cwd=tmp_path, text=True, capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Component callbacks executed" in result.stdout
