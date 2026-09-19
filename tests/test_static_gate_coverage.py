from __future__ import annotations

import inspect
from pathlib import Path
from typing import Sequence, get_args, get_type_hints

import core
import bundle_support
import check_python_sources
from root_requests import RootInput

ROOT = Path(__file__).resolve().parents[1]


def test_rpm_resolver_compatibility_facade_retains_static_contract() -> None:
    hints = get_type_hints(core.resolve)
    assert hints["root_requests"] == Sequence[RootInput]
    assert hints["packages"] == Sequence[core.Package]
    assert hints["options"] == core.BuildOptions[core.TargetInventory]
    assert hints["reporter"] is core.Reporter
    assert hints["return"] is core.ResolutionResult
    signature = inspect.signature(core.resolve)
    assert all(parameter.annotation is not inspect.Parameter.empty
               for parameter in signature.parameters.values())
    assert signature.return_annotation is not inspect.Signature.empty


def test_baseline_split_facade_preserves_package_family_type() -> None:
    hints = get_type_hints(core.split_against_baseline)
    package_type = get_args(hints["selected"])[0]
    first_return, second_return = get_args(hints["return"])
    assert get_args(first_return)[0] is package_type
    assert get_args(second_return)[0] is package_type
    assert package_type.__bound__ is bundle_support.BaselinePackage


def test_python_source_gate_discovers_new_modules_automatically(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "source_manifest.py").write_text("value = 1\n", encoding="utf-8")
    (root / "newly_extracted.py").write_text("value = 2\n", encoding="utf-8")
    package = root / "pkg"
    package.mkdir()
    (package / "nested.py").write_text("value = 3\n", encoding="utf-8")
    discovered = {relative for relative, _path in check_python_sources.python_sources(root)}
    assert "newly_extracted.py" in discovered
    assert "pkg/nested.py" in discovered
    assert check_python_sources.check_python_sources(root) == []


def test_python_source_gate_rejects_syntax_errors(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    failures = check_python_sources.check_python_sources(root)
    assert len(failures) == 1
    assert failures[0].startswith("broken.py:")


def test_release_and_static_gates_use_automatic_source_syntax_check() -> None:
    static = (ROOT / ".github" / "workflows" / "static-analysis.yml").read_text(encoding="utf-8")
    windows = (ROOT / ".github" / "workflows" / "windows-release.yml").read_text(encoding="utf-8")
    build = (ROOT / "build_exe.bat").read_text(encoding="utf-8")
    assert "python check_python_sources.py" in static
    assert "& $python check_python_sources.py" in windows
    assert '"%PY%" check_python_sources.py' in build
    stale = "compileall -q app.py core.py apt_core.py arch_core.py"
    assert stale not in windows
    assert stale not in build


def test_core_no_longer_needs_b023_exemption() -> None:
    ruff = (ROOT / "ruff.toml").read_text(encoding="utf-8")
    assert '"core.py" = ["B023"]' not in ruff
