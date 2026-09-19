from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Sequence, get_args, get_type_hints

import core
import artifact_verification
import bundle_support
import check_python_sources
import package_acquisition
import package_contracts
import package_transfer
import repository_loader
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


def test_shared_artifact_helpers_are_package_family_neutral() -> None:
    core_hints = get_type_hints(core.verify_package_artifact)
    engine_hints = get_type_hints(artifact_verification.verify_package_artifact)
    acquisition_hints = get_type_hints(package_acquisition.copy_or_download)
    transfer_hints = get_type_hints(package_transfer.package_download_limit)
    assert core_hints["pkg"] is package_contracts.PackageArtifact
    assert engine_hints["pkg"] is package_contracts.PackageArtifact
    assert acquisition_hints["pkg"] is package_contracts.PackageArtifact
    assert transfer_hints["pkg"] is package_contracts.PackageArtifact
    assert package_contracts.PackageArtifact in core.DownloadPackage.__mro__



def test_repository_loader_service_callbacks_match_shared_artifact_contract() -> None:
    annotations = get_type_hints(repository_loader.RepositoryLoaderServices)
    digest_callback = annotations["package_has_selected_digest"]
    verification_callback = annotations["artifact_verification"]
    digest_args = get_args(digest_callback)
    verification_args = get_args(verification_callback)
    assert digest_args[0] == [package_contracts.PackageArtifact]
    assert verification_args[0] == [package_contracts.PackageArtifact]


def test_extracted_service_bundles_do_not_require_object_artifact_callbacks() -> None:
    service_sources = (
        ROOT / "repository_loader.py",
        ROOT / "package_acquisition.py",
        ROOT / "artifact_verification.py",
    )
    offenders: list[str] = []
    for path in service_sources:
        source = path.read_text(encoding="utf-8")
        if "Callable[[object]" in source:
            offenders.append(path.name)
    assert offenders == []

def _core_surface_used_by(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "core":
            names.update(alias.name for alias in node.names)
        elif (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
              and node.value.id == "core"):
            names.add(node.attr)
    return names


def _contains_concrete_rpm_package(annotation: object) -> bool:
    if annotation is core.Package:
        return True
    return any(_contains_concrete_rpm_package(item) for item in get_args(annotation))


def test_shared_apt_arch_core_surface_does_not_hardcode_rpm_package() -> None:
    apt_surface = _core_surface_used_by(ROOT / "apt_core.py")
    arch_surface = _core_surface_used_by(ROOT / "arch_core.py")
    offenders: list[str] = []
    for name in sorted(apt_surface | arch_surface):
        value = getattr(core, name, None)
        if not inspect.isfunction(value):
            continue
        hints = get_type_hints(value)
        if any(_contains_concrete_rpm_package(annotation) for annotation in hints.values()):
            # RPM-only resolver/publication APIs are allowed only when neither
            # non-RPM backend consumes them. Any APT/Arch consumer must use a
            # structural or generic package contract.
            offenders.append(name)
    assert offenders == []


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
    assert static.index("Host contract acceptance and rejection") < static.index("- name: mypy")
    assert "package_contracts.py" in (ROOT / "mypy.ini").read_text(encoding="utf-8")
    stale = "compileall -q app.py core.py apt_core.py arch_core.py"
    assert stale not in windows
    assert stale not in build


def test_core_no_longer_needs_b023_exemption() -> None:
    ruff = (ROOT / "ruff.toml").read_text(encoding="utf-8")
    assert '"core.py" = ["B023"]' not in ruff
