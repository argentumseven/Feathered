from __future__ import annotations

import pickle
import subprocess
import sys
from pathlib import Path

import core
import core_models


MODEL_NAMES = (
    "ArtifactVerification",
    "BuildOptions",
    "Package",
    "ProviderMatch",
    "RepoDataRef",
    "RepoTrust",
    "Requirement",
    "ResolutionResult",
    "TargetInventory",
)


def test_core_keeps_historical_model_imports() -> None:
    for name in MODEL_NAMES:
        assert getattr(core, name) is getattr(core_models, name)


def test_core_models_does_not_import_core_at_runtime() -> None:
    root = Path(core_models.__file__).resolve().parent
    probe = (
        "import sys; "
        "import core_models; "
        "assert 'core' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", probe], cwd=root, check=True)


def test_extracted_models_preserve_basic_behavior() -> None:
    repo = core.RepoSpec("Example", "https://example.invalid/repo")
    requirement = core.Requirement("libdemo", version="1.2")
    package = core.Package(
        name="demo",
        arch="x86_64",
        epoch="0",
        version="1.2",
        release="3",
        location="Packages/demo.rpm",
        checksum_type="sha256",
        checksum="deadbeef",
        repo=repo,
        size=7,
        requires=[requirement],
    )
    assert requirement.evr == ("0", "1.2", "")
    assert package.nevra == "demo-1.2-3.x86_64"
    assert package.evr == ("0", "1.2", "3")
    assert package.evr_text == "1.2-3"

    result = core.ResolutionResult(selected=[package], unresolved=[], roots=[package])
    assert result.total_size == 7
    assert core.BuildOptions().retries == 3


def test_mutable_defaults_remain_independent() -> None:
    left = core.ArtifactVerification()
    right = core.ArtifactVerification()
    left.notes.append("left-only")
    assert right.notes == []

    first = core.TargetInventory()
    second = core.TargetInventory()
    first.nevras.add("demo-1.2-3.x86_64")
    assert second.nevras == set()


def test_models_are_pickle_round_trip_compatible_through_core_aliases() -> None:
    repo = core.RepoSpec("Example", "https://example.invalid/repo")
    package = core.Package(
        "demo", "x86_64", "0", "1", "1",
        "demo.rpm", "sha256", "deadbeef", repo,
    )
    restored = pickle.loads(pickle.dumps(package))
    assert type(restored) is core.Package
    assert restored.nevra == package.nevra
