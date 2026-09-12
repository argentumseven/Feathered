"""Source startup must not depend on Python adding cwd/script paths."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_source_app_imports_in_isolated_python_from_another_directory(tmp_path):
    # -I ignores PYTHONPATH and omits both cwd and the script directory.
    # Use a non-main name to exercise all composition imports without a display.
    # The old app.py raises ModuleNotFoundError: feathered_app here.
    probe = """
import pathlib
import runpy
import sys
source = pathlib.Path(sys.argv[1]).resolve()
assert str(source.parent) not in sys.path
namespace = runpy.run_path(str(source), run_name="feathered_launch_probe")
import feathered_app.context
assert pathlib.Path(feathered_app.context.__file__).resolve() == source.parent / "feathered_app" / "context.py"
assert namespace["App"].__name__ == "App"
print("Source application imports succeeded")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", probe, str(ROOT / "app.py")],
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Source application imports succeeded" in result.stdout
