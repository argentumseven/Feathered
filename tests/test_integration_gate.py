"""The CI gate must reject skipped/deselected tests and malformed shell steps."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("body,arguments,code", [
    ("def test_case(): pass\n", [], 0),
    ("import pytest\ndef test_case(): pytest.skip('no tool')\n", [], 1),
    ("import pytest\npytest.skip('no module', allow_module_level=True)\n", [], 1),
    ("def test_case(): pass\n", ["-k", "absent"], 1),
])
def test_required_tests_must_execute(tmp_path, body, arguments, code):
    path = tmp_path / "test_fixture.py"
    path.write_text(body)
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "require_executed_tests",
                             str(path), *arguments], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == code, result.stdout + result.stderr


def test_native_workflow_shell_steps_parse_individually():
    if not shutil.which("bash"):
        pytest.skip("bash is required to parse Linux workflow steps")
    workflow = yaml.safe_load((ROOT / ".github/workflows/native-conformance.yml").read_text())
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "run" not in step:
                continue
            result = subprocess.run(["bash", "-n"], input=step["run"], text=True,
                                    capture_output=True, timeout=10)
            assert result.returncode == 0, (step.get("name"), result.stderr)
